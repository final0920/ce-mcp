use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::app_state::AppState;
use super::config::local_app_data_dir;
use super::console;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
const STALE_TTL: Duration = Duration::from_secs(15);
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(400);
const DISCOVERY_PROBE_HEADER: &str = "X-CE-MCP-Discovery: 1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceRegistryRecord {
    pub schema_version: u32,
    pub instance_id: String,
    pub ce_pid: u32,
    pub target_pid: u32,
    pub plugin_id: i32,
    pub bind_addr: String,
    pub requested_bind_addr: String,
    pub dll_path: Option<String>,
    pub debug_log_path: Option<String>,
    pub transport: String,
    pub server_name: String,
    pub server_version: String,
    pub started_at_unix_ms: u64,
    pub last_heartbeat_unix_ms: u64,
}

pub struct InstanceRegistryHandle {
    stop_flag: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    registry_file: PathBuf,
}

impl InstanceRegistryHandle {
    pub fn start(app: Arc<AppState>) -> Result<Self, String> {
        let registry_dir = registry_dir()
            .ok_or_else(|| "instance discovery unavailable: LOCALAPPDATA is not set".to_owned())?;
        fs::create_dir_all(&registry_dir)
            .map_err(|error| format!("failed to create instance registry directory: {}", error))?;

        prune_stale_entries(&registry_dir, Some(app.instance_id()));

        let registry_file = registry_dir.join(registry_file_name(app.ce_process_id()));
        write_record(&registry_file, &app.instance_registry_record())?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop_flag);
        let worker_app = Arc::clone(&app);
        let worker_registry_dir = registry_dir.clone();
        let worker_registry_file = registry_file.clone();

        let worker = thread::Builder::new()
            .name("ce_plugin_discovery".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    prune_stale_entries(&worker_registry_dir, Some(worker_app.instance_id()));

                    if let Err(error) = write_record(
                        &worker_registry_file,
                        &worker_app.instance_registry_record(),
                    ) {
                        console::warn(format!("实例注册表写入失败: {}", error));
                    }

                    thread::sleep(HEARTBEAT_INTERVAL);
                }
            })
            .map_err(|error| format!("failed to spawn instance registry worker: {}", error))?;

        Ok(Self {
            stop_flag,
            worker: Some(worker),
            registry_file,
        })
    }

    pub fn stop(&mut self) -> Result<(), String> {
        self.stop_flag.store(true, Ordering::Relaxed);

        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }

        match fs::remove_file(&self.registry_file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "failed to remove instance registry file: {}",
                error
            )),
        }
    }
}

pub fn registry_dir() -> Option<PathBuf> {
    local_app_data_dir().map(|path| path.join("ce-mcp").join("instances"))
}

fn registry_file_name(ce_process_id: u32) -> String {
    format!("ce-{}.json", ce_process_id)
}

fn write_record(path: &Path, record: &InstanceRegistryRecord) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(record)
        .map_err(|error| format!("failed to serialize instance registry record: {}", error))?;
    let temp_path = path.with_extension("json.tmp");
    fs::write(&temp_path, payload)
        .map_err(|error| format!("failed to write instance registry temp file: {}", error))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("failed to replace instance registry file: {}", error))?;
    }
    fs::rename(&temp_path, path)
        .map_err(|error| format!("failed to finalize instance registry file: {}", error))
}

fn prune_stale_entries(registry_dir: &Path, active_instance_id: Option<&str>) {
    let Ok(entries) = fs::read_dir(registry_dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        let record = match read_record(&path) {
            Some(record) => record,
            None => {
                let _ = fs::remove_file(&path);
                continue;
            }
        };

        if active_instance_id
            .map(|instance_id| instance_id == record.instance_id)
            .unwrap_or(false)
        {
            continue;
        }

        if !record_is_live(&record) {
            let _ = fs::remove_file(&path);
        }
    }
}

fn read_record(path: &Path) -> Option<InstanceRegistryRecord> {
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str::<InstanceRegistryRecord>(&content).ok()
}

fn record_is_live(record: &InstanceRegistryRecord) -> bool {
    if record.bind_addr.trim().is_empty() {
        return false;
    }
    if record_expired(record, current_unix_ms()) {
        return false;
    }
    if !process_exists(record.ce_pid) {
        return false;
    }

    probe_health(record)
}

fn record_expired(record: &InstanceRegistryRecord, now_unix_ms: u64) -> bool {
    now_unix_ms.saturating_sub(record.last_heartbeat_unix_ms) > STALE_TTL.as_millis() as u64
}

fn probe_health(record: &InstanceRegistryRecord) -> bool {
    let Ok(addr) = SocketAddr::from_str(record.bind_addr.as_str()) else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, HEALTH_PROBE_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(HEALTH_PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HEALTH_PROBE_TIMEOUT));

    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {}\r\n{}\r\nConnection: close\r\n\r\n",
        record.bind_addr, DISCOVERY_PROBE_HEADER
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }

    let Some(body) = response.split("\r\n\r\n").nth(1) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<Value>(body) else {
        return false;
    };

    json.get("instance_id").and_then(Value::as_str) == Some(record.instance_id.as_str())
        && json.get("ce_pid").and_then(Value::as_u64) == Some(record.ce_pid as u64)
}

#[cfg(windows)]
fn process_exists(pid: u32) -> bool {
    use core::ffi::c_void;

    type Handle = *mut c_void;

    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit_handle: i32, process_id: u32) -> Handle;
        fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    if pid == 0 {
        return false;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }

    let mut exit_code = 0_u32;
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) != 0 };
    unsafe {
        let _ = CloseHandle(handle);
    }

    ok && exit_code == STILL_ACTIVE
}

#[cfg(not(windows))]
fn process_exists(pid: u32) -> bool {
    pid != 0
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{record_expired, registry_file_name, InstanceRegistryRecord};

    #[test]
    fn registry_file_name_uses_ce_pid() {
        assert_eq!(registry_file_name(4321), "ce-4321.json");
    }

    #[test]
    fn heartbeat_ttl_marks_old_records_as_stale() {
        let record = InstanceRegistryRecord {
            schema_version: 1,
            instance_id: "abc".to_owned(),
            ce_pid: 100,
            target_pid: 200,
            plugin_id: 1,
            bind_addr: "127.0.0.1:20000".to_owned(),
            requested_bind_addr: "127.0.0.1:0".to_owned(),
            dll_path: None,
            debug_log_path: None,
            transport: "http".to_owned(),
            server_name: "ce".to_owned(),
            server_version: "0.3.0".to_owned(),
            started_at_unix_ms: 10,
            last_heartbeat_unix_ms: 10,
        };

        assert!(record_expired(&record, 30_000));
        assert!(!record_expired(&record, 10_500));
    }
}
