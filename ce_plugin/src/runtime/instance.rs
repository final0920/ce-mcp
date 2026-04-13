use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::{plugin_base_dir, plugin_module_path};
use super::RuntimeConfig;

pub struct RuntimeInstance {
    instance_id: String,
    ce_process_id: u32,
    plugin_id: i32,
    started_at_unix_ms: u64,
    dll_path: Option<PathBuf>,
    debug_log_path: Option<PathBuf>,
    requested_bind_addr: String,
    bind_addr: RwLock<String>,
}

impl RuntimeInstance {
    pub fn new(plugin_id: i32, config: &RuntimeConfig) -> Self {
        let ce_process_id = std::process::id();
        let started_at_unix_ms = current_unix_ms();
        let dll_path = plugin_module_path();
        let instance_id = generate_instance_id(
            ce_process_id,
            plugin_id,
            started_at_unix_ms,
            dll_path.as_deref(),
        );
        let requested_bind_addr = config.requested_bind_addr.clone();
        let debug_log_path = if config.debug_enabled {
            build_debug_log_path(ce_process_id, instance_id.as_str())
        } else {
            None
        };

        Self {
            instance_id,
            ce_process_id,
            plugin_id,
            started_at_unix_ms,
            dll_path,
            debug_log_path,
            requested_bind_addr: requested_bind_addr.clone(),
            bind_addr: RwLock::new(requested_bind_addr),
        }
    }

    pub fn instance_id(&self) -> &str {
        self.instance_id.as_str()
    }

    pub fn ce_process_id(&self) -> u32 {
        self.ce_process_id
    }

    pub fn plugin_id(&self) -> i32 {
        self.plugin_id
    }

    pub fn started_at_unix_ms(&self) -> u64 {
        self.started_at_unix_ms
    }

    pub fn dll_path(&self) -> Option<&Path> {
        self.dll_path.as_deref()
    }

    pub fn debug_log_path(&self) -> Option<&Path> {
        self.debug_log_path.as_deref()
    }

    pub fn requested_bind_addr(&self) -> &str {
        self.requested_bind_addr.as_str()
    }

    pub fn bind_addr(&self) -> String {
        self.bind_addr
            .read()
            .map(|value| value.clone())
            .unwrap_or_else(|_| self.requested_bind_addr.clone())
    }

    pub fn set_bind_addr(&self, bind_addr: impl Into<String>) {
        if let Ok(mut guard) = self.bind_addr.write() {
            *guard = bind_addr.into();
        }
    }
}

fn build_debug_log_path(ce_process_id: u32, instance_id: &str) -> Option<PathBuf> {
    let base_dir = plugin_base_dir()?;
    let short_id = &instance_id[..8];
    Some(base_dir.join(format!(
        "ce_plugin.{}.{}.debug.log",
        ce_process_id, short_id
    )))
}

fn generate_instance_id(
    ce_process_id: u32,
    plugin_id: i32,
    started_at_unix_ms: u64,
    dll_path: Option<&Path>,
) -> String {
    let material = format!(
        "{}:{}:{}:{}",
        ce_process_id,
        plugin_id,
        started_at_unix_ms,
        dll_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "unknown-dll".to_owned())
    );
    format!("{:x}", md5::compute(material.as_bytes()))
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::RuntimeInstance;
    use crate::runtime::RuntimeConfig;

    #[test]
    fn instance_uses_instance_specific_log_name() {
        let config = RuntimeConfig {
            host: "127.0.0.1".to_owned(),
            port: 0,
            requested_bind_addr: "127.0.0.1:0".to_owned(),
            allow_remote: false,
            auth_enabled: false,
            auth_token: None,
            dispatch_timeout_ms: 5_000,
            console_log_enabled: true,
            debug_enabled: true,
            console_title: "test".to_owned(),
            server_name: "ce".to_owned(),
            server_version: "0.3.0".to_owned(),
        };

        let instance = RuntimeInstance::new(7, &config);

        assert_eq!(instance.plugin_id(), 7);
        assert_eq!(instance.requested_bind_addr(), "127.0.0.1:0");
        assert!(!instance.instance_id().is_empty());
    }
}
