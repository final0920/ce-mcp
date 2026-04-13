use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub host: String,
    pub port: u16,
    pub requested_bind_addr: String,
    pub allow_remote: bool,
    pub auth_enabled: bool,
    pub auth_token: Option<String>,
    pub dispatch_timeout_ms: u64,
    pub console_log_enabled: bool,
    pub debug_enabled: bool,
    pub console_title: String,
    pub server_name: String,
    pub server_version: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct JsonConfig {
    #[serde(default)]
    server: JsonServerConfig,
    #[serde(default)]
    auth: JsonAuthConfig,
    #[serde(default)]
    runtime: JsonRuntimeConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct JsonServerConfig {
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct JsonAuthConfig {
    enabled: Option<bool>,
    token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct JsonRuntimeConfig {
    dispatch_timeout_ms: Option<u64>,
    console_log_enabled: Option<bool>,
    debug_enabled: Option<bool>,
    console_title: Option<String>,
}

impl RuntimeConfig {
    pub fn load() -> Self {
        Self::from_json_config(load_json_config().unwrap_or_default())
    }

    pub fn validate_startup_policy(&self) -> Result<(), String> {
        if self.is_public_bind() && (!self.auth_enabled || self.auth_token.is_none()) {
            return Err(
                "refusing to start: public bind requires auth.enabled=true with non-empty token"
                    .to_owned(),
            );
        }

        Ok(())
    }

    pub fn is_public_bind(&self) -> bool {
        is_public_host(self.host.as_str())
    }

    pub fn uses_auto_port(&self) -> bool {
        self.port == 0
    }

    fn from_json_config(json_config: JsonConfig) -> Self {
        let host = json_config
            .server
            .host
            .clone()
            .unwrap_or_else(|| "127.0.0.1".to_owned());
        let port = json_config.server.port.unwrap_or(0);

        Self {
            host: host.clone(),
            port,
            requested_bind_addr: format_bind_addr(host.as_str(), port),
            allow_remote: !is_loopback_host(host.as_str()),
            auth_enabled: json_config.auth.enabled.unwrap_or(false),
            auth_token: json_config
                .auth
                .token
                .clone()
                .filter(|value| !value.trim().is_empty()),
            dispatch_timeout_ms: json_config
                .runtime
                .dispatch_timeout_ms
                .filter(|value| *value > 0)
                .unwrap_or(5_000),
            console_log_enabled: json_config.runtime.console_log_enabled.unwrap_or(true),
            debug_enabled: json_config.runtime.debug_enabled.unwrap_or(false),
            console_title: json_config
                .runtime
                .console_title
                .clone()
                .unwrap_or_else(|| "流云MCP插件".to_owned()),
            server_name: "cheatengine-ce-plugin".to_owned(),
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

fn load_json_config() -> Option<JsonConfig> {
    let config_path = resolve_json_config_path()?;
    let content = fs::read_to_string(config_path).ok()?;
    serde_json::from_str::<JsonConfig>(&content).ok()
}

fn resolve_json_config_path() -> Option<PathBuf> {
    let base_dir = plugin_base_dir().or_else(executable_base_dir)?;
    let candidates = [
        base_dir.join("ce_plugin.json"),
        base_dir.join("ce_plugin.config.json"),
    ];

    candidates.into_iter().find(|path| path.is_file())
}

pub(crate) fn format_bind_addr(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn is_loopback_host(host: &str) -> bool {
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }

    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn is_public_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return false;
    }
    if matches!(host, "0.0.0.0" | "::") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => !(ip.is_private() || ip.is_loopback()),
        Ok(IpAddr::V6(ip)) => !(ip.is_loopback() || ip.is_unique_local()),
        Err(_) => true,
    }
}

fn executable_base_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

pub(crate) fn plugin_base_dir() -> Option<PathBuf> {
    plugin_module_path().and_then(|path| path.parent().map(Path::to_path_buf))
}

#[cfg(windows)]
pub(crate) fn plugin_module_path() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    type Hmodule = *mut core::ffi::c_void;

    unsafe extern "system" {
        fn GetModuleHandleExW(
            flags: u32,
            module_name: *const core::ffi::c_void,
            module: *mut Hmodule,
        ) -> i32;
        fn GetModuleFileNameW(module: Hmodule, filename: *mut u16, size: u32) -> u32;
    }

    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002;
    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;

    fn anchor() {}

    let mut module: Hmodule = core::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            anchor as *const () as *const core::ffi::c_void,
            &mut module,
        )
    };
    if ok == 0 || module.is_null() {
        return None;
    }

    let mut buffer = vec![0u16; 260];
    let len = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 {
        return None;
    }
    buffer.truncate(len as usize);
    let path = OsString::from_wide(&buffer);
    Some(PathBuf::from(path))
}

#[cfg(not(windows))]
pub(crate) fn plugin_module_path() -> Option<PathBuf> {
    None
}

pub(crate) fn local_app_data_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::{JsonConfig, JsonRuntimeConfig, JsonServerConfig, RuntimeConfig};

    #[test]
    fn defaults_to_auto_port() {
        let config = RuntimeConfig::from_json_config(JsonConfig::default());

        assert_eq!(config.port, 0);
        assert_eq!(config.requested_bind_addr, "127.0.0.1:0");
        assert!(config.uses_auto_port());
    }

    #[test]
    fn keeps_explicit_fixed_port() {
        let config = RuntimeConfig::from_json_config(JsonConfig {
            server: JsonServerConfig {
                host: Some("127.0.0.1".to_owned()),
                port: Some(18765),
            },
            auth: Default::default(),
            runtime: JsonRuntimeConfig::default(),
        });

        assert_eq!(config.port, 18765);
        assert_eq!(config.requested_bind_addr, "127.0.0.1:18765");
        assert!(!config.uses_auto_port());
    }
}
