use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub host: String,
    pub port: u16,
    pub bind_addr: String,
    pub allow_remote: bool,
    pub auth_enabled: bool,
    pub auth_token: Option<String>,
    pub dispatch_timeout_ms: u64,
    pub console_log_enabled: bool,
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
    console_title: Option<String>,
}

impl RuntimeConfig {
    pub fn load() -> Self {
        let json_config = load_json_config().unwrap_or_default();
        let kv_config = load_key_value_config().unwrap_or_default();

        let bind_addr = env_string("CE_PLUGIN_BIND_ADDR")
            .or_else(|| kv_string(&kv_config, "CE_PLUGIN_BIND_ADDR"))
            .unwrap_or_else(|| {
                let host = env_string("CE_PLUGIN_HOST")
                    .or_else(|| json_config.server.host.clone())
                    .or_else(|| kv_string(&kv_config, "CE_PLUGIN_HOST"))
                    .unwrap_or_else(|| "127.0.0.1".to_owned());
                let port = env_u16("CE_PLUGIN_PORT")
                    .or(json_config.server.port)
                    .or_else(|| kv_u16(&kv_config, "CE_PLUGIN_PORT"))
                    .unwrap_or(18765);
                format_bind_addr(host.as_str(), port)
            });

        let (host, port) =
            parse_bind_addr(bind_addr.as_str()).unwrap_or_else(|| ("127.0.0.1".to_owned(), 18765));
        let allow_remote = !is_loopback_host(host.as_str());

        let auth_enabled = env_bool("CE_PLUGIN_AUTH_ENABLED")
            .or(json_config.auth.enabled)
            .or_else(|| kv_bool(&kv_config, "CE_PLUGIN_AUTH_ENABLED"))
            .unwrap_or(false);
        let auth_token = env_string("CE_PLUGIN_AUTH_TOKEN")
            .or_else(|| json_config.auth.token.clone())
            .or_else(|| kv_string(&kv_config, "CE_PLUGIN_AUTH_TOKEN"))
            .filter(|value| !value.trim().is_empty());

        Self {
            host: host.clone(),
            port,
            bind_addr: format_bind_addr(host.as_str(), port),
            allow_remote,
            auth_enabled,
            auth_token,
            dispatch_timeout_ms: env_u64("CE_PLUGIN_DISPATCH_TIMEOUT_MS")
                .or(json_config.runtime.dispatch_timeout_ms)
                .or_else(|| kv_u64(&kv_config, "CE_PLUGIN_DISPATCH_TIMEOUT_MS"))
                .filter(|value| *value > 0)
                .unwrap_or(5_000),
            console_log_enabled: env_bool("CE_PLUGIN_CONSOLE_LOG")
                .map(|value| !value)
                .or_else(|| json_config.runtime.console_log_enabled)
                .or_else(|| kv_bool(&kv_config, "CE_PLUGIN_CONSOLE_LOG").map(|value| !value))
                .unwrap_or(true),
            console_title: env_string("CE_PLUGIN_CONSOLE_TITLE")
                .or_else(|| json_config.runtime.console_title.clone())
                .or_else(|| kv_string(&kv_config, "CE_PLUGIN_CONSOLE_TITLE"))
                .unwrap_or_else(|| "流云MCP插件".to_owned()),
            server_name: "cheatengine-ce-plugin".to_owned(),
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
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
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn env_bool(key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|value| parse_bool(value.as_str()))
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn env_u16(key: &str) -> Option<u16> {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
}

fn kv_string(file_config: &HashMap<String, String>, key: &str) -> Option<String> {
    file_config
        .get(key)
        .cloned()
        .filter(|value| !value.trim().is_empty())
}

fn kv_bool(file_config: &HashMap<String, String>, key: &str) -> Option<bool> {
    file_config
        .get(key)
        .and_then(|value| parse_bool(value.as_str()))
}

fn kv_u64(file_config: &HashMap<String, String>, key: &str) -> Option<u64> {
    file_config
        .get(key)
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn kv_u16(file_config: &HashMap<String, String>, key: &str) -> Option<u16> {
    file_config
        .get(key)
        .and_then(|value| value.trim().parse::<u16>().ok())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn load_json_config() -> Option<JsonConfig> {
    let config_path = resolve_json_config_path()?;
    let content = fs::read_to_string(config_path).ok()?;
    serde_json::from_str::<JsonConfig>(&content).ok()
}

fn load_key_value_config() -> Option<HashMap<String, String>> {
    let config_path = resolve_kv_config_path()?;
    let content = fs::read_to_string(config_path).ok()?;
    Some(parse_key_value_config(content.as_str()))
}

fn resolve_json_config_path() -> Option<PathBuf> {
    let base_dir = plugin_base_dir().or_else(executable_base_dir)?;
    let candidates = [
        base_dir.join("ce_plugin.json"),
        base_dir.join("ce_plugin.config.json"),
    ];

    candidates.into_iter().find(|path| path.is_file())
}

fn resolve_kv_config_path() -> Option<PathBuf> {
    let base_dir = plugin_base_dir().or_else(executable_base_dir)?;
    let candidates = [
        base_dir.join("ce_plugin.config"),
        base_dir.join("ce_plugin.env"),
    ];

    candidates.into_iter().find(|path| path.is_file())
}

fn parse_key_value_config(content: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        let mut value = value.trim().to_owned();
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len().saturating_sub(1)].to_owned();
        }
        values.insert(key.to_owned(), value);
    }

    values
}

fn parse_bind_addr(value: &str) -> Option<(String, u16)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_owned();
        let port_text = rest[end + 1..].strip_prefix(':')?;
        let port = port_text.parse::<u16>().ok()?;
        return Some((host, port));
    }

    let (host, port_text) = trimmed.rsplit_once(':')?;
    Some((host.to_owned(), port_text.parse::<u16>().ok()?))
}

fn format_bind_addr(host: &str, port: u16) -> String {
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

#[cfg(windows)]
fn plugin_base_dir() -> Option<PathBuf> {
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
    PathBuf::from(path).parent().map(Path::to_path_buf)
}

#[cfg(not(windows))]
fn plugin_base_dir() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::{format_bind_addr, parse_bind_addr, parse_key_value_config};

    #[test]
    fn parses_simple_key_value_config() {
        let values = parse_key_value_config(
            r#"
            # comment
            CE_PLUGIN_BIND_ADDR=0.0.0.0:18765
            CE_PLUGIN_AUTH_ENABLED=1
            CE_PLUGIN_CONSOLE_TITLE="流云MCP插件"
            "#,
        );

        assert_eq!(
            values.get("CE_PLUGIN_BIND_ADDR").map(String::as_str),
            Some("0.0.0.0:18765")
        );
        assert_eq!(
            values.get("CE_PLUGIN_AUTH_ENABLED").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            values.get("CE_PLUGIN_CONSOLE_TITLE").map(String::as_str),
            Some("流云MCP插件")
        );
    }

    #[test]
    fn parses_bind_addr() {
        assert_eq!(
            parse_bind_addr("127.0.0.1:18765"),
            Some(("127.0.0.1".to_owned(), 18765))
        );
        assert_eq!(
            parse_bind_addr("[::1]:18765"),
            Some(("::1".to_owned(), 18765))
        );
        assert_eq!(format_bind_addr("::1", 18765), "[::1]:18765");
    }
}
