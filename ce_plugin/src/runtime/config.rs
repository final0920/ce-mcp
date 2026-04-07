use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub bind_addr: String,
    pub allow_remote: bool,
    pub dispatch_timeout_ms: u64,
    pub console_log_enabled: bool,
    pub console_title: String,
    pub server_name: String,
    pub server_version: String,
}

impl RuntimeConfig {
    pub fn load() -> Self {
        let file_config = load_file_config().unwrap_or_default();

        Self {
            bind_addr: string_setting(&file_config, "CE_PLUGIN_BIND_ADDR")
                .unwrap_or_else(|| "127.0.0.1:18765".to_owned()),
            allow_remote: bool_setting(&file_config, "CE_PLUGIN_ALLOW_REMOTE").unwrap_or(false),
            dispatch_timeout_ms: u64_setting(&file_config, "CE_PLUGIN_DISPATCH_TIMEOUT_MS")
                .filter(|value| *value > 0)
                .unwrap_or(5_000),
            console_log_enabled: !bool_setting(&file_config, "CE_PLUGIN_CONSOLE_LOG")
                .map(|value| !value)
                .unwrap_or(false),
            console_title: string_setting(&file_config, "CE_PLUGIN_CONSOLE_TITLE")
                .unwrap_or_else(|| "流云MCP插件".to_owned()),
            server_name: "cheatengine-ce-plugin".to_owned(),
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

fn string_setting(file_config: &HashMap<String, String>, key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            file_config
                .get(key)
                .cloned()
                .filter(|value| !value.trim().is_empty())
        })
}

fn bool_setting(file_config: &HashMap<String, String>, key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|value| parse_bool(value.as_str()))
        .or_else(|| {
            file_config
                .get(key)
                .and_then(|value| parse_bool(value.as_str()))
        })
}

fn u64_setting(file_config: &HashMap<String, String>, key: &str) -> Option<u64> {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .or_else(|| {
            file_config
                .get(key)
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn load_file_config() -> Option<HashMap<String, String>> {
    let config_path = resolve_config_path()?;
    let content = fs::read_to_string(config_path).ok()?;
    Some(parse_key_value_config(content.as_str()))
}

fn resolve_config_path() -> Option<PathBuf> {
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
        };

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
    use super::parse_key_value_config;

    #[test]
    fn parses_simple_key_value_config() {
        let values = parse_key_value_config(
            r#"
            # comment
            CE_PLUGIN_BIND_ADDR=0.0.0.0:18765
            CE_PLUGIN_ALLOW_REMOTE=1
            CE_PLUGIN_CONSOLE_TITLE="流云MCP插件"
            "#,
        );

        assert_eq!(
            values.get("CE_PLUGIN_BIND_ADDR").map(String::as_str),
            Some("0.0.0.0:18765")
        );
        assert_eq!(
            values.get("CE_PLUGIN_ALLOW_REMOTE").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            values.get("CE_PLUGIN_CONSOLE_TITLE").map(String::as_str),
            Some("流云MCP插件")
        );
    }
}
