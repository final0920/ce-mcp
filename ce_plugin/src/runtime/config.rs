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
        Self {
            bind_addr: std::env::var("CE_PLUGIN_BIND_ADDR")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "127.0.0.1:18765".to_owned()),
            allow_remote: env_true("CE_PLUGIN_ALLOW_REMOTE"),
            dispatch_timeout_ms: std::env::var("CE_PLUGIN_DISPATCH_TIMEOUT_MS")
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(5_000),
            console_log_enabled: !env_false("CE_PLUGIN_CONSOLE_LOG"),
            console_title: std::env::var("CE_PLUGIN_CONSOLE_TITLE")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "流云MCP插件".to_owned()),
            server_name: "cheatengine-ce-plugin".to_owned(),
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

fn env_false(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(false)
}

fn env_true(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}
