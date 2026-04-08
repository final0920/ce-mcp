pub(crate) const SOURCE_LABEL: &str = "embedded:ce_plugin/src/lua";

const BOOTSTRAP_LUA: &str = include_str!("bootstrap.lua");
const PROTOCOL_LUA: &str = include_str!("protocol.lua");
const BRIDGE_LUA: &str = include_str!("bridge.lua");

pub(crate) fn bootstrap_source() -> String {
    let bootstrap = BOOTSTRAP_LUA.replace("__CE_MCP_VERSION__", env!("CARGO_PKG_VERSION"));
    format!("{bootstrap}\n\n{PROTOCOL_LUA}\n\n{BRIDGE_LUA}")
}

#[cfg(test)]
mod tests {
    use super::{bootstrap_source, SOURCE_LABEL};

    #[test]
    fn bootstrap_source_uses_embedded_assets() {
        let source = bootstrap_source();
        assert!(source.contains("local VERSION = \"0.1.0\""));
        assert!(source.contains("local function dispatch(method, params_json)"));
        assert!(source.contains("local function cleanupZombieState()"));
        assert!(!source.contains("StartMCPBridge()"));
        assert!(!source.contains("local function PipeWorker(thread)"));
        assert_eq!(SOURCE_LABEL, "embedded:ce_plugin/src/lua");
    }
}
