pub(crate) const SOURCE_LABEL: &str = "embedded:ce_plugin/src/lua";

const BOOTSTRAP_LUA: &str = include_str!("bootstrap.lua");
const PROTOCOL_LUA: &str = include_str!("protocol.lua");
const COMMON_LUA: &str = include_str!("common.lua");
const DEBUG_LUA: &str = include_str!("debug.lua");
const SCRIPT_LUA: &str = include_str!("script.lua");
const DISPATCH_LUA: &str = include_str!("dispatch.lua");
const BRIDGE_LUA: &str = include_str!("bridge.lua");
const TRANSPORT_LUA: &str = include_str!("transport.lua");
const RUNTIME_LUA: &str = include_str!("runtime.lua");

pub(crate) fn bootstrap_source() -> String {
    let bootstrap = BOOTSTRAP_LUA.replace("__CE_MCP_VERSION__", env!("CARGO_PKG_VERSION"));
    format!(
        "{bootstrap}\n\n{PROTOCOL_LUA}\n\n{COMMON_LUA}\n\n{DEBUG_LUA}\n\n{SCRIPT_LUA}\n\n{DISPATCH_LUA}\n\n{BRIDGE_LUA}\n\n{TRANSPORT_LUA}\n\n{RUNTIME_LUA}"
    )
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
        assert!(source.contains("v0.2.0 modular backend layout"));
        assert!(source.contains("__ce_mcp_embedded_transport_submit_json"));
        assert!(source.contains("createLoopbackTransport"));
        assert!(!source.contains("StartMCPBridge()"));
        assert!(!source.contains("local function PipeWorker(thread)"));
        assert_eq!(SOURCE_LABEL, "embedded:ce_plugin/src/lua");
    }
}
