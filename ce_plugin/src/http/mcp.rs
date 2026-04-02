use serde::Deserialize;
use serde_json::{json, Value};

use crate::runtime;
use crate::tools::{self, ToolResponse};

pub struct McpContext<'a> {
    pub plugin_id: i32,
    pub bind_addr: &'a str,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: Option<String>,
    params: Option<Value>,
}

pub fn bootstrap(plugin_id: i32, bind_addr: &str) -> String {
    format!(
        "{{\"status\":\"bootstrapped\",\"plugin_id\":{},\"bind_addr\":\"{}\"}}",
        plugin_id, bind_addr
    )
}

pub fn health_payload(ctx: &McpContext<'_>) -> String {
    let (
        dispatcher_mode,
        dispatcher_available,
        dispatch_timeout_ms,
        console_log_enabled,
        lua_state_export_available,
        script_runtime_ready,
    ) = runtime::app_state()
        .map(|app| {
            (
                app.dispatcher_mode(),
                app.dispatcher_available(),
                app.config().dispatch_timeout_ms,
                app.config().console_log_enabled,
                app.lua_state_export_available(),
                app.script_runtime_ready(),
            )
        })
        .unwrap_or(("uninitialized", false, 0, false, false, false));

    format!(
        "{{\"status\":\"ok\",\"plugin_id\":{},\"bind_addr\":\"{}\",\"transport\":\"http\",\"dispatcher_mode\":\"{}\",\"dispatcher_available\":{},\"dispatch_timeout_ms\":{},\"console_log_enabled\":{},\"lua_state_export_available\":{},\"script_runtime_ready\":{},\"supported_ce_versions\":[\"7.5-x64\",\"7.6-x64\"]}}",
        ctx.plugin_id,
        ctx.bind_addr,
        dispatcher_mode,
        dispatcher_available,
        dispatch_timeout_ms,
        console_log_enabled,
        lua_state_export_available,
        script_runtime_ready
    )
}

pub fn handle_post_mcp(body: &str, ctx: &McpContext<'_>) -> String {
    let parsed = serde_json::from_str::<JsonRpcRequest>(body);
    let request = match parsed {
        Ok(request) => request,
        Err(error) => {
            return jsonrpc_error(Value::Null, -32700, format!("parse error: {}", error));
        }
    };

    let id = request.id.unwrap_or(Value::Null);
    if let Some(version) = request.jsonrpc.as_deref() {
        if version != "2.0" {
            return jsonrpc_error(id, -32600, "invalid request: jsonrpc must be \"2.0\"");
        }
    }

    let method = match request.method {
        Some(method) if !method.trim().is_empty() => method,
        _ => return jsonrpc_error(id, -32600, "invalid request: missing method"),
    };

    let params = request.params.unwrap_or_else(|| json!({}));
    if !(params.is_null() || params.is_array() || params.is_object()) {
        return jsonrpc_error(
            id,
            -32602,
            "invalid params: params must be object, array, or null",
        );
    }
    let params_json = if params.is_null() {
        "{}".to_owned()
    } else {
        params.to_string()
    };

    let response = dispatch_method(&method, params_json.as_str(), ctx);

    if response.success {
        match serde_json::from_str::<Value>(&response.body_json) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string(),
            Err(error) => jsonrpc_error(id, -32603, format!("invalid tool result json: {}", error)),
        }
    } else {
        let (code, message) = map_tool_error(&response.body_json);
        jsonrpc_error(id, code, message)
    }
}

#[allow(dead_code)]
pub fn handle_request(method: &str, params_json: &str) -> ToolResponse {
    tools::dispatch(method, params_json)
}

fn dispatch_method(method: &str, params_json: &str, ctx: &McpContext<'_>) -> ToolResponse {
    if method == "ping" {
        let (
            dispatcher_mode,
            dispatcher_available,
            dispatch_timeout_ms,
            console_log_enabled,
            lua_state_export_available,
            script_runtime_ready,
        ) = runtime::app_state()
            .map(|app| {
                (
                    app.dispatcher_mode(),
                    app.dispatcher_available(),
                    app.config().dispatch_timeout_ms,
                    app.config().console_log_enabled,
                    app.lua_state_export_available(),
                    app.script_runtime_ready(),
                )
            })
            .unwrap_or(("uninitialized", false, 0, false, false, false));

        return ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "message": "pong",
                "plugin_id": ctx.plugin_id,
                "bind_addr": ctx.bind_addr,
                "transport": "http",
                "dispatcher_mode": dispatcher_mode,
                "dispatcher_available": dispatcher_available,
                "dispatch_timeout_ms": dispatch_timeout_ms,
                "console_log_enabled": console_log_enabled,
                "lua_state_export_available": lua_state_export_available,
                "script_runtime_ready": script_runtime_ready
            })
            .to_string(),
        };
    }

    if let Some(app) = runtime::app_state() {
        return app.dispatch_tool(method, params_json);
    }

    tools::dispatch(method, params_json)
}

fn map_tool_error(error: &str) -> (i32, String) {
    if error.starts_with("method not found:") {
        return (-32601, error.to_owned());
    }
    if error.starts_with("main-thread dispatcher executor unavailable:")
        || error.starts_with("serialized dispatcher executor unavailable:")
    {
        return (-32005, error.to_owned());
    }
    if error.starts_with("dispatcher timed out") {
        return (-32006, error.to_owned());
    }
    if error.starts_with("dispatcher is shutting down") {
        return (-32007, error.to_owned());
    }
    if error.starts_with("script execution requires window-message-hook dispatcher mode")
        || error.starts_with("CE get_lua_state export unavailable")
        || error.starts_with("CE returned null lua state")
        || error.starts_with("unable to locate CE Lua runtime exports")
        || error.starts_with("CE Lua global autoAssemble is unavailable")
    {
        return (-32008, error.to_owned());
    }
    if error.starts_with("not implemented in ce_plugin tools skeleton:") {
        return (-32004, error.to_owned());
    }
    if error.starts_with("invalid params json:") {
        return (-32602, error.to_owned());
    }
    if error.starts_with("missing ")
        || error.contains(" must be ")
        || error.starts_with("unsupported ")
        || error.starts_with("invalid ")
    {
        return (-32602, error.to_owned());
    }

    (-32000, error.to_owned())
}

fn jsonrpc_error(id: Value, code: i32, message: impl Into<String>) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
    .to_string()
}
