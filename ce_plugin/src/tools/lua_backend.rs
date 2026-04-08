use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::runtime::console;
use crate::{lua, runtime};

use super::{in_main_thread_dispatch, script, util, ToolResponse};

pub(crate) const INTERNAL_DISPATCH_METHOD: &str = "__ce_mcp_call_lua_backend";

const LUA_BACKEND_SENTINEL: &str = "__ce_mcp_rust_backend";
const LUA_BACKEND_DISPATCH: &str = "__ce_mcp_rust_dispatch_json";
const LUA_BACKEND_READY: &str = "ce-mcp-rust-lua-backend-ready";

static LUA_BACKEND_STATE: OnceLock<Mutex<BackendState>> = OnceLock::new();
static LUA_BOOTSTRAP_CHUNK: OnceLock<String> = OnceLock::new();

#[derive(Debug, Default)]
struct BackendState {
    bootstrapped: bool,
}

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    if method != INTERNAL_DISPATCH_METHOD {
        return None;
    }

    Some(dispatch_internal(params_json))
}

pub fn call_lua_tool(method: &str, params_json: &str) -> ToolResponse {
    console::info(format!(
        "[lua_backend] step=enter method={} params_len={} in_main_thread_dispatch={}",
        method,
        params_json.len(),
        in_main_thread_dispatch()
    ));

    if in_main_thread_dispatch() {
        return call_lua_tool_direct(method, params_json);
    }

    let payload = json!({
        "method": method,
        "params_json": params_json,
    });

    let timeout = current_dispatch_timeout();
    console::info(format!(
        "[lua_backend] step=dispatch_via_dispatcher_begin method={} timeout_ms={}",
        method,
        timeout.as_millis()
    ));
    let response = util::dispatch_via_dispatcher(
        INTERNAL_DISPATCH_METHOD,
        payload.to_string().as_str(),
        timeout,
    );
    console::info(format!(
        "[lua_backend] step=dispatch_via_dispatcher_end method={} success={}",
        method, response.success
    ));
    response
}

fn dispatch_internal(params_json: &str) -> ToolResponse {
    let params = match serde_json::from_str::<Value>(params_json) {
        Ok(value) => value,
        Err(error) => {
            return error_response(format!("invalid lua backend dispatch payload: {}", error))
        }
    };

    let method = match params.get("method").and_then(Value::as_str) {
        Some(method) if !method.trim().is_empty() => method,
        _ => return error_response("missing lua backend method".to_owned()),
    };
    let forwarded_params = params
        .get("params_json")
        .and_then(Value::as_str)
        .unwrap_or("{}");

    call_lua_tool_direct(method, forwarded_params)
}

fn call_lua_tool_direct(method: &str, params_json: &str) -> ToolResponse {
    console::info(format!(
        "[lua_backend] step=direct_begin method={} params_len={}",
        method,
        params_json.len()
    ));
    match call_lua_tool_inner(method, params_json, true) {
        Ok(response) => {
            console::info(format!(
                "[lua_backend] step=direct_end method={} success={}",
                method, response.success
            ));
            response
        }
        Err(error) => {
            console::error(format!(
                "[lua_backend] step=direct_error method={} error={}",
                method, error
            ));
            error_response(error)
        }
    }
}

fn call_lua_tool_inner(
    method: &str,
    params_json: &str,
    allow_rebootstrap: bool,
) -> Result<ToolResponse, String> {
    ensure_backend_bootstrapped()?;

    match dispatch_to_lua(method, params_json) {
        Ok(response) => Ok(response),
        Err(error) if allow_rebootstrap && should_retry_after_rebootstrap(&error) => {
            console::warn(format!(
                "[lua_backend] step=rebootstrap_begin method={} error={}",
                method, error
            ));
            mark_backend_unbootstrapped()?;
            ensure_backend_bootstrapped()?;
            let retried = dispatch_to_lua(method, params_json);
            if retried.is_ok() {
                console::info(format!(
                    "[lua_backend] step=rebootstrap_end method={} success=true",
                    method
                ));
            }
            retried
        }
        Err(error) => Err(error),
    }
}

fn ensure_backend_bootstrapped() -> Result<(), String> {
    let state = backend_state();
    let mut guard = state
        .lock()
        .map_err(|_| "lua backend state lock poisoned".to_owned())?;

    if guard.bootstrapped {
        console::info("[lua_backend] step=bootstrap_skip reason=already_bootstrapped");
        return Ok(());
    }

    let bootstrap = bootstrap_chunk();
    console::info(format!(
        "[lua_backend] step=bootstrap_begin chunk_len={}",
        bootstrap.len()
    ));
    let response = script::execute_lua_snippet(bootstrap, false)?;
    let ready = response
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| "lua backend bootstrap returned non-string result".to_owned())?;

    console::info(format!(
        "[lua_backend] step=bootstrap_marker marker={}",
        ready
    ));
    if ready != LUA_BACKEND_READY && ready != "already-bootstrapped" {
        return Err(format!(
            "lua backend bootstrap returned unexpected marker: {}",
            ready
        ));
    }

    guard.bootstrapped = true;
    console::info("[lua_backend] step=bootstrap_end success=true");
    Ok(())
}

fn dispatch_to_lua(method: &str, params_json: &str) -> Result<ToolResponse, String> {
    console::info(format!(
        "[lua_backend] step=call_global_begin function={} method={} params_len={}",
        LUA_BACKEND_DISPATCH,
        method,
        params_json.len()
    ));
    let response = script::call_lua_global(LUA_BACKEND_DISPATCH, &[method, params_json], false)?;
    let encoded = response
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| "lua backend dispatch returned non-string result".to_owned())?;

    console::info(format!(
        "[lua_backend] step=call_global_end function={} method={} result_len={}",
        LUA_BACKEND_DISPATCH,
        method,
        encoded.len()
    ));
    console::info(format!(
        "[lua_backend] step=parse_result_begin method={}",
        method
    ));
    let body: Value = serde_json::from_str(encoded)
        .map_err(|error| format!("lua backend returned invalid json: {}", error))?;

    let success = body.get("success").and_then(Value::as_bool).unwrap_or(true);
    console::info(format!(
        "[lua_backend] step=parse_result_end method={} success={}",
        method, success
    ));

    if success {
        return Ok(ToolResponse {
            success: true,
            body_json: body.to_string(),
        });
    }

    let body_json = body.to_string();
    let error = body
        .get("error")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or(body_json.clone());

    Ok(ToolResponse {
        success: false,
        body_json: if error == body_json { body_json } else { error },
    })
}

fn current_dispatch_timeout() -> Duration {
    runtime::app_state()
        .map(|app| Duration::from_millis(app.config().dispatch_timeout_ms))
        .unwrap_or_else(|| Duration::from_secs(5))
}

fn should_retry_after_rebootstrap(error: &str) -> bool {
    error.contains(LUA_BACKEND_DISPATCH)
        || error.contains("attempt to call a nil value")
        || error.contains("lua backend dispatch returned non-string result")
}

fn mark_backend_unbootstrapped() -> Result<(), String> {
    let state = backend_state();
    let mut guard = state
        .lock()
        .map_err(|_| "lua backend state lock poisoned".to_owned())?;
    guard.bootstrapped = false;
    console::warn("[lua_backend] step=mark_unbootstrapped reason=rebootstrap_requested");
    Ok(())
}

fn backend_state() -> &'static Mutex<BackendState> {
    LUA_BACKEND_STATE.get_or_init(|| Mutex::new(BackendState::default()))
}

fn bootstrap_chunk() -> &'static str {
    LUA_BOOTSTRAP_CHUNK
        .get_or_init(build_bootstrap_chunk)
        .as_str()
}

fn build_bootstrap_chunk() -> String {
    let embedded_source = lua::bootstrap_source();
    let sentinel = json_string_literal(LUA_BACKEND_SENTINEL);
    let dispatch = json_string_literal(LUA_BACKEND_DISPATCH);
    let version = json_string_literal(env!("CARGO_PKG_VERSION"));
    let source = json_string_literal(lua::SOURCE_LABEL);
    let ready = json_string_literal(LUA_BACKEND_READY);

    format!(
        r#"
local existing_backend = _G[{sentinel}]
if type(existing_backend) == "table" and type(_G[{dispatch}]) == "function" then
    return "already-bootstrapped"
end

if type(existing_backend) == "table" and type(existing_backend.cleanup) == "function" then
    pcall(existing_backend.cleanup)
end

{embedded_source}

_G[{sentinel}] = {{
    version = {version},
    source = {source},
    cleanup = cleanupZombieState,
}}
_G[{dispatch}] = dispatch

return {ready}
"#
    )
}

fn json_string_literal(value: &str) -> String {
    serde_json::to_string(value).expect("json string literal")
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}

#[cfg(test)]
mod tests {
    use super::{build_bootstrap_chunk, INTERNAL_DISPATCH_METHOD, LUA_BACKEND_DISPATCH};

    #[test]
    fn bootstrap_chunk_exports_dispatch_function() {
        let chunk = build_bootstrap_chunk();
        assert!(chunk.contains(LUA_BACKEND_DISPATCH));
        assert!(chunk.contains("embedded:ce_plugin/src/lua"));
        assert!(chunk.contains("cleanupZombieState"));
        assert!(!chunk.contains("StartMCPBridge()"));
    }

    #[test]
    fn internal_dispatch_method_name_is_stable() {
        assert_eq!(INTERNAL_DISPATCH_METHOD, "__ce_mcp_call_lua_backend");
    }
}
