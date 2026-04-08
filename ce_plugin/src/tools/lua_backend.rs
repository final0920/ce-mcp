use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::runtime::console;
use crate::{lua, runtime};

use super::{in_main_thread_dispatch, lua_host, util, ToolResponse};

pub(crate) const INTERNAL_DISPATCH_METHOD: &str = "__ce_mcp_call_lua_backend";

const LUA_BACKEND_SENTINEL: &str = "__ce_mcp_rust_backend";
const LUA_BACKEND_DISPATCH: &str = "__ce_mcp_rust_dispatch_json";
const LUA_BACKEND_RUNTIME_STATUS: &str = "__ce_mcp_embedded_runtime_status_json";
const LUA_BACKEND_RUNTIME_START: &str = "__ce_mcp_embedded_runtime_start_json";
const LUA_BACKEND_TRANSPORT_SUBMIT: &str = "__ce_mcp_embedded_transport_submit_json";
const LUA_BACKEND_TRANSPORT_STEP: &str = "__ce_mcp_embedded_transport_step_json";
const LUA_BACKEND_TRANSPORT_RECV: &str = "__ce_mcp_embedded_transport_recv_json";
const LUA_BACKEND_READY: &str = "ce-mcp-rust-lua-backend-ready";
const MAX_TRANSPORT_PUMPS: usize = 8;

static LUA_BACKEND_STATE: OnceLock<Mutex<BackendState>> = OnceLock::new();
static LUA_BOOTSTRAP_CHUNK: OnceLock<String> = OnceLock::new();

#[derive(Debug, Default)]
struct BackendState {
    bootstrapped: bool,
    next_request_id: u64,
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
    let response = lua_host::execute_snippet(bootstrap, false)?;
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
    drop(guard);
    ensure_runtime_started()?;
    console::info("[lua_backend] step=bootstrap_end success=true");
    Ok(())
}

fn dispatch_to_lua(method: &str, params_json: &str) -> Result<ToolResponse, String> {
    let request_id = next_request_id()?;
    let submit_payload = json!({
        "id": request_id,
        "method": method,
        "params_json": params_json,
    })
    .to_string();

    console::info(format!(
        "[lua_backend] step=transport_submit_begin function={} method={} request_id={}",
        LUA_BACKEND_TRANSPORT_SUBMIT, method, request_id
    ));
    let submit = call_json_global(LUA_BACKEND_TRANSPORT_SUBMIT, &[submit_payload.as_str()])?;
    ensure_success(LUA_BACKEND_TRANSPORT_SUBMIT, &submit)?;
    console::info(format!(
        "[lua_backend] step=transport_submit_end method={} request_id={}",
        method, request_id
    ));

    let response = recv_response_for_request(method, &request_id)?;

    let encoded = response
        .get("body_json")
        .and_then(Value::as_str)
        .ok_or_else(|| "lua backend transport response missing body_json".to_owned())?;

    console::info(format!(
        "[lua_backend] step=parse_result_begin method={} request_id={}",
        method, request_id
    ));
    let body: Value = serde_json::from_str(encoded)
        .map_err(|error| format!("lua backend returned invalid json: {}", error))?;

    let success = body.get("success").and_then(Value::as_bool).unwrap_or(true);
    console::info(format!(
        "[lua_backend] step=parse_result_end method={} request_id={} success={}",
        method, request_id, success
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

fn next_request_id() -> Result<String, String> {
    let state = backend_state();
    let mut guard = state
        .lock()
        .map_err(|_| "lua backend state lock poisoned".to_owned())?;
    guard.next_request_id = guard.next_request_id.saturating_add(1);
    Ok(format!("rust-req-{}", guard.next_request_id))
}

fn ensure_runtime_started() -> Result<(), String> {
    let status = call_json_global(LUA_BACKEND_RUNTIME_STATUS, &[])?;
    ensure_success(LUA_BACKEND_RUNTIME_STATUS, &status)?;
    if status
        .get("running")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        console::info("[lua_backend] step=runtime_status running=true");
        return Ok(());
    }

    console::warn("[lua_backend] step=runtime_status running=false, restarting");
    let start = call_json_global(
        LUA_BACKEND_RUNTIME_START,
        &["{\"reason\":\"rust-ensure-runtime\"}"],
    )?;
    ensure_success(LUA_BACKEND_RUNTIME_START, &start)?;
    if !start
        .get("running")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("embedded runtime start returned non-running state".to_owned());
    }
    console::info("[lua_backend] step=runtime_start success=true");
    Ok(())
}

fn recv_response_for_request(
    method: &str,
    request_id: &str,
) -> Result<serde_json::Map<String, Value>, String> {
    for pump in 1..=MAX_TRANSPORT_PUMPS {
        console::info(format!(
            "[lua_backend] step=transport_step_begin function={} method={} request_id={} pump={}",
            LUA_BACKEND_TRANSPORT_STEP, method, request_id, pump
        ));
        let step = call_json_global(LUA_BACKEND_TRANSPORT_STEP, &["1"])?;
        ensure_success(LUA_BACKEND_TRANSPORT_STEP, &step)?;
        console::info(format!(
            "[lua_backend] step=transport_step_end method={} request_id={} pump={} processed={} idle={}",
            method,
            request_id,
            pump,
            step.get("processed").and_then(Value::as_u64).unwrap_or(0),
            step.get("idle").and_then(Value::as_bool).unwrap_or(false)
        ));

        console::info(format!(
            "[lua_backend] step=transport_recv_begin function={} method={} request_id={} pump={}",
            LUA_BACKEND_TRANSPORT_RECV, method, request_id, pump
        ));
        let recv = call_json_global(LUA_BACKEND_TRANSPORT_RECV, &[])?;
        ensure_success(LUA_BACKEND_TRANSPORT_RECV, &recv)?;
        console::info(format!(
            "[lua_backend] step=transport_recv_end method={} request_id={} pump={} idle={}",
            method,
            request_id,
            pump,
            recv.get("idle").and_then(Value::as_bool).unwrap_or(false)
        ));

        let Some(response) = recv.get("response").and_then(Value::as_object) else {
            if recv.get("idle").and_then(Value::as_bool).unwrap_or(false) {
                continue;
            }
            return Err("lua backend transport recv returned no response envelope".to_owned());
        };

        let response_id = response
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "lua backend transport response missing id".to_owned())?;
        if response_id == request_id {
            return Ok(response.clone());
        }

        console::warn(format!(
            "[lua_backend] step=transport_recv_skip method={} expected_id={} got_id={} pump={}",
            method, request_id, response_id, pump
        ));
    }

    Err(format!(
        "lua backend transport timed out waiting for response {} after {} pumps",
        request_id, MAX_TRANSPORT_PUMPS
    ))
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
    let runtime_status = json_string_literal(LUA_BACKEND_RUNTIME_STATUS);
    let runtime_start = json_string_literal(LUA_BACKEND_RUNTIME_START);
    let transport_submit = json_string_literal(LUA_BACKEND_TRANSPORT_SUBMIT);
    let transport_step = json_string_literal(LUA_BACKEND_TRANSPORT_STEP);
    let transport_recv = json_string_literal(LUA_BACKEND_TRANSPORT_RECV);
    let version = json_string_literal(env!("CARGO_PKG_VERSION"));
    let source = json_string_literal(lua::SOURCE_LABEL);
    let ready = json_string_literal(LUA_BACKEND_READY);

    format!(
        r#"
local existing_backend = _G[{sentinel}]
if type(existing_backend) == "table"
   and type(_G[{dispatch}]) == "function"
   and type(_G[{runtime_status}]) == "function"
   and type(_G[{runtime_start}]) == "function"
   and type(_G[{transport_submit}]) == "function"
   and type(_G[{transport_step}]) == "function"
   and type(_G[{transport_recv}]) == "function" then
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

if type(_G[{runtime_start}]) == "function" then
    pcall(_G[{runtime_start}], '{{"reason":"rust-bootstrap"}}')
end

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

fn call_json_global(function_name: &str, args: &[&str]) -> Result<Value, String> {
    console::info(format!(
        "[lua_backend] step=call_global_begin function={} argc={}",
        function_name,
        args.len()
    ));
    let response = lua_host::call_global(function_name, args, false)?;
    let encoded = response
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{} returned non-string result", function_name))?;
    console::info(format!(
        "[lua_backend] step=call_global_end function={} result_len={}",
        function_name,
        encoded.len()
    ));
    serde_json::from_str::<Value>(encoded)
        .map_err(|error| format!("{} returned invalid json: {}", function_name, error))
}

fn ensure_success(function_name: &str, body: &Value) -> Result<(), String> {
    if body.get("success").and_then(Value::as_bool).unwrap_or(true) {
        Ok(())
    } else {
        Err(body
            .get("error")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{} returned error body", function_name)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_bootstrap_chunk, INTERNAL_DISPATCH_METHOD, LUA_BACKEND_DISPATCH,
        LUA_BACKEND_TRANSPORT_SUBMIT,
    };

    #[test]
    fn bootstrap_chunk_exports_dispatch_function() {
        let chunk = build_bootstrap_chunk();
        assert!(chunk.contains(LUA_BACKEND_DISPATCH));
        assert!(chunk.contains(LUA_BACKEND_TRANSPORT_SUBMIT));
        assert!(chunk.contains("embedded:ce_plugin/src/lua"));
        assert!(chunk.contains("cleanupZombieState"));
        assert!(!chunk.contains("StartMCPBridge()"));
    }

    #[test]
    fn internal_dispatch_method_name_is_stable() {
        assert_eq!(INTERNAL_DISPATCH_METHOD, "__ce_mcp_call_lua_backend");
    }
}
