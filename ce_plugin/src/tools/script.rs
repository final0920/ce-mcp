use std::fs;

use serde_json::{json, Value};

use super::{lua_backend, lua_host, util, ToolResponse};

const METHODS: &[&str] = &[
    "evaluate_lua",
    "evaluate_lua_file",
    "auto_assemble",
    "auto_assemble_file",
];

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "evaluate_lua" => evaluate_lua(params_json),
        "evaluate_lua_file" => evaluate_lua_file(params_json),
        "auto_assemble" => auto_assemble(params_json),
        "auto_assemble_file" => auto_assemble_file(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

pub(crate) fn execute_lua_snippet(code: &str, structured: bool) -> Result<Value, String> {
    lua_host::execute_snippet(code, structured)
}

pub(crate) fn call_lua_global(
    function_name: &str,
    args: &[&str],
    structured: bool,
) -> Result<Value, String> {
    lua_host::call_global(function_name, args, structured)
}

#[allow(dead_code)]
pub(crate) fn execute_auto_assemble(script: &str) -> Result<Value, String> {
    lua_host::execute_auto_assemble(script)
}

fn evaluate_lua(params_json: &str) -> ToolResponse {
    lua_backend::call_lua_tool("evaluate_lua", params_json)
}

fn evaluate_lua_file(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let path = match params.get("path").and_then(Value::as_str) {
        Some(path) if !path.trim().is_empty() => path,
        _ => return error_response("missing path".to_owned()),
    };

    let code = match fs::read_to_string(path) {
        Ok(code) => code,
        Err(error) => return error_response(format!("failed to read lua file: {}", error)),
    };

    let proxy = json!({
        "code": code,
        "structured": params.get("structured").and_then(Value::as_bool).unwrap_or(false),
        "structured_result": params.get("structured_result").and_then(Value::as_bool).unwrap_or(false)
    });

    lua_backend::call_lua_tool("evaluate_lua", proxy.to_string().as_str())
}

fn auto_assemble(params_json: &str) -> ToolResponse {
    lua_backend::call_lua_tool("auto_assemble", params_json)
}

fn auto_assemble_file(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let path = match params.get("path").and_then(Value::as_str) {
        Some(path) if !path.trim().is_empty() => path,
        _ => return error_response("missing path".to_owned()),
    };

    let script = match fs::read_to_string(path) {
        Ok(script) => script,
        Err(error) => {
            return error_response(format!("failed to read auto assembler file: {}", error))
        }
    };

    let proxy = json!({ "script": script });
    lua_backend::call_lua_tool("auto_assemble", proxy.to_string().as_str())
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
