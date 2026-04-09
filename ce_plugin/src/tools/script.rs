use std::fs;

use serde_json::{json, Value};

use super::{lua_host, util, ToolResponse};

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
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let code = match params.get("code").and_then(Value::as_str) {
        Some(code) if !code.trim().is_empty() => code,
        _ => return error_response("No code provided".to_owned()),
    };

    let structured = params
        .get("structured")
        .or_else(|| params.get("structured_result"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match lua_host::execute_snippet(code, structured) {
        Ok(result) => success_response(normalize_evaluate_lua_response(result, structured)),
        Err(error) => error_response(error),
    }
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
        "structured_result": params
            .get("structured_result")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });

    evaluate_lua(&proxy.to_string())
}

fn auto_assemble(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let script = params
        .get("script")
        .or_else(|| params.get("code"))
        .and_then(Value::as_str)
        .filter(|script| !script.trim().is_empty());
    let Some(script) = script else {
        return error_response("No script provided".to_owned());
    };

    match lua_host::execute_auto_assemble(script) {
        Ok(result) => success_response(result),
        Err(error) => error_response(error),
    }
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

    auto_assemble(&json!({ "script": script }).to_string())
}

fn normalize_evaluate_lua_response(mut result: Value, structured: bool) -> Value {
    let first_result = result
        .get("result")
        .cloned()
        .unwrap_or_else(|| Value::String("nil".to_owned()));

    let result_text = match first_result {
        Value::String(text) => text,
        Value::Null => "nil".to_owned(),
        other => serde_json::to_string(&other).unwrap_or_else(|_| "null".to_owned()),
    };

    if let Some(object) = result.as_object_mut() {
        object.insert("success".to_owned(), Value::Bool(true));
        object.insert("result".to_owned(), Value::String(result_text));
        if structured && !object.contains_key("structured_result") {
            object.insert(
                "structured_result".to_owned(),
                object
                    .get("results")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
    }

    result
}

fn success_response(body: Value) -> ToolResponse {
    ToolResponse {
        success: true,
        body_json: body.to_string(),
    }
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}