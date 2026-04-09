use std::time::Duration;

use serde_json::Value;

use crate::domain::context::RequestContext;
use crate::runtime;

use super::ToolResponse;

pub fn not_implemented(method: &str) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: format!("not implemented in ce_plugin tools skeleton: {}", method),
    }
}

pub fn method_not_found(method: &str) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: format!("method not found: {}", method),
    }
}

pub fn dispatch_via_dispatcher(method: &str, params_json: &str, timeout: Duration) -> ToolResponse {
    let Some(app) = runtime::app_state() else {
        return ToolResponse {
            success: false,
            body_json: "plugin runtime unavailable".to_owned(),
        };
    };

    match app.dispatcher().execute(method, params_json, timeout) {
        Ok(response) => response,
        Err(error) => ToolResponse {
            success: false,
            body_json: error,
        },
    }
}

pub fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn lua_string_literal(value: &str) -> String {
    for depth in 0..8 {
        let eq = "=".repeat(depth);
        let close = format!("]{}]", eq);
        if !value.contains(&close) {
            return format!("[{}[{}]{}]", eq, value, eq);
        }
    }

    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn lua_scalar_literal(value: &Value) -> Result<String, String> {
    match value {
        Value::String(text) => Ok(lua_string_literal(text)),
        Value::Bool(flag) => Ok(flag.to_string()),
        Value::Number(number) => Ok(number.to_string()),
        Value::Null => Ok("nil".to_owned()),
        _ => Err("value must be a scalar json value".to_owned()),
    }
}

pub fn lua_array_literal(values: &[Value]) -> Result<String, String> {
    let mut rendered = Vec::with_capacity(values.len());
    for value in values {
        rendered.push(lua_scalar_literal(value)?);
    }
    Ok(format!("{{{}}}", rendered.join(", ")))
}

pub fn parse_address(value: Option<&Value>) -> Result<usize, String> {
    let Some(value) = value else {
        return Err("missing address".to_owned());
    };

    if let Some(number) = value.as_u64() {
        return usize::try_from(number).map_err(|_| "address out of range".to_owned());
    }

    if let Some(text) = value.as_str() {
        let trimmed = text.trim();
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            return usize::from_str_radix(hex, 16)
                .map_err(|_| format!("invalid hex address: {}", text));
        }

        return trimmed
            .parse::<usize>()
            .map_err(|_| format!("invalid address: {}", text));
    }

    Err("address must be a string or number".to_owned())
}

pub fn format_address(address: usize) -> String {
    if cfg!(target_pointer_width = "64") {
        format!("0x{:016X}", address)
    } else {
        format!("0x{:08X}", address)
    }
}

pub fn format_u64_hex(value: u64) -> String {
    format!("0x{:016X}", value)
}

pub fn format_rva(value: usize) -> String {
    format!("0x{:X}", value)
}

pub fn parse_params(params_json: &str) -> Result<Value, String> {
    serde_json::from_str::<Value>(params_json)
        .map_err(|error| format!("invalid params json: {}", error))
}

pub fn parse_request_context(params: &Value) -> RequestContext {
    let tags = params
        .get("tags")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty());

    RequestContext {
        build_version: params
            .get("build_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        session_id: params
            .get("session_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        scenario_id: params
            .get("scenario_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        tags,
    }
}
