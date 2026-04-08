use serde_json::Value;

use super::{lua_backend, ToolResponse};

pub(crate) fn call_tool_json(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
    let response = lua_backend::call_lua_tool(method, params_json);
    if !response.success {
        return Err(response);
    }

    serde_json::from_str::<Value>(&response.body_json).map_err(|error| ToolResponse {
        success: false,
        body_json: format!(
            "lua backend returned invalid json for {}: {}",
            method, error
        ),
    })
}

pub(crate) fn call_tool_json_value(method: &str, params: &Value) -> Result<Value, ToolResponse> {
    call_tool_json(method, &params.to_string())
}

pub(crate) fn call_tool_json_string_err(method: &str, params: &Value) -> Result<Value, String> {
    call_tool_json_value(method, params).map_err(|response| response.body_json)
}
