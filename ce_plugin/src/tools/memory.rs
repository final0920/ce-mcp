use serde_json::{json, Value};

use super::{addressing, lua_host, process, util, ToolResponse};
use crate::runtime;

const METHODS: &[&str] = &[
    "read_memory",
    "read_integer",
    "read_string",
    "read_pointer",
    "read_pointer_chain",
    "write_integer",
    "write_memory",
    "write_string",
];

const LUA_TO_HEX_HELPER: &str = r###"
local function ce_mcp_to_hex(num)
    if not num then return "nil" end
    if num < 0 then
        return string.format("-0x%X", -num)
    elseif num > 0xFFFFFFFF then
        local high = math.floor(num / 0x100000000)
        local low = num % 0x100000000
        return string.format("0x%X%08X", high, low)
    else
        return string.format("0x%08X", num)
    end
end
"###;

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "read_memory" => read_memory(params_json),
        "read_integer" => read_integer(params_json),
        "read_string" => read_string(params_json),
        "read_pointer" => read_pointer(params_json),
        "read_pointer_chain" => read_pointer_chain(params_json),
        "write_integer" => write_integer(params_json),
        "write_memory" => write_memory(params_json),
        "write_string" => write_string(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn read_memory(params_json: &str) -> ToolResponse {
    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("read_memory", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let normalized_address = response_address(body.get("address"))
        .and_then(|address| normalize_address(address, &modules));

    let Some(object) = body.as_object_mut() else {
        return error_response("CE read_memory returned non-object body".to_owned());
    };

    object.insert("normalized_address".to_owned(), json!(normalized_address));
    success_response(body)
}

fn read_integer(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let requested_type = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("dword")
        .to_owned();
    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("read_integer", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let integer_type = body
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or(requested_type.as_str())
        .to_owned();
    let normalized_address = response_address(body.get("address"))
        .and_then(|address| normalize_address(address, &modules));
    let value_u64 = response_u64(body.get("value"));
    let hex = normalized_integer_hex(
        integer_type.as_str(),
        body.get("hex").or_else(|| body.get("value")),
    );

    let Some(object) = body.as_object_mut() else {
        return error_response("CE read_integer returned non-object body".to_owned());
    };

    object
        .entry("type".to_owned())
        .or_insert_with(|| Value::String(requested_type.clone()));
    object.insert("normalized_address".to_owned(), json!(normalized_address));
    if integer_type == "qword" {
        if let Some(value) = value_u64 {
            object.insert(
                "value".to_owned(),
                Value::String(util::format_u64_hex(value)),
            );
            object.insert("value_decimal".to_owned(), Value::String(value.to_string()));
        }
    }
    if let Some(hex) = hex {
        object.insert("hex".to_owned(), Value::String(hex));
    }

    success_response(body)
}

fn read_string(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let max_length = params
        .get("max_length")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(256)
        .min(4096);
    let wide = params.get("wide").and_then(Value::as_bool).unwrap_or(false);
    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("read_string", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let normalized_address = response_address(body.get("address"))
        .and_then(|address| normalize_address(address, &modules));

    let Some(object) = body.as_object_mut() else {
        return error_response("CE read_string returned non-object body".to_owned());
    };

    object.insert("normalized_address".to_owned(), json!(normalized_address));
    object
        .entry("wide".to_owned())
        .or_insert_with(|| Value::Bool(wide));
    object
        .entry("max_length".to_owned())
        .or_insert_with(|| json!(max_length));

    success_response(body)
}

fn read_pointer(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let offsets = params
        .get("offsets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !offsets.is_empty() {
        return read_pointer_chain(params_json);
    }

    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("read_pointer", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let address_value = body
        .get("final_address")
        .or_else(|| body.get("address"))
        .or_else(|| body.get("base"));
    let address_text = response_address_text(address_value);
    let normalized_address =
        response_address(address_value).and_then(|address| normalize_address(address, &modules));
    let pointer_value = response_u64(body.get("value"));

    if pointer_value.is_none() {
        return error_response(format!(
            "failed to read pointer at {}",
            address_text.as_deref().unwrap_or("unknown address")
        ));
    }

    let value_normalized = pointer_value.and_then(|value| normalize_pointer_value(value, &modules));

    let Some(object) = body.as_object_mut() else {
        return error_response("CE read_pointer returned non-object body".to_owned());
    };

    if let Some(address) = address_text {
        object.insert("address".to_owned(), Value::String(address));
    }
    object.insert("normalized_address".to_owned(), json!(normalized_address));
    if let Some(value) = pointer_value {
        object.insert(
            "value".to_owned(),
            Value::String(util::format_u64_hex(value)),
        );
        object.insert("value_decimal".to_owned(), Value::String(value.to_string()));
        object.insert("hex".to_owned(), Value::String(util::format_u64_hex(value)));
    }
    object.insert("value_normalized".to_owned(), json!(value_normalized));
    success_response(body)
}

fn read_pointer_chain(params_json: &str) -> ToolResponse {
    let mut params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    if let Some(object) = params.as_object_mut() {
        if object.get("base").is_none() {
            if let Some(address) = object.get("address").cloned() {
                object.insert("base".to_owned(), address);
            }
        }
    }

    let forwarded_params = params.to_string();
    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("read_pointer_chain", &forwarded_params) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let base_value = body.get("base_address").or_else(|| body.get("base"));
    let base_text = response_address_text(base_value);
    let base_normalized =
        response_address(base_value).and_then(|address| normalize_address(address, &modules));
    let final_address = body.get("final_address");
    let final_text = response_address_text(final_address);
    let final_address_value = response_address(final_address);
    let final_address_normalized =
        final_address_value.and_then(|address| normalize_address(address, &modules));
    let final_read_value = response_u64(body.get("final_value"));
    let final_value_normalized =
        final_read_value.and_then(|value| normalize_pointer_value(value, &modules));
    let path = body.get("chain").and_then(Value::as_array).map(|steps| {
        steps
            .iter()
            .map(|step| normalize_pointer_chain_step(step, &modules))
            .collect::<Vec<_>>()
    });

    let Some(object) = body.as_object_mut() else {
        return error_response("CE read_pointer_chain returned non-object body".to_owned());
    };

    if let Some(base_address) = base_text {
        object.insert("base_address".to_owned(), Value::String(base_address));
    }
    object.insert("base_normalized_address".to_owned(), json!(base_normalized));
    if let Some(final_address) = final_text {
        object.insert("final_address".to_owned(), Value::String(final_address));
    }
    object.insert(
        "final_address_normalized".to_owned(),
        json!(final_address_normalized),
    );
    if let Some(value) = final_read_value {
        object.insert(
            "final_value".to_owned(),
            Value::String(util::format_u64_hex(value)),
        );
        object.insert(
            "final_value_decimal".to_owned(),
            Value::String(value.to_string()),
        );
    }
    object.insert(
        "final_value_normalized".to_owned(),
        json!(final_value_normalized),
    );
    if let Some(address) = final_address_value {
        object.insert(
            "resolved_address".to_owned(),
            Value::String(util::format_u64_hex(address as u64)),
        );
    }
    if let Some(path) = path {
        object.insert("path".to_owned(), Value::Array(path));
    }
    success_response(body)
}

fn write_memory(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let bytes = match parse_byte_array(params.get("bytes")) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    let mut body = match write_bytes_via_ce(address, &bytes) {
        Ok(body) => body,
        Err(response) => return response,
    };

    if let Err(error) = enrich_write_memory_response(&mut body, address, bytes.len()) {
        return error_response(error);
    }

    success_response(body)
}

fn write_integer(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let integer_type = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("dword")
        .to_owned();

    let bytes = match integer_type.as_str() {
        "byte" => one_u8(params.get("value")).map(|value| vec![value]),
        "word" => one_u16(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "dword" => one_u32(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "qword" => one_u64(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "float" => one_f32(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "double" => one_f64(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        other => Err(format!("unsupported integer type: {}", other)),
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    let mut body = match write_bytes_via_ce(address, &bytes) {
        Ok(body) => body,
        Err(response) => return response,
    };

    if let Err(error) = enrich_write_memory_response(&mut body, address, bytes.len()) {
        return error_response(error);
    }

    let Some(object) = body.as_object_mut() else {
        return error_response("CE write_memory returned non-object body".to_owned());
    };

    object.insert("type".to_owned(), Value::String(integer_type.clone()));
    if integer_type == "qword" {
        if let Some(value) = response_u64(params.get("value")) {
            object.insert(
                "value".to_owned(),
                Value::String(util::format_u64_hex(value)),
            );
            object.insert("value_decimal".to_owned(), Value::String(value.to_string()));
        }
    } else if let Some(value) = params.get("value").cloned() {
        object.insert("value".to_owned(), value);
    }
    if let Some(hex) = normalized_integer_hex(integer_type.as_str(), params.get("value")) {
        object.insert("hex".to_owned(), Value::String(hex));
    }
    object.insert(
        "write_path".to_owned(),
        Value::String("ce_runtime.write_memory".to_owned()),
    );

    success_response(body)
}

fn write_string(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let value = match params
        .get("value")
        .or_else(|| params.get("string"))
        .and_then(Value::as_str)
    {
        Some(value) => value,
        None => return error_response("missing string value".to_owned()),
    };
    let wide = params.get("wide").and_then(Value::as_bool).unwrap_or(false);

    let bytes = if wide {
        value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>()
    } else {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        bytes
    };

    let mut body = match write_bytes_via_ce(address, &bytes) {
        Ok(body) => body,
        Err(response) => return response,
    };

    if let Err(error) = enrich_write_memory_response(&mut body, address, bytes.len()) {
        return error_response(error);
    }

    let Some(object) = body.as_object_mut() else {
        return error_response("CE write_memory returned non-object body".to_owned());
    };

    object.insert("wide".to_owned(), Value::Bool(wide));
    object.insert("length".to_owned(), json!(value.len()));
    object.insert(
        "write_path".to_owned(),
        Value::String("ce_runtime.write_memory".to_owned()),
    );

    success_response(body)
}

fn write_bytes_via_ce(address: usize, bytes: &[u8]) -> Result<Value, ToolResponse> {
    let forwarded_params = json!({
        "address": util::format_address(address),
        "bytes": bytes,
    })
    .to_string();

    call_ce_tool_json("write_memory", &forwarded_params)
}

fn enrich_write_memory_response(
    body: &mut Value,
    address: usize,
    size: usize,
) -> Result<(), String> {
    let modules = process::current_modules();
    let normalized_address = response_address(body.get("address"))
        .or(Some(address))
        .and_then(|value| normalize_address(value, &modules));

    let object = body
        .as_object_mut()
        .ok_or_else(|| "CE write_memory returned non-object body".to_owned())?;

    object
        .entry("address".to_owned())
        .or_insert_with(|| Value::String(util::format_address(address)));
    object.insert("normalized_address".to_owned(), json!(normalized_address));
    object
        .entry("size".to_owned())
        .or_insert_with(|| json!(size));
    object
        .entry("bytes_written".to_owned())
        .or_insert_with(|| json!(size));

    Ok(())
}

fn parse_byte_array(value: Option<&Value>) -> Result<Vec<u8>, String> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| "missing bytes".to_owned())?;

    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let number = match value.as_u64() {
            Some(number) if number <= 0xFF => number as u8,
            _ => return Err("bytes must be an array of 0..255".to_owned()),
        };
        output.push(number);
    }

    if output.is_empty() {
        return Err("missing bytes".to_owned());
    }

    Ok(output)
}

fn call_ce_tool_json(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
    let params = util::parse_params(params_json).map_err(error_response)?;
    call_ce_memory_tool(method, &params)
}

fn execute_ce_memory_snippet(code: &str) -> Result<Value, ToolResponse> {
    lua_host::execute_snippet_result(code).map_err(error_response)
}

fn call_ce_memory_tool(method: &str, params: &Value) -> Result<Value, ToolResponse> {
    match method {
        "read_memory" => ce_read_memory(params),
        "read_integer" => ce_read_integer(params),
        "read_string" => ce_read_string(params),
        "read_pointer" => ce_read_pointer(params),
        "read_pointer_chain" => ce_read_pointer_chain(params),
        "write_memory" => ce_write_memory(params),
        other => Err(error_response(format!(
            "unsupported CE memory tool: {}",
            other
        ))),
    }
}

fn ce_read_memory(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let size = params
        .get("size")
        .and_then(Value::as_u64)
        .unwrap_or(256)
        .min(65_536);
    let code = format!(
        r###"{}
local address = {}
local size = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local bytes = readBytes(address, size, true)
if not bytes then return {{ success = false, error = "Failed to read at " .. ce_mcp_to_hex(address) }} end
local hex = {{}}
for i, byte in ipairs(bytes) do hex[i] = string.format("%02X", byte) end
return {{ success = true, address = ce_mcp_to_hex(address), size = #bytes, data = table.concat(hex, " "), bytes = bytes }}
"###,
        LUA_TO_HEX_HELPER, address_lua, size
    );
    execute_ce_memory_snippet(&code)
}

fn ce_read_integer(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let integer_type = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("dword");
    let type_lua = util::lua_string_literal(integer_type);
    let code = format!(
        r###"{}
local address = {}
local integer_type = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local value = nil
if integer_type == "byte" then
    local bytes = readBytes(address, 1, true)
    if bytes and #bytes > 0 then value = bytes[1] end
elseif integer_type == "word" then value = readSmallInteger(address)
elseif integer_type == "dword" then value = readInteger(address)
elseif integer_type == "qword" then value = readQword(address)
elseif integer_type == "float" then value = readFloat(address)
elseif integer_type == "double" then value = readDouble(address)
else return {{ success = false, error = "Unknown type: " .. tostring(integer_type) }} end
if value == nil then return {{ success = false, error = "Failed to read at " .. ce_mcp_to_hex(address) }} end
return {{ success = true, address = ce_mcp_to_hex(address), value = value, type = integer_type, hex = ce_mcp_to_hex(value) }}
"###,
        LUA_TO_HEX_HELPER, address_lua, type_lua
    );
    execute_ce_memory_snippet(&code)
}

fn ce_read_string(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let max_length = params
        .get("max_length")
        .and_then(Value::as_u64)
        .unwrap_or(256)
        .min(4096);
    let wide = params
        .get("wide")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .to_string();
    let code = format!(
        r###"{}
local address = {}
local max_length = {}
local wide = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local str = readString(address, max_length, wide)
local sanitized = ""
if str then
    for i = 1, #str do
        local byte = str:byte(i)
        if byte >= 32 and byte < 127 then
            sanitized = sanitized .. str:sub(i, i)
        elseif byte == 9 or byte == 10 or byte == 13 then
            sanitized = sanitized .. " "
        else
            sanitized = sanitized .. string.format("\\x%02X", byte)
        end
    end
end
return {{ success = true, address = ce_mcp_to_hex(address), value = sanitized, wide = wide, length = str and #str or 0, raw_length = #sanitized }}
"###,
        LUA_TO_HEX_HELPER, address_lua, max_length, wide
    );
    execute_ce_memory_snippet(&code)
}

fn ce_read_pointer(params: &Value) -> Result<Value, ToolResponse> {
    let base = params
        .get("base")
        .or_else(|| params.get("address"))
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let base_lua = util::lua_scalar_literal(base).map_err(error_response)?;
    let offsets = params
        .get("offsets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let offsets_lua = util::lua_array_literal(&offsets).map_err(error_response)?;
    let code = format!(
        r###"{}
local base = {}
local offsets = {}
if type(base) == "string" then base = getAddressSafe(base) end
if not base then return {{ success = false, error = "Invalid base address" }} end
local current_address = base
local path = {{ ce_mcp_to_hex(base) }}
for _, offset in ipairs(offsets) do
    local ptr = readPointer(current_address)
    if not ptr then return {{ success = false, error = "Failed to read pointer at " .. ce_mcp_to_hex(current_address), path = path }} end
    current_address = ptr + offset
    table.insert(path, ce_mcp_to_hex(current_address))
end
local final_value = readPointer(current_address)
return {{ success = true, base = ce_mcp_to_hex(base), final_address = ce_mcp_to_hex(current_address), value = final_value, path = path }}
"###,
        LUA_TO_HEX_HELPER, base_lua, offsets_lua
    );
    execute_ce_memory_snippet(&code)
}

fn ce_read_pointer_chain(params: &Value) -> Result<Value, ToolResponse> {
    let base = params
        .get("base")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let base_lua = util::lua_scalar_literal(base).map_err(error_response)?;
    let offsets = params
        .get("offsets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let offsets_lua = util::lua_array_literal(&offsets).map_err(error_response)?;
    let code = format!(
        r###"{}
local base = {}
local offsets = {}
if type(base) == "string" then base = getAddressSafe(base) end
if not base then return {{ success = false, error = "Invalid base address" }} end
local current_address = base
local chain = {{ {{ step = 0, address = ce_mcp_to_hex(current_address), description = "base" }} }}
for i, offset in ipairs(offsets) do
    local ptr = readPointer(current_address)
    if not ptr then return {{ success = false, error = "Failed to read pointer at step " .. i, partial_chain = chain, failed_at_address = ce_mcp_to_hex(current_address) }} end
    current_address = ptr + offset
    table.insert(chain, {{ step = i, address = ce_mcp_to_hex(current_address), offset = offset, hex_offset = string.format("+0x%X", offset), pointer_value = ce_mcp_to_hex(ptr) }})
end
local final_value = nil
pcall(function() final_value = readPointer(current_address) end)
return {{ success = true, base = ce_mcp_to_hex(base), offsets = offsets, final_address = ce_mcp_to_hex(current_address), final_value = final_value, chain = chain }}
"###,
        LUA_TO_HEX_HELPER, base_lua, offsets_lua
    );
    execute_ce_memory_snippet(&code)
}

fn ce_write_memory(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let bytes = params
        .get("bytes")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| error_response("No bytes provided".to_owned()))?;
    let bytes_lua = util::lua_array_literal(&bytes).map_err(error_response)?;
    let code = format!(
        r###"{}
local address = {}
local bytes = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
if not bytes or #bytes == 0 then return {{ success = false, error = "No bytes provided" }} end
local ok, err = pcall(writeBytes, address, bytes)
if not ok then return {{ success = false, error = "Write failed: " .. tostring(err), address = ce_mcp_to_hex(address) }} end
return {{ success = true, address = ce_mcp_to_hex(address), bytes_written = #bytes, size = #bytes }}
"###,
        LUA_TO_HEX_HELPER, address_lua, bytes_lua
    );
    execute_ce_memory_snippet(&code)
}
fn success_response(body: Value) -> ToolResponse {
    ToolResponse {
        success: true,
        body_json: body.to_string(),
    }
}

fn response_address_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| response_address(value).map(util::format_address))
}

fn response_address(value: Option<&Value>) -> Option<usize> {
    value.and_then(|value| util::parse_address(Some(value)).ok())
}

fn response_u64(value: Option<&Value>) -> Option<u64> {
    let value = value?;

    if let Some(number) = value.as_u64() {
        return Some(number);
    }

    if let Some(number) = value.as_i64() {
        return u64::try_from(number).ok();
    }

    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }

    text.parse::<u64>().ok()
}

fn response_f64(value: Option<&Value>) -> Option<f64> {
    let value = value?;

    if let Some(number) = value.as_f64() {
        return Some(number);
    }

    value.as_str()?.trim().parse::<f64>().ok()
}

fn normalized_integer_hex(integer_type: &str, value: Option<&Value>) -> Option<String> {
    match integer_type {
        "byte" => response_u64(value)
            .and_then(|value| u8::try_from(value).ok())
            .map(|value| format!("0x{:02X}", value)),
        "word" => response_u64(value)
            .and_then(|value| u16::try_from(value).ok())
            .map(|value| format!("0x{:04X}", value)),
        "dword" => response_u64(value)
            .and_then(|value| u32::try_from(value).ok())
            .map(|value| format!("0x{:08X}", value)),
        "qword" => response_u64(value).map(util::format_u64_hex),
        "float" => response_f64(value).map(|value| format!("0x{:08X}", (value as f32).to_bits())),
        "double" => response_f64(value).map(|value| format!("0x{:016X}", value.to_bits())),
        _ => None,
    }
}

fn normalize_pointer_chain_step(step: &Value, modules: &[runtime::ModuleInfo]) -> Value {
    let Some(source) = step.as_object() else {
        return step.clone();
    };

    let mut object = source.clone();
    let normalized_address = response_address(object.get("address"))
        .and_then(|address| normalize_address(address, modules));
    object.insert("normalized_address".to_owned(), json!(normalized_address));
    object
        .entry("offset".to_owned())
        .or_insert_with(|| Value::Number(0.into()));

    if let Some(pointer) = response_u64(
        object
            .get("pointer")
            .or_else(|| object.get("pointer_value")),
    ) {
        object.insert(
            "pointer".to_owned(),
            Value::String(util::format_u64_hex(pointer)),
        );
        object.insert(
            "pointer_decimal".to_owned(),
            Value::String(pointer.to_string()),
        );
        object.insert(
            "pointer_normalized".to_owned(),
            json!(normalize_pointer_value(pointer, modules)),
        );
    }

    Value::Object(object)
}

fn normalize_address(
    address: usize,
    modules: &[runtime::ModuleInfo],
) -> Option<crate::domain::address::AddressRef> {
    addressing::normalize_address_from_modules(address, modules)
}

fn normalize_pointer_value(
    value: u64,
    modules: &[runtime::ModuleInfo],
) -> Option<crate::domain::address::AddressRef> {
    usize::try_from(value)
        .ok()
        .and_then(|address| normalize_address(address, modules))
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}

fn one_u8(value: Option<&Value>) -> Result<u8, String> {
    response_u64(value)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| "value must be an unsigned integer <= 255".to_owned())
}

fn one_u16(value: Option<&Value>) -> Result<u16, String> {
    response_u64(value)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| "value must be an unsigned integer <= 65535".to_owned())
}

fn one_u32(value: Option<&Value>) -> Result<u32, String> {
    response_u64(value)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "value must be an unsigned integer <= 0xFFFFFFFF".to_owned())
}

fn one_u64(value: Option<&Value>) -> Result<u64, String> {
    response_u64(value).ok_or_else(|| "value must be an unsigned integer".to_owned())
}

fn one_f32(value: Option<&Value>) -> Result<f32, String> {
    response_f64(value)
        .map(|value| value as f32)
        .ok_or_else(|| "value must be numeric".to_owned())
}

fn one_f64(value: Option<&Value>) -> Result<f64, String> {
    response_f64(value).ok_or_else(|| "value must be numeric".to_owned())
}
