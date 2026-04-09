use serde_json::{json, Value};

use super::{addressing, lua_host, process, util, ToolResponse};
use crate::runtime;

const METHODS: &[&str] = &[
    "scan_all",
    "get_scan_results",
    "next_scan",
    "aob_scan",
    "search_string",
    "generate_signature",
    "get_memory_regions",
    "enum_memory_regions_full",
    "checksum_memory",
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
const DEFAULT_REGION_MAX: usize = 100;
const DEFAULT_FULL_REGION_MAX: usize = 500;
const DEFAULT_SCAN_LIMIT: usize = 100;
const MAX_SCAN_LIMIT: usize = 10_000;

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "scan_all" => scan_all(params_json),
        "get_scan_results" => get_scan_results(params_json),
        "next_scan" => next_scan(params_json),
        "get_memory_regions" => get_memory_regions(params_json),
        "enum_memory_regions_full" => enum_memory_regions_full(params_json),
        "checksum_memory" => checksum_memory(params_json),
        "aob_scan" => aob_scan(params_json),
        "search_string" => search_string(params_json),
        "generate_signature" => generate_signature(params_json),
        _ => return None,
    };
    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn scan_all(params_json: &str) -> ToolResponse {
    let (forwarded_params, resolved_type) = match normalize_scan_all_params(params_json) {
        Ok(result) => result,
        Err(error) => return error_response(error),
    };

    let mut body = match call_ce_tool_json("scan_all", &forwarded_params) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("CE scan_all returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("type".to_owned())
        .or_insert_with(|| Value::String(resolved_type));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("scan session via CE runtime"));

    success_response(body)
}

fn get_scan_results(params_json: &str) -> ToolResponse {
    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("get_scan_results", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    normalize_scan_address_entries(&mut body, "results", &modules, false);

    let Some(object) = body.as_object_mut() else {
        return error_response("CE get_scan_results returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("scan results sourced from CE runtime"));

    success_response(body)
}

fn next_scan(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let scan_type = params
        .get("scan_type")
        .and_then(Value::as_str)
        .unwrap_or("exact");
    if !is_supported_next_scan_type(scan_type) {
        return error_response(format!("unsupported scan_type: {}", scan_type));
    }
    if scan_type_requires_target_value(scan_type) && params.get("value").is_none() {
        return error_response("missing value".to_owned());
    }

    let mut body = match call_ce_tool_json("next_scan", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("CE next_scan returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("next scan executed via CE runtime"));

    success_response(body)
}

fn get_memory_regions(params_json: &str) -> ToolResponse {
    let mut params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let Some(object) = params.as_object_mut() else {
        return error_response("invalid params json: expected object".to_owned());
    };

    let max = parse_usize(
        object.get("max"),
        DEFAULT_REGION_MAX,
        DEFAULT_FULL_REGION_MAX,
    );
    object.insert("max".to_owned(), json!(max));

    let mut body = match call_ce_tool_json("get_memory_regions", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("CE get_memory_regions returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("memory regions sourced from CE runtime"));

    success_response(body)
}

fn enum_memory_regions_full(params_json: &str) -> ToolResponse {
    let mut params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let Some(object) = params.as_object_mut() else {
        return error_response("invalid params json: expected object".to_owned());
    };

    let max = parse_usize(object.get("max"), DEFAULT_FULL_REGION_MAX, MAX_SCAN_LIMIT);
    object.insert("max".to_owned(), json!(max));

    let mut body = match call_ce_tool_json("enum_memory_regions_full", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("CE enum_memory_regions_full returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("full memory map sourced from CE runtime"));

    success_response(body)
}

fn checksum_memory(params_json: &str) -> ToolResponse {
    let mut params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let Some(object) = params.as_object_mut() else {
        return error_response("invalid params json: expected object".to_owned());
    };

    let address = match util::parse_address(object.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let size = parse_positive_size(object.get("size"), 256, 1024 * 1024);

    object.insert(
        "address".to_owned(),
        Value::String(util::format_address(address)),
    );
    object.insert("size".to_owned(), json!(size));

    let mut body = match call_ce_tool_json("checksum_memory", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("CE checksum_memory returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("memory checksum calculated via CE runtime"));

    success_response(body)
}

fn aob_scan(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let pattern_text = match params.get("pattern").and_then(Value::as_str) {
        Some(pattern) if !pattern.trim().is_empty() => pattern.trim(),
        _ => return error_response("missing pattern".to_owned()),
    };
    if let Err(error) = parse_aob_pattern(pattern_text) {
        return error_response(error);
    }

    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("aob_scan", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    normalize_scan_address_entries(&mut body, "addresses", &modules, true);

    let Some(object) = body.as_object_mut() else {
        return error_response("CE aob_scan returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("pattern".to_owned())
        .or_insert_with(|| Value::String(pattern_text.to_owned()));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("AOB scan executed via CE runtime"));

    success_response(body)
}

fn search_string(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let search_text = match params
        .get("string")
        .or_else(|| params.get("pattern"))
        .and_then(Value::as_str)
    {
        Some(text) if !text.is_empty() => text,
        _ => return error_response("No search string".to_owned()),
    };

    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("search_string", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    normalize_scan_address_entries(&mut body, "addresses", &modules, false);

    let Some(object) = body.as_object_mut() else {
        return error_response("CE search_string returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("query".to_owned())
        .or_insert_with(|| Value::String(search_text.to_owned()));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("string search executed via CE runtime"));

    success_response(body)
}

fn generate_signature(params_json: &str) -> ToolResponse {
    let mut params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let Some(object) = params.as_object_mut() else {
        return error_response("invalid params json: expected object".to_owned());
    };

    let address = match util::parse_address(object.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    object.insert(
        "address".to_owned(),
        Value::String(util::format_address(address)),
    );

    let mut body = match call_ce_tool_json("generate_signature", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("CE generate_signature returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("signature generated via CE runtime"));

    success_response(body)
}

fn normalize_scan_all_params(params_json: &str) -> Result<(String, String), String> {
    let mut params = util::parse_params(params_json)?;
    let Some(object) = params.as_object_mut() else {
        return Err("invalid params json: expected object".to_owned());
    };

    let value = object
        .get("value")
        .ok_or_else(|| "missing value".to_owned())?;
    let requested_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("dword");
    let resolved_type = resolve_scan_type(requested_type, value)?;

    object.insert("type".to_owned(), Value::String(resolved_type.clone()));
    Ok((params.to_string(), resolved_type))
}

fn resolve_scan_type(requested_type: &str, value: &Value) -> Result<String, String> {
    let resolved_type = match requested_type {
        "exact" => {
            if value.is_number() {
                "dword"
            } else {
                let Some(text) = value.as_str() else {
                    return Err("value must be a string or number".to_owned());
                };
                if looks_like_aob_pattern(text) {
                    "array"
                } else {
                    "string"
                }
            }
        }
        "byte" | "word" | "dword" | "qword" | "float" | "double" | "string" | "array" => {
            requested_type
        }
        other => return Err(format!("unsupported scan type: {}", other)),
    };

    validate_scan_value(resolved_type, value)?;
    Ok(resolved_type.to_owned())
}

fn validate_scan_value(value_type: &str, value: &Value) -> Result<(), String> {
    match value_type {
        "byte" => {
            let number = parse_u64_value(value, "value must be an unsigned integer <= 255")?;
            u8::try_from(number)
                .map(|_| ())
                .map_err(|_| "value must be an unsigned integer <= 255".to_owned())
        }
        "word" => {
            let number = parse_u64_value(value, "value must be an unsigned integer <= 65535")?;
            u16::try_from(number)
                .map(|_| ())
                .map_err(|_| "value must be an unsigned integer <= 65535".to_owned())
        }
        "dword" => {
            let number = parse_u64_value(value, "value must be an unsigned integer <= 0xFFFFFFFF")?;
            u32::try_from(number)
                .map(|_| ())
                .map_err(|_| "value must be an unsigned integer <= 0xFFFFFFFF".to_owned())
        }
        "qword" => parse_u64_value(value, "value must be an unsigned integer").map(|_| ()),
        "float" | "double" => parse_f64_value(value).map(|_| ()),
        "string" => {
            let text = value
                .as_str()
                .ok_or_else(|| "value must be a string".to_owned())?;
            if text.is_empty() {
                return Err("value must not be empty".to_owned());
            }
            Ok(())
        }
        "array" => {
            let text = value
                .as_str()
                .ok_or_else(|| "value must be an AOB pattern string".to_owned())?;
            parse_aob_pattern(text).map(|_| ())
        }
        _ => Err(format!("unsupported scan type: {}", value_type)),
    }
}

fn execute_ce_scan_snippet(code: &str) -> Result<Value, ToolResponse> {
    lua_host::execute_snippet_result(code).map_err(error_response)
}

fn call_ce_tool_json(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
    let params = util::parse_params(params_json).map_err(error_response)?;
    match method {
        "scan_all" => ce_scan_all(&params),
        "get_scan_results" => ce_get_scan_results(&params),
        "next_scan" => ce_next_scan(&params),
        "aob_scan" => ce_aob_scan(&params),
        "search_string" => ce_search_string(&params),
        "generate_signature" => ce_generate_signature(&params),
        "get_memory_regions" => ce_get_memory_regions(&params),
        "enum_memory_regions_full" => ce_enum_memory_regions_full(&params),
        "checksum_memory" => ce_checksum_memory(&params),
        other => Err(error_response(format!("unsupported CE scan tool: {}", other))),
    }
}

fn ce_scan_all(params: &Value) -> Result<Value, ToolResponse> {
    let value = params
        .get("value")
        .ok_or_else(|| error_response("missing value".to_owned()))?;
    let value_lua = util::lua_scalar_literal(value).map_err(error_response)?;
    let value_type = params.get("type").and_then(Value::as_str).unwrap_or("dword");
    let value_type_lua = util::lua_string_literal(value_type);
    let protection = util::lua_string_literal(
        params
            .get("protection")
            .and_then(Value::as_str)
            .unwrap_or("+W-C"),
    );
    let code = format!(
        r###"
local value = {}
local value_type = {}
local protection = {}
local ms = createMemScan()
local scan_option = soExactValue
local vartype = vtDword
if value_type == "byte" then vartype = vtByte
elseif value_type == "word" then vartype = vtWord
elseif value_type == "qword" then vartype = vtQword
elseif value_type == "float" then vartype = vtSingle
elseif value_type == "double" then vartype = vtDouble
elseif value_type == "string" then vartype = vtString
elseif value_type == "array" then vartype = vtByteArray end
ms.firstScan(scan_option, vartype, rtRounded, tostring(value), nil, 0, 0x7FFFFFFFFFFFFFFF, protection, fsmNotAligned, "1", false, false, false, false)
ms.waitTillDone()
local fl = createFoundList(ms)
fl.initialize()
_G.__ce_mcp_scan_memscan = ms
_G.__ce_mcp_scan_foundlist = fl
return {{ success = true, count = fl.getCount() }}
"###,
        value_lua, value_type_lua, protection
    );
    execute_ce_scan_snippet(&code)
}

fn ce_get_scan_results(params: &Value) -> Result<Value, ToolResponse> {
    let max = params
        .get("max")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_SCAN_LIMIT as u64)
        .min(MAX_SCAN_LIMIT as u64);
    let code = format!(
        r###"
local max = {}
local fl = _G.__ce_mcp_scan_foundlist
if not fl then return {{ success = false, error = "No scan results. Run scan_all first." }} end
local results = {{}}
local count = math.min(fl.getCount(), max)
for i = 0, count - 1 do
    local addr_str = fl.getAddress(i)
    if addr_str and not addr_str:match("^0x") and not addr_str:match("^0X") then
        addr_str = "0x" .. addr_str
    end
    table.insert(results, {{ address = addr_str, value = fl.getValue(i) }})
end
return {{ success = true, results = results, total = fl.getCount(), returned = count }}
"###,
        max
    );
    execute_ce_scan_snippet(&code)
}

fn ce_next_scan(params: &Value) -> Result<Value, ToolResponse> {
    let scan_type = params.get("scan_type").and_then(Value::as_str).unwrap_or("exact");
    let scan_type_lua = util::lua_string_literal(scan_type);
    let value_lua = match params.get("value") {
        Some(value) => util::lua_scalar_literal(value).map_err(error_response)?,
        None => "nil".to_owned(),
    };
    let code = format!(
        r###"
local scan_type = {}
local value = {}
local ms = _G.__ce_mcp_scan_memscan
if not ms then return {{ success = false, error = "No previous scan. Run scan_all first." }} end
local scan_option = soExactValue
if scan_type == "increased" then scan_option = soIncreasedValue
elseif scan_type == "decreased" then scan_option = soDecreasedValue
elseif scan_type == "changed" then scan_option = soChanged
elseif scan_type == "unchanged" then scan_option = soUnchanged
elseif scan_type == "bigger" then scan_option = soBiggerThan
elseif scan_type == "smaller" then scan_option = soSmallerThan end
if scan_option == soExactValue then
    ms.nextScan(scan_option, rtRounded, tostring(value), nil, false, false, false, false, false)
else
    ms.nextScan(scan_option, rtRounded, nil, nil, false, false, false, false, false)
end
ms.waitTillDone()
if _G.__ce_mcp_scan_foundlist then _G.__ce_mcp_scan_foundlist.destroy() end
local fl = createFoundList(ms)
fl.initialize()
_G.__ce_mcp_scan_foundlist = fl
return {{ success = true, count = fl.getCount() }}
"###,
        scan_type_lua, value_lua
    );
    execute_ce_scan_snippet(&code)
}

fn ce_aob_scan(params: &Value) -> Result<Value, ToolResponse> {
    let pattern = util::lua_string_literal(params.get("pattern").and_then(Value::as_str).unwrap_or(""));
    let protection = util::lua_string_literal(params.get("protection").and_then(Value::as_str).unwrap_or("+X"));
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_SCAN_LIMIT as u64);
    let code = format!(
        r###"
local pattern = {}
local protection = {}
local limit = {}
local results = AOBScan(pattern, protection)
if not results then return {{ success = true, count = 0, addresses = {{}} }} end
local addresses = {{}}
for i = 0, math.min(results.Count - 1, limit - 1) do
    local addr_str = results.getString(i)
    local addr = tonumber(addr_str, 16)
    table.insert(addresses, {{ address = "0x" .. addr_str, value = addr }})
end
results.destroy()
return {{ success = true, count = #addresses, pattern = pattern, addresses = addresses }}
"###,
        pattern, protection, limit
    );
    execute_ce_scan_snippet(&code)
}

fn ce_search_string(params: &Value) -> Result<Value, ToolResponse> {
    let search_text = params
        .get("string")
        .or_else(|| params.get("pattern"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let search_lua = util::lua_string_literal(search_text);
    let wide = params.get("wide").and_then(Value::as_bool).unwrap_or(false).to_string();
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_SCAN_LIMIT as u64);
    let code = format!(
        r###"
local search_text = {}
local wide = {}
local limit = {}
local pattern = ""
for i = 1, #search_text do
    if i > 1 then pattern = pattern .. " " end
    pattern = pattern .. string.format("%02X", search_text:byte(i))
    if wide then pattern = pattern .. " 00" end
end
local results = AOBScan(pattern)
if not results then return {{ success = true, count = 0, addresses = {{}} }} end
local addresses = {{}}
for i = 0, math.min(results.Count - 1, limit - 1) do
    local addr_str = results.getString(i)
    table.insert(addresses, {{ address = "0x" .. addr_str, value = tonumber(addr_str, 16) }})
end
results.destroy()
return {{ success = true, count = #addresses, addresses = addresses }}
"###,
        search_lua, wide, limit
    );
    execute_ce_scan_snippet(&code)
}

fn ce_generate_signature(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let code = format!(
        r###"{}
local address = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local ok, signature, offset = pcall(getUniqueAOB, address)
if not ok then return {{ success = false, address = ce_mcp_to_hex(address), error = "getUniqueAOB failed: " .. tostring(signature) }} end
if not signature or signature == "" then return {{ success = false, address = ce_mcp_to_hex(address), error = "Could not generate unique signature - pattern not unique enough" }} end
local byte_count = 0
for _ in signature:gmatch("%S+") do byte_count = byte_count + 1 end
return {{ success = true, address = ce_mcp_to_hex(address), signature = signature, offset_from_start = offset or 0, byte_count = byte_count, usage_hint = string.format("aob_scan('%s') then add offset %d to reach target", signature, offset or 0) }}
"###,
        LUA_TO_HEX_HELPER, address_lua
    );
    execute_ce_scan_snippet(&code)
}

fn ce_get_memory_regions(params: &Value) -> Result<Value, ToolResponse> {
    let max = params
        .get("max")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_REGION_MAX as u64);
    let code = format!(
        r###"{}
local max = {}
local ok, regions = pcall(enumMemoryRegions)
if not ok or not regions then return {{ success = false, error = "enumMemoryRegions failed" }} end
local result = {{}}
for i, region in ipairs(regions) do
    if i > max then break end
    local protect = region.Protect or 0
    local state = region.State or 0
    table.insert(result, {{
        base = ce_mcp_to_hex(region.BaseAddress or 0),
        size = region.RegionSize or 0,
        protect = protect,
        state = state,
        readable = protect == 0x02 or protect == 0x04 or protect == 0x20 or protect == 0x40,
        writable = protect == 0x04 or protect == 0x08 or protect == 0x40 or protect == 0x80,
        executable = protect == 0x10 or protect == 0x20 or protect == 0x40 or protect == 0x80,
    }})
end
return {{ success = true, count = #result, regions = result }}
"###,
        LUA_TO_HEX_HELPER, max
    );
    execute_ce_scan_snippet(&code)
}

fn ce_enum_memory_regions_full(params: &Value) -> Result<Value, ToolResponse> {
    let max = params
        .get("max")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_FULL_REGION_MAX as u64);
    let code = format!(
        r###"{}
local max = {}
local ok, regions = pcall(enumMemoryRegions)
if not ok or not regions then return {{ success = false, error = "enumMemoryRegions failed" }} end
local result = {{}}
for i, region in ipairs(regions) do
    if i > max then break end
    local protect = region.Protect or 0
    local state = region.State or 0
    local protect_string = string.format("0x%X", protect)
    if protect == 0x10 then protect_string = "X"
    elseif protect == 0x20 then protect_string = "RX"
    elseif protect == 0x40 then protect_string = "RWX"
    elseif protect == 0x80 then protect_string = "WX"
    elseif protect == 0x02 then protect_string = "R"
    elseif protect == 0x04 then protect_string = "RW"
    elseif protect == 0x08 then protect_string = "W" end
    table.insert(result, {{
        base = ce_mcp_to_hex(region.BaseAddress or 0),
        allocation_base = ce_mcp_to_hex(region.AllocationBase or 0),
        size = region.RegionSize or 0,
        state = state,
        protect = protect,
        protect_string = protect_string,
        type = region.Type or 0,
        is_committed = state == 0x1000,
        is_reserved = state == 0x2000,
        is_free = state == 0x10000,
    }})
end
return {{ success = true, count = #result, regions = result }}
"###,
        LUA_TO_HEX_HELPER, max
    );
    execute_ce_scan_snippet(&code)
}

fn ce_checksum_memory(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let size = params.get("size").and_then(Value::as_u64).unwrap_or(256);
    let code = format!(
        r###"{}
local address = {}
local size = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local ok, hash = pcall(md5memory, address, size)
if ok and hash then return {{ success = true, address = ce_mcp_to_hex(address), size = size, md5_hash = hash }} end
return {{ success = false, address = ce_mcp_to_hex(address), size = size, error = "Failed to calculate MD5: " .. tostring(hash) }}
"###,
        LUA_TO_HEX_HELPER, address_lua, size
    );
    execute_ce_scan_snippet(&code)
}
fn success_response(body: Value) -> ToolResponse {
    ToolResponse {
        success: true,
        body_json: body.to_string(),
    }
}

fn normalize_scan_address_entries(
    body: &mut Value,
    field: &str,
    modules: &[runtime::ModuleInfo],
    preserve_value_address: bool,
) {
    let Some(entries) = body.get_mut(field).and_then(Value::as_array_mut) else {
        return;
    };

    for entry in entries.iter_mut() {
        let Some(object) = entry.as_object_mut() else {
            continue;
        };

        let parsed_address = response_address(object.get("address"));
        if let Some(address) = parsed_address {
            object.insert(
                "address".to_owned(),
                Value::String(util::format_address(address)),
            );
            object.insert(
                "normalized_address".to_owned(),
                json!(addressing::normalize_address_from_modules(address, modules)),
            );
            if preserve_value_address && !object.contains_key("value") {
                object.insert("value".to_owned(), json!(address));
            }
        } else {
            object.insert("normalized_address".to_owned(), Value::Null);
        }
    }
}

fn response_address(value: Option<&Value>) -> Option<usize> {
    value.and_then(|value| util::parse_address(Some(value)).ok())
}

fn is_supported_next_scan_type(scan_type: &str) -> bool {
    matches!(
        scan_type,
        "exact" | "increased" | "decreased" | "changed" | "unchanged" | "bigger" | "smaller"
    )
}

fn scan_type_requires_target_value(scan_type: &str) -> bool {
    matches!(scan_type, "exact" | "bigger" | "smaller")
}

fn parse_u64_value(value: &Value, error: &str) -> Result<u64, String> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    if let Some(text) = value.as_str() {
        let trimmed = text.trim();
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex, 16).map_err(|_| error.to_owned());
        }
        return trimmed.parse::<u64>().map_err(|_| error.to_owned());
    }
    Err(error.to_owned())
}

fn parse_f64_value(value: &Value) -> Result<f64, String> {
    if let Some(number) = value.as_f64() {
        return Ok(number);
    }
    if let Some(text) = value.as_str() {
        return text
            .trim()
            .parse::<f64>()
            .map_err(|_| "value must be numeric".to_owned());
    }
    Err("value must be numeric".to_owned())
}

fn looks_like_aob_pattern(value: &str) -> bool {
    if !value.contains(char::is_whitespace) {
        return false;
    }

    value.split_whitespace().all(|token| {
        token == "?"
            || token == "??"
            || (token.len() == 2 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
    })
}

fn parse_aob_pattern(pattern: &str) -> Result<Vec<Option<u8>>, String> {
    let mut parsed = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            parsed.push(None);
            continue;
        }

        let cleaned = token.trim();
        if cleaned.len() != 2 {
            return Err(format!("invalid AOB token: {}", token));
        }
        let value =
            u8::from_str_radix(cleaned, 16).map_err(|_| format!("invalid AOB token: {}", token))?;
        parsed.push(Some(value));
    }

    if parsed.is_empty() {
        return Err("pattern is empty".to_owned());
    }

    Ok(parsed)
}

fn parse_positive_size(value: Option<&Value>, default: usize, max: usize) -> usize {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(max)
}

fn parse_usize(value: Option<&Value>, default: usize, max: usize) -> usize {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
        .min(max)
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
