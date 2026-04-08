use serde_json::{json, Value};

use super::{addressing, lua_backend, process, util, ToolResponse};
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

    let mut body = match call_lua_tool_json("scan_all", &forwarded_params) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("lua scan_all returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("type".to_owned())
        .or_insert_with(|| Value::String(resolved_type));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("scan session via embedded lua backend"));

    success_response(body)
}

fn get_scan_results(params_json: &str) -> ToolResponse {
    let modules = process::current_modules();
    let mut body = match call_lua_tool_json("get_scan_results", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    normalize_scan_address_entries(&mut body, "results", &modules, false);

    let Some(object) = body.as_object_mut() else {
        return error_response("lua get_scan_results returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("scan results sourced from embedded lua backend"));

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

    let mut body = match call_lua_tool_json("next_scan", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("lua next_scan returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("next scan executed via embedded lua backend"));

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

    let mut body = match call_lua_tool_json("get_memory_regions", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("lua get_memory_regions returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("memory regions sourced from embedded lua backend"));

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

    let mut body = match call_lua_tool_json("enum_memory_regions_full", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("lua enum_memory_regions_full returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("full memory map sourced from embedded lua backend"));

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

    let mut body = match call_lua_tool_json("checksum_memory", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("lua checksum_memory returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("memory checksum calculated via embedded lua backend"));

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
    let mut body = match call_lua_tool_json("aob_scan", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    normalize_scan_address_entries(&mut body, "addresses", &modules, true);

    let Some(object) = body.as_object_mut() else {
        return error_response("lua aob_scan returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("pattern".to_owned())
        .or_insert_with(|| Value::String(pattern_text.to_owned()));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("AOB scan executed via embedded lua backend"));

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
    let mut body = match call_lua_tool_json("search_string", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    normalize_scan_address_entries(&mut body, "addresses", &modules, false);

    let Some(object) = body.as_object_mut() else {
        return error_response("lua search_string returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("query".to_owned())
        .or_insert_with(|| Value::String(search_text.to_owned()));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("string search executed via embedded lua backend"));

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

    let mut body = match call_lua_tool_json("generate_signature", &params.to_string()) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let Some(object) = body.as_object_mut() else {
        return error_response("lua generate_signature returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("signature generated via embedded lua backend"));

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

fn call_lua_tool_json(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
    let response = lua_backend::call_lua_tool(method, params_json);
    if !response.success {
        return Err(response);
    }

    serde_json::from_str::<Value>(&response.body_json)
        .map_err(|error| error_response(format!("invalid {} lua response json: {}", method, error)))
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
