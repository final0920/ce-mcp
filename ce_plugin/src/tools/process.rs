use serde_json::{json, Value};

use super::{addressing, lua_backend, util, ToolResponse};
use crate::runtime;

const METHODS: &[&str] = &[
    "ping",
    "get_process_info",
    "enum_modules",
    "get_thread_list",
    "get_symbol_address",
    "get_address_info",
    "normalize_address",
    "get_rtti_classname",
];

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "ping" => ping(),
        "get_process_info" => get_process_info(),
        "enum_modules" => enum_modules(),
        "get_thread_list" => get_thread_list(),
        "get_symbol_address" => get_symbol_address(params_json),
        "get_address_info" => get_address_info(params_json),
        "normalize_address" => normalize_address(params_json),
        "get_rtti_classname" => get_rtti_classname(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

pub(crate) fn current_modules() -> Vec<runtime::ModuleInfo> {
    // 主路径优先走 CE/Lua 后端，避免把 Toolhelp32 枚举重新扩散回业务层。
    match lua_modules_from_backend() {
        Ok(modules) => modules,
        Err(_) => native_current_modules(),
    }
}

fn native_current_modules() -> Vec<runtime::ModuleInfo> {
    // 这里只保留宿主侧兜底：当 Lua 后端不可用时，用 Toolhelp32 给地址归一化/线程工具提供最小模块视图。
    let Some(app) = runtime::app_state() else {
        return Vec::new();
    };

    let process_id = app.opened_process_id().unwrap_or(0);
    if process_id == 0 {
        return Vec::new();
    }

    runtime::enum_modules(process_id).unwrap_or_default()
}

fn ping() -> ToolResponse {
    let details = runtime::app_state()
        .map(|app| {
            format!(
                "\"plugin_id\":{},\"bind_addr\":\"{}\",\"server_name\":\"{}\",\"server_version\":\"{}\"",
                app.plugin_id(),
                util::escape_json(app.config().bind_addr.as_str()),
                util::escape_json(app.config().server_name.as_str()),
                util::escape_json(app.config().server_version.as_str())
            )
        })
        .unwrap_or_else(|| {
            "\"plugin_id\":-1,\"bind_addr\":\"unknown\",\"server_name\":\"cheatengine-ce-plugin\",\"server_version\":\"unknown\""
                .to_owned()
        });

    ToolResponse {
        success: true,
        body_json: format!(
            "{{\"success\":true,\"message\":\"ce_plugin runtime alive\",\"supported_ce_versions\":[\"7.5-x64\",\"7.6-x64\"],{}}}",
            details
        ),
    }
}

fn call_lua_json_tool(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
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

fn is_no_process_attached_response(response: &ToolResponse) -> bool {
    response.body_json.contains("No process attached")
}

fn unattached_process_info_body() -> Value {
    json!({
        "success": true,
        "process_id": 0,
        "attached": false,
        "process_name": "unattached",
        "module_count": 0,
        "modules": [],
        "main_module": Value::Null,
        "architecture": "x64",
        "note": "no process attached (lua backend)"
    })
}

fn lua_process_attached() -> Result<bool, ToolResponse> {
    match call_lua_json_tool("get_process_info", "{}") {
        Ok(body) => Ok(body.get("process_id").and_then(Value::as_u64).unwrap_or(0) != 0),
        Err(response) if is_no_process_attached_response(&response) => Ok(false),
        Err(response) => Err(response),
    }
}

fn lua_module_from_value(value: &Value) -> Option<runtime::ModuleInfo> {
    let address = util::parse_address(value.get("address")).ok()?;
    Some(runtime::ModuleInfo {
        name: value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("???")
            .to_owned(),
        base_address: address,
        size: value
            .get("size")
            .and_then(Value::as_u64)
            .and_then(|size| u32::try_from(size).ok())
            .unwrap_or(0),
        path: value
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

fn enrich_lua_modules_in_place(body: &mut Value) -> Vec<runtime::ModuleInfo> {
    let Some(modules) = body.get_mut("modules").and_then(Value::as_array_mut) else {
        return Vec::new();
    };

    let mut parsed = Vec::with_capacity(modules.len());
    for module in modules.iter_mut() {
        let Some(info) = lua_module_from_value(module) else {
            continue;
        };

        if let Some(object) = module.as_object_mut() {
            if !object.contains_key("path") {
                object.insert("path".to_owned(), json!(info.path.clone()));
            }
            if !object.contains_key("normalized") {
                object.insert(
                    "normalized".to_owned(),
                    addressing::normalized_module_metadata(&info),
                );
            }
        }

        parsed.push(info);
    }

    parsed
}

fn lua_modules_from_backend() -> Result<Vec<runtime::ModuleInfo>, ToolResponse> {
    let mut body = match call_lua_json_tool("enum_modules", "{}") {
        Ok(value) => value,
        Err(response) if is_no_process_attached_response(&response) => return Ok(Vec::new()),
        Err(response) => return Err(response),
    };

    Ok(enrich_lua_modules_in_place(&mut body))
}

fn main_module_json(module: &runtime::ModuleInfo) -> Value {
    json!({
        "module_name": module.name,
        "module_base": util::format_address(module.base_address),
        "size": module.size,
        "path": module.path,
        "normalized": addressing::normalized_module_metadata(module),
    })
}

fn get_process_info() -> ToolResponse {
    match call_lua_json_tool("get_process_info", "{}") {
        Ok(mut body) => {
            let modules = enrich_lua_modules_in_place(&mut body);
            let attached = body.get("process_id").and_then(Value::as_u64).unwrap_or(0) != 0;

            if let Some(object) = body.as_object_mut() {
                object.insert("success".to_owned(), Value::Bool(true));
                object.insert("attached".to_owned(), Value::Bool(attached));
                object.insert("module_count".to_owned(), json!(modules.len()));
                if !object.contains_key("architecture") {
                    object.insert("architecture".to_owned(), json!("x64"));
                }
                if !object.contains_key("note") {
                    object.insert(
                        "note".to_owned(),
                        json!("live process response via embedded lua backend"),
                    );
                }
                if !object.contains_key("main_module") {
                    object.insert(
                        "main_module".to_owned(),
                        modules.first().map(main_module_json).unwrap_or(Value::Null),
                    );
                }
            }

            ToolResponse {
                success: true,
                body_json: body.to_string(),
            }
        }
        Err(response) if is_no_process_attached_response(&response) => ToolResponse {
            success: true,
            body_json: unattached_process_info_body().to_string(),
        },
        Err(response) => response,
    }
}

fn enum_modules() -> ToolResponse {
    let attached = match lua_process_attached() {
        Ok(attached) => attached,
        Err(response) => return response,
    };

    if !attached {
        return ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "modules": [],
                "count": 0,
                "attached": false,
            })
            .to_string(),
        };
    }

    let mut body = match call_lua_json_tool("enum_modules", "{}") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let modules = enrich_lua_modules_in_place(&mut body);

    if let Some(object) = body.as_object_mut() {
        object.insert("success".to_owned(), Value::Bool(true));
        object.insert("count".to_owned(), json!(modules.len()));
        object.insert("attached".to_owned(), Value::Bool(true));
    }

    ToolResponse {
        success: true,
        body_json: body.to_string(),
    }
}

fn get_thread_list() -> ToolResponse {
    let Some(app) = runtime::app_state() else {
        return ToolResponse {
            success: false,
            body_json: "runtime not initialized".to_owned(),
        };
    };

    let process_id = app.opened_process_id().unwrap_or(0);
    if process_id == 0 {
        return ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "count": 0,
                "threads": [],
                "attached": false,
            })
            .to_string(),
        };
    }

    match runtime::enum_threads(process_id) {
        Ok(threads) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "count": threads.len(),
                "threads": threads.into_iter().map(|thread| json!({
                    "thread_id": thread.thread_id,
                    "owner_process_id": thread.owner_process_id,
                })).collect::<Vec<_>>(),
            })
            .to_string(),
        },
        Err(error) => ToolResponse {
            success: false,
            body_json: error,
        },
    }
}

fn get_symbol_address(params_json: &str) -> ToolResponse {
    let Some(_app) = runtime::app_state() else {
        return ToolResponse {
            success: false,
            body_json: "runtime not initialized".to_owned(),
        };
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let symbol = match params
        .get("symbol")
        .or_else(|| params.get("name"))
        .and_then(Value::as_str)
    {
        Some(symbol) if !symbol.trim().is_empty() => symbol.trim(),
        _ => return error_response("missing symbol".to_owned()),
    };
    let modules = current_modules();

    match resolve_symbol_address(symbol, &modules) {
        Ok(address) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "symbol": symbol,
                "address": util::format_address(address),
                "value": address,
            })
            .to_string(),
        },
        Err(error) => error_response(error),
    }
}

pub(crate) fn address_info_json(
    address: usize,
    modules: &[runtime::ModuleInfo],
    include_modules: bool,
    include_symbols: bool,
    include_sections: bool,
) -> Value {
    let module = find_module_for_address(address, modules);
    let normalized_address = addressing::normalize_address_from_modules(address, modules);

    let module_json = if include_modules {
        module.map(|module| {
            json!({
                "name": module.name,
                "path": module.path,
                "base": util::format_address(module.base_address),
                "size": module.size,
                "offset": address.saturating_sub(module.base_address),
                "normalized": addressing::normalized_module_metadata(module),
            })
        })
    } else {
        None
    };

    let symbol_json = if include_symbols {
        module.map(|module| {
            let offset = address.saturating_sub(module.base_address);
            json!({
                "name": format!("{}+0x{:X}", module.name, offset),
                "kind": "module_offset",
                "resolved_by": "module_enumeration",
                "note": "PE symbol engine not wired yet; using module-relative fallback",
            })
        })
    } else {
        None
    };

    let section_json = if include_sections {
        Some(json!({
            "available": false,
            "note": "PE section parsing not implemented in ce_plugin yet",
        }))
    } else {
        None
    };

    json!({
        "success": true,
        "address": util::format_address(address),
        "normalized_address": normalized_address,
        "module": module_json,
        "symbol": symbol_json,
        "section": section_json,
        "has_module_match": module.is_some(),
    })
}

fn get_address_info(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let include_modules = params
        .get("include_modules")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let include_symbols = params
        .get("include_symbols")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let include_sections = params
        .get("include_sections")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let lua_body = match call_lua_json_tool("get_address_info", params_json) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let address = match util::parse_address(lua_body.get("address")) {
        Ok(address) => address,
        Err(error) => {
            return error_response(format!(
                "lua backend get_address_info returned invalid address: {}",
                error
            ))
        }
    };
    let modules = match lua_modules_from_backend() {
        Ok(modules) => modules,
        Err(response) => return response,
    };

    let mut body = address_info_json(
        address,
        &modules,
        include_modules,
        include_symbols,
        include_sections,
    );

    if let (Some(lua_object), Some(body_object)) = (lua_body.as_object(), body.as_object_mut()) {
        if let Some(symbolic_name) = lua_object.get("symbolic_name") {
            body_object.insert("symbolic_name".to_owned(), symbolic_name.clone());
        }
        if let Some(is_in_module) = lua_object.get("is_in_module") {
            if is_in_module.as_bool().unwrap_or(false) {
                body_object.insert("has_module_match".to_owned(), Value::Bool(true));
            }
            body_object.insert("is_in_module".to_owned(), is_in_module.clone());
        }
        if let Some(options_used) = lua_object.get("options_used") {
            body_object.insert("options_used".to_owned(), options_used.clone());
        }
        if include_symbols {
            let has_symbol = body_object
                .get("symbol")
                .map(|value| !value.is_null())
                .unwrap_or(false);
            let symbolic_name = lua_object.get("symbolic_name").and_then(Value::as_str);
            let address_text = lua_object.get("address").and_then(Value::as_str);
            if !has_symbol {
                if let Some(symbolic_name) = symbolic_name {
                    if Some(symbolic_name) != address_text {
                        body_object.insert(
                            "symbol".to_owned(),
                            json!({
                                "name": symbolic_name,
                                "kind": "lua_symbolic_name",
                                "resolved_by": "lua_backend",
                            }),
                        );
                    }
                }
            }
        }
    }

    ToolResponse {
        success: true,
        body_json: body.to_string(),
    }
}

fn normalize_address(params_json: &str) -> ToolResponse {
    let Some(_app) = runtime::app_state() else {
        return ToolResponse {
            success: false,
            body_json: "runtime not initialized".to_owned(),
        };
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let modules = current_modules();
    let address = match resolve_address_param(params.get("address"), &modules) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "address": util::format_address(address),
            "normalized_address": addressing::normalize_address_from_modules(address, &modules),
        })
        .to_string(),
    }
}

fn get_rtti_classname(params_json: &str) -> ToolResponse {
    let Some(app) = runtime::app_state() else {
        return ToolResponse {
            success: false,
            body_json: "runtime not initialized".to_owned(),
        };
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let modules = current_modules();
    let address = match resolve_address_param(params.get("address"), &modules) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    let lua_result = lua_rtti_classname(address, &modules);
    if let Ok(body) = &lua_result {
        if body.get("found").and_then(Value::as_bool).unwrap_or(false) {
            return ToolResponse {
                success: true,
                body_json: body.to_string(),
            };
        }
    }

    let Some(handle) = app.opened_process_handle() else {
        return match lua_result {
            Ok(body) => ToolResponse {
                success: true,
                body_json: body.to_string(),
            },
            Err(error) => error_response(format!(
                "process handle unavailable and lua RTTI lookup failed: {}",
                error
            )),
        };
    };

    match resolve_rtti_classname_native(handle, address, &modules) {
        Ok(Some(result)) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "address": util::format_address(address),
                "normalized_address": addressing::normalize_address_from_modules(address, &modules),
                "class_name": result.class_name,
                "decorated_name": result.decorated_name,
                "found": true,
                "rtti_module": result.module_name,
                "resolver": "msvc_x64_rtti_fallback",
            })
            .to_string(),
        },
        Ok(None) => match lua_result {
            Ok(body) => ToolResponse {
                success: true,
                body_json: body.to_string(),
            },
            Err(_) => ToolResponse {
                success: true,
                body_json: json!({
                    "success": true,
                    "address": util::format_address(address),
                    "normalized_address": addressing::normalize_address_from_modules(address, &modules),
                    "class_name": Value::Null,
                    "decorated_name": Value::Null,
                    "found": false,
                    "rtti_module": Value::Null,
                    "resolver": "msvc_x64_rtti_fallback",
                    "note": "No RTTI information found at this address",
                })
                .to_string(),
            },
        },
        Err(error) => match lua_result {
            Ok(body) => ToolResponse {
                success: true,
                body_json: body.to_string(),
            },
            Err(lua_error) => {
                error_response(format!("lua RTTI lookup failed: {}; native fallback failed: {}", lua_error, error))
            }
        },
    }
}

pub(crate) fn resolve_symbol_address(
    symbol: &str,
    modules: &[runtime::ModuleInfo],
) -> Result<usize, String> {
    let trimmed = symbol.trim();
    if let Ok(address) = util::parse_address(Some(&Value::String(trimmed.to_owned()))) {
        return Ok(address);
    }
    if let Some(address) = parse_plain_hex_or_dec(trimmed) {
        return Ok(address);
    }

    let Some((module_name, offset_text)) = split_module_expression(trimmed) else {
        return Err(format!(
            "unsupported symbol format: {} (expected address or module+offset)",
            symbol
        ));
    };
    let offset = parse_offset(offset_text)?;
    let module = find_module_by_name(module_name, modules)
        .ok_or_else(|| format!("module not found: {}", module_name))?;
    Ok(module.base_address.saturating_add(offset))
}

fn split_module_expression(symbol: &str) -> Option<(&str, &str)> {
    let (module_name, offset_text) = symbol.rsplit_once('+')?;
    let module_name = module_name.trim();
    let offset_text = offset_text.trim();
    if module_name.is_empty() || offset_text.is_empty() {
        return None;
    }
    Some((module_name, offset_text))
}

fn parse_offset(value: &str) -> Result<usize, String> {
    parse_number_text(value.trim()).ok_or_else(|| format!("invalid module offset: {}", value))
}

fn parse_plain_hex_or_dec(text: &str) -> Option<usize> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    parse_number_text(trimmed)
}

fn parse_number_text(text: &str) -> Option<usize> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return usize::from_str_radix(hex, 16).ok();
    }

    if text.chars().all(|ch| ch.is_ascii_digit()) {
        return text.parse::<usize>().ok();
    }

    if text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return usize::from_str_radix(text, 16).ok();
    }

    None
}

pub(crate) fn resolve_address_param(
    raw_address: Option<&Value>,
    modules: &[runtime::ModuleInfo],
) -> Result<usize, String> {
    let Some(raw_address) = raw_address else {
        return Err("missing address".to_owned());
    };
    match raw_address {
        Value::String(text) => resolve_symbol_address(text, modules),
        _ => util::parse_address(Some(raw_address)),
    }
}

pub(crate) fn find_module_by_name<'a>(
    module_name: &str,
    modules: &'a [runtime::ModuleInfo],
) -> Option<&'a runtime::ModuleInfo> {
    let needle = module_name.trim().to_ascii_lowercase();
    modules
        .iter()
        .find(|module| module_name_matches(&needle, module))
}

fn module_name_matches(needle: &str, module: &runtime::ModuleInfo) -> bool {
    let module_name = module.name.to_ascii_lowercase();
    let module_path = module.path.to_ascii_lowercase();
    if module_name == needle || module_path.ends_with(needle) {
        return true;
    }

    let module_stem = module_name
        .strip_suffix(".exe")
        .or_else(|| module_name.strip_suffix(".dll"))
        .unwrap_or(module_name.as_str());
    let needle_stem = needle
        .strip_suffix(".exe")
        .or_else(|| needle.strip_suffix(".dll"))
        .unwrap_or(needle);

    module_stem == needle_stem
}

pub(crate) fn find_module_for_address<'a>(
    address: usize,
    modules: &'a [runtime::ModuleInfo],
) -> Option<&'a runtime::ModuleInfo> {
    modules.iter().find(|module| {
        let start = module.base_address;
        let end = start.saturating_add(module.size as usize);
        start <= address && address < end
    })
}

struct RttiClassResult {
    class_name: String,
    decorated_name: String,
    module_name: Option<String>,
}

fn lua_rtti_classname(address: usize, modules: &[runtime::ModuleInfo]) -> Result<Value, String> {
    let mut body = call_lua_json_tool(
        "get_rtti_classname",
        &json!({ "address": util::format_address(address) }).to_string(),
    )
    .map_err(|response| response.body_json)?;
    let Some(object) = body.as_object_mut() else {
        return Err("lua get_rtti_classname returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object.insert("address".to_owned(), json!(util::format_address(address)));
    object.insert(
        "normalized_address".to_owned(),
        json!(addressing::normalize_address_from_modules(address, modules)),
    );
    object
        .entry("decorated_name".to_owned())
        .or_insert(Value::Null);
    object
        .entry("rtti_module".to_owned())
        .or_insert(Value::Null);
    object
        .entry("resolver".to_owned())
        .or_insert(json!("ce_getRTTIClassName"));

    Ok(body)
}

fn resolve_rtti_classname_native(
    handle: *mut core::ffi::c_void,
    object_address: usize,
    modules: &[runtime::ModuleInfo],
) -> Result<Option<RttiClassResult>, String> {
    let vftable = match read_u64(handle, object_address) {
        Ok(value) => value as usize,
        Err(_) => return Ok(None),
    };
    if vftable < 8 {
        return Ok(None);
    }

    let col_address = match read_u64(handle, vftable.saturating_sub(8)) {
        Ok(value) => value as usize,
        Err(_) => return Ok(None),
    };
    if col_address == 0 {
        return Ok(None);
    }

    let col = match runtime::read_process_memory(handle, col_address, 24) {
        Ok(bytes) if bytes.len() == 24 => bytes,
        _ => return Ok(None),
    };

    let type_desc_rva = u32::from_le_bytes(col[12..16].try_into().unwrap_or([0; 4])) as usize;
    let self_rva = u32::from_le_bytes(col[20..24].try_into().unwrap_or([0; 4])) as usize;
    if type_desc_rva == 0 || self_rva == 0 || self_rva > col_address {
        return Ok(None);
    }

    let image_base = col_address.saturating_sub(self_rva);
    let type_desc_address = image_base.saturating_add(type_desc_rva);
    let decorated_name = match read_c_string(handle, type_desc_address.saturating_add(16), 256) {
        Some(name) if !name.is_empty() => name,
        _ => return Ok(None),
    };
    let class_name =
        demangle_msvc_type_name(&decorated_name).unwrap_or_else(|| decorated_name.clone());
    let module_name =
        find_module_for_address(image_base, modules).map(|module| module.name.clone());

    Ok(Some(RttiClassResult {
        class_name,
        decorated_name,
        module_name,
    }))
}

fn read_u64(handle: *mut core::ffi::c_void, address: usize) -> Result<u64, String> {
    let bytes = runtime::read_process_memory(handle, address, 8)?;
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "unexpected read length for u64".to_owned())?;
    Ok(u64::from_le_bytes(array))
}

fn read_c_string(
    handle: *mut core::ffi::c_void,
    address: usize,
    max_length: usize,
) -> Option<String> {
    let mut size = max_length.min(256);
    while size >= 32 {
        if let Ok(bytes) = runtime::read_process_memory(handle, address, size) {
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            if end > 0 {
                return Some(String::from_utf8_lossy(&bytes[..end]).to_string());
            }
        }
        size /= 2;
    }
    None
}

fn demangle_msvc_type_name(name: &str) -> Option<String> {
    let stripped = name
        .strip_prefix(".?AV")
        .or_else(|| name.strip_prefix(".?AU"))
        .or_else(|| name.strip_prefix(".?AW"))?;
    let body = stripped.strip_suffix("@@").unwrap_or(stripped);
    let mut parts = body
        .split('@')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }
    parts.reverse();
    Some(parts.join("::"))
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
