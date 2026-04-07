use serde_json::{json, Value};

use super::{addressing, util, ToolResponse};
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

fn get_process_info() -> ToolResponse {
    let Some(app) = runtime::app_state() else {
        return ToolResponse {
            success: false,
            body_json: "runtime not initialized".to_owned(),
        };
    };

    let process_id = app.opened_process_id().unwrap_or(0);
    let attached = process_id != 0;
    let process_name = app
        .opened_process_handle()
        .and_then(|handle| runtime::query_process_image_name(handle).ok())
        .unwrap_or_else(|| {
            if attached {
                "attached-process".to_owned()
            } else {
                "unattached".to_owned()
            }
        });
    let modules = if attached {
        runtime::enum_modules(process_id).unwrap_or_default()
    } else {
        Vec::new()
    };
    let modules_json = modules
        .iter()
        .map(|module| {
            json!({
                "name": module.name,
                "address": util::format_address(module.base_address),
                "size": module.size,
                "path": module.path,
                "normalized": addressing::normalized_module_metadata(module),
            })
        })
        .collect::<Vec<_>>();
    let main_module = modules.first().map(|module| {
        json!({
            "module_name": module.name,
            "module_base": util::format_address(module.base_address),
            "size": module.size,
            "path": module.path,
            "normalized": addressing::normalized_module_metadata(module),
        })
    });

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "process_id": process_id,
            "attached": attached,
            "process_name": process_name,
            "module_count": modules_json.len(),
            "modules": modules_json,
            "main_module": main_module,
            "architecture": "x64",
            "note": "live process response; symbol/rtti integration pending"
        })
        .to_string(),
    }
}

fn enum_modules() -> ToolResponse {
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
                "modules": [],
                "count": 0,
                "attached": false,
            })
            .to_string(),
        };
    }

    match runtime::enum_modules(process_id) {
        Ok(modules) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "count": modules.len(),
                "modules": modules.into_iter().map(|module| json!({
                    "name": module.name,
                    "address": util::format_address(module.base_address),
                    "size": module.size,
                    "is_64bit": true,
                    "path": module.path,
                    "normalized": addressing::normalized_module_metadata(&module),
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

    let modules = current_modules();
    let address = match resolve_address_param(params.get("address"), &modules) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    ToolResponse {
        success: true,
        body_json: address_info_json(
            address,
            &modules,
            include_modules,
            include_symbols,
            include_sections,
        )
        .to_string(),
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
    let Some(handle) = app.opened_process_handle() else {
        return error_response("process handle unavailable".to_owned());
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

    match resolve_rtti_classname(handle, address, &modules) {
        Ok(Some(result)) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "address": util::format_address(address),
                "class_name": result.class_name,
                "decorated_name": result.decorated_name,
                "found": true,
                "rtti_module": result.module_name,
                "resolver": "msvc_x64_rtti",
            })
            .to_string(),
        },
        Ok(None) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "address": util::format_address(address),
                "class_name": Value::Null,
                "found": false,
                "note": "No MSVC x64 RTTI information found at this address",
            })
            .to_string(),
        },
        Err(error) => error_response(error),
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

fn resolve_rtti_classname(
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
