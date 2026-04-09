use serde_json::{json, Value};

use super::{addressing, lua_host, util, ToolResponse};
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
    // Module state must come from Cheat Engine's own runtime capabilities.
    lua_modules_from_backend().unwrap_or_default()
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

fn call_ce_json_tool_from_json(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
    let params = util::parse_params(params_json).map_err(error_response)?;
    call_ce_json_tool(method, &params)
}

fn call_ce_json_tool(method: &str, params: &Value) -> Result<Value, ToolResponse> {
    match method {
        "get_process_info" => ce_get_process_info(),
        "enum_modules" => ce_enum_modules(),
        "get_thread_list" => ce_get_thread_list(),
        "get_symbol_address" => ce_get_symbol_address(params),
        "get_address_info" => ce_get_address_info(params),
        "get_rtti_classname" => ce_get_rtti_classname(params),
        other => Err(error_response(format!("unsupported CE process tool: {}", other))),
    }
}

fn execute_ce_process_snippet(code: &str) -> Result<Value, ToolResponse> {
    lua_host::execute_snippet_result(code).map_err(error_response)
}

fn ce_get_process_info() -> Result<Value, ToolResponse> {
    let code = format!(
        r###"{}
pcall(reinitializeSymbolhandler)
local pid = getOpenedProcessID()
if not pid or pid == 0 then
    return {{ success = false, error = "No process attached" }}
end

local modules = enumModules(pid)
if not modules or #modules == 0 then
    modules = enumModules()
end

local module_list = {{}}
for i, module in ipairs(modules or {{}}) do
    if i > 50 then break end
    table.insert(module_list, {{
        name = module.Name or "???",
        address = ce_mcp_to_hex(module.Address or 0),
        size = module.Size or 0,
        path = module.PathToFile or module.Path or ""
    }})
end

local process_name = (process and process ~= "" and process) or "L2.exe"
return {{
    success = true,
    process_id = pid,
    process_name = process_name,
    module_count = #module_list,
    modules = module_list,
    used_aob_fallback = false
}}
"###,
        LUA_TO_HEX_HELPER
    );
    execute_ce_process_snippet(&code)
}

fn ce_enum_modules() -> Result<Value, ToolResponse> {
    let code = format!(
        r###"{}
local pid = getOpenedProcessID()
local modules = enumModules(pid)
if not modules or #modules == 0 then
    modules = enumModules()
end

local result = {{}}
for _, module in ipairs(modules or {{}}) do
    table.insert(result, {{
        name = module.Name or "???",
        address = ce_mcp_to_hex(module.Address or 0),
        size = module.Size or 0,
        path = module.PathToFile or module.Path or ""
    }})
end

return {{ success = true, count = #result, modules = result }}
"###,
        LUA_TO_HEX_HELPER
    );
    execute_ce_process_snippet(&code)
}

fn ce_get_thread_list() -> Result<Value, ToolResponse> {
    let code = r###"
local list = createStringlist()
getThreadlist(list)

local threads = {}
for i = 0, list.Count - 1 do
    local id_hex = list[i]
    table.insert(threads, {
        id_hex = id_hex,
        id_int = tonumber(id_hex, 16)
    })
end

list.destroy()
return { success = true, count = #threads, threads = threads }
"###;
    execute_ce_process_snippet(code)
}

fn ce_get_symbol_address(params: &Value) -> Result<Value, ToolResponse> {
    let symbol = params
        .get("symbol")
        .or_else(|| params.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error_response("missing symbol".to_owned()))?;
    let symbol_lua = util::lua_string_literal(symbol);
    let code = format!(
        r###"{}
local symbol = {}
local addr = getAddressSafe(symbol)
if addr then
    return {{ success = true, symbol = symbol, address = ce_mcp_to_hex(addr), value = addr }}
end
return {{ success = false, error = "Symbol not found: " .. symbol }}
"###,
        LUA_TO_HEX_HELPER, symbol_lua
    );
    execute_ce_process_snippet(&code)
}

fn ce_get_address_info(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let include_modules = params
        .get("include_modules")
        .and_then(Value::as_bool)
        .unwrap_or(true)
        .to_string();
    let include_symbols = params
        .get("include_symbols")
        .and_then(Value::as_bool)
        .unwrap_or(true)
        .to_string();
    let include_sections = params
        .get("include_sections")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .to_string();

    let code = format!(
        r###"{}
local address = {}
local include_modules = {}
local include_symbols = {}
local include_sections = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end

local symbolic_name = getNameFromAddress(address, include_modules, include_symbols, include_sections)
local is_in_module = false
local ok_in_module, in_module_result = pcall(inModule, address)
if ok_in_module and in_module_result then
    is_in_module = true
elseif symbolic_name and symbolic_name:match("%+") then
    is_in_module = true
end
if symbolic_name and symbolic_name:match("^%x+$") then
    symbolic_name = "0x" .. symbolic_name
end

return {{
    success = true,
    address = ce_mcp_to_hex(address),
    symbolic_name = symbolic_name or ce_mcp_to_hex(address),
    is_in_module = is_in_module,
    options_used = {{
        include_modules = include_modules,
        include_symbols = include_symbols,
        include_sections = include_sections,
    }}
}}
"###,
        LUA_TO_HEX_HELPER, address_lua, include_modules, include_symbols, include_sections
    );
    execute_ce_process_snippet(&code)
}

fn ce_get_rtti_classname(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let code = format!(
        r###"{}
local address = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end

local class_name = getRTTIClassName(address)
if class_name then
    return {{
        success = true,
        address = ce_mcp_to_hex(address),
        class_name = class_name,
        found = true
    }}
end
return {{
    success = true,
    address = ce_mcp_to_hex(address),
    class_name = nil,
    found = false,
    note = "No RTTI information found at this address"
}}
"###,
        LUA_TO_HEX_HELPER, address_lua
    );
    execute_ce_process_snippet(&code)
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
        "note": "no process attached (ce runtime)"
    })
}

fn lua_current_process_id() -> Result<u32, ToolResponse> {
    match call_ce_json_tool_from_json("get_process_info", "{}") {
        Ok(body) => Ok(body
            .get("process_id")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0)),
        Err(response) if is_no_process_attached_response(&response) => Ok(0),
        Err(response) => Err(response),
    }
}

fn lua_process_attached() -> Result<bool, ToolResponse> {
    lua_current_process_id().map(|process_id| process_id != 0)
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

fn lua_thread_info_json(value: &Value, process_id: u32) -> Option<Value> {
    let thread_id = value
        .get("thread_id")
        .and_then(Value::as_u64)
        .or_else(|| value.get("id_int").and_then(Value::as_u64))
        .or_else(|| {
            value
                .get("id_hex")
                .and_then(Value::as_str)
                .and_then(|text| {
                    let trimmed = text
                        .strip_prefix("0x")
                        .or_else(|| text.strip_prefix("0X"))
                        .unwrap_or(text);
                    u32::from_str_radix(trimmed, 16).ok()
                })
                .map(u64::from)
        })
        .and_then(|value| u32::try_from(value).ok())?;

    Some(json!({
        "thread_id": thread_id,
        "owner_process_id": process_id,
    }))
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
    let mut body = match call_ce_json_tool_from_json("enum_modules", "{}") {
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
    match call_ce_json_tool_from_json("get_process_info", "{}") {
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
                        json!("live process response via CE runtime"),
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

    let mut body = match call_ce_json_tool_from_json("enum_modules", "{}") {
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
    let process_id = match lua_current_process_id() {
        Ok(process_id) => process_id,
        Err(response) => return response,
    };

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

    let mut body = match call_ce_json_tool_from_json("get_thread_list", "{}") {
        Ok(value) => value,
        Err(response) => return response,
    };

    let threads = body
        .get("threads")
        .and_then(Value::as_array)
        .map(|threads| {
            threads
                .iter()
                .filter_map(|thread| lua_thread_info_json(thread, process_id))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let Some(object) = body.as_object_mut() else {
        return error_response("lua get_thread_list returned non-object body".to_owned());
    };

    object.insert("success".to_owned(), Value::Bool(true));
    object.insert("count".to_owned(), json!(threads.len()));
    object.insert("attached".to_owned(), Value::Bool(true));
    object.insert("resolver".to_owned(), json!("ce_getThreadlist"));
    object.insert("threads".to_owned(), Value::Array(threads));

    ToolResponse {
        success: true,
        body_json: body.to_string(),
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

    let ce_body = match call_ce_json_tool_from_json("get_address_info", params_json) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let address = match util::parse_address(ce_body.get("address")) {
        Ok(address) => address,
        Err(error) => {
            return error_response(format!(
                "CE get_address_info returned invalid address: {}",
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

    if let (Some(lua_object), Some(body_object)) = (ce_body.as_object(), body.as_object_mut()) {
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
                                "resolved_by": "ce_runtime",
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
    if runtime::app_state().is_none() {
        return ToolResponse {
            success: false,
            body_json: "runtime not initialized".to_owned(),
        };
    }
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let modules = current_modules();
    let address = match resolve_address_param(params.get("address"), &modules) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    match ce_rtti_classname(address, &modules) {
        Ok(body) => ToolResponse {
            success: true,
            body_json: body.to_string(),
        },
        Err(error) => error_response(format!("CE RTTI lookup failed: {}", error)),
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

fn ce_rtti_classname(address: usize, modules: &[runtime::ModuleInfo]) -> Result<Value, String> {
    let mut body = call_ce_json_tool_from_json(
        "get_rtti_classname",
        &json!({ "address": util::format_address(address) }).to_string(),
    )
    .map_err(|response| response.body_json)?;
    let Some(object) = body.as_object_mut() else {
        return Err("CE get_rtti_classname returned non-object body".to_owned());
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

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
