use serde_json::{json, Value};

use super::{addressing, lua_host, process, util, ToolResponse};
use crate::runtime::ModuleInfo;

const METHODS: &[&str] = &[
    "disassemble",
    "get_instruction_info",
    "find_function_boundaries",
    "analyze_function",
    "find_references",
    "find_call_references",
    "dissect_structure",
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
        "disassemble" => disassemble(params_json),
        "get_instruction_info" => get_instruction_info(params_json),
        "find_function_boundaries" => find_function_boundaries(params_json),
        "analyze_function" => analyze_function(params_json),
        "find_references" => find_references(params_json),
        "find_call_references" => find_call_references(params_json),
        "dissect_structure" => dissect_structure(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn disassemble(params_json: &str) -> ToolResponse {
    let body = match call_ce_tool_json("disassemble", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    match normalize_lua_disassemble_response(&body.to_string()) {
        Ok(body_json) => ToolResponse {
            success: true,
            body_json,
        },
        Err(error) => error_response(error),
    }
}

fn get_instruction_info(params_json: &str) -> ToolResponse {
    let body = match call_ce_tool_json("get_instruction_info", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    match normalize_lua_instruction_info_response(body) {
        Ok(body_json) => ToolResponse {
            success: true,
            body_json,
        },
        Err(error) => error_response(error),
    }
}

fn find_function_boundaries(params_json: &str) -> ToolResponse {
    let body = match call_ce_tool_json("find_function_boundaries", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    match normalize_lua_function_boundaries_response(body) {
        Ok(body_json) => ToolResponse {
            success: true,
            body_json,
        },
        Err(error) => error_response(error),
    }
}

fn analyze_function(params_json: &str) -> ToolResponse {
    let body = match call_ce_tool_json("analyze_function", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    match normalize_lua_analyze_function_response(body) {
        Ok(body_json) => ToolResponse {
            success: true,
            body_json,
        },
        Err(error) => error_response(error),
    }
}

fn find_references(params_json: &str) -> ToolResponse {
    let modules = process::current_modules();
    let mut body = match call_ce_tool_json("find_references", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let target_text = body
        .get("target")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let target_normalized = response_address(body.get("target"))
        .and_then(|target| addressing::normalize_address_from_modules(target, &modules));
    let references_count = body
        .get("references")
        .and_then(Value::as_array)
        .map(|references| references.len())
        .unwrap_or(0);

    if let Some(references) = body.get_mut("references").and_then(Value::as_array_mut) {
        for reference in references.iter_mut() {
            let Some(object) = reference.as_object_mut() else {
                continue;
            };

            let normalized_address = response_address(object.get("address"))
                .and_then(|address| addressing::normalize_address_from_modules(address, &modules));
            object.insert("normalized_address".to_owned(), json!(normalized_address));
            if let Some(target) = target_text.as_ref() {
                object
                    .entry("target".to_owned())
                    .or_insert_with(|| Value::String(target.clone()));
            }
            object
                .entry("target_normalized".to_owned())
                .or_insert_with(|| json!(target_normalized.clone()));
        }
    }

    let Some(object) = body.as_object_mut() else {
        return error_response("lua find_references returned non-object body".to_owned());
    };

    object.insert("target_normalized".to_owned(), json!(target_normalized));
    object
        .entry("count".to_owned())
        .or_insert_with(|| json!(references_count));
    object
        .entry("arch".to_owned())
        .or_insert_with(|| json!("x64"));
    object
        .entry("note".to_owned())
        .or_insert_with(|| json!("reference scan via CE runtime"));

    ToolResponse {
        success: true,
        body_json: body.to_string(),
    }
}

fn find_call_references(params_json: &str) -> ToolResponse {
    let body = match call_ce_tool_json("find_call_references", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    match normalize_lua_find_call_references_response(body) {
        Ok(body_json) => ToolResponse {
            success: true,
            body_json,
        },
        Err(error) => error_response(error),
    }
}

fn dissect_structure(params_json: &str) -> ToolResponse {
    let body = match call_ce_tool_json("dissect_structure", params_json) {
        Ok(body) => body,
        Err(response) => return response,
    };

    match normalize_lua_dissect_structure_response(body) {
        Ok(body_json) => ToolResponse {
            success: true,
            body_json,
        },
        Err(error) => error_response(error),
    }
}

fn normalize_lua_disassemble_response(body_json: &str) -> Result<String, String> {
    let mut body: Value = serde_json::from_str(body_json)
        .map_err(|error| format!("invalid lua disassemble result json: {}", error))?;
    let object = body
        .as_object_mut()
        .ok_or_else(|| "lua disassemble result must be a json object".to_owned())?;

    let modules = process::current_modules();
    let address_value = object
        .get("address")
        .cloned()
        .or_else(|| object.get("start_address").cloned());
    let address = address_value
        .as_ref()
        .and_then(|value| util::parse_address(Some(value)).ok());

    if !object.contains_key("address") {
        if let Some(value) = address_value.clone() {
            object.insert("address".to_owned(), value);
        }
    }
    if !object.contains_key("normalized_address") {
        object.insert(
            "normalized_address".to_owned(),
            json!(address
                .and_then(|value| addressing::normalize_address_from_modules(value, &modules))),
        );
    }

    let instruction_count =
        if let Some(instructions) = object.get_mut("instructions").and_then(Value::as_array_mut) {
            for instruction in instructions.iter_mut() {
                let Some(instruction_object) = instruction.as_object_mut() else {
                    continue;
                };

                let instruction_address = instruction_object
                    .get("address")
                    .and_then(|value| util::parse_address(Some(value)).ok());
                let instruction_size = instruction_object
                    .get("size")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok());
                let next_address = instruction_address
                    .zip(instruction_size)
                    .map(|(addr, size)| addr.saturating_add(size));

                if !instruction_object.contains_key("text") {
                    if let Some(text) = instruction_object.get("instruction").cloned() {
                        instruction_object.insert("text".to_owned(), text);
                    }
                }
                if !instruction_object.contains_key("length") {
                    if let Some(size) = instruction_object.get("size").cloned() {
                        instruction_object.insert("length".to_owned(), size);
                    }
                }
                if !instruction_object.contains_key("normalized_address") {
                    instruction_object.insert(
                        "normalized_address".to_owned(),
                        json!(instruction_address.and_then(|value| {
                            addressing::normalize_address_from_modules(value, &modules)
                        })),
                    );
                }
                if !instruction_object.contains_key("next_address") {
                    instruction_object.insert(
                        "next_address".to_owned(),
                        json!(next_address.map(util::format_address)),
                    );
                }
                if !instruction_object.contains_key("next_address_normalized") {
                    instruction_object.insert(
                        "next_address_normalized".to_owned(),
                        json!(next_address.and_then(|value| {
                            addressing::normalize_address_from_modules(value, &modules)
                        })),
                    );
                }
                if !instruction_object.contains_key("mnemonic") {
                    if let Some(mnemonic) = instruction_object
                        .get("instruction")
                        .and_then(Value::as_str)
                        .and_then(|text| text.split_whitespace().next())
                    {
                        instruction_object
                            .insert("mnemonic".to_owned(), json!(mnemonic.to_ascii_lowercase()));
                    }
                }
            }

            Some(instructions.len())
        } else {
            None
        };

    if let Some(instruction_count) = instruction_count {
        object.insert("count".to_owned(), json!(instruction_count));
    }

    Ok(body.to_string())
}

fn normalize_lua_instruction_info_response(mut body: Value) -> Result<String, String> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| "lua get_instruction_info returned non-object body".to_owned())?;
    let modules = process::current_modules();
    let address = response_address(object.get("address"))
        .ok_or_else(|| "lua get_instruction_info response missing address".to_owned())?;

    object.insert("address".to_owned(), json!(util::format_address(address)));
    object.insert(
        "normalized_address".to_owned(),
        json!(addressing::normalize_address_from_modules(
            address, &modules
        )),
    );

    if !matches!(object.get("instruction"), Some(Value::Object(_))) {
        let instruction = synthesize_lua_instruction_info(&*object, address, &modules);
        object.insert("instruction".to_owned(), instruction);
    }

    Ok(body.to_string())
}

fn normalize_lua_function_boundaries_response(mut body: Value) -> Result<String, String> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| "lua find_function_boundaries returned non-object body".to_owned())?;
    let modules = process::current_modules();
    let query_address_value = object
        .get("query_address")
        .cloned()
        .or_else(|| object.get("address").cloned());
    let query_address = query_address_value
        .as_ref()
        .and_then(|value| util::parse_address(Some(value)).ok());
    let function_start = response_address(object.get("function_start"));
    let function_end = response_address(object.get("function_end"));
    let found = object
        .get("found")
        .and_then(Value::as_bool)
        .unwrap_or(function_start.is_some());

    if !object.contains_key("query_address") {
        if let Some(value) = query_address_value {
            object.insert("query_address".to_owned(), value);
        }
    }
    object.insert("found".to_owned(), json!(found));
    object.insert(
        "query_normalized_address".to_owned(),
        json!(query_address
            .and_then(|value| { addressing::normalize_address_from_modules(value, &modules) })),
    );
    object.insert(
        "function_start_normalized".to_owned(),
        json!(function_start
            .and_then(|value| { addressing::normalize_address_from_modules(value, &modules) })),
    );
    object.insert(
        "function_end_normalized".to_owned(),
        json!(function_end
            .and_then(|value| { addressing::normalize_address_from_modules(value, &modules) })),
    );
    if let (Some(start), Some(end)) = (function_start, function_end) {
        object.insert(
            "function_size".to_owned(),
            json!(end.saturating_sub(start).saturating_add(1)),
        );
    }
    object
        .entry("arch".to_owned())
        .or_insert_with(|| json!("x64"));

    let needs_note = object.get("note").map_or(true, Value::is_null);
    if needs_note {
        let note = if !found {
            Some("No standard function prologue found within search range")
        } else if function_start.is_some() && function_end.is_none() {
            Some("Function end not found within search range")
        } else {
            None
        };
        if let Some(note) = note {
            object.insert("note".to_owned(), json!(note));
        }
    }

    Ok(body.to_string())
}

fn normalize_lua_analyze_function_response(mut body: Value) -> Result<String, String> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| "lua analyze_function returned non-object body".to_owned())?;
    let modules = process::current_modules();
    let query_address_value = object
        .get("query_address")
        .cloned()
        .or_else(|| object.get("address").cloned());
    let query_address = query_address_value
        .as_ref()
        .and_then(|value| util::parse_address(Some(value)).ok());
    let function_start = response_address(object.get("function_start"));
    let function_end = response_address(object.get("function_end"));

    if !object.contains_key("query_address") {
        if let Some(value) = query_address_value {
            object.insert("query_address".to_owned(), value);
        }
    }
    object.insert(
        "query_normalized_address".to_owned(),
        json!(query_address
            .and_then(|value| { addressing::normalize_address_from_modules(value, &modules) })),
    );
    object.insert(
        "function_start_normalized".to_owned(),
        json!(function_start
            .and_then(|value| { addressing::normalize_address_from_modules(value, &modules) })),
    );
    object.insert(
        "function_end_normalized".to_owned(),
        json!(function_end
            .and_then(|value| { addressing::normalize_address_from_modules(value, &modules) })),
    );
    if let (Some(start), Some(end)) = (function_start, function_end) {
        object.insert(
            "function_size".to_owned(),
            json!(end.saturating_sub(start).saturating_add(1)),
        );
    }
    object
        .entry("arch".to_owned())
        .or_insert_with(|| json!("x64"));

    let call_count = if let Some(calls) = object.get_mut("calls").and_then(Value::as_array_mut) {
        for call in calls.iter_mut() {
            let Some(call_object) = call.as_object_mut() else {
                continue;
            };

            let call_site = response_address(
                call_object
                    .get("call_site")
                    .or_else(|| call_object.get("address")),
            );
            let target = response_address(call_object.get("target"));

            if !call_object.contains_key("call_site") {
                if let Some(value) = call_object.get("address").cloned() {
                    call_object.insert("call_site".to_owned(), value);
                }
            }
            call_object.insert(
                "call_site_normalized".to_owned(),
                json!(call_site.and_then(|value| {
                    addressing::normalize_address_from_modules(value, &modules)
                })),
            );
            call_object.insert(
                "target_normalized".to_owned(),
                json!(target.and_then(|value| {
                    addressing::normalize_address_from_modules(value, &modules)
                })),
            );

            let normalized_type = match call_object.get("type").and_then(Value::as_str) {
                Some("relative") => Some("direct"),
                Some("direct") => Some("direct"),
                Some("indirect") => Some("indirect"),
                Some(other) => Some(other),
                None if target.is_some() => Some("direct"),
                None => Some("indirect"),
            };
            if let Some(value) = normalized_type {
                call_object.insert("type".to_owned(), json!(value));
            }
        }

        calls.len()
    } else {
        0
    };

    object.insert("call_count".to_owned(), json!(call_count));
    let needs_note = object.get("note").map_or(true, Value::is_null);
    if needs_note && function_start.is_some() && function_end.is_none() {
        object.insert(
            "note".to_owned(),
            json!("Function end not found within search range"),
        );
    }

    Ok(body.to_string())
}

fn normalize_lua_dissect_structure_response(mut body: Value) -> Result<String, String> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| "lua dissect_structure returned non-object body".to_owned())?;
    let modules = process::current_modules();
    let base_address =
        response_address(object.get("base_address").or_else(|| object.get("address")));

    if let Some(base_address) = base_address {
        object.insert(
            "base_address".to_owned(),
            json!(util::format_address(base_address)),
        );
    }
    object.insert(
        "base_address_normalized".to_owned(),
        json!(base_address
            .and_then(|value| { addressing::normalize_address_from_modules(value, &modules) })),
    );

    let element_count = if let Some(elements) =
        object.get_mut("elements").and_then(Value::as_array_mut)
    {
        for element in elements.iter_mut() {
            let Some(element_object) = element.as_object_mut() else {
                continue;
            };

            let offset = element_object
                .get("offset")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or_default();
            element_object
                .entry("hex_offset".to_owned())
                .or_insert_with(|| json!(format!("+0x{:X}", offset)));
            let needs_name = element_object
                .get("name")
                .and_then(Value::as_str)
                .map(|value| value.trim().is_empty())
                .unwrap_or(true);
            if needs_name {
                element_object.insert("name".to_owned(), json!(format!("field_{:04X}", offset)));
            }

            if let Some(vartype_code) = element_object.get("vartype").and_then(Value::as_i64) {
                element_object.insert("vartype_code".to_owned(), json!(vartype_code));
                element_object.insert(
                    "vartype".to_owned(),
                    json!(cheat_engine_vartype_name(vartype_code)),
                );
            }

            element_object
                .entry("confidence".to_owned())
                .or_insert_with(|| json!("auto_guess"));
        }

        elements.len()
    } else {
        0
    };

    object.insert("element_count".to_owned(), json!(element_count));
    object
        .entry("resolver".to_owned())
        .or_insert_with(|| json!("lua_auto_guess"));
    object.entry("note".to_owned()).or_insert_with(|| {
        json!("structure inference via CE Structure.autoGuess (legacy native heuristic removed)")
    });

    Ok(body.to_string())
}

fn normalize_lua_find_call_references_response(mut body: Value) -> Result<String, String> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| "lua find_call_references returned non-object body".to_owned())?;
    let modules = process::current_modules();
    let function_address = response_address(
        object
            .get("function_address")
            .or_else(|| object.get("address")),
    )
    .ok_or_else(|| "lua find_call_references response missing function_address".to_owned())?;
    let function_address_normalized =
        addressing::normalize_address_from_modules(function_address, &modules);

    object.insert(
        "function_address".to_owned(),
        json!(util::format_address(function_address)),
    );
    object.insert(
        "function_address_normalized".to_owned(),
        json!(function_address_normalized.clone()),
    );

    let caller_count =
        if let Some(callers) = object.get_mut("callers").and_then(Value::as_array_mut) {
            for caller in callers.iter_mut() {
                let Some(caller_object) = caller.as_object_mut() else {
                    continue;
                };

                let caller_address = response_address(
                    caller_object
                        .get("caller_address")
                        .or_else(|| caller_object.get("address")),
                );
                if !caller_object.contains_key("caller_address") {
                    if let Some(value) = caller_object.get("address").cloned() {
                        caller_object.insert("caller_address".to_owned(), value);
                    }
                }
                caller_object.insert(
                    "caller_address_normalized".to_owned(),
                    json!(caller_address.and_then(|value| {
                        addressing::normalize_address_from_modules(value, &modules)
                    })),
                );
                caller_object
                    .entry("target".to_owned())
                    .or_insert_with(|| json!(util::format_address(function_address)));
                caller_object
                    .entry("target_normalized".to_owned())
                    .or_insert_with(|| json!(function_address_normalized.clone()));
            }

            callers.len()
        } else {
            0
        };

    object.insert("count".to_owned(), json!(caller_count));
    object
        .entry("arch".to_owned())
        .or_insert_with(|| json!("x64"));

    Ok(body.to_string())
}

fn synthesize_lua_instruction_info(
    response: &serde_json::Map<String, Value>,
    address: usize,
    modules: &[ModuleInfo],
) -> Value {
    let text = response
        .get("instruction")
        .and_then(Value::as_str)
        .unwrap_or("???");
    let size = response
        .get("size")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok());
    let next_address = response_address(response.get("next_address"))
        .or_else(|| size.map(|value| address.saturating_add(value)));
    let near_branch_target = response_address(response.get("near_branch_target"));

    json!({
        "address": util::format_address(address),
        "normalized_address": addressing::normalize_address_from_modules(address, modules),
        "bytes": response.get("bytes").cloned().unwrap_or(Value::Null),
        "text": text,
        "mnemonic": response
            .get("mnemonic")
            .cloned()
            .unwrap_or_else(|| json!(infer_instruction_mnemonic(text))),
        "length": size,
        "next_address": next_address.map(util::format_address),
        "next_address_normalized": next_address
            .and_then(|value| addressing::normalize_address_from_modules(value, modules)),
        "op_count": response.get("op_count").cloned().unwrap_or(Value::Null),
        "is_invalid": response
            .get("is_invalid")
            .cloned()
            .unwrap_or_else(|| json!(instruction_text_invalid(text))),
        "is_stack_instruction": response
            .get("is_stack_instruction")
            .cloned()
            .unwrap_or(Value::Null),
        "flow_control": response.get("flow_control").cloned().unwrap_or(Value::Null),
        "near_branch_target": near_branch_target.map(util::format_address),
        "near_branch_target_normalized": near_branch_target
            .and_then(|target| addressing::normalize_address_from_modules(target, modules)),
        "is_ip_rel_memory_operand": response
            .get("is_ip_rel_memory_operand")
            .cloned()
            .unwrap_or_else(|| json!(false)),
        "ip_rel_memory_address": response
            .get("ip_rel_memory_address")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

fn infer_instruction_mnemonic(text: &str) -> Option<String> {
    text.split_whitespace()
        .next()
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn instruction_text_invalid(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.is_empty() || trimmed == "???"
}

fn cheat_engine_vartype_name(vartype: i64) -> &'static str {
    match vartype {
        0 => "byte",
        1 => "word",
        2 => "dword",
        3 => "float",
        4 => "double",
        5 => "bit",
        6 => "qword",
        7 => "string",
        8 => "byte_array",
        9 => "binary",
        10 => "all",
        11 => "auto_assembler",
        12 => "pointer",
        13 => "custom",
        14 => "grouped",
        15 => "unicode_string",
        16 => "code_page_string",
        _ => "unknown",
    }
}

fn execute_ce_analysis_snippet(code: &str) -> Result<Value, ToolResponse> {
    lua_host::execute_snippet_result(code).map_err(error_response)
}

fn call_ce_tool_json(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
    let params = util::parse_params(params_json).map_err(error_response)?;
    match method {
        "disassemble" => ce_disassemble(&params),
        "get_instruction_info" => ce_get_instruction_info(&params),
        "find_function_boundaries" => ce_find_function_boundaries(&params),
        "analyze_function" => ce_analyze_function(&params),
        "find_references" => ce_find_references(&params),
        "find_call_references" => ce_find_call_references(&params),
        "dissect_structure" => ce_dissect_structure(&params),
        other => Err(error_response(format!(
            "unsupported CE analysis tool: {}",
            other
        ))),
    }
}

fn ce_disassemble(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let count = params.get("count").and_then(Value::as_u64).unwrap_or(20);
    let code = format!(
        r###"
{}
local address = {}
local count = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local instructions = {{}}
local current = address
for i = 1, count do
    local ok, text = pcall(disassemble, current)
    if not ok or not text then break end
    local size = getInstructionSize(current) or 1
    local bytes = readBytes(current, size, true) or {{}}
    local bytes_hex = {{}}
    for _, byte in ipairs(bytes) do table.insert(bytes_hex, string.format("%02X", byte)) end
    table.insert(instructions, {{ address = ce_mcp_to_hex(current), offset = current - address, size = size, bytes = table.concat(bytes_hex, " "), instruction = text }})
    current = current + size
end
return {{ success = true, start_address = ce_mcp_to_hex(address), count = #instructions, instructions = instructions }}
"###,
        LUA_TO_HEX_HELPER, address_lua, count
    );
    execute_ce_analysis_snippet(&code)
}

fn ce_get_instruction_info(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let code = format!(
        r###"
{}
local address = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local ok, text = pcall(disassemble, address)
if not ok or not text then return {{ success = false, error = "Failed to disassemble at " .. ce_mcp_to_hex(address) }} end
local size = getInstructionSize(address) or 1
local bytes = readBytes(address, size, true) or {{}}
local bytes_hex = {{}}
for _, byte in ipairs(bytes) do table.insert(bytes_hex, string.format("%02X", byte)) end
local previous = getPreviousOpcode(address)
return {{ success = true, address = ce_mcp_to_hex(address), instruction = text, size = size, bytes = table.concat(bytes_hex, " "), previous_instruction = previous and ce_mcp_to_hex(previous) or nil }}
"###,
        LUA_TO_HEX_HELPER, address_lua
    );
    execute_ce_analysis_snippet(&code)
}

fn ce_find_function_boundaries(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let max_search = params
        .get("max_search")
        .and_then(Value::as_u64)
        .unwrap_or(4096);
    let code = format!(
        r###"
{}
local address = {}
local max_search = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local is64 = targetIs64Bit()
local function_start = nil
local prologue_type = nil
for offset = 0, max_search do
    local check_addr = address - offset
    local b1 = readBytes(check_addr, 1, false)
    local b2 = readBytes(check_addr + 1, 1, false)
    local b3 = readBytes(check_addr + 2, 1, false)
    local b4 = readBytes(check_addr + 3, 1, false)
    if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then function_start = check_addr prologue_type = "x86_standard" break end
    if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then function_start = check_addr prologue_type = "x64_standard" break end
    if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then function_start = check_addr prologue_type = "x64_leaf" break end
end
local function_end = nil
if function_start then
    for offset = 0, max_search do
        local b = readBytes(function_start + offset, 1, false)
        if b == 0xC3 or b == 0xC2 then function_end = function_start + offset break end
    end
end
local found = function_start ~= nil
return {{ success = true, found = found, query_address = ce_mcp_to_hex(address), function_start = function_start and ce_mcp_to_hex(function_start) or nil, function_end = function_end and ce_mcp_to_hex(function_end) or nil, function_size = (function_start and function_end) and (function_end - function_start + 1) or nil, prologue_type = prologue_type, arch = is64 and "x64" or "x86", note = (not found) and "No standard function prologue found within search range" or nil }}
"###,
        LUA_TO_HEX_HELPER, address_lua, max_search
    );
    execute_ce_analysis_snippet(&code)
}

fn ce_analyze_function(params: &Value) -> Result<Value, ToolResponse> {
    let boundaries = ce_find_function_boundaries(params)?;
    let function_start = boundaries
        .get("function_start")
        .cloned()
        .unwrap_or(Value::Null);
    if function_start.is_null() {
        return Ok(
            json!({"success": true, "query_address": params.get("address").cloned().unwrap_or(Value::Null), "calls": [], "arch": "x64", "note": "No standard function prologue found within search range"}),
        );
    }
    let function_end = boundaries
        .get("function_end")
        .cloned()
        .unwrap_or(Value::Null);
    let start_lua = util::lua_scalar_literal(&function_start).map_err(error_response)?;
    let end_lua = util::lua_scalar_literal(&function_end).map_err(error_response)?;
    let code = format!(
        r###"
{}
local function_start = {}
local function_end = {}
if type(function_start) == "string" then function_start = getAddressSafe(function_start) end
if type(function_end) == "string" then function_end = getAddressSafe(function_end) end
local current = function_start
local calls = {{}}
while current and function_end and current <= function_end do
    local ok, text = pcall(disassemble, current)
    if not ok or not text then break end
    local size = getInstructionSize(current) or 1
    if text:lower():find("call") then
        table.insert(calls, {{ call_site = ce_mcp_to_hex(current), instruction = text }})
    end
    current = current + size
end
return {{ success = true, query_address = ce_mcp_to_hex(function_start), function_start = ce_mcp_to_hex(function_start), function_end = function_end and ce_mcp_to_hex(function_end) or nil, calls = calls, arch = targetIs64Bit() and "x64" or "x86" }}
"###,
        LUA_TO_HEX_HELPER, start_lua, end_lua
    );
    execute_ce_analysis_snippet(&code)
}

fn ce_find_references(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(50);
    let code = format!(
        r###"
{}
local target = {}
local limit = {}
if type(target) == "string" then target = getAddressSafe(target) end
if not target then return {{ success = false, error = "Invalid address" }} end
local is64 = targetIs64Bit()
local pattern
if is64 and target > 0xFFFFFFFF then
    local bytes = {{}}
    local temp = target
    for i = 1, 8 do bytes[i] = temp % 256 temp = math.floor(temp / 256) end
    pattern = string.format("%02X %02X %02X %02X %02X %02X %02X %02X", bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8])
else
    local b1 = target % 256
    local b2 = math.floor(target / 256) % 256
    local b3 = math.floor(target / 65536) % 256
    local b4 = math.floor(target / 16777216) % 256
    pattern = string.format("%02X %02X %02X %02X", b1, b2, b3, b4)
end
local results = AOBScan(pattern, "+X")
if not results then return {{ success = true, target = ce_mcp_to_hex(target), count = 0, references = {{}}, arch = is64 and "x64" or "x86" }} end
local refs = {{}}
for i = 0, math.min(results.Count - 1, limit - 1) do
    local ref_addr = tonumber(results.getString(i), 16)
    table.insert(refs, {{ address = ce_mcp_to_hex(ref_addr), instruction = disassemble(ref_addr) or "???" }})
end
results.destroy()
return {{ success = true, target = ce_mcp_to_hex(target), count = #refs, references = refs, arch = is64 and "x64" or "x86" }}
"###,
        LUA_TO_HEX_HELPER, address_lua, limit
    );
    execute_ce_analysis_snippet(&code)
}

fn ce_find_call_references(params: &Value) -> Result<Value, ToolResponse> {
    let function_address = params
        .get("address")
        .or_else(|| params.get("function_address"))
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let func_lua = util::lua_scalar_literal(function_address).map_err(error_response)?;
    let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(100);
    let code = format!(
        r###"
{}
local func = {}
local limit = {}
if type(func) == "string" then func = getAddressSafe(func) end
if not func then return {{ success = false, error = "Invalid function address" }} end
local callers = {{}}
local results = AOBScan("E8 ?? ?? ?? ??", "+X")
if results then
    for i = 0, results.Count - 1 do
        if #callers >= limit then break end
        local call_addr = tonumber(results.getString(i), 16)
        local rel = readInteger(call_addr + 1)
        if rel then
            if rel > 0x7FFFFFFF then rel = rel - 0x100000000 end
            local target = call_addr + 5 + rel
            if target == func then
                table.insert(callers, {{ caller_address = ce_mcp_to_hex(call_addr), instruction = disassemble(call_addr) or "???" }})
            end
        end
    end
    results.destroy()
end
return {{ success = true, function_address = ce_mcp_to_hex(func), count = #callers, callers = callers }}
"###,
        LUA_TO_HEX_HELPER, func_lua, limit
    );
    execute_ce_analysis_snippet(&code)
}

fn ce_dissect_structure(params: &Value) -> Result<Value, ToolResponse> {
    let address = params
        .get("address")
        .ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let size = params.get("size").and_then(Value::as_u64).unwrap_or(256);
    let code = format!(
        r###"
{}
local address = {}
local size = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local ok, struct = pcall(createStructure, "MCP_TempStruct")
if not ok or not struct then return {{ success = false, error = "Failed to create structure" }} end
pcall(function() struct:autoGuess(address, 0, size) end)
local elements = {{}}
local count = struct.Count or 0
for i = 0, count - 1 do
    local elem = struct.Element[i]
    if elem then
        local current_value = nil
        pcall(function() current_value = elem:getValue(address) end)
        table.insert(elements, {{ offset = elem.Offset, hex_offset = string.format("+0x%X", elem.Offset), name = elem.Name or "", vartype = elem.Vartype, bytesize = elem.Bytesize, current_value = current_value }})
    end
end
struct.destroy()
return {{ success = true, address = ce_mcp_to_hex(address), size = size, field_count = #elements, fields = elements }}
"###,
        LUA_TO_HEX_HELPER, address_lua, size
    );
    execute_ce_analysis_snippet(&code)
}
fn response_address(value: Option<&Value>) -> Option<usize> {
    value.and_then(|value| util::parse_address(Some(value)).ok())
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
