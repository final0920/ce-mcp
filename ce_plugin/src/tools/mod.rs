#![allow(dead_code)]

mod alias;
mod analysis;
mod debug;
mod memory;
mod process;
mod scan;
mod script;
mod util;

use std::borrow::Cow;

use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct ToolResponse {
    pub success: bool,
    pub body_json: String,
}

pub fn dispatch_p0(method: &str, params_json: &str) -> ToolResponse {
    dispatch(method, params_json)
}

pub fn dispatch(method: &str, params_json: &str) -> ToolResponse {
    dispatch_direct(method, params_json)
}

pub fn dispatch_direct(method: &str, params_json: &str) -> ToolResponse {
    if let Some(canonical) = alias::canonical_method(method) {
        let normalized = normalize_alias_params(method, params_json);
        return dispatch_canonical(canonical, normalized.as_ref());
    }

    dispatch_canonical(method, params_json)
}

pub fn requires_serialized_dispatch(method: &str) -> bool {
    let canonical = alias::canonical_method(method).unwrap_or(method);
    matches!(
        canonical,
        "get_symbol_address"
            | "get_address_info"
            | "get_rtti_classname"
            | "disassemble"
            | "get_instruction_info"
            | "find_function_boundaries"
            | "analyze_function"
            | "find_references"
            | "find_call_references"
            | "dissect_structure"
            | "set_breakpoint"
            | "set_data_breakpoint"
            | "remove_breakpoint"
            | "list_breakpoints"
            | "clear_all_breakpoints"
            | "get_breakpoint_hits"
            | "get_physical_address"
            | "start_dbvm_watch"
            | "stop_dbvm_watch"
            | "poll_dbvm_watch"
            | "evaluate_lua"
            | "evaluate_lua_file"
            | "auto_assemble"
            | "auto_assemble_file"
    )
}

fn dispatch_canonical(method: &str, params_json: &str) -> ToolResponse {
    if let Some(response) = process::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = memory::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = scan::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = analysis::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = debug::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = script::dispatch(method, params_json) {
        return response;
    }

    util::method_not_found(method)
}

fn normalize_alias_params<'a>(method: &str, params_json: &'a str) -> Cow<'a, str> {
    match method {
        "find_what_writes_safe" => inject_default_param(params_json, "mode", json!("w")),
        "find_what_accesses_safe" => inject_default_param(params_json, "mode", json!("r")),
        _ => Cow::Borrowed(params_json),
    }
}

fn inject_default_param<'a>(params_json: &'a str, key: &str, value: Value) -> Cow<'a, str> {
    let Ok(mut params) = serde_json::from_str::<Value>(params_json) else {
        return Cow::Borrowed(params_json);
    };
    let Some(object) = params.as_object_mut() else {
        return Cow::Borrowed(params_json);
    };

    if object.contains_key(key) {
        return Cow::Borrowed(params_json);
    }

    object.insert(key.to_owned(), value);
    Cow::Owned(params.to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize_alias_params;

    #[test]
    fn access_alias_injects_read_mode_when_missing() {
        let normalized =
            normalize_alias_params("find_what_accesses_safe", r#"{"address":"0x1234"}"#);
        assert_eq!(normalized.as_ref(), r#"{"address":"0x1234","mode":"r"}"#);
    }

    #[test]
    fn access_alias_keeps_explicit_mode() {
        let normalized = normalize_alias_params(
            "find_what_accesses_safe",
            r#"{"address":"0x1234","mode":"rw"}"#,
        );
        assert_eq!(normalized.as_ref(), r#"{"address":"0x1234","mode":"rw"}"#);
    }
}
