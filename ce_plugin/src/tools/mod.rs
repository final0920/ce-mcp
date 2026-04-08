#![allow(dead_code)]

mod addressing;
mod analysis;
mod batch;
mod debug;
mod fingerprint;
mod lua_backend;
mod lua_client;
mod lua_host;
mod memory;
mod process;
mod registry;
mod scan;
mod script;
mod util;

use std::cell::Cell;

pub use registry::{all_tools, find_tool};

thread_local! {
    static MAIN_THREAD_DISPATCH_DEPTH: Cell<usize> = Cell::new(0);
}

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

pub(crate) fn dispatch_from_main_thread(method: &str, params_json: &str) -> ToolResponse {
    let _guard = MainThreadDispatchGuard::enter();
    dispatch_direct(method, params_json)
}

pub(crate) fn in_main_thread_dispatch() -> bool {
    MAIN_THREAD_DISPATCH_DEPTH.with(|depth| depth.get() > 0)
}

pub fn dispatch_direct(method: &str, params_json: &str) -> ToolResponse {
    dispatch_canonical(method, params_json)
}

pub fn requires_serialized_dispatch(method: &str) -> bool {
    matches!(
        method,
        "get_symbol_address"
            | "get_address_info"
            | "batch_get_address_info"
            | "batch_disassemble"
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
            | lua_backend::INTERNAL_DISPATCH_METHOD
    )
}

fn dispatch_canonical(method: &str, params_json: &str) -> ToolResponse {
    if let Some(response) = process::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = fingerprint::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = memory::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = batch::dispatch(method, params_json) {
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
    if let Some(response) = lua_backend::dispatch(method, params_json) {
        return response;
    }
    if let Some(response) = script::dispatch(method, params_json) {
        return response;
    }

    util::method_not_found(method)
}

struct MainThreadDispatchGuard;

impl MainThreadDispatchGuard {
    fn enter() -> Self {
        MAIN_THREAD_DISPATCH_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self
    }
}

impl Drop for MainThreadDispatchGuard {
    fn drop(&mut self) {
        MAIN_THREAD_DISPATCH_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}
