#![allow(dead_code)]

mod addressing;
mod analysis;
mod batch;
mod debug;
mod fingerprint;
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

const INTERNAL_CLEANUP_METHOD: &str = "__ce_mcp_cleanup_runtime_state";

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
            | INTERNAL_CLEANUP_METHOD
    )
}

pub fn cleanup_ce_runtime_state() -> ToolResponse {
    cleanup_ce_runtime_state_direct()
}

fn dispatch_canonical(method: &str, params_json: &str) -> ToolResponse {
    if method == INTERNAL_CLEANUP_METHOD {
        return cleanup_ce_runtime_state_direct();
    }
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
    if let Some(response) = script::dispatch(method, params_json) {
        return response;
    }

    util::method_not_found(method)
}

fn cleanup_ce_runtime_state_direct() -> ToolResponse {
    // Release CE-side globals created by scan/debug bridges so plugin reloads start cleanly.
    let code = r###"
local function ce_mcp_cleanup_runtime_state()
    if _G.__ce_mcp_breakpoints then
        for _, bp in pairs(_G.__ce_mcp_breakpoints) do
            if bp and bp.address then
                pcall(function() debug_removeBreakpoint(bp.address) end)
            end
        end
    end

    if _G.__ce_mcp_active_watches then
        for _, watch in pairs(_G.__ce_mcp_active_watches) do
            if watch and watch.id then
                pcall(function() dbvm_watch_disable(watch.id) end)
            end
        end
    end

    if _G.__ce_mcp_scan_foundlist then
        pcall(function() _G.__ce_mcp_scan_foundlist.destroy() end)
    end
    if _G.__ce_mcp_scan_memscan then
        pcall(function() _G.__ce_mcp_scan_memscan.destroy() end)
    end

    _G.__ce_mcp_breakpoints = nil
    _G.__ce_mcp_breakpoint_hits = nil
    _G.__ce_mcp_hw_bp_slots = nil
    _G.__ce_mcp_active_watches = nil
    _G.__ce_mcp_scan_foundlist = nil
    _G.__ce_mcp_scan_memscan = nil

    return { success = true, cleaned = true }
end

return ce_mcp_cleanup_runtime_state()
"###;

    match lua_host::execute_snippet_result(code) {
        Ok(body) => ToolResponse {
            success: true,
            body_json: body.to_string(),
        },
        Err(error) => ToolResponse {
            success: false,
            body_json: error,
        },
    }
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
