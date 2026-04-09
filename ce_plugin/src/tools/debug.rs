use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::{addressing, lua_host, process, util, ToolResponse};
use crate::domain::context::RequestContext;
use crate::domain::evidence::{EvidenceRecord, EvidenceType};
use crate::runtime;

const METHODS: &[&str] = &[
    "set_breakpoint",
    "set_data_breakpoint",
    "remove_breakpoint",
    "list_breakpoints",
    "clear_all_breakpoints",
    "get_breakpoint_hits",
    "get_physical_address",
    "start_dbvm_watch",
    "stop_dbvm_watch",
    "poll_dbvm_watch",
];

const DEBUG_LUA_HELPER: &str = r###"
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

local function ce_mcp_capture_registers()
    local is64 = targetIs64Bit()
    if is64 then
        return {
            RAX = RAX and ce_mcp_to_hex(RAX) or nil,
            RBX = RBX and ce_mcp_to_hex(RBX) or nil,
            RCX = RCX and ce_mcp_to_hex(RCX) or nil,
            RDX = RDX and ce_mcp_to_hex(RDX) or nil,
            RSI = RSI and ce_mcp_to_hex(RSI) or nil,
            RDI = RDI and ce_mcp_to_hex(RDI) or nil,
            RBP = RBP and ce_mcp_to_hex(RBP) or nil,
            RSP = RSP and ce_mcp_to_hex(RSP) or nil,
            RIP = RIP and ce_mcp_to_hex(RIP) or nil,
            arch = "x64"
        }
    end
    return {
        EAX = EAX and ce_mcp_to_hex(EAX) or nil,
        EBX = EBX and ce_mcp_to_hex(EBX) or nil,
        ECX = ECX and ce_mcp_to_hex(ECX) or nil,
        EDX = EDX and ce_mcp_to_hex(EDX) or nil,
        ESI = ESI and ce_mcp_to_hex(ESI) or nil,
        EDI = EDI and ce_mcp_to_hex(EDI) or nil,
        EBP = EBP and ce_mcp_to_hex(EBP) or nil,
        ESP = ESP and ce_mcp_to_hex(ESP) or nil,
        EIP = EIP and ce_mcp_to_hex(EIP) or nil,
        arch = "x86"
    }
end

local function ce_mcp_capture_stack(depth)
    local stack = {}
    local is64 = targetIs64Bit()
    local ptrSize = is64 and 8 or 4
    local sp = is64 and (RSP or ESP) or ESP
    if not sp then return stack end
    for i = 0, depth - 1 do
        local val = is64 and readQword(sp + i * ptrSize) or readInteger(sp + i * ptrSize)
        if val then stack[i] = ce_mcp_to_hex(val) end
    end
    return stack
end

local function ce_mcp_debug_init()
    _G.__ce_mcp_breakpoints = _G.__ce_mcp_breakpoints or {}
    _G.__ce_mcp_breakpoint_hits = _G.__ce_mcp_breakpoint_hits or {}
    _G.__ce_mcp_hw_bp_slots = _G.__ce_mcp_hw_bp_slots or {}
    _G.__ce_mcp_active_watches = _G.__ce_mcp_active_watches or {}
end
"###;

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "set_breakpoint" => set_breakpoint(params_json),
        "set_data_breakpoint" => set_data_breakpoint(params_json),
        "remove_breakpoint" => remove_breakpoint(params_json),
        "list_breakpoints" => list_breakpoints(params_json),
        "clear_all_breakpoints" => clear_all_breakpoints(params_json),
        "get_breakpoint_hits" => get_breakpoint_hits(params_json),
        "get_physical_address" => get_physical_address(params_json),
        "start_dbvm_watch" => start_dbvm_watch(params_json),
        "poll_dbvm_watch" => poll_dbvm_watch(params_json),
        "stop_dbvm_watch" => stop_dbvm_watch(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn success_response(body: Value) -> ToolResponse {
    ToolResponse {
        success: true,
        body_json: body.to_string(),
    }
}

fn execute_ce_debug_snippet(code: &str) -> Result<Value, ToolResponse> {
    lua_host::execute_snippet_result(code).map_err(error_response)
}

fn call_ce_debug_tool_from_json(method: &str, params_json: &str) -> Result<Value, ToolResponse> {
    let params = util::parse_params(params_json).map_err(error_response)?;
    call_ce_debug_tool(method, &params)
}

fn call_ce_debug_tool(method: &str, params: &Value) -> Result<Value, ToolResponse> {
    match method {
        "set_breakpoint" => ce_set_breakpoint(params),
        "set_data_breakpoint" => ce_set_data_breakpoint(params),
        "remove_breakpoint" => ce_remove_breakpoint(params),
        "list_breakpoints" => ce_list_breakpoints(),
        "clear_all_breakpoints" => ce_clear_all_breakpoints(),
        "get_breakpoint_hits" => ce_get_breakpoint_hits(params),
        "get_physical_address" => ce_get_physical_address(params),
        "start_dbvm_watch" => ce_start_dbvm_watch(params),
        "poll_dbvm_watch" => ce_poll_dbvm_watch(params),
        "stop_dbvm_watch" => ce_stop_dbvm_watch(params),
        other => Err(error_response(format!("unsupported CE debug tool: {}", other))),
    }
}

fn set_breakpoint(params_json: &str) -> ToolResponse {
    match call_ce_debug_tool_from_json("set_breakpoint", params_json) {
        Ok(body) => success_response(body),
        Err(response) => response,
    }
}

fn set_data_breakpoint(params_json: &str) -> ToolResponse {
    match call_ce_debug_tool_from_json("set_data_breakpoint", params_json) {
        Ok(body) => success_response(body),
        Err(response) => response,
    }
}

fn remove_breakpoint(params_json: &str) -> ToolResponse {
    match call_ce_debug_tool_from_json("remove_breakpoint", params_json) {
        Ok(body) => success_response(body),
        Err(response) => response,
    }
}

fn list_breakpoints(params_json: &str) -> ToolResponse {
    match call_ce_debug_tool_from_json("list_breakpoints", params_json) {
        Ok(body) => success_response(body),
        Err(response) => response,
    }
}

fn clear_all_breakpoints(params_json: &str) -> ToolResponse {
    match call_ce_debug_tool_from_json("clear_all_breakpoints", params_json) {
        Ok(body) => success_response(body),
        Err(response) => response,
    }
}

fn get_breakpoint_hits(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);
    let response = match call_ce_debug_tool("get_breakpoint_hits", &params) {
        Ok(body) => success_response(body),
        Err(response) => response,
    };
    enrich_breakpoint_hits_response(response, &ctx)
}

fn get_physical_address(params_json: &str) -> ToolResponse {
    match call_ce_debug_tool_from_json("get_physical_address", params_json) {
        Ok(body) => success_response(body),
        Err(response) => response,
    }
}

fn start_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);
    let response = match call_ce_debug_tool("start_dbvm_watch", &params) {
        Ok(body) => success_response(body),
        Err(response) => response,
    };
    enrich_dbvm_watch_start_response(response, &ctx)
}

fn poll_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);
    let response = match call_ce_debug_tool("poll_dbvm_watch", &params) {
        Ok(body) => success_response(body),
        Err(response) => response,
    };
    enrich_dbvm_watch_hits_response(response, &ctx, "poll")
}

fn stop_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);
    let response = match call_ce_debug_tool("stop_dbvm_watch", &params) {
        Ok(body) => success_response(body),
        Err(response) => response,
    };
    enrich_dbvm_watch_hits_response(response, &ctx, "stop")
}

fn ce_set_breakpoint(params: &Value) -> Result<Value, ToolResponse> {
    let address = params.get("address").ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let id_lua = util::lua_string_literal(params.get("id").and_then(Value::as_str).unwrap_or(""));
    let capture_registers = params.get("capture_registers").and_then(Value::as_bool).unwrap_or(true).to_string();
    let capture_stack = params.get("capture_stack").and_then(Value::as_bool).unwrap_or(false).to_string();
    let stack_depth = params.get("stack_depth").and_then(Value::as_u64).unwrap_or(16);
    let code = format!(r###"{}
ce_mcp_debug_init()
local address = {}
local bp_id = {}
local capture_registers = {}
local capture_stack = {}
local stack_depth = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
if bp_id == "" then bp_id = tostring(address) end
local slot = nil
for i = 1, 4 do if not _G.__ce_mcp_hw_bp_slots[i] then slot = i break end end
if not slot then return {{ success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }} end
pcall(function() debug_removeBreakpoint(address) end)
_G.__ce_mcp_breakpoint_hits[bp_id] = {{}}
debug_setBreakpoint(address, 1, bptExecute, bpmDebugRegister, function()
    local hit = {{ id = bp_id, address = ce_mcp_to_hex(address), timestamp = os.time(), breakpoint_type = "hardware_execute" }}
    if capture_registers then hit.registers = ce_mcp_capture_registers() end
    if capture_stack then hit.stack = ce_mcp_capture_stack(stack_depth) end
    table.insert(_G.__ce_mcp_breakpoint_hits[bp_id], hit)
    debug_continueFromBreakpoint(co_run)
    return 1
end)
_G.__ce_mcp_hw_bp_slots[slot] = {{ id = bp_id, address = address }}
_G.__ce_mcp_breakpoints[bp_id] = {{ address = address, slot = slot, type = "execute" }}
return {{ success = true, id = bp_id, address = ce_mcp_to_hex(address), slot = slot, method = "hardware_debug_register" }}
"###, DEBUG_LUA_HELPER, address_lua, id_lua, capture_registers, capture_stack, stack_depth);
    execute_ce_debug_snippet(&code)
}

fn ce_set_data_breakpoint(params: &Value) -> Result<Value, ToolResponse> {
    let address = params.get("address").ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let id_lua = util::lua_string_literal(params.get("id").and_then(Value::as_str).unwrap_or(""));
    let access_type = util::lua_string_literal(params.get("access_type").and_then(Value::as_str).unwrap_or("w"));
    let size = params.get("size").and_then(Value::as_u64).unwrap_or(4);
    let code = format!(r###"{}
ce_mcp_debug_init()
local address = {}
local bp_id = {}
local access_type = {}
local size = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
if bp_id == "" then bp_id = tostring(address) end
local slot = nil
for i = 1, 4 do if not _G.__ce_mcp_hw_bp_slots[i] then slot = i break end end
if not slot then return {{ success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }} end
local bp_type = bptWrite
if access_type == "r" then bp_type = bptAccess elseif access_type == "rw" then bp_type = bptAccess end
_G.__ce_mcp_breakpoint_hits[bp_id] = {{}}
debug_setBreakpoint(address, size, bp_type, bpmDebugRegister, function()
    local arch = targetIs64Bit()
    local inst_ptr = arch and RIP or EIP
    local hit = {{ id = bp_id, type = "data_" .. access_type, address = ce_mcp_to_hex(address), timestamp = os.time(), instruction_address = inst_ptr and ce_mcp_to_hex(inst_ptr) or nil, registers = ce_mcp_capture_registers() }}
    table.insert(_G.__ce_mcp_breakpoint_hits[bp_id], hit)
    debug_continueFromBreakpoint(co_run)
    return 1
end)
_G.__ce_mcp_hw_bp_slots[slot] = {{ id = bp_id, address = address }}
_G.__ce_mcp_breakpoints[bp_id] = {{ address = address, slot = slot, type = "data_" .. access_type }}
return {{ success = true, id = bp_id, address = ce_mcp_to_hex(address), slot = slot, access_type = access_type, size = size, method = "hardware_debug_register" }}
"###, DEBUG_LUA_HELPER, address_lua, id_lua, access_type, size);
    execute_ce_debug_snippet(&code)
}

fn ce_remove_breakpoint(params: &Value) -> Result<Value, ToolResponse> {
    let id_lua = util::lua_string_literal(params.get("id").and_then(Value::as_str).unwrap_or(""));
    let code = format!(r###"{}
ce_mcp_debug_init()
local bp_id = {}
local bp = _G.__ce_mcp_breakpoints[bp_id]
if not bp then return {{ success = false, error = "Breakpoint not found: " .. tostring(bp_id) }} end
pcall(function() debug_removeBreakpoint(bp.address) end)
if bp.slot then _G.__ce_mcp_hw_bp_slots[bp.slot] = nil end
_G.__ce_mcp_breakpoints[bp_id] = nil
return {{ success = true, id = bp_id }}
"###, DEBUG_LUA_HELPER, id_lua);
    execute_ce_debug_snippet(&code)
}

fn ce_list_breakpoints() -> Result<Value, ToolResponse> {
    let code = format!(r###"{}
ce_mcp_debug_init()
local list = {{}}
for id, bp in pairs(_G.__ce_mcp_breakpoints) do
    table.insert(list, {{ id = id, address = ce_mcp_to_hex(bp.address), type = bp.type or "execution", slot = bp.slot }})
end
return {{ success = true, count = #list, breakpoints = list }}
"###, DEBUG_LUA_HELPER);
    execute_ce_debug_snippet(&code)
}

fn ce_clear_all_breakpoints() -> Result<Value, ToolResponse> {
    let code = format!(r###"{}
ce_mcp_debug_init()
local count = 0
for id, bp in pairs(_G.__ce_mcp_breakpoints) do
    pcall(function() debug_removeBreakpoint(bp.address) end)
    count = count + 1
end
_G.__ce_mcp_breakpoints = {{}}
_G.__ce_mcp_breakpoint_hits = {{}}
_G.__ce_mcp_hw_bp_slots = {{}}
return {{ success = true, removed = count }}
"###, DEBUG_LUA_HELPER);
    execute_ce_debug_snippet(&code)
}

fn ce_get_breakpoint_hits(params: &Value) -> Result<Value, ToolResponse> {
    let id_lua = match params.get("id") { Some(value) => util::lua_scalar_literal(value).map_err(error_response)?, None => "nil".to_owned() };
    let clear = params.get("clear").and_then(Value::as_bool).unwrap_or(true).to_string();
    let code = format!(r###"{}
ce_mcp_debug_init()
local bp_id = {}
local clear = {}
local hits
if bp_id and bp_id ~= nil then
    hits = _G.__ce_mcp_breakpoint_hits[bp_id] or {{}}
    if clear then _G.__ce_mcp_breakpoint_hits[bp_id] = {{}} end
else
    hits = {{}}
    for _, hits_for_bp in pairs(_G.__ce_mcp_breakpoint_hits) do
        for _, hit in ipairs(hits_for_bp) do table.insert(hits, hit) end
    end
    if clear then _G.__ce_mcp_breakpoint_hits = {{}} end
end
return {{ success = true, count = #hits, hits = hits }}
"###, DEBUG_LUA_HELPER, id_lua, clear);
    execute_ce_debug_snippet(&code)
}

fn ce_get_physical_address(params: &Value) -> Result<Value, ToolResponse> {
    let address = params.get("address").ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let code = format!(r###"{}
local address = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local ok, phys = pcall(dbk_getPhysicalAddress, address)
if not ok then return {{ success = false, virtual_address = ce_mcp_to_hex(address), error = "DBK driver not loaded. Run dbk_initialize() first or load it via CE settings." }} end
if not phys or phys == 0 then return {{ success = false, virtual_address = ce_mcp_to_hex(address), error = "Could not resolve physical address. Page may not be present in RAM." }} end
return {{ success = true, virtual_address = ce_mcp_to_hex(address), physical_address = ce_mcp_to_hex(phys), physical_int = phys }}
"###, DEBUG_LUA_HELPER, address_lua);
    execute_ce_debug_snippet(&code)
}

fn ce_start_dbvm_watch(params: &Value) -> Result<Value, ToolResponse> {
    let address = params.get("address").ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let mode = util::lua_string_literal(params.get("mode").and_then(Value::as_str).unwrap_or("w"));
    let max_entries = params.get("max_entries").and_then(Value::as_u64).unwrap_or(1000);
    let code = format!(r###"{}
ce_mcp_debug_init()
local address = {}
local mode = {}
local max_entries = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
if not dbk_initialized() then return {{ success = false, error = "DBK driver not loaded. Go to Settings -> Debugger -> Kernelmode" }} end
if not dbvm_initialized() then pcall(dbvm_initialize) end
if not dbvm_initialized() then return {{ success = false, error = "DBVM not running. Go to Settings -> Debugger -> Use DBVM" }} end
local ok, phys = pcall(dbk_getPhysicalAddress, address)
if not ok or not phys or phys == 0 then return {{ success = false, virtual_address = ce_mcp_to_hex(address), error = "Could not resolve physical address. Page might be paged out or invalid." }} end
local watch_key = ce_mcp_to_hex(address)
if _G.__ce_mcp_active_watches[watch_key] then return {{ success = false, virtual_address = ce_mcp_to_hex(address), error = "Already watching this address. Call stop_dbvm_watch first." }} end
local options = 1 + 2 + 8
local watch_id = nil
local ok_watch, result
if mode == "x" then ok_watch, result = pcall(dbvm_watch_executes, phys, 1, options, max_entries)
elseif mode == "r" or mode == "rw" then ok_watch, result = pcall(dbvm_watch_reads, phys, 1, options, max_entries)
else ok_watch, result = pcall(dbvm_watch_writes, phys, 1, options, max_entries) end
watch_id = ok_watch and result or nil
if not ok_watch then return {{ success = false, virtual_address = ce_mcp_to_hex(address), physical_address = ce_mcp_to_hex(phys), error = "DBVM watch CRASHED/FAILED: " .. tostring(result) }} end
if not watch_id then return {{ success = false, virtual_address = ce_mcp_to_hex(address), physical_address = ce_mcp_to_hex(phys), error = "DBVM watch returned nil (check CE console for details)" }} end
_G.__ce_mcp_active_watches[watch_key] = {{ id = watch_id, physical = phys, mode = mode, start_time = os.time() }}
return {{ success = true, status = "monitoring", virtual_address = ce_mcp_to_hex(address), physical_address = ce_mcp_to_hex(phys), watch_id = watch_id, mode = mode, note = "Call poll_dbvm_watch to get logs without stopping, or stop_dbvm_watch to end" }}
"###, DEBUG_LUA_HELPER, address_lua, mode, max_entries);
    execute_ce_debug_snippet(&code)
}

fn ce_poll_dbvm_watch(params: &Value) -> Result<Value, ToolResponse> {
    let address = params.get("address").ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let max_results = params.get("max_results").and_then(Value::as_u64).unwrap_or(1000);
    let code = format!(r###"{}
ce_mcp_debug_init()
local address = {}
local max_results = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local watch_key = ce_mcp_to_hex(address)
local watch_info = _G.__ce_mcp_active_watches[watch_key]
if not watch_info then return {{ success = false, virtual_address = ce_mcp_to_hex(address), error = "No active watch found for this address. Call start_dbvm_watch first." }} end
local results = {{}}
local ok_log, log = pcall(dbvm_watch_retrievelog, watch_info.id)
if ok_log and log then
    local count = math.min(#log, max_results)
    for i = 1, count do
        local entry = log[i]
        table.insert(results, {{ hit_number = i, ESP = entry.RSP and (entry.RSP % 0x100000000) or nil, RSP = entry.RSP and ce_mcp_to_hex(entry.RSP) or nil, EIP = entry.RIP and (entry.RIP % 0x100000000) or nil, RIP = entry.RIP and ce_mcp_to_hex(entry.RIP) or nil, EAX = entry.RAX and (entry.RAX % 0x100000000) or nil, ECX = entry.RCX and (entry.RCX % 0x100000000) or nil, EDX = entry.RDX and (entry.RDX % 0x100000000) or nil, ESI = entry.RSI and (entry.RSI % 0x100000000) or nil, EDI = entry.RDI and (entry.RDI % 0x100000000) or nil }})
    end
end
local uptime = os.time() - (watch_info.start_time or os.time())
return {{ success = true, status = "active", virtual_address = ce_mcp_to_hex(address), physical_address = ce_mcp_to_hex(watch_info.physical), mode = watch_info.mode, uptime_seconds = uptime, hit_count = #results, hits = results, note = "Watch still active. Call again to get more logs, or stop_dbvm_watch to end." }}
"###, DEBUG_LUA_HELPER, address_lua, max_results);
    execute_ce_debug_snippet(&code)
}

fn ce_stop_dbvm_watch(params: &Value) -> Result<Value, ToolResponse> {
    let address = params.get("address").ok_or_else(|| error_response("missing address".to_owned()))?;
    let address_lua = util::lua_scalar_literal(address).map_err(error_response)?;
    let max_results = params.get("max_results").and_then(Value::as_u64).unwrap_or(1000);
    let code = format!(r###"{}
ce_mcp_debug_init()
local address = {}
local max_results = {}
if type(address) == "string" then address = getAddressSafe(address) end
if not address then return {{ success = false, error = "Invalid address" }} end
local watch_key = ce_mcp_to_hex(address)
local watch_info = _G.__ce_mcp_active_watches[watch_key]
if not watch_info then return {{ success = false, virtual_address = ce_mcp_to_hex(address), error = "No active watch found for this address. Call start_dbvm_watch first." }} end
local results = {{}}
local ok_log, log = pcall(dbvm_watch_retrievelog, watch_info.id)
if ok_log and log then
    local count = math.min(#log, max_results)
    for i = 1, count do
        local entry = log[i]
        table.insert(results, {{ hit_number = i, ESP = entry.RSP and (entry.RSP % 0x100000000) or nil, RSP = entry.RSP and ce_mcp_to_hex(entry.RSP) or nil, EIP = entry.RIP and (entry.RIP % 0x100000000) or nil, RIP = entry.RIP and ce_mcp_to_hex(entry.RIP) or nil, EAX = entry.RAX and (entry.RAX % 0x100000000) or nil, ECX = entry.RCX and (entry.RCX % 0x100000000) or nil, EDX = entry.RDX and (entry.RDX % 0x100000000) or nil, ESI = entry.RSI and (entry.RSI % 0x100000000) or nil, EDI = entry.RDI and (entry.RDI % 0x100000000) or nil }})
    end
end
pcall(dbvm_watch_disable, watch_info.id)
_G.__ce_mcp_active_watches[watch_key] = nil
local uptime = os.time() - (watch_info.start_time or os.time())
return {{ success = true, status = "stopped", virtual_address = ce_mcp_to_hex(address), physical_address = ce_mcp_to_hex(watch_info.physical), mode = watch_info.mode, uptime_seconds = uptime, hit_count = #results, hits = results }}
"###, DEBUG_LUA_HELPER, address_lua, max_results);
    execute_ce_debug_snippet(&code)
}
fn current_modules() -> Vec<runtime::ModuleInfo> {
    process::current_modules()
}

fn enrich_breakpoint_hits_response(response: ToolResponse, ctx: &RequestContext) -> ToolResponse {
    if !response.success {
        return response;
    }

    let Ok(mut body) = serde_json::from_str::<Value>(&response.body_json) else {
        return response;
    };
    let Some(object) = body.as_object_mut() else {
        return response;
    };
    let Some(hits) = object.get("hits").and_then(Value::as_array) else {
        return response;
    };

    let modules = current_modules();
    let evidence = hits
        .iter()
        .enumerate()
        .filter_map(|(index, hit)| build_breakpoint_evidence(hit, index, ctx, &modules))
        .collect::<Vec<_>>();

    object.insert("evidence".to_owned(), json!(evidence));
    ToolResponse {
        success: true,
        body_json: Value::Object(object.clone()).to_string(),
    }
}

fn build_breakpoint_evidence(
    hit: &Value,
    index: usize,
    ctx: &RequestContext,
    modules: &[runtime::ModuleInfo],
) -> Option<EvidenceRecord> {
    let hit_obj = hit.as_object()?;
    let breakpoint_id = hit_obj
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("breakpoint");
    let address_value = hit_obj.get("address");
    let address = util::parse_address(address_value).ok();
    let normalized_address =
        address.and_then(|value| addressing::normalize_address_from_modules(value, modules));
    let registers = hit_obj
        .get("registers")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_owned()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .filter(|map| !map.is_empty());
    let timestamp = hit_obj
        .get("timestamp")
        .map(|value| match value {
            Value::Number(number) => number.to_string(),
            Value::String(text) => text.clone(),
            _ => "unknown".to_owned(),
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let summary = hit_obj
        .get("instruction")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            hit_obj
                .get("breakpoint_type")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });

    Some(EvidenceRecord {
        evidence_id: format!("{}-{}", breakpoint_id, index),
        event_type: EvidenceType::BreakpointHit,
        captured_at: timestamp,
        session_id: ctx.session_id.clone(),
        scenario_id: ctx.scenario_id.clone(),
        address: normalized_address,
        thread_id: None,
        registers,
        summary,
        payload: hit.clone(),
        tags: ctx.tags.clone().unwrap_or_default(),
    })
}

fn enrich_dbvm_watch_start_response(response: ToolResponse, ctx: &RequestContext) -> ToolResponse {
    if !response.success {
        return response;
    }

    let Ok(mut body) = serde_json::from_str::<Value>(&response.body_json) else {
        return response;
    };
    let Some(object) = body.as_object_mut() else {
        return response;
    };

    let modules = current_modules();
    let evidence = build_dbvm_watch_start_evidence(&Value::Object(object.clone()), ctx, &modules)
        .into_iter()
        .collect::<Vec<_>>();

    object.insert("evidence".to_owned(), json!(evidence));
    ToolResponse {
        success: true,
        body_json: Value::Object(object.clone()).to_string(),
    }
}

fn enrich_dbvm_watch_hits_response(
    response: ToolResponse,
    ctx: &RequestContext,
    phase: &str,
) -> ToolResponse {
    if !response.success {
        return response;
    }

    let Ok(mut body) = serde_json::from_str::<Value>(&response.body_json) else {
        return response;
    };
    let Some(object) = body.as_object_mut() else {
        return response;
    };
    let Some(hits) = object.get("hits").and_then(Value::as_array) else {
        object.insert("evidence".to_owned(), json!([]));
        return ToolResponse {
            success: true,
            body_json: Value::Object(object.clone()).to_string(),
        };
    };

    let modules = current_modules();
    let watch_payload = Value::Object(object.clone());
    let evidence = hits
        .iter()
        .enumerate()
        .filter_map(|(index, hit)| {
            build_dbvm_watch_hit_evidence(hit, index, phase, ctx, &modules, &watch_payload)
        })
        .collect::<Vec<_>>();

    object.insert("evidence".to_owned(), json!(evidence));
    ToolResponse {
        success: true,
        body_json: Value::Object(object.clone()).to_string(),
    }
}

fn build_dbvm_watch_start_evidence(
    body: &Value,
    ctx: &RequestContext,
    modules: &[runtime::ModuleInfo],
) -> Option<EvidenceRecord> {
    let body_obj = body.as_object()?;
    let watch_key = body_obj
        .get("virtual_address")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let physical_address = body_obj
        .get("physical_address")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mode = body_obj
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let address = util::parse_address(body_obj.get("virtual_address"))
        .ok()
        .and_then(|value| addressing::normalize_address_from_modules(value, modules));
    let captured_at =
        scalar_to_string(body_obj.get("started_at")).unwrap_or_else(|| "unknown".to_owned());

    Some(EvidenceRecord {
        evidence_id: format!("dbvm-watch-start-{}", watch_key),
        event_type: EvidenceType::ManualNote,
        captured_at,
        session_id: ctx.session_id.clone(),
        scenario_id: ctx.scenario_id.clone(),
        address,
        thread_id: None,
        registers: None,
        summary: Some(format!(
            "dbvm watch started: {} -> {} ({})",
            watch_key, physical_address, mode
        )),
        payload: body.clone(),
        tags: ctx.tags.clone().unwrap_or_default(),
    })
}

fn build_dbvm_watch_hit_evidence(
    hit: &Value,
    index: usize,
    phase: &str,
    ctx: &RequestContext,
    modules: &[runtime::ModuleInfo],
    watch_payload: &Value,
) -> Option<EvidenceRecord> {
    let hit_obj = hit.as_object()?;
    let watch_obj = watch_payload.as_object()?;
    let watch_key = watch_obj
        .get("virtual_address")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mode = watch_obj
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let instruction_address = hit_obj
        .get("instruction_address")
        .or_else(|| hit_obj.get("RIP"));
    let address = util::parse_address(instruction_address)
        .ok()
        .and_then(|value| addressing::normalize_address_from_modules(value, modules));
    let registers = collect_registers(hit_obj);
    let captured_at = scalar_to_string(hit_obj.get("timestamp"))
        .or_else(|| scalar_to_string(watch_obj.get("observed_at")))
        .or_else(|| scalar_to_string(watch_obj.get("stopped_at")))
        .unwrap_or_else(|| "unknown".to_owned());
    let summary = hit_obj
        .get("instruction")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("dbvm watch {} hit #{} on {}", mode, index + 1, watch_key));

    let mut payload = hit.clone();
    if let Value::Object(payload_obj) = &mut payload {
        if let Some(value) = watch_obj.get("virtual_address") {
            payload_obj.insert("watched_virtual_address".to_owned(), value.clone());
        }
        if let Some(value) = watch_obj.get("physical_address") {
            payload_obj.insert("watched_physical_address".to_owned(), value.clone());
        }
        if let Some(value) = watch_obj.get("mode") {
            payload_obj.insert("watch_mode".to_owned(), value.clone());
        }
        payload_obj.insert("watch_phase".to_owned(), Value::String(phase.to_owned()));
    }

    Some(EvidenceRecord {
        evidence_id: format!("dbvm-watch-{}-{}-{}", phase, watch_key, index),
        event_type: EvidenceType::BreakpointHit,
        captured_at,
        session_id: ctx.session_id.clone(),
        scenario_id: ctx.scenario_id.clone(),
        address,
        thread_id: None,
        registers,
        summary: Some(summary),
        payload,
        tags: ctx.tags.clone().unwrap_or_default(),
    })
}

fn collect_registers(hit_obj: &Map<String, Value>) -> Option<BTreeMap<String, String>> {
    if let Some(map) = hit_obj.get("registers").and_then(Value::as_object) {
        let registers = map
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|text| (key.clone(), text.to_owned())))
            .collect::<BTreeMap<_, _>>();
        if !registers.is_empty() {
            return Some(registers);
        }
    }

    const REGISTER_KEYS: &[&str] = &[
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP", "R8", "R9", "R10", "R11",
        "R12", "R13", "R14", "R15", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
    ];

    let registers = REGISTER_KEYS
        .iter()
        .filter_map(|key| {
            hit_obj
                .get(*key)
                .and_then(Value::as_str)
                .map(|text| ((*key).to_owned(), text.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();

    if registers.is_empty() {
        None
    } else {
        Some(registers)
    }
}

fn scalar_to_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
