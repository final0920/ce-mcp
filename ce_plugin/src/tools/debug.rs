use serde_json::{Map, Value};

use super::{script, util, ToolResponse};

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

const BREAKPOINT_BOOTSTRAP: &str = r#"
_G.__ce_plugin_breakpoint_state = _G.__ce_plugin_breakpoint_state or {
  breakpoints = {},
  breakpoint_hits = {},
  hw_bp_slots = {}
}
_G.__ce_plugin_breakpoint_api = _G.__ce_plugin_breakpoint_api or {}

local state = _G.__ce_plugin_breakpoint_state
local api = _G.__ce_plugin_breakpoint_api

if not api.toHex then
  function api.toHex(num)
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

  function api.getArchInfo()
    local is64 = targetIs64Bit()
    local ptrSize = is64 and 8 or 4
    local stackPtr = is64 and (RSP or ESP) or ESP
    local instPtr = is64 and (RIP or EIP) or EIP
    return {
      is64bit = is64,
      ptrSize = ptrSize,
      stackPtr = stackPtr,
      instPtr = instPtr
    }
  end

  function api.captureRegisters()
    local is64 = targetIs64Bit()
    if is64 then
      return {
        RAX = RAX and api.toHex(RAX) or nil,
        RBX = RBX and api.toHex(RBX) or nil,
        RCX = RCX and api.toHex(RCX) or nil,
        RDX = RDX and api.toHex(RDX) or nil,
        RSI = RSI and api.toHex(RSI) or nil,
        RDI = RDI and api.toHex(RDI) or nil,
        RBP = RBP and api.toHex(RBP) or nil,
        RSP = RSP and api.toHex(RSP) or nil,
        RIP = RIP and api.toHex(RIP) or nil,
        R8 = R8 and api.toHex(R8) or nil,
        R9 = R9 and api.toHex(R9) or nil,
        R10 = R10 and api.toHex(R10) or nil,
        R11 = R11 and api.toHex(R11) or nil,
        R12 = R12 and api.toHex(R12) or nil,
        R13 = R13 and api.toHex(R13) or nil,
        R14 = R14 and api.toHex(R14) or nil,
        R15 = R15 and api.toHex(R15) or nil,
        EFLAGS = EFLAGS and api.toHex(EFLAGS) or nil,
        arch = "x64"
      }
    end

    return {
      EAX = EAX and api.toHex(EAX) or nil,
      EBX = EBX and api.toHex(EBX) or nil,
      ECX = ECX and api.toHex(ECX) or nil,
      EDX = EDX and api.toHex(EDX) or nil,
      ESI = ESI and api.toHex(ESI) or nil,
      EDI = EDI and api.toHex(EDI) or nil,
      EBP = EBP and api.toHex(EBP) or nil,
      ESP = ESP and api.toHex(ESP) or nil,
      EIP = EIP and api.toHex(EIP) or nil,
      EFLAGS = EFLAGS and api.toHex(EFLAGS) or nil,
      arch = "x86"
    }
  end

  function api.captureStack(depth)
    local arch = api.getArchInfo()
    local stack = {}
    local stackPtr = arch.stackPtr
    if not stackPtr then return stack end

    for i = 0, depth - 1 do
      local okRead, value
      if arch.is64bit then
        okRead, value = pcall(readQword, stackPtr + i * arch.ptrSize)
      else
        okRead, value = pcall(readInteger, stackPtr + i * arch.ptrSize)
      end
      if okRead and value then
        stack[i] = api.toHex(value)
      end
    end

    return stack
  end

  function api.findTrackedBreakpointIdByAddress(address)
    for id, bp in pairs(state.breakpoints) do
      if bp.address == address then
        return id, bp
      end
    end
    return nil, nil
  end

  function api.removeTrackedBreakpoint(bpId, clearHits)
    local bp = state.breakpoints[bpId]
    if not bp then
      return false
    end

    pcall(function() debug_removeBreakpoint(bp.address) end)

    if bp.slot then
      state.hw_bp_slots[bp.slot] = nil
    end

    state.breakpoints[bpId] = nil
    if clearHits ~= false then
      state.breakpoint_hits[bpId] = nil
    end

    return true
  end

  function api.reserveHardwareBreakpointSlot(preferredSlot)
    if preferredSlot and preferredSlot >= 1 and preferredSlot <= 4 and not state.hw_bp_slots[preferredSlot] then
      return preferredSlot
    end

    for i = 1, 4 do
      if not state.hw_bp_slots[i] then
        return i
      end
    end

    return nil
  end
end
"#;

enum AddressParam {
    Numeric(usize),
    Expression(String),
}

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

fn set_breakpoint(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let address = match parse_breakpoint_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let breakpoint_id = match parse_optional_id(params.get("id")) {
        Ok(id) => id,
        Err(error) => return error_response(error),
    };
    let capture_registers = params
        .get("capture_registers")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let capture_stack = params
        .get("capture_stack")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stack_depth = params
        .get("stack_depth")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(16)
        .clamp(1, 256);

    let code = format!(
        r#"
{}
{}
local bpId = {}
local captureRegs = {}
local captureStackFlag = {}
local stackDepth = {}

if not addr then
  return {{ success = false, error = "Invalid address" }}
end

if not debug_setBreakpoint or not debug_removeBreakpoint or not debug_continueFromBreakpoint then
  return {{ success = false, error = "CE debugger breakpoint API unavailable" }}
end

bpId = bpId or tostring(addr)

local preferredSlot = nil
local existingById = state.breakpoints[bpId]
if existingById then
  preferredSlot = existingById.slot
  api.removeTrackedBreakpoint(bpId, false)
end

local existingAddrId, existingByAddr = api.findTrackedBreakpointIdByAddress(addr)
if existingAddrId and existingAddrId ~= bpId then
  preferredSlot = preferredSlot or existingByAddr.slot
  api.removeTrackedBreakpoint(existingAddrId, false)
end

pcall(function() debug_removeBreakpoint(addr) end)

local slot = api.reserveHardwareBreakpointSlot(preferredSlot)
if not slot then
  return {{ success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }}
end

state.breakpoint_hits[bpId] = {{}}

local okSet, setErr = pcall(
  debug_setBreakpoint,
  addr,
  1,
  bptExecute,
  bpmDebugRegister,
  function()
    local hitData = {{
      id = bpId,
      address = api.toHex(addr),
      timestamp = os.time(),
      breakpoint_type = "hardware_execute"
    }}

    if captureRegs then
      local okRegs, registers = pcall(api.captureRegisters)
      if okRegs then
        hitData.registers = registers
      end
    end

    if captureStackFlag then
      local okStack, stack = pcall(api.captureStack, stackDepth)
      if okStack then
        hitData.stack = stack
      end
    end

    state.breakpoint_hits[bpId] = state.breakpoint_hits[bpId] or {{}}
    table.insert(state.breakpoint_hits[bpId], hitData)
    pcall(function() debug_continueFromBreakpoint(co_run) end)
    return 1
  end
)

if not okSet then
  state.breakpoint_hits[bpId] = nil
  return {{ success = false, error = "debug_setBreakpoint failed: " .. tostring(setErr) }}
end

state.hw_bp_slots[slot] = {{ id = bpId, address = addr }}
state.breakpoints[bpId] = {{ address = addr, slot = slot, type = "execute" }}

return {{
  success = true,
  id = bpId,
  address = api.toHex(addr),
  slot = slot,
  method = "hardware_debug_register"
}}
"#,
        BREAKPOINT_BOOTSTRAP,
        build_address_binding(&address),
        lua_string_or_nil(breakpoint_id.as_deref()),
        lua_bool(capture_registers),
        lua_bool(capture_stack),
        stack_depth,
    );

    execute_debug_snippet(code.as_str())
}

fn set_data_breakpoint(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let address = match parse_breakpoint_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let breakpoint_id = match parse_optional_id(params.get("id")) {
        Ok(id) => id,
        Err(error) => return error_response(error),
    };
    let access_type = params
        .get("access_type")
        .and_then(Value::as_str)
        .unwrap_or("w")
        .trim()
        .to_ascii_lowercase();
    if !matches!(access_type.as_str(), "r" | "w" | "rw") {
        return error_response("invalid access_type: must be one of r, w, rw".to_owned());
    }
    let size = params
        .get("size")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(4);
    if !matches!(size, 1 | 2 | 4 | 8) {
        return error_response("invalid size: must be one of 1, 2, 4, 8".to_owned());
    }

    let code = format!(
        r#"
{}
{}
local bpId = {}
local accessType = {}
local size = {}

if not addr then
  return {{ success = false, error = "Invalid address" }}
end

if not debug_setBreakpoint or not debug_removeBreakpoint or not debug_continueFromBreakpoint then
  return {{ success = false, error = "CE debugger breakpoint API unavailable" }}
end

bpId = bpId or tostring(addr)

local preferredSlot = nil
local existingById = state.breakpoints[bpId]
if existingById then
  preferredSlot = existingById.slot
  api.removeTrackedBreakpoint(bpId, false)
end

local existingAddrId, existingByAddr = api.findTrackedBreakpointIdByAddress(addr)
if existingAddrId and existingAddrId ~= bpId then
  preferredSlot = preferredSlot or existingByAddr.slot
  api.removeTrackedBreakpoint(existingAddrId, false)
end

pcall(function() debug_removeBreakpoint(addr) end)

local slot = api.reserveHardwareBreakpointSlot(preferredSlot)
if not slot then
  return {{ success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }}
end

local bpType = bptWrite
if accessType == "r" or accessType == "rw" then
  bpType = bptAccess
end

state.breakpoint_hits[bpId] = {{}}

local okSet, setErr = pcall(
  debug_setBreakpoint,
  addr,
  size,
  bpType,
  bpmDebugRegister,
  function()
    local arch = api.getArchInfo()
    local instruction = "???"
    if arch.instPtr then
      local okDisassemble, disassembled = pcall(disassemble, arch.instPtr)
      if okDisassemble and disassembled then
        instruction = disassembled
      end
    end

    local okValue, value
    if arch.is64bit then
      okValue, value = pcall(readQword, addr)
    else
      okValue, value = pcall(readInteger, addr)
    end
    if not okValue then
      value = nil
    end

    local hitData = {{
      id = bpId,
      type = "data_" .. accessType,
      address = api.toHex(addr),
      timestamp = os.time(),
      breakpoint_type = "hardware_data",
      value = value,
      registers = api.captureRegisters(),
      instruction = instruction,
      arch = arch.is64bit and "x64" or "x86"
    }}

    state.breakpoint_hits[bpId] = state.breakpoint_hits[bpId] or {{}}
    table.insert(state.breakpoint_hits[bpId], hitData)
    pcall(function() debug_continueFromBreakpoint(co_run) end)
    return 1
  end
)

if not okSet then
  state.breakpoint_hits[bpId] = nil
  return {{ success = false, error = "debug_setBreakpoint failed: " .. tostring(setErr) }}
end

state.hw_bp_slots[slot] = {{ id = bpId, address = addr }}
state.breakpoints[bpId] = {{ address = addr, slot = slot, type = "data" }}

return {{
  success = true,
  id = bpId,
  address = api.toHex(addr),
  slot = slot,
  access_type = accessType,
  method = "hardware_debug_register"
}}
"#,
        BREAKPOINT_BOOTSTRAP,
        build_address_binding(&address),
        lua_string_or_nil(breakpoint_id.as_deref()),
        json_string(access_type.as_str()),
        size,
    );

    execute_debug_snippet(code.as_str())
}

fn remove_breakpoint(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let breakpoint_id = match require_id(params.get("id")) {
        Ok(id) => id,
        Err(error) => return error_response(error),
    };

    let code = format!(
        r#"
{}
local bpId = {}

if api.removeTrackedBreakpoint(bpId) then
  return {{ success = true, id = bpId }}
end

return {{ success = false, error = "Breakpoint not found: " .. tostring(bpId) }}
"#,
        BREAKPOINT_BOOTSTRAP,
        json_string(breakpoint_id.as_str()),
    );

    execute_debug_snippet(code.as_str())
}

fn list_breakpoints(params_json: &str) -> ToolResponse {
    if let Err(error) = util::parse_params(params_json) {
        return error_response(error);
    }

    let code = format!(
        r#"
{}
local list = {{}}
for id, bp in pairs(state.breakpoints) do
  table.insert(list, {{
    id = id,
    address = api.toHex(bp.address),
    type = bp.type or "execution",
    slot = bp.slot
  }})
end

return {{
  success = true,
  count = #list,
  breakpoints = list
}}
"#,
        BREAKPOINT_BOOTSTRAP,
    );

    execute_debug_snippet(code.as_str())
}

fn clear_all_breakpoints(params_json: &str) -> ToolResponse {
    if let Err(error) = util::parse_params(params_json) {
        return error_response(error);
    }

    let code = format!(
        r#"
{}
local ids = {{}}
local removed = 0

for id, _ in pairs(state.breakpoints) do
  ids[#ids + 1] = id
end

for _, id in ipairs(ids) do
  if api.removeTrackedBreakpoint(id) then
    removed = removed + 1
  end
end

return {{
  success = true,
  removed = removed
}}
"#,
        BREAKPOINT_BOOTSTRAP,
    );

    execute_debug_snippet(code.as_str())
}

fn get_breakpoint_hits(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let breakpoint_id = match parse_optional_id(params.get("id")) {
        Ok(id) => id,
        Err(error) => return error_response(error),
    };
    let clear = params.get("clear").and_then(Value::as_bool).unwrap_or(true);

    let code = format!(
        r#"
{}
local bpId = {}
local clear = {}
local hits

if bpId then
  hits = state.breakpoint_hits[bpId] or {{}}
  if clear then
    state.breakpoint_hits[bpId] = {{}}
  end
else
  hits = {{}}
  for id, hitsForBp in pairs(state.breakpoint_hits) do
    for _, hit in ipairs(hitsForBp) do
      table.insert(hits, hit)
    end
  end
  if clear then
    state.breakpoint_hits = {{}}
  end
end

return {{
  success = true,
  count = #hits,
  hits = hits
}}
"#,
        BREAKPOINT_BOOTSTRAP,
        lua_string_or_nil(breakpoint_id.as_deref()),
        lua_bool(clear),
    );

    execute_debug_snippet(code.as_str())
}

fn get_physical_address(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    let code = format!(
        r#"
local addr = {}
local ok, phys = pcall(dbk_getPhysicalAddress, addr)
if not ok then
  return {{
    success = false,
    virtual_address = string.format("0x%X", addr),
    error = "DBK driver not loaded. Run dbk_initialize() first or load it via CE settings."
  }}
end
if not phys or phys == 0 then
  return {{
    success = false,
    virtual_address = string.format("0x%X", addr),
    error = "Could not resolve physical address. Page may not be present in RAM."
  }}
end
return {{
  success = true,
  virtual_address = string.format("0x%X", addr),
  physical_address = string.format("0x%X", phys),
  physical_int = phys
}}
"#,
        address
    );

    execute_structured_snippet(code.as_str())
}

fn start_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let mode = params
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("w")
        .trim()
        .to_ascii_lowercase();
    if !matches!(mode.as_str(), "w" | "r" | "rw" | "x") {
        return error_response("invalid mode: must be one of w, r, rw, x".to_owned());
    }
    let max_entries = params
        .get("max_entries")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(1000)
        .clamp(1, 10_000);

    let mode_lua = serde_json::to_string(mode.as_str()).unwrap_or_else(|_| "\"w\"".to_owned());
    let code = format!(
        r#"
local addr = {}
local mode = {}
local maxEntries = {}
_G.__ce_plugin_dbvm_watches = _G.__ce_plugin_dbvm_watches or {{}}
local watches = _G.__ce_plugin_dbvm_watches
local watchKey = string.format("0x%X", addr)

if not dbk_initialized() then
  return {{
    success = false,
    virtual_address = watchKey,
    error = "DBK driver not loaded. Go to Settings -> Debugger -> Kernelmode"
  }}
end

if not dbvm_initialized() then
  pcall(dbvm_initialize)
  if not dbvm_initialized() then
    return {{
      success = false,
      virtual_address = watchKey,
      error = "DBVM not running. Go to Settings -> Debugger -> Use DBVM"
    }}
  end
end

local okPhys, phys = pcall(dbk_getPhysicalAddress, addr)
if not okPhys or not phys or phys == 0 then
  return {{
    success = false,
    virtual_address = watchKey,
    error = "Could not resolve physical address. Page might be paged out or invalid."
  }}
end

if watches[watchKey] then
  return {{
    success = false,
    virtual_address = watchKey,
    physical_address = string.format("0x%X", phys),
    error = "Already watching this address. Call stop_dbvm_watch first."
  }}
end

local options = 1 + 2 + 8
local okWatch, watchId
if mode == "x" then
  if not dbvm_watch_executes then
    return {{
      success = false,
      virtual_address = watchKey,
      physical_address = string.format("0x%X", phys),
      error = "dbvm_watch_executes function missing from CE Lua engine"
    }}
  end
  okWatch, watchId = pcall(dbvm_watch_executes, phys, 1, options, maxEntries)
elseif mode == "r" or mode == "rw" then
  okWatch, watchId = pcall(dbvm_watch_reads, phys, 1, options, maxEntries)
else
  okWatch, watchId = pcall(dbvm_watch_writes, phys, 1, options, maxEntries)
end

if not okWatch then
  return {{
    success = false,
    virtual_address = watchKey,
    physical_address = string.format("0x%X", phys),
    error = "DBVM watch CRASHED/FAILED: " .. tostring(watchId)
  }}
end

if not watchId then
  return {{
    success = false,
    virtual_address = watchKey,
    physical_address = string.format("0x%X", phys),
    error = "DBVM watch returned nil (check CE console for details)"
  }}
end

watches[watchKey] = {{
  id = watchId,
  physical = phys,
  mode = mode,
  start_time = os.time()
}}

return {{
  success = true,
  status = "monitoring",
  virtual_address = watchKey,
  physical_address = string.format("0x%X", phys),
  watch_id = watchId,
  mode = mode,
  note = "Call poll_dbvm_watch to get logs without stopping, or stop_dbvm_watch to end"
}}
"#,
        address, mode_lua, max_entries
    );

    execute_structured_snippet(code.as_str())
}

fn poll_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let max_results = params
        .get("max_results")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(1000)
        .clamp(1, 10_000);

    let code = format!(
        r#"
local addr = {}
local maxResults = {}
_G.__ce_plugin_dbvm_watches = _G.__ce_plugin_dbvm_watches or {{}}
local watches = _G.__ce_plugin_dbvm_watches
local watchKey = string.format("0x%X", addr)
local watchInfo = watches[watchKey]

if not watchInfo then
  return {{
    success = false,
    virtual_address = watchKey,
    error = "No active watch found for this address. Call start_dbvm_watch first."
  }}
end

local okLog, log = pcall(dbvm_watch_retrievelog, watchInfo.id)
local results = {{}}
if okLog and log then
  local count = math.min(#log, maxResults)
  for i = 1, count do
    local entry = log[i]
    results[#results + 1] = {{
      hit_number = i,
      ESP = entry.RSP and (entry.RSP % 0x100000000) or nil,
      RSP = entry.RSP and string.format("0x%X", entry.RSP) or nil,
      EIP = entry.RIP and (entry.RIP % 0x100000000) or nil,
      RIP = entry.RIP and string.format("0x%X", entry.RIP) or nil,
      EAX = entry.RAX and (entry.RAX % 0x100000000) or nil,
      ECX = entry.RCX and (entry.RCX % 0x100000000) or nil,
      EDX = entry.RDX and (entry.RDX % 0x100000000) or nil,
      EBX = entry.RBX and (entry.RBX % 0x100000000) or nil,
      ESI = entry.RSI and (entry.RSI % 0x100000000) or nil,
      EDI = entry.RDI and (entry.RDI % 0x100000000) or nil
    }}
  end
end

return {{
  success = true,
  status = "active",
  virtual_address = watchKey,
  physical_address = string.format("0x%X", watchInfo.physical),
  mode = watchInfo.mode,
  uptime_seconds = os.time() - (watchInfo.start_time or os.time()),
  hit_count = #results,
  hits = results,
  note = "Watch still active. Call again to get more logs, or stop_dbvm_watch to end."
}}
"#,
        address, max_results
    );

    execute_structured_snippet(code.as_str())
}

fn stop_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    let code = format!(
        r#"
local addr = {}
_G.__ce_plugin_dbvm_watches = _G.__ce_plugin_dbvm_watches or {{}}
local watches = _G.__ce_plugin_dbvm_watches
local watchKey = string.format("0x%X", addr)
local watchInfo = watches[watchKey]

if not watchInfo then
  return {{
    success = false,
    virtual_address = watchKey,
    error = "No active watch found for this address"
  }}
end

local okLog, log = pcall(dbvm_watch_retrievelog, watchInfo.id)
local results = {{}}
if okLog and log then
  for i, entry in ipairs(log) do
    local instruction = "???"
    if entry.RIP then
      local okDis, text = pcall(disassemble, entry.RIP)
      if okDis and text then
        instruction = text
      end
    end
    results[#results + 1] = {{
      hit_number = i,
      instruction_address = entry.RIP and string.format("0x%X", entry.RIP) or nil,
      instruction = instruction,
      registers = {{
        RAX = entry.RAX and string.format("0x%X", entry.RAX) or nil,
        RBX = entry.RBX and string.format("0x%X", entry.RBX) or nil,
        RCX = entry.RCX and string.format("0x%X", entry.RCX) or nil,
        RDX = entry.RDX and string.format("0x%X", entry.RDX) or nil,
        RSI = entry.RSI and string.format("0x%X", entry.RSI) or nil,
        RDI = entry.RDI and string.format("0x%X", entry.RDI) or nil,
        RBP = entry.RBP and string.format("0x%X", entry.RBP) or nil,
        RSP = entry.RSP and string.format("0x%X", entry.RSP) or nil,
        RIP = entry.RIP and string.format("0x%X", entry.RIP) or nil
      }}
    }}
  end
end

pcall(dbvm_watch_disable, watchInfo.id)
watches[watchKey] = nil

return {{
  success = true,
  virtual_address = watchKey,
  physical_address = string.format("0x%X", watchInfo.physical),
  mode = watchInfo.mode,
  hit_count = #results,
  duration_seconds = os.time() - (watchInfo.start_time or os.time()),
  hits = results,
  note = (#results > 0) and "Found instructions that accessed the memory" or "No accesses detected during monitoring"
}}
"#,
        address
    );

    execute_structured_snippet(code.as_str())
}

fn parse_breakpoint_address(value: Option<&Value>) -> Result<AddressParam, String> {
    let Some(value) = value else {
        return Err("missing address".to_owned());
    };

    if value.is_number() {
        return util::parse_address(Some(value)).map(AddressParam::Numeric);
    }

    let Some(text) = value.as_str() else {
        return Err("address must be a string or number".to_owned());
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("missing address".to_owned());
    }

    match util::parse_address(Some(value)) {
        Ok(address) => Ok(AddressParam::Numeric(address)),
        Err(_) => Ok(AddressParam::Expression(trimmed.to_owned())),
    }
}

fn parse_optional_id(value: Option<&Value>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        Value::Null => Ok(None),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_owned()))
            }
        }
        Value::Number(number) => Ok(Some(number.to_string())),
        Value::Bool(flag) => Ok(Some(flag.to_string())),
        _ => Err("id must be a string, number, boolean, or null".to_owned()),
    }
}

fn require_id(value: Option<&Value>) -> Result<String, String> {
    parse_optional_id(value)?.ok_or_else(|| "missing id".to_owned())
}

fn build_address_binding(address: &AddressParam) -> String {
    match address {
        AddressParam::Numeric(address) => format!("local addr = {}\n", address),
        AddressParam::Expression(expression) => format!(
            "local rawAddr = {}\nlocal addr = getAddressSafe(rawAddr)\n",
            json_string(expression.as_str())
        ),
    }
}

fn lua_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn lua_string_or_nil(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "nil".to_owned())
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

fn merge_structured_body(body: Value) -> Value {
    let mut response = Map::new();

    if let Some(object) = body.as_object() {
        if let Some(engine) = object.get("engine") {
            response.insert("engine".to_owned(), engine.clone());
        }
        if let Some(lua_module) = object.get("lua_module") {
            response.insert("lua_module".to_owned(), lua_module.clone());
        }
        if let Some(Value::Object(structured)) = object.get("structured_result") {
            for (key, value) in structured {
                response.insert(key.clone(), value.clone());
            }
        }
    }

    if response.is_empty() {
        return body;
    }

    Value::Object(response)
}

fn execute_debug_snippet(code: &str) -> ToolResponse {
    match script::execute_lua_snippet(code, true) {
        Ok(body) => ToolResponse {
            success: true,
            body_json: merge_structured_body(body).to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn execute_structured_snippet(code: &str) -> ToolResponse {
    match script::execute_lua_snippet(code, true) {
        Ok(body) => ToolResponse {
            success: true,
            body_json: merge_structured_body(body).to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
