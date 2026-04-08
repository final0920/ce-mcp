use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::{addressing, lua_backend, process, script, util, ToolResponse};
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
    lua_backend::call_lua_tool("set_breakpoint", params_json)
}

fn set_data_breakpoint(params_json: &str) -> ToolResponse {
    lua_backend::call_lua_tool("set_data_breakpoint", params_json)
}

fn remove_breakpoint(params_json: &str) -> ToolResponse {
    lua_backend::call_lua_tool("remove_breakpoint", params_json)
}

fn list_breakpoints(params_json: &str) -> ToolResponse {
    lua_backend::call_lua_tool("list_breakpoints", params_json)
}

fn clear_all_breakpoints(params_json: &str) -> ToolResponse {
    lua_backend::call_lua_tool("clear_all_breakpoints", params_json)
}

fn get_breakpoint_hits(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);

    enrich_breakpoint_hits_response(
        lua_backend::call_lua_tool("get_breakpoint_hits", params_json),
        &ctx,
    )
}

fn get_physical_address(params_json: &str) -> ToolResponse {
    lua_backend::call_lua_tool("get_physical_address", params_json)
}

fn start_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);

    enrich_dbvm_watch_start_response(
        lua_backend::call_lua_tool("start_dbvm_watch", params_json),
        &ctx,
    )
}

fn poll_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);

    enrich_dbvm_watch_hits_response(
        lua_backend::call_lua_tool("poll_dbvm_watch", params_json),
        &ctx,
        "poll",
    )
}

fn stop_dbvm_watch(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let ctx = util::parse_request_context(&params);

    enrich_dbvm_watch_hits_response(
        lua_backend::call_lua_tool("stop_dbvm_watch", params_json),
        &ctx,
        "stop",
    )
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
