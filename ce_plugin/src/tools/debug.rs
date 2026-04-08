use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::{addressing, lua_backend, process, util, ToolResponse};
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
