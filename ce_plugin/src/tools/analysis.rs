use core::ffi::c_void;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, Mnemonic};
use serde_json::{json, Value};

use super::{addressing, util, ToolResponse};
use crate::runtime;

const METHODS: &[&str] = &[
    "disassemble",
    "get_instruction_info",
    "find_function_boundaries",
    "analyze_function",
    "find_references",
    "find_call_references",
    "dissect_structure",
];
const MAX_DISASSEMBLY_COUNT: usize = 256;
const MAX_DISASSEMBLY_BYTES: usize = 4096;
const MAX_INSTRUCTION_BYTES: usize = 15;

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
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let count = parse_usize(params.get("count"), 20, MAX_DISASSEMBLY_COUNT);
    let bytes_to_read = count
        .saturating_mul(MAX_INSTRUCTION_BYTES)
        .min(MAX_DISASSEMBLY_BYTES)
        .max(MAX_INSTRUCTION_BYTES);

    let bytes = match runtime::read_process_memory(handle, address, bytes_to_read) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    let modules = current_modules();
    let instructions = decode_instructions(address, &bytes, count, &modules);
    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "address": util::format_address(address),
            "normalized_address": addressing::normalize_address_from_modules(address, &modules),
            "count": instructions.len(),
            "instructions": instructions,
        })
        .to_string(),
    }
}

fn get_instruction_info(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    let bytes = match runtime::read_process_memory(handle, address, MAX_INSTRUCTION_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    let modules = current_modules();
    let instruction = match decode_one_instruction(address, &bytes, &modules) {
        Ok(instruction) => instruction,
        Err(error) => return error_response(error),
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "address": util::format_address(address),
            "normalized_address": addressing::normalize_address_from_modules(address, &modules),
            "instruction": instruction,
        })
        .to_string(),
    }
}

fn find_function_boundaries(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let max_search = parse_usize(params.get("max_search"), 4096, 0x20_000);

    match locate_function_boundaries(handle, address, max_search) {
        Ok(boundary) => {
            let modules = current_modules();
            ToolResponse {
                success: true,
                body_json: json!({
                    "success": true,
                    "found": true,
                    "query_address": util::format_address(address),
                    "query_normalized_address": addressing::normalize_address_from_modules(address, &modules),
                    "function_start": util::format_address(boundary.start),
                    "function_start_normalized": addressing::normalize_address_from_modules(boundary.start, &modules),
                    "function_end": boundary.end.map(util::format_address),
                    "function_end_normalized": boundary.end.and_then(|end| addressing::normalize_address_from_modules(end, &modules)),
                    "function_size": boundary.end.map(|end| end.saturating_sub(boundary.start).saturating_add(1)),
                    "prologue_type": boundary.prologue_type,
                    "arch": "x64",
                    "note": boundary.note,
                })
                .to_string(),
            }
        }
        Err(error) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "found": false,
                "query_address": util::format_address(address),
                "arch": "x64",
                "note": error,
            })
            .to_string(),
        },
    }
}

fn analyze_function(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    let boundary = match locate_function_boundaries(handle, address, 4096) {
        Ok(boundary) => boundary,
        Err(error) => return error_response(error),
    };
    let end = boundary
        .end
        .unwrap_or_else(|| boundary.start.saturating_add(MAX_DISASSEMBLY_BYTES));
    let byte_len = end
        .saturating_sub(boundary.start)
        .saturating_add(1)
        .min(MAX_DISASSEMBLY_BYTES);
    let bytes = match runtime::read_process_memory(
        handle,
        boundary.start,
        byte_len.max(MAX_INSTRUCTION_BYTES),
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    let modules = current_modules();
    let decoded = decode_instruction_records(boundary.start, &bytes, MAX_DISASSEMBLY_COUNT);
    let mut calls = Vec::new();
    for record in &decoded {
        if flow_control_is_call(record.instruction.flow_control()) {
            calls.push(json!({
                "call_site": util::format_address(record.address),
                "call_site_normalized": addressing::normalize_address_from_modules(record.address, &modules),
                "instruction": record.text,
                "target": record.branch_target.map(util::format_address),
                "target_normalized": record.branch_target.and_then(|target| addressing::normalize_address_from_modules(target, &modules)),
                "type": if record.branch_target.is_some() { "direct" } else { "indirect" },
            }));
        }
    }

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "function_start": util::format_address(boundary.start),
            "function_start_normalized": addressing::normalize_address_from_modules(boundary.start, &modules),
            "function_end": boundary.end.map(util::format_address),
            "function_end_normalized": boundary.end.and_then(|end| addressing::normalize_address_from_modules(end, &modules)),
            "prologue_type": boundary.prologue_type,
            "arch": "x64",
            "instruction_count": decoded.len(),
            "call_count": calls.len(),
            "calls": calls,
            "note": boundary.note,
        })
        .to_string(),
    }
}

fn find_references(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let target = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let limit = parse_usize(params.get("limit"), 50, 500);

    let modules = current_modules();
    let references = match collect_references(handle, target, limit, false, &modules) {
        Ok(references) => references,
        Err(error) => return error_response(error),
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "target": util::format_address(target),
            "target_normalized": addressing::normalize_address_from_modules(target, &modules),
            "count": references.len(),
            "references": references,
            "arch": "x64",
            "note": "native reference scan currently covers direct branch targets and RIP-relative memory references in executable regions",
        })
        .to_string(),
    }
}

fn find_call_references(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let target = match util::parse_address(
        params
            .get("function_address")
            .or_else(|| params.get("address")),
    ) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let limit = parse_usize(params.get("limit"), 100, 1000);

    let modules = current_modules();
    let callers = match collect_references(handle, target, limit, true, &modules) {
        Ok(references) => references,
        Err(error) => return error_response(error),
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "function_address": util::format_address(target),
            "function_address_normalized": addressing::normalize_address_from_modules(target, &modules),
            "count": callers.len(),
            "callers": callers,
            "arch": "x64",
        })
        .to_string(),
    }
}

fn dissect_structure(params_json: &str) -> ToolResponse {
    let Some(app) = runtime::app_state() else {
        return runtime_unavailable("runtime not initialized");
    };
    let Some(handle) = app.opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let size = parse_usize(params.get("size"), 256, 2048);

    let bytes = match runtime::read_process_memory(handle, address, size) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };
    let process_id = app.opened_process_id().unwrap_or(0);
    let modules = if process_id != 0 {
        runtime::enum_modules(process_id).unwrap_or_default()
    } else {
        Vec::new()
    };
    let regions = runtime::enum_memory_regions(handle, None).unwrap_or_default();

    let mut elements = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if let Some((byte_len, value)) = detect_ascii_string(&bytes[offset..]) {
            elements.push(json!({
                "offset": offset,
                "hex_offset": format!("+0x{:X}", offset),
                "name": format!("field_{:04X}", offset),
                "vartype": "ascii_string",
                "bytesize": byte_len,
                "current_value": value,
                "confidence": "medium",
            }));
            offset = offset.saturating_add(align_up(byte_len, 4));
            continue;
        }

        if let Some((byte_len, value)) = detect_utf16_string(&bytes[offset..]) {
            elements.push(json!({
                "offset": offset,
                "hex_offset": format!("+0x{:X}", offset),
                "name": format!("field_{:04X}", offset),
                "vartype": "utf16_string",
                "bytesize": byte_len,
                "current_value": value,
                "confidence": "medium",
            }));
            offset = offset.saturating_add(align_up(byte_len, 4));
            continue;
        }

        if offset % 8 == 0 && offset + 8 <= bytes.len() {
            let pointer =
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8])) as usize;
            if let Some(pointer_info) = describe_pointer(pointer, &modules, &regions) {
                elements.push(json!({
                    "offset": offset,
                    "hex_offset": format!("+0x{:X}", offset),
                    "name": format!("field_{:04X}", offset),
                    "vartype": "pointer",
                    "bytesize": 8,
                    "current_value": util::format_address(pointer),
                    "target": pointer_info,
                    "confidence": "high",
                }));
                offset = offset.saturating_add(8);
                continue;
            }
        }

        if offset + 4 <= bytes.len() {
            let raw = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]));
            let float = f32::from_le_bytes(raw.to_le_bytes());
            let (vartype, current_value, confidence) = if looks_reasonable_float(float) {
                ("float", json!(float), "low")
            } else {
                ("dword", json!(raw), "low")
            };
            elements.push(json!({
                "offset": offset,
                "hex_offset": format!("+0x{:X}", offset),
                "name": format!("field_{:04X}", offset),
                "vartype": vartype,
                "bytesize": 4,
                "current_value": current_value,
                "confidence": confidence,
            }));
            offset = offset.saturating_add(4);
            continue;
        }

        elements.push(json!({
            "offset": offset,
            "hex_offset": format!("+0x{:X}", offset),
            "name": format!("field_{:04X}", offset),
            "vartype": "byte",
            "bytesize": 1,
            "current_value": bytes[offset],
            "confidence": "low",
        }));
        offset += 1;
    }

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "base_address": util::format_address(address),
            "size_analyzed": bytes.len(),
            "element_count": elements.len(),
            "elements": elements,
            "resolver": "native_heuristic",
            "note": "heuristic structure inference from readable memory; not CE autoGuess parity",
        })
        .to_string(),
    }
}

fn decode_instructions(
    address: usize,
    bytes: &[u8],
    count: usize,
    modules: &[runtime::ModuleInfo],
) -> Vec<Value> {
    decode_instruction_records(address, bytes, count)
        .into_iter()
        .map(|record| {
            json!({
                "address": util::format_address(record.address),
                "normalized_address": addressing::normalize_address_from_modules(record.address, modules),
                "bytes": record.bytes_text,
                "text": record.text,
                "mnemonic": format_mnemonic(record.instruction.mnemonic()),
                "length": record.instruction.len(),
                "next_address": util::format_address(record.instruction.next_ip() as usize),
                "next_address_normalized": addressing::normalize_address_from_modules(record.instruction.next_ip() as usize, modules),
            })
        })
        .collect()
}

fn decode_one_instruction(
    address: usize,
    bytes: &[u8],
    modules: &[runtime::ModuleInfo],
) -> Result<Value, String> {
    let record = decode_instruction_records(address, bytes, 1)
        .into_iter()
        .next()
        .ok_or_else(|| format!("invalid instruction at {}", util::format_address(address)))?;

    Ok(json!({
        "address": util::format_address(address),
        "normalized_address": addressing::normalize_address_from_modules(address, modules),
        "bytes": record.bytes_text,
        "text": record.text,
        "mnemonic": format_mnemonic(record.instruction.mnemonic()),
        "length": record.instruction.len() as usize,
        "next_address": util::format_address(record.instruction.next_ip() as usize),
        "next_address_normalized": addressing::normalize_address_from_modules(record.instruction.next_ip() as usize, modules),
        "op_count": record.instruction.op_count(),
        "is_invalid": false,
        "is_stack_instruction": record.instruction.is_stack_instruction(),
        "flow_control": format!("{:?}", record.instruction.flow_control()).to_ascii_lowercase(),
        "near_branch_target": record.branch_target.map(util::format_address),
        "near_branch_target_normalized": record.branch_target.and_then(|target| addressing::normalize_address_from_modules(target, modules)),
        "is_ip_rel_memory_operand": record.instruction.is_ip_rel_memory_operand(),
        "ip_rel_memory_address": record
            .instruction
            .is_ip_rel_memory_operand()
            .then(|| util::format_address(record.instruction.ip_rel_memory_address() as usize)),
    }))
}

#[derive(Clone)]
struct DecodedRecord {
    address: usize,
    instruction: iced_x86::Instruction,
    text: String,
    bytes_text: String,
    branch_target: Option<usize>,
}

#[derive(Clone)]
struct FunctionBoundary {
    start: usize,
    end: Option<usize>,
    prologue_type: &'static str,
    note: Option<String>,
}

fn decode_instruction_records(address: usize, bytes: &[u8], count: usize) -> Vec<DecodedRecord> {
    let mut decoder = Decoder::with_ip(64, bytes, address as u64, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut records = Vec::new();

    while decoder.can_decode() && records.len() < count {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }

        let start = instruction.ip().saturating_sub(address as u64) as usize;
        let len = instruction.len() as usize;
        let end = start.saturating_add(len).min(bytes.len());
        let instr_bytes = &bytes[start..end];
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let branch_target = if flow_control_has_branch_target(instruction.flow_control()) {
            Some(instruction.near_branch_target() as usize)
        } else {
            None
        };

        records.push(DecodedRecord {
            address: instruction.ip() as usize,
            instruction,
            text,
            bytes_text: format_instruction_bytes(instr_bytes),
            branch_target,
        });
    }

    records
}

fn locate_function_boundaries(
    handle: *mut c_void,
    address: usize,
    max_search: usize,
) -> Result<FunctionBoundary, String> {
    let start = find_function_start(handle, address, max_search)
        .ok_or_else(|| "No standard function prologue found within search range".to_owned())?;
    let end = find_function_end(handle, start.0, max_search);
    Ok(FunctionBoundary {
        start: start.0,
        end,
        prologue_type: start.1,
        note: end
            .is_none()
            .then(|| "Function end not found within search range".to_owned()),
    })
}

fn find_function_start(
    handle: *mut c_void,
    address: usize,
    max_search: usize,
) -> Option<(usize, &'static str)> {
    let search_start = address.saturating_sub(max_search);
    let span = address.saturating_sub(search_start).saturating_add(4);
    let bytes = runtime::read_process_memory(handle, search_start, span).ok()?;

    for offset in (0..=address.saturating_sub(search_start)).rev() {
        let idx = offset;
        let b1 = *bytes.get(idx)?;
        let b2 = *bytes.get(idx + 1).unwrap_or(&0);
        let b3 = *bytes.get(idx + 2).unwrap_or(&0);
        let b4 = *bytes.get(idx + 3).unwrap_or(&0);

        if b1 == 0x55 && b2 == 0x48 && b3 == 0x89 && b4 == 0xE5 {
            return Some((search_start + idx, "x64_standard"));
        }
        if b1 == 0x48 && b2 == 0x83 && b3 == 0xEC {
            return Some((search_start + idx, "x64_leaf"));
        }
        if b1 == 0x40 && b2 == 0x53 && b3 == 0x48 && b4 == 0x83 {
            return Some((search_start + idx, "x64_nonleaf"));
        }
    }

    None
}

fn find_function_end(handle: *mut c_void, start: usize, max_search: usize) -> Option<usize> {
    let bytes = runtime::read_process_memory(handle, start, max_search).ok()?;
    let decoded = decode_instruction_records(start, &bytes, MAX_DISASSEMBLY_COUNT);
    for record in decoded {
        if matches!(
            record.instruction.mnemonic(),
            Mnemonic::Ret | Mnemonic::Retf
        ) {
            return Some(
                record
                    .address
                    .saturating_add(record.instruction.len() as usize)
                    .saturating_sub(1),
            );
        }
    }
    None
}

fn collect_references(
    handle: *mut c_void,
    target: usize,
    limit: usize,
    calls_only: bool,
    modules: &[runtime::ModuleInfo],
) -> Result<Vec<Value>, String> {
    let regions = runtime::enum_memory_regions(handle, None)?;
    let mut results = Vec::new();

    for region in regions {
        if results.len() >= limit {
            break;
        }
        if !runtime::is_region_usable(&region) || !runtime::is_region_executable(&region) {
            continue;
        }
        let bytes_to_read = region.region_size.min(MAX_DISASSEMBLY_BYTES * 16);
        let bytes = match runtime::read_process_memory(handle, region.base_address, bytes_to_read) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        for record in
            decode_instruction_records(region.base_address, &bytes, MAX_DISASSEMBLY_COUNT * 16)
        {
            if results.len() >= limit {
                break;
            }
            if instruction_references_target(&record, target, calls_only) {
                results.push(json!({
                    if calls_only { "caller_address" } else { "address" }: util::format_address(record.address),
                    if calls_only { "caller_address_normalized" } else { "normalized_address" }: addressing::normalize_address_from_modules(record.address, modules),
                    "instruction": record.text,
                    "target": record.branch_target.map(util::format_address),
                    "target_normalized": record.branch_target.and_then(|target| addressing::normalize_address_from_modules(target, modules)),
                }));
            }
        }
    }

    Ok(results)
}

fn instruction_references_target(record: &DecodedRecord, target: usize, calls_only: bool) -> bool {
    let instruction = &record.instruction;
    if calls_only {
        return flow_control_is_call(instruction.flow_control())
            && record.branch_target == Some(target);
    }

    if record.branch_target == Some(target) {
        return true;
    }
    if instruction.is_ip_rel_memory_operand()
        && instruction.ip_rel_memory_address() as usize == target
    {
        return true;
    }

    false
}

fn detect_ascii_string(bytes: &[u8]) -> Option<(usize, String)> {
    let mut out = Vec::new();
    for byte in bytes.iter().take(64).copied() {
        if byte == 0 {
            break;
        }
        if !(byte == b' ' || byte.is_ascii_graphic()) {
            break;
        }
        out.push(byte);
    }
    if out.len() < 4 {
        return None;
    }
    Some((
        out.len().saturating_add(1),
        String::from_utf8_lossy(&out).to_string(),
    ))
}

fn detect_utf16_string(bytes: &[u8]) -> Option<(usize, String)> {
    let mut words = Vec::new();
    for chunk in bytes.chunks_exact(2).take(32) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        if word > 0x7E || word < 0x20 {
            break;
        }
        words.push(word);
    }
    if words.len() < 4 {
        return None;
    }
    Some((
        words.len().saturating_mul(2).saturating_add(2),
        String::from_utf16_lossy(&words),
    ))
}

fn describe_pointer(
    pointer: usize,
    modules: &[runtime::ModuleInfo],
    regions: &[runtime::MemoryRegionInfo],
) -> Option<Value> {
    if pointer == 0 {
        return None;
    }
    if let Some(module) = modules.iter().find(|module| {
        let start = module.base_address;
        let end = start.saturating_add(module.size as usize);
        start <= pointer && pointer < end
    }) {
        return Some(json!({
            "kind": "module",
            "module_name": module.name,
            "module_base": util::format_address(module.base_address),
            "offset": pointer.saturating_sub(module.base_address),
        }));
    }

    let region = regions.iter().find(|region| {
        let start = region.base_address;
        let end = start.saturating_add(region.region_size);
        start <= pointer && pointer < end && runtime::is_region_readable(region)
    })?;

    Some(json!({
        "kind": "memory",
        "base": util::format_address(region.base_address),
        "offset": pointer.saturating_sub(region.base_address),
        "protection": runtime::protection_to_string(region.protect),
    }))
}

fn looks_reasonable_float(value: f32) -> bool {
    value.is_finite() && value.abs() >= 0.0001 && value.abs() <= 1.0e9
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn format_instruction_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(" ")
}

fn flow_control_is_call(flow: FlowControl) -> bool {
    matches!(flow, FlowControl::Call | FlowControl::IndirectCall)
}

fn flow_control_has_branch_target(flow: FlowControl) -> bool {
    matches!(
        flow,
        FlowControl::Call
            | FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::XbeginXabortXend
    )
}

fn format_mnemonic(mnemonic: Mnemonic) -> String {
    format!("{:?}", mnemonic).to_ascii_lowercase()
}

fn parse_usize(value: Option<&Value>, default: usize, max: usize) -> usize {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
        .min(max)
}

fn opened_process_handle() -> Option<*mut c_void> {
    runtime::app_state().and_then(|app| app.opened_process_handle())
}

fn current_modules() -> Vec<runtime::ModuleInfo> {
    let Some(app) = runtime::app_state() else {
        return Vec::new();
    };

    let process_id = app.opened_process_id().unwrap_or(0);
    if process_id == 0 {
        return Vec::new();
    }

    runtime::enum_modules(process_id).unwrap_or_default()
}

fn runtime_unavailable(message: &str) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message.to_owned(),
    }
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
