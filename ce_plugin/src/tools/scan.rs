use core::ffi::c_void;
use std::collections::HashSet;

use serde_json::{json, Value};

use super::{util, ToolResponse};
use crate::runtime;

const METHODS: &[&str] = &[
    "scan_all",
    "get_scan_results",
    "next_scan",
    "aob_scan",
    "search_string",
    "generate_signature",
    "get_memory_regions",
    "enum_memory_regions_full",
    "checksum_memory",
];
const DEFAULT_REGION_MAX: usize = 100;
const DEFAULT_FULL_REGION_MAX: usize = 500;
const DEFAULT_SCAN_LIMIT: usize = 100;
const DEFAULT_SCAN_RESULTS_MAX: usize = 100;
const MAX_SCAN_LIMIT: usize = 10_000;
const MAX_SESSION_RESULTS: usize = 250_000;
const CHUNK_SIZE: usize = 64 * 1024;

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "scan_all" => scan_all(params_json),
        "get_scan_results" => get_scan_results(params_json),
        "next_scan" => next_scan(params_json),
        "get_memory_regions" => get_memory_regions(params_json),
        "enum_memory_regions_full" => enum_memory_regions_full(params_json),
        "checksum_memory" => checksum_memory(params_json),
        "aob_scan" => aob_scan(params_json),
        "search_string" => search_string(params_json),
        "generate_signature" => generate_signature(params_json),
        _ => return None,
    };
    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn scan_all(params_json: &str) -> ToolResponse {
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
    let Some(raw_value) = params.get("value") else {
        return error_response("missing value".to_owned());
    };
    let value_type = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("dword");
    let prepared = match prepare_scan_value(value_type, raw_value) {
        Ok(prepared) => prepared,
        Err(error) => return error_response(error),
    };
    let protection = params
        .get("protection")
        .and_then(Value::as_str)
        .unwrap_or("+W-C");

    let addresses = match scan_pattern(
        handle,
        &prepared.pattern,
        Some(protection),
        MAX_SESSION_RESULTS + 1,
    ) {
        Ok(addresses) => addresses,
        Err(error) => return error_response(error),
    };

    let truncated = addresses.len() > MAX_SESSION_RESULTS;
    let mut entries = Vec::with_capacity(addresses.len().min(MAX_SESSION_RESULTS));
    for address in addresses.into_iter().take(MAX_SESSION_RESULTS) {
        let value_bytes = match runtime::read_process_memory(handle, address, prepared.byte_len) {
            Ok(bytes) if bytes.len() == prepared.byte_len => bytes,
            _ => continue,
        };
        entries.push(runtime::ScanEntry {
            address,
            value_bytes,
        });
    }

    let count = entries.len();
    if let Err(error) = app.with_scan_session(|session| {
        *session = Some(runtime::ScanSession {
            kind: prepared.kind,
            entries,
        });
        Ok(())
    }) {
        return error_response(error);
    }

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": count,
            "type": prepared.kind.label(),
            "truncated": truncated,
            "limit": MAX_SESSION_RESULTS,
        })
        .to_string(),
    }
}

fn get_scan_results(params_json: &str) -> ToolResponse {
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
    let max = parse_usize(
        params.get("max"),
        DEFAULT_SCAN_RESULTS_MAX,
        MAX_SESSION_RESULTS,
    );

    let (kind, entries, total) = match app.with_scan_session(|session| {
        let Some(session) = session.as_ref() else {
            return Err("No scan results. Run scan_all first.".to_owned());
        };
        Ok((
            session.kind,
            session
                .entries
                .iter()
                .take(max)
                .cloned()
                .collect::<Vec<_>>(),
            session.entries.len(),
        ))
    }) {
        Ok(snapshot) => snapshot,
        Err(error) => return error_response(error),
    };

    let results = entries
        .into_iter()
        .map(|entry| {
            let current_bytes =
                runtime::read_process_memory(handle, entry.address, entry.value_bytes.len())
                    .ok()
                    .filter(|bytes| bytes.len() == entry.value_bytes.len())
                    .unwrap_or(entry.value_bytes);
            json!({
                "address": util::format_address(entry.address),
                "value": bytes_to_json(kind, &current_bytes),
            })
        })
        .collect::<Vec<_>>();

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "results": results,
            "total": total,
            "returned": results.len(),
        })
        .to_string(),
    }
}

fn next_scan(params_json: &str) -> ToolResponse {
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
    let scan_type = match parse_next_scan_type(
        params
            .get("scan_type")
            .and_then(Value::as_str)
            .unwrap_or("exact"),
    ) {
        Ok(scan_type) => scan_type,
        Err(error) => return error_response(error),
    };

    let count = match app.with_scan_session(|session| {
        let Some(session) = session.as_mut() else {
            return Err("No previous scan. Run scan_all first.".to_owned());
        };

        if scan_type.requires_numeric_ordering() && !session.kind.supports_numeric_ordering() {
            return Err(format!(
                "scan_type {} is only supported for numeric scan types",
                scan_type.label()
            ));
        }

        let comparison_target = if scan_type.requires_target_value() {
            let Some(value) = params.get("value") else {
                return Err("missing value".to_owned());
            };
            Some(prepare_value_for_kind(session.kind, value)?)
        } else {
            None
        };

        let mut next_entries = Vec::with_capacity(session.entries.len());
        for mut entry in session.entries.drain(..) {
            let current_bytes = match runtime::read_process_memory(
                handle,
                entry.address,
                entry.value_bytes.len(),
            ) {
                Ok(bytes) if bytes.len() == entry.value_bytes.len() => bytes,
                _ => continue,
            };

            let keep = match scan_type {
                NextScanType::Exact => {
                    let target = comparison_target
                        .as_ref()
                        .ok_or_else(|| "missing value".to_owned())?;
                    if session.kind == runtime::ScanValueKind::Array {
                        match target.pattern.as_ref() {
                            Some(pattern) if pattern.len() == current_bytes.len() => {
                                pattern_matches(&current_bytes, pattern)
                            }
                            Some(_) => false,
                            None => current_bytes == target.bytes,
                        }
                    } else {
                        current_bytes == target.bytes
                    }
                }
                NextScanType::Changed => current_bytes != entry.value_bytes,
                NextScanType::Unchanged => current_bytes == entry.value_bytes,
                NextScanType::Increased | NextScanType::Decreased => compare_numeric(
                    session.kind,
                    &current_bytes,
                    &entry.value_bytes,
                    None,
                    scan_type,
                )?,
                NextScanType::Bigger | NextScanType::Smaller => {
                    let target = comparison_target
                        .as_ref()
                        .ok_or_else(|| "missing value".to_owned())?;
                    compare_numeric(
                        session.kind,
                        &current_bytes,
                        &entry.value_bytes,
                        Some(target),
                        scan_type,
                    )?
                }
            };

            if keep {
                entry.value_bytes = current_bytes;
                next_entries.push(entry);
            }
        }

        let count = next_entries.len();
        session.entries = next_entries;
        Ok(count)
    }) {
        Ok(count) => count,
        Err(error) => return error_response(error),
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": count,
        })
        .to_string(),
    }
}

fn get_memory_regions(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let max = parse_usize(
        params.get("max"),
        DEFAULT_REGION_MAX,
        DEFAULT_FULL_REGION_MAX,
    );

    let regions = match runtime::enum_memory_regions(handle, None) {
        Ok(regions) => regions,
        Err(error) => return error_response(error),
    };

    let anchors: [usize; 9] = [
        0x0001_0000,
        0x0040_0000,
        0x1000_0000,
        0x2000_0000,
        0x3000_0000,
        0x4000_0000,
        0x5000_0000,
        0x6000_0000,
        0x7000_0000,
    ];

    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let usable = regions
        .iter()
        .filter(|region| runtime::is_region_usable(region))
        .filter(|region| region.base_address != 0)
        .collect::<Vec<_>>();

    for anchor in anchors {
        if result.len() >= max {
            break;
        }
        let candidate = usable.iter().find(|region| {
            let end = region.base_address.saturating_add(region.region_size);
            region.base_address <= anchor && anchor < end
        });
        if let Some(region) = candidate {
            if seen.insert(region.base_address) {
                result.push(json!({
                    "base": util::format_address(region.base_address),
                    "size": region.region_size,
                    "protection": runtime::protection_to_string(region.protect),
                    "readable": runtime::is_region_readable(region),
                    "writable": runtime::is_region_writable(region),
                    "executable": runtime::is_region_executable(region),
                }));
            }
        }
    }

    for region in usable {
        if result.len() >= max {
            break;
        }
        if seen.insert(region.base_address) {
            result.push(json!({
                "base": util::format_address(region.base_address),
                "size": region.region_size,
                "protection": runtime::protection_to_string(region.protect),
                "readable": runtime::is_region_readable(region),
                "writable": runtime::is_region_writable(region),
                "executable": runtime::is_region_executable(region),
            }));
        }
    }

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": result.len(),
            "regions": result,
        })
        .to_string(),
    }
}

fn enum_memory_regions_full(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let max = parse_usize(params.get("max"), DEFAULT_FULL_REGION_MAX, MAX_SCAN_LIMIT);

    let regions = match runtime::enum_memory_regions(handle, Some(max)) {
        Ok(regions) => regions,
        Err(error) => return error_response(error),
    };

    let result = regions
        .into_iter()
        .map(|region| {
            json!({
                "base": util::format_address(region.base_address),
                "allocation_base": util::format_address(region.allocation_base),
                "allocation_protect": region.allocation_protect,
                "size": region.region_size,
                "state": region.state,
                "protect": region.protect,
                "protect_string": runtime::protection_to_string(region.protect),
                "type": region.type_,
                "is_committed": region.state == runtime::MEM_COMMIT,
                "is_reserved": region.state == runtime::MEM_RESERVE,
                "is_free": region.state == runtime::MEM_FREE,
            })
        })
        .collect::<Vec<_>>();

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": result.len(),
            "regions": result,
        })
        .to_string(),
    }
}

fn checksum_memory(params_json: &str) -> ToolResponse {
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
    let size = parse_positive_size(params.get("size"), 256, 1024 * 1024);

    let bytes = match runtime::read_process_memory(handle, address, size) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };
    let digest = md5::compute(bytes);

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "address": util::format_address(address),
            "size": size,
            "md5_hash": format!("{:x}", digest),
        })
        .to_string(),
    }
}

fn aob_scan(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let pattern_text = match params.get("pattern").and_then(Value::as_str) {
        Some(pattern) if !pattern.trim().is_empty() => pattern.trim(),
        _ => return error_response("missing pattern".to_owned()),
    };
    let protection = params
        .get("protection")
        .and_then(Value::as_str)
        .unwrap_or("+X");
    let limit = parse_usize(params.get("limit"), DEFAULT_SCAN_LIMIT, MAX_SCAN_LIMIT);
    let pattern = match parse_aob_pattern(pattern_text) {
        Ok(pattern) => pattern,
        Err(error) => return error_response(error),
    };

    let addresses = match scan_pattern(handle, &pattern, Some(protection), limit) {
        Ok(addresses) => addresses,
        Err(error) => return error_response(error),
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": addresses.len(),
            "pattern": pattern_text,
            "addresses": addresses
                .into_iter()
                .map(|address| json!({
                    "address": util::format_address(address),
                    "value": address,
                }))
                .collect::<Vec<_>>(),
        })
        .to_string(),
    }
}

fn search_string(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let search_text = match params
        .get("string")
        .or_else(|| params.get("pattern"))
        .and_then(Value::as_str)
    {
        Some(text) if !text.is_empty() => text,
        _ => return error_response("No search string".to_owned()),
    };
    let wide = params.get("wide").and_then(Value::as_bool).unwrap_or(false);
    let limit = parse_usize(params.get("limit"), DEFAULT_SCAN_LIMIT, MAX_SCAN_LIMIT);
    let pattern = encode_search_bytes(search_text, wide);

    let addresses = match scan_pattern(handle, &pattern, None, limit) {
        Ok(addresses) => addresses,
        Err(error) => return error_response(error),
    };

    let previews = addresses
        .into_iter()
        .map(|address| {
            json!({
                "address": util::format_address(address),
                "preview": read_preview_string(handle, address, wide),
            })
        })
        .collect::<Vec<_>>();

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": previews.len(),
            "addresses": previews,
        })
        .to_string(),
    }
}

fn generate_signature(params_json: &str) -> ToolResponse {
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

    let bytes = match runtime::read_process_memory(handle, address.saturating_sub(8), 64) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    let mut best: Option<(String, usize, usize)> = None;
    for prefix in 0..=8usize {
        for length in 6..=24usize {
            if prefix.saturating_add(length) > bytes.len() {
                break;
            }

            let slice = &bytes[prefix..prefix + length];
            let pattern = slice.iter().copied().map(Some).collect::<Vec<_>>();
            let matches = match scan_pattern(handle, &pattern, Some("+X"), 2) {
                Ok(matches) => matches,
                Err(_) => continue,
            };

            if matches.len() == 1 {
                let signature = format_instruction_bytes(slice);
                best = Some((signature, prefix, length));
                break;
            }
        }
        if best.is_some() {
            break;
        }
    }

    let Some((signature, offset_from_start, byte_count)) = best else {
        return error_response(
            "Could not generate unique signature - pattern not unique enough".to_owned(),
        );
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "address": util::format_address(address),
            "signature": signature,
            "offset_from_start": offset_from_start,
            "byte_count": byte_count,
            "usage_hint": format!("aob_scan('{}') then add offset {} to reach target", signature, offset_from_start),
            "note": "native signature generation currently uses exact executable-byte windows",
        })
        .to_string(),
    }
}

#[derive(Debug, Clone)]
struct PreparedScan {
    kind: runtime::ScanValueKind,
    byte_len: usize,
    pattern: Vec<Option<u8>>,
}

#[derive(Debug, Clone)]
struct PreparedValue {
    bytes: Vec<u8>,
    pattern: Option<Vec<Option<u8>>>,
}

#[derive(Debug, Clone, Copy)]
enum NextScanType {
    Exact,
    Increased,
    Decreased,
    Changed,
    Unchanged,
    Bigger,
    Smaller,
}

impl NextScanType {
    fn label(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Increased => "increased",
            Self::Decreased => "decreased",
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
            Self::Bigger => "bigger",
            Self::Smaller => "smaller",
        }
    }

    fn requires_target_value(&self) -> bool {
        matches!(self, Self::Exact | Self::Bigger | Self::Smaller)
    }

    fn requires_numeric_ordering(&self) -> bool {
        matches!(
            self,
            Self::Increased | Self::Decreased | Self::Bigger | Self::Smaller
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum ComparableValue {
    Unsigned(u64),
    Float(f64),
}

fn prepare_scan_value(type_name: &str, value: &Value) -> Result<PreparedScan, String> {
    let kind = match type_name {
        "byte" => runtime::ScanValueKind::Byte,
        "word" => runtime::ScanValueKind::Word,
        "dword" => runtime::ScanValueKind::Dword,
        "qword" => runtime::ScanValueKind::Qword,
        "float" => runtime::ScanValueKind::Float,
        "double" => runtime::ScanValueKind::Double,
        "string" => runtime::ScanValueKind::String,
        "array" => runtime::ScanValueKind::Array,
        "exact" => infer_exact_kind(value)?,
        other => return Err(format!("unsupported scan type: {}", other)),
    };

    let prepared = prepare_value_for_kind(kind, value)?;
    let pattern = prepared
        .pattern
        .unwrap_or_else(|| prepared.bytes.into_iter().map(Some).collect::<Vec<_>>());
    let byte_len = pattern.len();
    if byte_len == 0 {
        return Err("pattern is empty".to_owned());
    }

    Ok(PreparedScan {
        kind,
        byte_len,
        pattern,
    })
}

fn prepare_value_for_kind(
    kind: runtime::ScanValueKind,
    value: &Value,
) -> Result<PreparedValue, String> {
    match kind {
        runtime::ScanValueKind::Byte => {
            let number = parse_u64_value(value, "value must be an unsigned integer <= 255")?;
            let byte = u8::try_from(number)
                .map_err(|_| "value must be an unsigned integer <= 255".to_owned())?;
            Ok(PreparedValue {
                bytes: vec![byte],
                pattern: None,
            })
        }
        runtime::ScanValueKind::Word => {
            let number = parse_u64_value(value, "value must be an unsigned integer <= 65535")?;
            let word = u16::try_from(number)
                .map_err(|_| "value must be an unsigned integer <= 65535".to_owned())?;
            Ok(PreparedValue {
                bytes: word.to_le_bytes().to_vec(),
                pattern: None,
            })
        }
        runtime::ScanValueKind::Dword => {
            let number = parse_u64_value(value, "value must be an unsigned integer <= 0xFFFFFFFF")?;
            let dword = u32::try_from(number)
                .map_err(|_| "value must be an unsigned integer <= 0xFFFFFFFF".to_owned())?;
            Ok(PreparedValue {
                bytes: dword.to_le_bytes().to_vec(),
                pattern: None,
            })
        }
        runtime::ScanValueKind::Qword => {
            let qword = parse_u64_value(value, "value must be an unsigned integer")?;
            Ok(PreparedValue {
                bytes: qword.to_le_bytes().to_vec(),
                pattern: None,
            })
        }
        runtime::ScanValueKind::Float => {
            let float = parse_f64_value(value)?
                .to_string()
                .parse::<f32>()
                .map_err(|_| "value must be numeric".to_owned())?;
            Ok(PreparedValue {
                bytes: float.to_le_bytes().to_vec(),
                pattern: None,
            })
        }
        runtime::ScanValueKind::Double => {
            let double = parse_f64_value(value)?;
            Ok(PreparedValue {
                bytes: double.to_le_bytes().to_vec(),
                pattern: None,
            })
        }
        runtime::ScanValueKind::String => {
            let text = value
                .as_str()
                .ok_or_else(|| "value must be a string".to_owned())?;
            let bytes = text.as_bytes().to_vec();
            if bytes.is_empty() {
                return Err("value must not be empty".to_owned());
            }
            Ok(PreparedValue {
                bytes,
                pattern: None,
            })
        }
        runtime::ScanValueKind::Array => {
            let text = value
                .as_str()
                .ok_or_else(|| "value must be an AOB pattern string".to_owned())?;
            let pattern = parse_aob_pattern(text)?;
            let bytes = pattern
                .iter()
                .map(|byte| byte.unwrap_or(0))
                .collect::<Vec<_>>();
            Ok(PreparedValue {
                bytes,
                pattern: Some(pattern),
            })
        }
    }
}

fn infer_exact_kind(value: &Value) -> Result<runtime::ScanValueKind, String> {
    if value.is_number() {
        return Ok(runtime::ScanValueKind::Dword);
    }

    let Some(text) = value.as_str() else {
        return Err("value must be a string or number".to_owned());
    };
    if looks_like_aob_pattern(text) {
        Ok(runtime::ScanValueKind::Array)
    } else {
        Ok(runtime::ScanValueKind::String)
    }
}

fn parse_next_scan_type(value: &str) -> Result<NextScanType, String> {
    match value {
        "exact" => Ok(NextScanType::Exact),
        "increased" => Ok(NextScanType::Increased),
        "decreased" => Ok(NextScanType::Decreased),
        "changed" => Ok(NextScanType::Changed),
        "unchanged" => Ok(NextScanType::Unchanged),
        "bigger" => Ok(NextScanType::Bigger),
        "smaller" => Ok(NextScanType::Smaller),
        other => Err(format!("unsupported scan_type: {}", other)),
    }
}

fn compare_numeric(
    kind: runtime::ScanValueKind,
    current_bytes: &[u8],
    previous_bytes: &[u8],
    target: Option<&PreparedValue>,
    scan_type: NextScanType,
) -> Result<bool, String> {
    let current = decode_comparable(kind, current_bytes)?;
    let previous = decode_comparable(kind, previous_bytes)?;
    let target_value = match target {
        Some(target) => Some(decode_comparable(kind, &target.bytes)?),
        None => None,
    };

    let keep = match (current, previous, target_value) {
        (ComparableValue::Unsigned(current), ComparableValue::Unsigned(previous), maybe_target) => {
            match scan_type {
                NextScanType::Increased => current > previous,
                NextScanType::Decreased => current < previous,
                NextScanType::Bigger => current > expect_unsigned_target(maybe_target)?,
                NextScanType::Smaller => current < expect_unsigned_target(maybe_target)?,
                _ => false,
            }
        }
        (ComparableValue::Float(current), ComparableValue::Float(previous), maybe_target) => {
            match scan_type {
                NextScanType::Increased => current > previous,
                NextScanType::Decreased => current < previous,
                NextScanType::Bigger => current > expect_float_target(maybe_target)?,
                NextScanType::Smaller => current < expect_float_target(maybe_target)?,
                _ => false,
            }
        }
        _ => return Err("numeric comparison type mismatch".to_owned()),
    };

    Ok(keep)
}

fn expect_unsigned_target(target: Option<ComparableValue>) -> Result<u64, String> {
    match target {
        Some(ComparableValue::Unsigned(value)) => Ok(value),
        _ => Err("target value type mismatch".to_owned()),
    }
}

fn expect_float_target(target: Option<ComparableValue>) -> Result<f64, String> {
    match target {
        Some(ComparableValue::Float(value)) => Ok(value),
        _ => Err("target value type mismatch".to_owned()),
    }
}

fn decode_comparable(
    kind: runtime::ScanValueKind,
    bytes: &[u8],
) -> Result<ComparableValue, String> {
    match kind {
        runtime::ScanValueKind::Byte => Ok(ComparableValue::Unsigned(
            *bytes.first().unwrap_or(&0) as u64
        )),
        runtime::ScanValueKind::Word => Ok(ComparableValue::Unsigned(
            u16::from_le_bytes(fixed_bytes::<2>(bytes)?).into(),
        )),
        runtime::ScanValueKind::Dword => Ok(ComparableValue::Unsigned(
            u32::from_le_bytes(fixed_bytes::<4>(bytes)?).into(),
        )),
        runtime::ScanValueKind::Qword => Ok(ComparableValue::Unsigned(u64::from_le_bytes(
            fixed_bytes::<8>(bytes)?,
        ))),
        runtime::ScanValueKind::Float => Ok(ComparableValue::Float(f32::from_le_bytes(
            fixed_bytes::<4>(bytes)?,
        ) as f64)),
        runtime::ScanValueKind::Double => Ok(ComparableValue::Float(f64::from_le_bytes(
            fixed_bytes::<8>(bytes)?,
        ))),
        runtime::ScanValueKind::String | runtime::ScanValueKind::Array => {
            Err("non-numeric scan type".to_owned())
        }
    }
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("unexpected value size: expected {}", N))
}

fn bytes_to_json(kind: runtime::ScanValueKind, bytes: &[u8]) -> Value {
    match kind {
        runtime::ScanValueKind::Byte => json!(bytes.first().copied().unwrap_or(0)),
        runtime::ScanValueKind::Word => json!(u16::from_le_bytes(
            fixed_bytes::<2>(bytes).unwrap_or([0; 2])
        )),
        runtime::ScanValueKind::Dword => json!(u32::from_le_bytes(
            fixed_bytes::<4>(bytes).unwrap_or([0; 4])
        )),
        runtime::ScanValueKind::Qword => json!(u64::from_le_bytes(
            fixed_bytes::<8>(bytes).unwrap_or([0; 8])
        )),
        runtime::ScanValueKind::Float => {
            json!(f32::from_le_bytes(
                fixed_bytes::<4>(bytes).unwrap_or([0; 4])
            ))
        }
        runtime::ScanValueKind::Double => {
            json!(f64::from_le_bytes(
                fixed_bytes::<8>(bytes).unwrap_or([0; 8])
            ))
        }
        runtime::ScanValueKind::String => json!(String::from_utf8_lossy(bytes).to_string()),
        runtime::ScanValueKind::Array => json!(bytes
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect::<Vec<_>>()
            .join(" ")),
    }
}

fn parse_u64_value(value: &Value, error: &str) -> Result<u64, String> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    if let Some(text) = value.as_str() {
        let trimmed = text.trim();
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex, 16).map_err(|_| error.to_owned());
        }
        return trimmed.parse::<u64>().map_err(|_| error.to_owned());
    }
    Err(error.to_owned())
}

fn format_instruction_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_f64_value(value: &Value) -> Result<f64, String> {
    if let Some(number) = value.as_f64() {
        return Ok(number);
    }
    if let Some(text) = value.as_str() {
        return text
            .trim()
            .parse::<f64>()
            .map_err(|_| "value must be numeric".to_owned());
    }
    Err("value must be numeric".to_owned())
}

fn looks_like_aob_pattern(value: &str) -> bool {
    if !value.contains(char::is_whitespace) {
        return false;
    }

    value.split_whitespace().all(|token| {
        token == "?"
            || token == "??"
            || (token.len() == 2 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
    })
}

fn scan_pattern(
    handle: *mut c_void,
    pattern: &[Option<u8>],
    protection: Option<&str>,
    limit: usize,
) -> Result<Vec<usize>, String> {
    if pattern.is_empty() {
        return Err("pattern is empty".to_owned());
    }

    let mut matches = Vec::new();
    let regions = runtime::enum_memory_regions(handle, None)?;

    for region in regions {
        if matches.len() >= limit {
            break;
        }
        if !runtime::is_region_usable(&region) || region.base_address == 0 {
            continue;
        }
        if let Some(protection) = protection {
            if !region_matches_filter(&region, protection) {
                continue;
            }
        } else if !runtime::is_region_readable(&region) {
            continue;
        }

        scan_region(handle, &region, pattern, limit, &mut matches);
    }

    Ok(matches)
}

fn scan_region(
    handle: *mut c_void,
    region: &runtime::MemoryRegionInfo,
    pattern: &[Option<u8>],
    limit: usize,
    matches: &mut Vec<usize>,
) {
    let overlap = pattern.len().saturating_sub(1);
    let mut offset = 0usize;

    while offset < region.region_size && matches.len() < limit {
        let chunk_body = CHUNK_SIZE.min(region.region_size - offset);
        let chunk_total = chunk_body
            .saturating_add(overlap)
            .min(region.region_size - offset);
        let address = region.base_address.saturating_add(offset);
        let bytes = match runtime::read_process_memory(handle, address, chunk_total) {
            Ok(bytes) => bytes,
            Err(_) => {
                offset = offset.saturating_add(CHUNK_SIZE);
                continue;
            }
        };

        for relative in find_pattern_offsets(&bytes, pattern, chunk_body) {
            let absolute = address.saturating_add(relative);
            if matches.last().copied() == Some(absolute) {
                continue;
            }
            matches.push(absolute);
            if matches.len() >= limit {
                break;
            }
        }

        offset = offset.saturating_add(CHUNK_SIZE);
    }
}

fn find_pattern_offsets(bytes: &[u8], pattern: &[Option<u8>], cutoff: usize) -> Vec<usize> {
    if bytes.len() < pattern.len() || pattern.is_empty() {
        return Vec::new();
    }

    let last_start = bytes.len() - pattern.len();
    let mut offsets = Vec::new();
    for start in 0..=last_start {
        if start >= cutoff {
            break;
        }
        if pattern_matches(&bytes[start..start + pattern.len()], pattern) {
            offsets.push(start);
        }
    }
    offsets
}

fn pattern_matches(candidate: &[u8], pattern: &[Option<u8>]) -> bool {
    candidate
        .iter()
        .zip(pattern.iter())
        .all(|(candidate, wanted)| match wanted {
            Some(wanted) => *candidate == *wanted,
            None => true,
        })
}

fn parse_aob_pattern(pattern: &str) -> Result<Vec<Option<u8>>, String> {
    let mut parsed = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            parsed.push(None);
            continue;
        }

        let cleaned = token.trim();
        if cleaned.len() != 2 {
            return Err(format!("invalid AOB token: {}", token));
        }
        let value =
            u8::from_str_radix(cleaned, 16).map_err(|_| format!("invalid AOB token: {}", token))?;
        parsed.push(Some(value));
    }

    if parsed.is_empty() {
        return Err("pattern is empty".to_owned());
    }

    Ok(parsed)
}

fn encode_search_bytes(text: &str, wide: bool) -> Vec<Option<u8>> {
    if wide {
        text.encode_utf16()
            .flat_map(|word| word.to_le_bytes())
            .map(Some)
            .collect()
    } else {
        text.as_bytes().iter().copied().map(Some).collect()
    }
}

fn read_preview_string(handle: *mut c_void, address: usize, wide: bool) -> String {
    let max_length = 50usize;
    let bytes_to_read = if wide {
        max_length.saturating_mul(2)
    } else {
        max_length
    };
    let bytes = match runtime::read_process_memory(handle, address, bytes_to_read) {
        Ok(bytes) => bytes,
        Err(_) => return String::new(),
    };

    if wide {
        let words = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|word| *word != 0)
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&words)
    } else {
        let slice = bytes
            .into_iter()
            .take_while(|byte| *byte != 0)
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&slice).to_string()
    }
}

fn region_matches_filter(region: &runtime::MemoryRegionInfo, filter: &str) -> bool {
    let mut mode = '+';
    let mut required = Vec::new();
    let mut forbidden = Vec::new();

    for ch in filter.chars() {
        match ch {
            '+' | '-' => mode = ch,
            'r' | 'R' | 'w' | 'W' | 'x' | 'X' | 'c' | 'C' => {
                let upper = ch.to_ascii_uppercase();
                if mode == '-' {
                    forbidden.push(upper);
                } else {
                    required.push(upper);
                }
            }
            _ => {}
        }
    }

    required.into_iter().all(|flag| region_flag(region, flag))
        && forbidden.into_iter().all(|flag| !region_flag(region, flag))
}

fn region_flag(region: &runtime::MemoryRegionInfo, flag: char) -> bool {
    match flag {
        'R' => runtime::is_region_readable(region),
        'W' => runtime::is_region_writable(region),
        'X' => runtime::is_region_executable(region),
        'C' => runtime::is_region_copy_on_write(region),
        _ => false,
    }
}

fn parse_positive_size(value: Option<&Value>, default: usize, max: usize) -> usize {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(max)
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
