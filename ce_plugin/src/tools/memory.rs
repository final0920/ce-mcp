use core::ffi::c_void;

use serde_json::{json, Value};

use super::{util, ToolResponse};
use crate::runtime;

const METHODS: &[&str] = &[
    "read_memory",
    "read_integer",
    "read_string",
    "read_pointer",
    "read_pointer_chain",
    "write_integer",
    "write_memory",
    "write_string",
];

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "read_memory" => read_memory(params_json),
        "read_integer" => read_integer(params_json),
        "read_string" => read_string(params_json),
        "read_pointer" => read_pointer(params_json),
        "read_pointer_chain" => read_pointer_chain(params_json),
        "write_integer" => write_integer(params_json),
        "write_memory" => write_memory(params_json),
        "write_string" => write_string(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn read_memory(params_json: &str) -> ToolResponse {
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
    let size = params
        .get("size")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(256)
        .min(65_536);

    match runtime::read_process_memory(handle, address, size) {
        Ok(bytes) => {
            let hex = bytes
                .iter()
                .map(|byte| format!("{:02X}", byte))
                .collect::<Vec<_>>()
                .join(" ");
            ToolResponse {
                success: true,
                body_json: json!({
                    "success": true,
                    "address": util::format_address(address),
                    "size": bytes.len(),
                    "data": hex,
                    "bytes": bytes,
                })
                .to_string(),
            }
        }
        Err(error) => error_response(error),
    }
}

fn read_integer(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };

    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let integer_type = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("dword");
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    let result = match integer_type {
        "byte" => read_scalar::<1, u8>(handle, address).map(|value| {
            json!({
                "success": true,
                "address": util::format_address(address),
                "value": value,
                "type": "byte",
                "hex": format!("0x{:02X}", value),
            })
        }),
        "word" => read_scalar::<2, u16>(handle, address).map(|value| {
            json!({
                "success": true,
                "address": util::format_address(address),
                "value": value,
                "type": "word",
                "hex": format!("0x{:04X}", value),
            })
        }),
        "dword" => read_scalar::<4, u32>(handle, address).map(|value| {
            json!({
                "success": true,
                "address": util::format_address(address),
                "value": value,
                "type": "dword",
                "hex": format!("0x{:08X}", value),
            })
        }),
        "qword" => read_scalar::<8, u64>(handle, address).map(|value| {
            json!({
                "success": true,
                "address": util::format_address(address),
                "value": value,
                "type": "qword",
                "hex": format!("0x{:016X}", value),
            })
        }),
        "float" => runtime::read_process_memory(handle, address, 4).map(|bytes| {
            let value = f32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]));
            json!({
                "success": true,
                "address": util::format_address(address),
                "value": value,
                "type": "float",
                "hex": format!("0x{:08X}", value.to_bits()),
            })
        }),
        "double" => runtime::read_process_memory(handle, address, 8).map(|bytes| {
            let value = f64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
            json!({
                "success": true,
                "address": util::format_address(address),
                "value": value,
                "type": "double",
                "hex": format!("0x{:016X}", value.to_bits()),
            })
        }),
        other => Err(format!("unsupported integer type: {}", other)),
    };

    match result {
        Ok(value) => ToolResponse {
            success: true,
            body_json: value.to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn read_string(params_json: &str) -> ToolResponse {
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
    let max_length = params
        .get("max_length")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(256)
        .min(4096);
    let wide = params.get("wide").and_then(Value::as_bool).unwrap_or(false);

    let bytes_to_read = if wide {
        max_length.saturating_mul(2)
    } else {
        max_length
    };
    let bytes = match runtime::read_process_memory(handle, address, bytes_to_read) {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    let value = if wide {
        let words = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|word| *word != 0)
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&words)
    } else {
        let slice = bytes
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&slice).to_string()
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "address": util::format_address(address),
            "value": value,
            "wide": wide,
            "max_length": max_length,
        })
        .to_string(),
    }
}

fn read_pointer(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let offsets = params
        .get("offsets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !offsets.is_empty() {
        return read_pointer_chain(params_json);
    }

    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let address = match util::parse_address(params.get("address")) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };

    match read_scalar::<8, u64>(handle, address) {
        Ok(value) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "address": util::format_address(address),
                "value": value,
                "hex": format!("0x{:016X}", value),
            })
            .to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn read_pointer_chain(params_json: &str) -> ToolResponse {
    let Some(handle) = opened_process_handle() else {
        return runtime_unavailable("process handle unavailable");
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let base = params.get("base").or_else(|| params.get("address"));
    let mut current = match util::parse_address(base) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let offsets = params
        .get("offsets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut path = vec![json!({
        "step": 0,
        "address": util::format_address(current),
        "offset": 0,
    })];

    for (index, offset) in offsets.iter().enumerate() {
        let offset = offset
            .as_i64()
            .ok_or_else(|| "offset must be an integer".to_owned());
        let offset = match offset {
            Ok(value) => value,
            Err(error) => return error_response(error),
        };

        let pointer = match read_scalar::<8, u64>(handle, current) {
            Ok(value) => value as i64,
            Err(error) => return error_response(error),
        };
        let next = pointer.saturating_add(offset);
        if next < 0 {
            return error_response("pointer chain resolved to negative address".to_owned());
        }
        current = next as usize;
        path.push(json!({
            "step": index + 1,
            "pointer": format!("0x{:016X}", pointer as u64),
            "offset": offset,
            "address": util::format_address(current),
        }));
    }

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "final_address": util::format_address(current),
            "final_value": format!("0x{:016X}", current as u64),
            "path": path,
        })
        .to_string(),
    }
}

fn write_memory(params_json: &str) -> ToolResponse {
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
    let bytes = match params.get("bytes").and_then(Value::as_array) {
        Some(values) => {
            let mut output = Vec::with_capacity(values.len());
            for value in values {
                let number = match value.as_u64() {
                    Some(number) if number <= 0xFF => number as u8,
                    _ => return error_response("bytes must be an array of 0..255".to_owned()),
                };
                output.push(number);
            }
            output
        }
        None => return error_response("missing bytes".to_owned()),
    };

    match runtime::write_process_memory(handle, address, &bytes) {
        Ok(()) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "address": util::format_address(address),
                "size": bytes.len(),
            })
            .to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn write_integer(params_json: &str) -> ToolResponse {
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
    let integer_type = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("dword");

    let bytes = match integer_type {
        "byte" => one_u8(params.get("value")).map(|value| vec![value]),
        "word" => one_u16(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "dword" => one_u32(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "qword" => one_u64(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "float" => one_f32(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        "double" => one_f64(params.get("value")).map(|value| value.to_le_bytes().to_vec()),
        other => Err(format!("unsupported integer type: {}", other)),
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error),
    };

    match runtime::write_process_memory(handle, address, &bytes) {
        Ok(()) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "address": util::format_address(address),
                "size": bytes.len(),
                "type": integer_type,
            })
            .to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn write_string(params_json: &str) -> ToolResponse {
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
    let value = match params.get("value").and_then(Value::as_str) {
        Some(value) => value,
        None => return error_response("missing string value".to_owned()),
    };
    let wide = params.get("wide").and_then(Value::as_bool).unwrap_or(false);

    let bytes = if wide {
        value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>()
    } else {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        bytes
    };

    match runtime::write_process_memory(handle, address, &bytes) {
        Ok(()) => ToolResponse {
            success: true,
            body_json: json!({
                "success": true,
                "address": util::format_address(address),
                "size": bytes.len(),
                "wide": wide,
            })
            .to_string(),
        },
        Err(error) => error_response(error),
    }
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

fn read_scalar<const N: usize, T>(handle: *mut c_void, address: usize) -> Result<T, String>
where
    T: util::FromLeBytes<N>,
{
    let bytes = runtime::read_process_memory(handle, address, N)?;
    let array: [u8; N] = bytes
        .try_into()
        .map_err(|_| format!("unexpected read length for {}", N))?;
    Ok(T::from_le_bytes(array))
}

fn one_u8(value: Option<&Value>) -> Result<u8, String> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| "value must be an unsigned integer <= 255".to_owned())
}

fn one_u16(value: Option<&Value>) -> Result<u16, String> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| "value must be an unsigned integer <= 65535".to_owned())
}

fn one_u32(value: Option<&Value>) -> Result<u32, String> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "value must be an unsigned integer <= 0xFFFFFFFF".to_owned())
}

fn one_u64(value: Option<&Value>) -> Result<u64, String> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| "value must be an unsigned integer".to_owned())
}

fn one_f32(value: Option<&Value>) -> Result<f32, String> {
    value
        .and_then(Value::as_f64)
        .map(|value| value as f32)
        .ok_or_else(|| "value must be numeric".to_owned())
}

fn one_f64(value: Option<&Value>) -> Result<f64, String> {
    value
        .and_then(Value::as_f64)
        .ok_or_else(|| "value must be numeric".to_owned())
}
