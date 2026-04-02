use std::time::Duration;

use serde_json::Value;

use crate::runtime;

use super::ToolResponse;

pub fn not_implemented(method: &str) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: format!("not implemented in ce_plugin tools skeleton: {}", method),
    }
}

pub fn method_not_found(method: &str) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: format!("method not found: {}", method),
    }
}

pub fn dispatch_via_dispatcher(method: &str, params_json: &str, timeout: Duration) -> ToolResponse {
    let Some(app) = runtime::app_state() else {
        return ToolResponse {
            success: false,
            body_json: "plugin runtime unavailable".to_owned(),
        };
    };

    match app.dispatcher().execute(method, params_json, timeout) {
        Ok(response) => response,
        Err(error) => ToolResponse {
            success: false,
            body_json: error,
        },
    }
}

pub fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn parse_address(value: Option<&Value>) -> Result<usize, String> {
    let Some(value) = value else {
        return Err("missing address".to_owned());
    };

    if let Some(number) = value.as_u64() {
        return usize::try_from(number).map_err(|_| "address out of range".to_owned());
    }

    if let Some(text) = value.as_str() {
        let trimmed = text.trim();
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            return usize::from_str_radix(hex, 16)
                .map_err(|_| format!("invalid hex address: {}", text));
        }

        return trimmed
            .parse::<usize>()
            .map_err(|_| format!("invalid address: {}", text));
    }

    Err("address must be a string or number".to_owned())
}

pub fn format_address(address: usize) -> String {
    if cfg!(target_pointer_width = "64") {
        format!("0x{:016X}", address)
    } else {
        format!("0x{:08X}", address)
    }
}

pub fn parse_params(params_json: &str) -> Result<Value, String> {
    serde_json::from_str::<Value>(params_json)
        .map_err(|error| format!("invalid params json: {}", error))
}

pub trait FromLeBytes<const N: usize> {
    fn from_le_bytes(bytes: [u8; N]) -> Self;
}

impl FromLeBytes<1> for u8 {
    fn from_le_bytes(bytes: [u8; 1]) -> Self {
        u8::from_le_bytes(bytes)
    }
}

impl FromLeBytes<2> for u16 {
    fn from_le_bytes(bytes: [u8; 2]) -> Self {
        u16::from_le_bytes(bytes)
    }
}

impl FromLeBytes<4> for u32 {
    fn from_le_bytes(bytes: [u8; 4]) -> Self {
        u32::from_le_bytes(bytes)
    }
}

impl FromLeBytes<8> for u64 {
    fn from_le_bytes(bytes: [u8; 8]) -> Self {
        u64::from_le_bytes(bytes)
    }
}
