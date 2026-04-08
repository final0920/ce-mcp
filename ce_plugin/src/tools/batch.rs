use serde_json::{json, Map, Value};

use super::{analysis, memory, process, util, ToolResponse};
use crate::runtime;

const METHODS: &[&str] = &[
    "batch_get_address_info",
    "batch_read_memory",
    "batch_disassemble",
];
const MAX_BATCH_ITEMS: usize = 256;
const MAX_READ_SIZE: usize = 65_536;

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "batch_get_address_info" => batch_get_address_info(params_json),
        "batch_read_memory" => batch_read_memory(params_json),
        "batch_disassemble" => batch_disassemble(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn batch_get_address_info(params_json: &str) -> ToolResponse {
    let Some(_app) = runtime::app_state() else {
        return error_response("runtime not initialized".to_owned());
    };

    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let addresses = match params.get("addresses").and_then(Value::as_array) {
        Some(values) => values,
        None => return error_response("missing addresses array".to_owned()),
    };

    let include_modules = params
        .get("include_modules")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let include_symbols = params
        .get("include_symbols")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let include_sections = params
        .get("include_sections")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let modules = process::current_modules();

    let results = addresses
        .iter()
        .take(MAX_BATCH_ITEMS)
        .enumerate()
        .map(
            |(index, raw)| match process::resolve_address_param(Some(raw), &modules) {
                Ok(address) => {
                    let mut value = process::address_info_json(
                        address,
                        &modules,
                        include_modules,
                        include_symbols,
                        include_sections,
                    );
                    if let Some(object) = value.as_object_mut() {
                        object.insert("index".to_owned(), json!(index));
                    }
                    value
                }
                Err(error) => json!({
                    "success": false,
                    "index": index,
                    "input": raw,
                    "error": error,
                }),
            },
        )
        .collect::<Vec<_>>();

    let error_count = results
        .iter()
        .filter(|value| {
            !value
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": results.len(),
            "success_count": results.len().saturating_sub(error_count),
            "error_count": error_count,
            "results": results,
        })
        .to_string(),
    }
}

fn batch_read_memory(params_json: &str) -> ToolResponse {
    let Some(_app) = runtime::app_state() else {
        return error_response("runtime not initialized".to_owned());
    };

    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let items = match params.get("items").and_then(Value::as_array) {
        Some(values) => values,
        None => return error_response("missing items array".to_owned()),
    };

    let results = items
        .iter()
        .take(MAX_BATCH_ITEMS)
        .enumerate()
        .map(|(index, item)| read_memory_item(item, index))
        .collect::<Vec<_>>();
    let error_count = results
        .iter()
        .filter(|value| {
            !value
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": results.len(),
            "success_count": results.len().saturating_sub(error_count),
            "error_count": error_count,
            "results": results,
        })
        .to_string(),
    }
}

fn batch_disassemble(params_json: &str) -> ToolResponse {
    let Some(_app) = runtime::app_state() else {
        return error_response("runtime not initialized".to_owned());
    };
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let items = match params.get("items").and_then(Value::as_array) {
        Some(values) => values,
        None => return error_response("missing items array".to_owned()),
    };

    let results = items
        .iter()
        .take(MAX_BATCH_ITEMS)
        .enumerate()
        .map(|(index, item)| disassemble_item(item, index))
        .collect::<Vec<_>>();
    let error_count = results
        .iter()
        .filter(|value| {
            !value
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "count": results.len(),
            "success_count": results.len().saturating_sub(error_count),
            "error_count": error_count,
            "results": results,
        })
        .to_string(),
    }
}

fn disassemble_item(item: &Value, index: usize) -> Value {
    let Some(object) = item.as_object() else {
        return json!({
            "success": false,
            "index": index,
            "input": item,
            "error": "batch_disassemble items must be objects",
        });
    };

    let params = json!({
        "address": object.get("address").cloned(),
        "count": object.get("count").cloned().unwrap_or_else(|| json!(20))
    });
    let Some(response) = analysis::dispatch("disassemble", &params.to_string()) else {
        return json!({
            "success": false,
            "index": index,
            "error": "disassemble dispatcher unavailable",
        });
    };
    if !response.success {
        return json!({
            "success": false,
            "index": index,
            "error": response.body_json,
        });
    }

    match serde_json::from_str::<Value>(&response.body_json) {
        Ok(mut value) => {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("index".to_owned(), json!(index));
                if let Some(label) = object.get("label").and_then(Value::as_str) {
                    obj.insert("label".to_owned(), json!(label));
                }
            }
            value
        }
        Err(error) => json!({
            "success": false,
            "index": index,
            "error": format!("invalid disassemble result json: {}", error),
        }),
    }
}

fn read_memory_item(item: &Value, index: usize) -> Value {
    let Some(object) = item.as_object() else {
        return json!({
            "success": false,
            "index": index,
            "input": item,
            "error": "batch_read_memory items must be objects",
        });
    };

    let Some(address) = object.get("address").cloned() else {
        return json!({
            "success": false,
            "index": index,
            "input": item,
            "error": "missing address",
        });
    };
    let size = object
        .get("size")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(256)
        .min(MAX_READ_SIZE);

    let mut forwarded = Map::new();
    forwarded.insert("address".to_owned(), address);
    forwarded.insert("size".to_owned(), json!(size));

    let Some(response) = memory::dispatch("read_memory", &Value::Object(forwarded).to_string())
    else {
        return json!({
            "success": false,
            "index": index,
            "error": "read_memory dispatcher unavailable",
        });
    };
    if !response.success {
        return json!({
            "success": false,
            "index": index,
            "input": item,
            "error": response.body_json,
        });
    }

    match serde_json::from_str::<Value>(&response.body_json) {
        Ok(mut value) => {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("index".to_owned(), json!(index));
                if let Some(label) = object.get("label").and_then(Value::as_str) {
                    obj.insert("label".to_owned(), json!(label));
                }
            }
            value
        }
        Err(error) => json!({
            "success": false,
            "index": index,
            "error": format!("invalid read_memory result json: {}", error),
        }),
    }
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}
