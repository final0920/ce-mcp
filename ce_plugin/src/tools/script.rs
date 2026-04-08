use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fs;
use std::sync::OnceLock;

use serde_json::{json, Map, Number, Value};

use crate::runtime;
use crate::runtime::console;

use super::{util, ToolResponse};

const METHODS: &[&str] = &[
    "evaluate_lua",
    "evaluate_lua_file",
    "auto_assemble",
    "auto_assemble_file",
];

const LUA_OK: c_int = 0;
const LUA_MULTRET: c_int = -1;
const LUA_TNIL: c_int = 0;
const LUA_TBOOLEAN: c_int = 1;
const LUA_TLIGHTUSERDATA: c_int = 2;
const LUA_TNUMBER: c_int = 3;
const LUA_TSTRING: c_int = 4;
const LUA_TTABLE: c_int = 5;
const LUA_TFUNCTION: c_int = 6;
const LUA_TUSERDATA: c_int = 7;
const LUA_TTHREAD: c_int = 8;
const STRUCTURED_DEPTH_LIMIT: usize = 4;
const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

type Hmodule = *mut c_void;
type LuaState = c_void;
type LuaInteger = isize;
type LuaNumber = f64;
type LuaKContext = isize;
type LuaKFunction =
    Option<unsafe extern "C" fn(state: *mut LuaState, status: c_int, ctx: LuaKContext) -> c_int>;

type LuaGetTop = unsafe extern "C" fn(state: *mut LuaState) -> c_int;
type LuaSetTop = unsafe extern "C" fn(state: *mut LuaState, index: c_int);
type LuaType = unsafe extern "C" fn(state: *mut LuaState, index: c_int) -> c_int;
type LuaTypeName = unsafe extern "C" fn(state: *mut LuaState, tag: c_int) -> *const c_char;
type LuaToLString =
    unsafe extern "C" fn(state: *mut LuaState, index: c_int, len: *mut usize) -> *const c_char;
type LuaToBoolean = unsafe extern "C" fn(state: *mut LuaState, index: c_int) -> c_int;
type LuaToIntegerX =
    unsafe extern "C" fn(state: *mut LuaState, index: c_int, is_num: *mut c_int) -> LuaInteger;
type LuaToNumberX =
    unsafe extern "C" fn(state: *mut LuaState, index: c_int, is_num: *mut c_int) -> LuaNumber;
type LuaRawLen = unsafe extern "C" fn(state: *mut LuaState, index: c_int) -> usize;
type LuaNext = unsafe extern "C" fn(state: *mut LuaState, index: c_int) -> c_int;
type LuaPushNil = unsafe extern "C" fn(state: *mut LuaState);
type LuaPushValue = unsafe extern "C" fn(state: *mut LuaState, index: c_int);
type LuaPushLString =
    unsafe extern "C" fn(state: *mut LuaState, text: *const c_char, len: usize) -> *const c_char;
type LuaGetGlobal = unsafe extern "C" fn(state: *mut LuaState, name: *const c_char) -> c_int;
type LuaLLoadString = unsafe extern "C" fn(state: *mut LuaState, code: *const c_char) -> c_int;
type LuaPCallK = unsafe extern "C" fn(
    state: *mut LuaState,
    nargs: c_int,
    nresults: c_int,
    errfunc: c_int,
    ctx: LuaKContext,
    k: LuaKFunction,
) -> c_int;

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleA(name: *const c_char) -> Hmodule;
    fn GetProcAddress(module: Hmodule, name: *const c_char) -> *mut c_void;
}

struct LuaApi {
    module_name: &'static str,
    lua_gettop: LuaGetTop,
    lua_settop: LuaSetTop,
    lua_type: LuaType,
    lua_typename: LuaTypeName,
    lua_tolstring: LuaToLString,
    lua_toboolean: LuaToBoolean,
    lua_tointegerx: LuaToIntegerX,
    lua_tonumberx: LuaToNumberX,
    lua_rawlen: LuaRawLen,
    lua_next: LuaNext,
    lua_pushnil: LuaPushNil,
    lua_pushvalue: LuaPushValue,
    lua_pushlstring: LuaPushLString,
    lua_getglobal: LuaGetGlobal,
    lua_l_loadstring: LuaLLoadString,
    lua_pcallk: LuaPCallK,
}

static LUA_API: OnceLock<Option<LuaApi>> = OnceLock::new();

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "evaluate_lua" => evaluate_lua(params_json),
        "evaluate_lua_file" => evaluate_lua_file(params_json),
        "auto_assemble" => auto_assemble(params_json),
        "auto_assemble_file" => auto_assemble_file(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

pub(crate) fn execute_lua_snippet(code: &str, structured: bool) -> Result<Value, String> {
    with_lua_runtime(|state, lua| execute_lua_code(state, lua, code, structured))
}

pub(crate) fn call_lua_global(
    function_name: &str,
    args: &[&str],
    structured: bool,
) -> Result<Value, String> {
    with_lua_runtime(|state, lua| execute_lua_global(state, lua, function_name, args, structured))
}

fn evaluate_lua(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let code = match params.get("code").and_then(Value::as_str) {
        Some(code) if !code.trim().is_empty() => code,
        _ => return error_response("missing code".to_owned()),
    };
    let structured = params
        .get("structured")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || params
            .get("structured_result")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    let result = execute_lua_snippet(code, structured);
    match result {
        Ok(body) => ToolResponse {
            success: true,
            body_json: body.to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn evaluate_lua_file(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let path = match params.get("path").and_then(Value::as_str) {
        Some(path) if !path.trim().is_empty() => path,
        _ => return error_response("missing path".to_owned()),
    };

    let code = match fs::read_to_string(path) {
        Ok(code) => code,
        Err(error) => return error_response(format!("failed to read lua file: {}", error)),
    };

    let proxy = json!({
        "code": code,
        "structured": params.get("structured").and_then(Value::as_bool).unwrap_or(false),
        "structured_result": params.get("structured_result").and_then(Value::as_bool).unwrap_or(false)
    });

    evaluate_lua(proxy.to_string().as_str())
}

fn auto_assemble(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let script = match params
        .get("script")
        .or_else(|| params.get("code"))
        .and_then(Value::as_str)
    {
        Some(script) if !script.trim().is_empty() => script,
        _ => return error_response("missing script".to_owned()),
    };

    let result = with_lua_runtime(|state, lua| execute_auto_assemble(state, lua, script));
    match result {
        Ok(body) => ToolResponse {
            success: true,
            body_json: body.to_string(),
        },
        Err(error) => error_response(error),
    }
}

fn auto_assemble_file(params_json: &str) -> ToolResponse {
    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };

    let path = match params.get("path").and_then(Value::as_str) {
        Some(path) if !path.trim().is_empty() => path,
        _ => return error_response("missing path".to_owned()),
    };

    let script = match fs::read_to_string(path) {
        Ok(script) => script,
        Err(error) => {
            return error_response(format!("failed to read auto assembler file: {}", error))
        }
    };

    let proxy = json!({ "script": script });
    auto_assemble(proxy.to_string().as_str())
}

fn with_lua_runtime<T, F>(callback: F) -> Result<T, String>
where
    F: FnOnce(*mut LuaState, &LuaApi) -> Result<T, String>,
{
    let app = runtime::app_state().ok_or_else(|| "plugin runtime unavailable".to_owned())?;
    console::info(format!(
        "[script] step=runtime_begin dispatcher_mode={} lua_state_export_available={}",
        app.dispatcher_mode(),
        app.lua_state_export_available()
    ));
    if app.dispatcher_mode() != "window-message-hook" {
        return Err("script execution requires window-message-hook dispatcher mode".to_owned());
    }

    let get_lua_state = app
        .exported_functions()
        .get_lua_state
        .ok_or_else(|| "CE get_lua_state export unavailable".to_owned())?;
    let state = unsafe { get_lua_state() }.cast::<LuaState>();
    if state.is_null() {
        return Err("CE returned null lua state".to_owned());
    }

    let lua = resolve_lua_api()?;
    console::info(format!(
        "[script] step=runtime_ready lua_module={} state_ptr={:p}",
        lua.module_name, state
    ));
    callback(state, lua)
}

fn execute_lua_code(
    state: *mut LuaState,
    lua: &LuaApi,
    code: &str,
    structured: bool,
) -> Result<Value, String> {
    let guard = StackGuard::new(state, lua);
    let code = CString::new(code).map_err(|_| "lua code contains interior null byte".to_owned())?;

    console::info(format!(
        "[script] step=load_begin kind=snippet structured={} code_len={} base_top={}",
        structured,
        code.as_bytes().len(),
        guard.top
    ));
    let status = unsafe { (lua.lua_l_loadstring)(state, code.as_ptr()) };
    if status != LUA_OK {
        let error = lua_error_string(state, lua);
        console::error(format!(
            "[script] step=load_error kind=snippet error={}",
            error
        ));
        return Err(format!("Compile error: {}", error));
    }
    console::info("[script] step=load_end kind=snippet success=true");

    console::info("[script] step=pcall_begin kind=snippet argc=0");
    let status = unsafe { (lua.lua_pcallk)(state, 0, LUA_MULTRET, 0, 0, None) };
    if status != LUA_OK {
        let error = lua_error_string(state, lua);
        console::error(format!(
            "[script] step=pcall_error kind=snippet error={}",
            error
        ));
        return Err(format!("Runtime error: {}", error));
    }
    console::info(format!(
        "[script] step=pcall_end kind=snippet top_after={}",
        unsafe { (lua.lua_gettop)(state) }
    ));

    collect_lua_results(state, lua, guard.top, structured)
}

fn execute_lua_global(
    state: *mut LuaState,
    lua: &LuaApi,
    function_name: &str,
    args: &[&str],
    structured: bool,
) -> Result<Value, String> {
    let guard = StackGuard::new(state, lua);
    let function_name = CString::new(function_name)
        .map_err(|_| "lua function name contains interior null byte".to_owned())?;

    console::info(format!(
        "[script] step=getglobal_begin function={} argc={} structured={} base_top={}",
        function_name.to_string_lossy(),
        args.len(),
        structured,
        guard.top
    ));
    unsafe {
        (lua.lua_getglobal)(state, function_name.as_ptr());
    }
    if unsafe { (lua.lua_type)(state, -1) } != LUA_TFUNCTION {
        let error = format!(
            "CE Lua global {} is unavailable",
            function_name.to_string_lossy()
        );
        console::error(format!("[script] step=getglobal_error error={}", error));
        return Err(error);
    }
    console::info(format!(
        "[script] step=getglobal_end function={} success=true",
        function_name.to_string_lossy()
    ));

    for arg in args {
        let arg = CString::new(*arg)
            .map_err(|_| "lua argument contains interior null byte".to_owned())?;
        unsafe {
            (lua.lua_pushlstring)(state, arg.as_ptr(), arg.as_bytes().len());
        }
    }

    console::info(format!(
        "[script] step=pcall_begin kind=global function={} argc={}",
        function_name.to_string_lossy(),
        args.len()
    ));
    let status = unsafe { (lua.lua_pcallk)(state, args.len() as c_int, LUA_MULTRET, 0, 0, None) };
    if status != LUA_OK {
        let error = lua_error_string(state, lua);
        console::error(format!(
            "[script] step=pcall_error kind=global function={} error={}",
            function_name.to_string_lossy(),
            error
        ));
        return Err(format!("Runtime error: {}", error));
    }
    console::info(format!(
        "[script] step=pcall_end kind=global function={} top_after={}",
        function_name.to_string_lossy(),
        unsafe { (lua.lua_gettop)(state) }
    ));

    collect_lua_results(state, lua, guard.top, structured)
}

fn collect_lua_results(
    state: *mut LuaState,
    lua: &LuaApi,
    base_top: c_int,
    structured: bool,
) -> Result<Value, String> {
    let top = unsafe { (lua.lua_gettop)(state) };
    let first_index = if top > base_top { base_top + 1 } else { 0 };
    let first_result = if first_index > 0 {
        lua_to_string_via_tostring(state, lua, first_index)?
    } else {
        "nil".to_owned()
    };

    let mut response = json!({
        "success": true,
        "engine": "ce-lua-state",
        "lua_module": lua.module_name,
        "result": first_result
    });

    let mut results = Vec::new();
    if first_index > 0 {
        for index in first_index..=top {
            results.push(lua_to_json(state, lua, index, 0)?);
        }
    }

    if let Some(object) = response.as_object_mut() {
        object.insert(
            "result_count".to_owned(),
            Value::Number(Number::from(results.len() as u64)),
        );
    }

    if structured {
        if let Some(object) = response.as_object_mut() {
            object.insert(
                "result_type".to_owned(),
                Value::String(if first_index > 0 {
                    lua_type_name_at(state, lua, first_index)
                } else {
                    "nil".to_owned()
                }),
            );
            object.insert(
                "structured_result".to_owned(),
                results.first().cloned().unwrap_or(Value::Null),
            );
            object.insert("results".to_owned(), Value::Array(results.clone()));
        }
    }

    Ok(response)
}

fn execute_auto_assemble(
    state: *mut LuaState,
    lua: &LuaApi,
    script: &str,
) -> Result<Value, String> {
    let guard = StackGuard::new(state, lua);
    let auto_assemble = CString::new("autoAssemble").expect("static string");
    let script =
        CString::new(script).map_err(|_| "script contains interior null byte".to_owned())?;

    console::info(format!(
        "[script] step=getglobal_begin function=autoAssemble argc=1 base_top={}",
        guard.top
    ));
    unsafe {
        (lua.lua_getglobal)(state, auto_assemble.as_ptr());
    }
    if unsafe { (lua.lua_type)(state, -1) } != LUA_TFUNCTION {
        console::error(
            "[script] step=getglobal_error error=CE Lua global autoAssemble is unavailable",
        );
        return Err("CE Lua global autoAssemble is unavailable".to_owned());
    }

    unsafe {
        (lua.lua_pushlstring)(state, script.as_ptr(), script.as_bytes().len());
    }

    console::info("[script] step=pcall_begin kind=auto_assemble argc=1");
    let status = unsafe { (lua.lua_pcallk)(state, 1, LUA_MULTRET, 0, 0, None) };
    if status != LUA_OK {
        let error = lua_error_string(state, lua);
        console::error(format!(
            "[script] step=pcall_error kind=auto_assemble error={}",
            error
        ));
        return Err(format!("AutoAssemble failed: {}", error));
    }

    let top = unsafe { (lua.lua_gettop)(state) };
    let first_result_index = guard.top + 1;
    let second_result_index = guard.top + 2;
    let executed = if top >= first_result_index {
        unsafe { (lua.lua_toboolean)(state, first_result_index) != 0 }
    } else {
        false
    };

    if !executed {
        let detail = if top >= second_result_index {
            lua_to_string_via_tostring(state, lua, second_result_index)?
        } else {
            "unknown failure".to_owned()
        };
        console::error(format!(
            "[script] step=auto_assemble_failed detail={}",
            detail
        ));
        return Err(format!("AutoAssemble failed: {}", detail));
    }

    let mut response = json!({
        "success": true,
        "engine": "ce-lua-state",
        "lua_module": lua.module_name,
        "executed": true,
        "message": "Script assembled successfully"
    });

    if top >= second_result_index {
        let second = lua_to_json(state, lua, second_result_index, 0)?;
        if let Some(object) = response.as_object_mut() {
            if let Some(symbols) = normalize_disable_info_symbols(&second) {
                object.insert("symbols".to_owned(), symbols);
            }
            object.insert("disable_info".to_owned(), second);
        }
    }

    console::info(format!(
        "[script] step=pcall_end kind=auto_assemble top_after={} executed=true",
        top
    ));
    Ok(response)
}

fn normalize_disable_info_symbols(disable_info: &Value) -> Option<Value> {
    let symbols = disable_info.as_object()?.get("symbols")?.as_object()?;
    let mut normalized = Map::new();

    for (name, address) in symbols {
        let hex = match address {
            Value::Number(number) => number.as_u64().map(format_symbol_address),
            Value::String(text) => Some(text.clone()),
            _ => None,
        }?;
        normalized.insert(name.clone(), Value::String(hex));
    }

    Some(Value::Object(normalized))
}

fn format_symbol_address(address: u64) -> String {
    if address > u32::MAX as u64 {
        let high = address / 0x1_0000_0000;
        let low = address % 0x1_0000_0000;
        format!("0x{:X}{:08X}", high, low)
    } else {
        format!("0x{:08X}", address)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::normalize_disable_info_symbols;

    #[test]
    fn normalize_disable_info_symbols_extracts_hex_map() {
        let normalized = normalize_disable_info_symbols(&json!({
            "symbols": {
                "alloc_target": 4660,
                "wide_ptr": 140737488355328u64
            }
        }))
        .expect("symbols should be extracted");

        assert_eq!(
            normalized,
            json!({
                "alloc_target": "0x00001234",
                "wide_ptr": "0x800000000000"
            })
        );
    }

    #[test]
    fn normalize_disable_info_symbols_returns_none_without_symbols() {
        assert!(normalize_disable_info_symbols(&json!({"note": "none"})).is_none());
    }
}

fn resolve_lua_api() -> Result<&'static LuaApi, String> {
    let api = LUA_API.get_or_init(load_lua_api);
    api.as_ref()
        .ok_or_else(|| "unable to locate CE Lua runtime exports".to_owned())
}

fn load_lua_api() -> Option<LuaApi> {
    const MODULES: &[&str] = &[
        "lua53-64.dll",
        "lua53.dll",
        "lua54-64.dll",
        "lua54.dll",
        "lua5.3-64.dll",
        "lua5.4-64.dll",
    ];

    for module_name in MODULES {
        let Ok(module_cstr) = CString::new(*module_name) else {
            continue;
        };
        let module = unsafe { GetModuleHandleA(module_cstr.as_ptr()) };
        if module.is_null() {
            continue;
        }

        let api = unsafe {
            LuaApi {
                module_name,
                lua_gettop: load_symbol(module, "lua_gettop")?,
                lua_settop: load_symbol(module, "lua_settop")?,
                lua_type: load_symbol(module, "lua_type")?,
                lua_typename: load_symbol(module, "lua_typename")?,
                lua_tolstring: load_symbol(module, "lua_tolstring")?,
                lua_toboolean: load_symbol(module, "lua_toboolean")?,
                lua_tointegerx: load_symbol(module, "lua_tointegerx")?,
                lua_tonumberx: load_symbol(module, "lua_tonumberx")?,
                lua_rawlen: load_symbol(module, "lua_rawlen")?,
                lua_next: load_symbol(module, "lua_next")?,
                lua_pushnil: load_symbol(module, "lua_pushnil")?,
                lua_pushvalue: load_symbol(module, "lua_pushvalue")?,
                lua_pushlstring: load_symbol(module, "lua_pushlstring")?,
                lua_getglobal: load_symbol(module, "lua_getglobal")?,
                lua_l_loadstring: load_symbol(module, "luaL_loadstring")?,
                lua_pcallk: load_symbol(module, "lua_pcallk")?,
            }
        };

        return Some(api);
    }

    None
}

unsafe fn load_symbol<T>(module: Hmodule, name: &str) -> Option<T>
where
    T: Copy,
{
    let symbol = CString::new(name).ok()?;
    let address = GetProcAddress(module, symbol.as_ptr());
    if address.is_null() {
        return None;
    }

    Some(std::mem::transmute_copy(&address))
}

fn lua_error_string(state: *mut LuaState, lua: &LuaApi) -> String {
    lua_to_string_via_tostring(state, lua, -1).unwrap_or_else(|_| "unknown lua error".to_owned())
}

fn lua_to_json(
    state: *mut LuaState,
    lua: &LuaApi,
    index: c_int,
    depth: usize,
) -> Result<Value, String> {
    let value_type = unsafe { (lua.lua_type)(state, index) };
    match value_type {
        LUA_TNIL => Ok(Value::Null),
        LUA_TBOOLEAN => Ok(Value::Bool(unsafe {
            (lua.lua_toboolean)(state, index) != 0
        })),
        LUA_TNUMBER => lua_number_to_json(state, lua, index),
        LUA_TSTRING => Ok(Value::String(lua_string_at(state, lua, index))),
        LUA_TTABLE => lua_table_to_json(state, lua, index, depth),
        LUA_TLIGHTUSERDATA | LUA_TFUNCTION | LUA_TUSERDATA | LUA_TTHREAD => Ok(json!({
            "lua_type": lua_type_name_at(state, lua, index),
            "repr": lua_to_string_via_tostring(state, lua, index)?
        })),
        _ => Ok(Value::String(lua_to_string_via_tostring(
            state, lua, index,
        )?)),
    }
}

fn lua_number_to_json(state: *mut LuaState, lua: &LuaApi, index: c_int) -> Result<Value, String> {
    let mut integer_flag = 0;
    let integer = unsafe { (lua.lua_tointegerx)(state, index, &mut integer_flag) };
    if integer_flag != 0 {
        return Ok(json_integer_value(integer));
    }

    let mut number_flag = 0;
    let number = unsafe { (lua.lua_tonumberx)(state, index, &mut number_flag) };
    if number_flag == 0 {
        return Ok(Value::String(lua_to_string_via_tostring(
            state, lua, index,
        )?));
    }

    match Number::from_f64(number) {
        Some(value) => Ok(Value::Number(value)),
        None => Ok(Value::String(number.to_string())),
    }
}

fn json_integer_value(integer: LuaInteger) -> Value {
    let integer = integer as i64;
    if fits_json_safe_integer(integer) {
        Value::Number(Number::from(integer))
    } else {
        Value::String(integer.to_string())
    }
}

fn fits_json_safe_integer(integer: i64) -> bool {
    integer.unsigned_abs() <= MAX_SAFE_JSON_INTEGER as u64
}

fn lua_table_to_json(
    state: *mut LuaState,
    lua: &LuaApi,
    index: c_int,
    depth: usize,
) -> Result<Value, String> {
    if depth >= STRUCTURED_DEPTH_LIMIT {
        return Ok(json!({
            "lua_type": "table",
            "repr": lua_to_string_via_tostring(state, lua, index)?
        }));
    }

    let abs_index = absolute_index(state, lua, index);
    let _scope = StackScope::new(state, lua);
    let array_len = unsafe { (lua.lua_rawlen)(state, abs_index) };
    let mut array_values = vec![Value::Null; array_len];
    let mut object = Map::new();
    let mut array_only = array_len > 0;

    unsafe {
        (lua.lua_pushnil)(state);
    }

    while unsafe { (lua.lua_next)(state, abs_index) } != 0 {
        let key_abs = absolute_index(state, lua, -2);
        let value_json = lua_to_json(state, lua, -1, depth + 1)?;

        let mut integer_flag = 0;
        let key_integer = unsafe { (lua.lua_tointegerx)(state, key_abs, &mut integer_flag) };
        if integer_flag != 0 && key_integer > 0 && (key_integer as usize) <= array_len {
            array_values[key_integer as usize - 1] = value_json.clone();
        } else {
            array_only = false;
            object.insert(
                lua_to_string_via_tostring(state, lua, key_abs)?,
                value_json.clone(),
            );
        }

        unsafe {
            (lua.lua_settop)(state, -2);
        }
    }

    if array_only && object.is_empty() {
        return Ok(Value::Array(array_values));
    }

    if array_len > 0 {
        object.insert("_array".to_owned(), Value::Array(array_values));
    }

    Ok(Value::Object(object))
}

fn lua_type_name_at(state: *mut LuaState, lua: &LuaApi, index: c_int) -> String {
    let tag = unsafe { (lua.lua_type)(state, index) };
    let ptr = unsafe { (lua.lua_typename)(state, tag) };
    if ptr.is_null() {
        return format!("type-{}", tag);
    }

    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn lua_string_at(state: *mut LuaState, lua: &LuaApi, index: c_int) -> String {
    let mut len = 0usize;
    let ptr = unsafe { (lua.lua_tolstring)(state, index, &mut len) };
    if ptr.is_null() {
        return String::new();
    }

    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    String::from_utf8_lossy(bytes).into_owned()
}

fn lua_to_string_via_tostring(
    state: *mut LuaState,
    lua: &LuaApi,
    index: c_int,
) -> Result<String, String> {
    let tostring = CString::new("tostring").expect("static string");
    let _scope = StackScope::new(state, lua);
    let abs_index = absolute_index(state, lua, index);

    unsafe {
        (lua.lua_getglobal)(state, tostring.as_ptr());
    }
    if unsafe { (lua.lua_type)(state, -1) } != LUA_TFUNCTION {
        return Ok(lua_string_at(state, lua, abs_index));
    }

    unsafe {
        (lua.lua_pushvalue)(state, abs_index);
    }

    let status = unsafe { (lua.lua_pcallk)(state, 1, 1, 0, 0, None) };
    if status != LUA_OK {
        return Err(lua_string_at(state, lua, -1));
    }

    Ok(lua_string_at(state, lua, -1))
}

fn absolute_index(state: *mut LuaState, lua: &LuaApi, index: c_int) -> c_int {
    if index > 0 {
        return index;
    }

    let top = unsafe { (lua.lua_gettop)(state) };
    top + index + 1
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}

struct StackGuard<'a> {
    state: *mut LuaState,
    lua: &'a LuaApi,
    top: c_int,
}

impl<'a> StackGuard<'a> {
    fn new(state: *mut LuaState, lua: &'a LuaApi) -> Self {
        let top = unsafe { (lua.lua_gettop)(state) };
        Self { state, lua, top }
    }
}

impl Drop for StackGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.lua.lua_settop)(self.state, self.top);
        }
    }
}

struct StackScope<'a> {
    state: *mut LuaState,
    lua: &'a LuaApi,
    top: c_int,
}

impl<'a> StackScope<'a> {
    fn new(state: *mut LuaState, lua: &'a LuaApi) -> Self {
        let top = unsafe { (lua.lua_gettop)(state) };
        Self { state, lua, top }
    }
}

impl Drop for StackScope<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.lua.lua_settop)(self.state, self.top);
        }
    }
}

#[cfg(test)]
mod json_integer_tests {
    use serde_json::Value;

    use super::{fits_json_safe_integer, json_integer_value, MAX_SAFE_JSON_INTEGER};

    #[test]
    fn safe_json_integer_threshold_matches_javascript_limit() {
        assert!(fits_json_safe_integer(MAX_SAFE_JSON_INTEGER));
        assert!(fits_json_safe_integer(-MAX_SAFE_JSON_INTEGER));
        assert!(!fits_json_safe_integer(MAX_SAFE_JSON_INTEGER + 1));
        assert!(!fits_json_safe_integer(-(MAX_SAFE_JSON_INTEGER + 1)));
    }

    #[test]
    fn large_lua_integers_become_strings() {
        assert_eq!(
            json_integer_value((MAX_SAFE_JSON_INTEGER + 1) as isize),
            Value::String((MAX_SAFE_JSON_INTEGER + 1).to_string())
        );
        assert_eq!(
            json_integer_value((-(MAX_SAFE_JSON_INTEGER + 1)) as isize),
            Value::String((-(MAX_SAFE_JSON_INTEGER + 1)).to_string())
        );
    }
}
