use core::ffi::{c_char, c_void};
use core::{mem, ptr};

pub const PLUGIN_VERSION_SDK: i32 = 6;

pub type CepShowMessage = unsafe extern "system" fn(message: *const c_char);
pub type CepGetLuaState = unsafe extern "system" fn() -> *mut c_void;
pub type CepRegisterFunction =
    unsafe extern "system" fn(plugin_id: i32, function_type: i32, init: *mut c_void) -> i32;
pub type CepUnregisterFunction = unsafe extern "system" fn(plugin_id: i32, function_id: i32) -> i32;
pub type CepGetMainWindowHandle = unsafe extern "system" fn() -> *mut c_void;
pub type CepProcessList =
    unsafe extern "system" fn(list_buffer: *mut c_char, list_size: i32) -> i32;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PluginVersion {
    pub version: i32,
    pub plugin_name: *const c_char,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExportedFunctions {
    pub sizeof_exported_functions: i32,
    pub show_message: Option<CepShowMessage>,
    pub register_function: Option<CepRegisterFunction>,
    pub unregister_function: Option<CepUnregisterFunction>,
    pub opened_process_id: *mut u32,
    pub opened_process_handle: *mut *mut c_void,
    pub get_main_window_handle: Option<CepGetMainWindowHandle>,
    pub process_list: Option<CepProcessList>,
    pub get_lua_state: Option<CepGetLuaState>,
}

impl ExportedFunctions {
    pub fn required_size() -> i32 {
        mem::size_of::<ExportedFunctions>() as i32
    }

    pub unsafe fn read_from_ptr(raw: *const ExportedFunctions) -> Option<Self> {
        if raw.is_null() {
            return None;
        }

        let advertised_size = ptr::read(raw.cast::<i32>());
        if advertised_size < Self::required_size() {
            return None;
        }

        Some(ptr::read(raw))
    }

    pub fn is_supported_sdk(&self) -> bool {
        self.sizeof_exported_functions >= Self::required_size()
    }
}

// Safety: this struct is a copied CE function/address table snapshot.
// We treat it as immutable process state and never mutate through these pointers
// from arbitrary threads without an explicit CE main-thread dispatch path.
unsafe impl Send for ExportedFunctions {}
unsafe impl Sync for ExportedFunctions {}
