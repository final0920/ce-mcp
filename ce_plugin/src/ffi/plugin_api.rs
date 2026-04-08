use core::ffi::{c_char, c_void};
use core::{mem, ptr};

pub const PLUGIN_VERSION_SDK: i32 = 6;

pub type CepShowMessage = unsafe extern "system" fn(message: *const c_char);
pub type CepGetLuaState = unsafe extern "system" fn() -> *mut c_void;
pub type CepRegisterFunction =
    unsafe extern "system" fn(plugin_id: i32, function_type: i32, init: *mut c_void) -> i32;
pub type CepUnregisterFunction = unsafe extern "system" fn(plugin_id: i32, function_id: i32) -> i32;
pub type CepGetMainWindowHandle = unsafe extern "system" fn() -> *mut c_void;
pub type CepAutoAssemble = unsafe extern "system" fn(script: *const c_char) -> i32;
pub type CepProcessList =
    unsafe extern "system" fn(list_buffer: *mut c_char, list_size: i32) -> i32;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PluginVersion {
    pub version: i32,
    pub plugin_name: *const c_char,
}

#[derive(Clone, Copy)]
pub struct ExportedFunctions {
    pub sizeof_exported_functions: i32,
    pub show_message: Option<CepShowMessage>,
    pub register_function: Option<CepRegisterFunction>,
    pub unregister_function: Option<CepUnregisterFunction>,
    pub opened_process_id: *mut u32,
    pub opened_process_handle: *mut *mut c_void,
    pub get_main_window_handle: Option<CepGetMainWindowHandle>,
    pub auto_assemble: Option<CepAutoAssemble>,
    pub process_list: Option<CepProcessList>,
    pub get_lua_state: Option<CepGetLuaState>,
}

impl ExportedFunctions {
    // SDK slot indexes after sizeofExportedFunctions (see cepluginsdk.h)
    const SLOT_SHOW_MESSAGE: usize = 0;
    const SLOT_REGISTER_FUNCTION: usize = 1;
    const SLOT_UNREGISTER_FUNCTION: usize = 2;
    const SLOT_OPENED_PROCESS_ID: usize = 3;
    const SLOT_OPENED_PROCESS_HANDLE: usize = 4;
    const SLOT_GET_MAIN_WINDOW_HANDLE: usize = 5;
    const SLOT_AUTO_ASSEMBLE: usize = 6;
    const SLOT_PROCESS_LIST: usize = 14;
    const SLOT_GET_LUA_STATE: usize = 156;

    fn base_offset() -> usize {
        let align = mem::size_of::<usize>();
        (mem::size_of::<i32>() + (align - 1)) & !(align - 1)
    }

    fn slot_offset(slot: usize) -> usize {
        Self::base_offset() + slot * mem::size_of::<usize>()
    }

    pub fn required_size() -> i32 {
        (Self::slot_offset(Self::SLOT_GET_MAIN_WINDOW_HANDLE) + mem::size_of::<usize>()) as i32
    }

    unsafe fn read_copy<T: Copy>(raw: *const u8, offset: usize) -> T {
        ptr::read(raw.add(offset).cast::<T>())
    }

    unsafe fn read_optional<T: Copy>(
        raw: *const u8,
        advertised_size: i32,
        slot: usize,
    ) -> Option<T> {
        let offset = Self::slot_offset(slot);
        if (advertised_size as usize) < offset + mem::size_of::<usize>() {
            return None;
        }
        Some(Self::read_copy(raw, offset))
    }

    pub unsafe fn read_from_ptr(raw: *const ExportedFunctions) -> Option<Self> {
        if raw.is_null() {
            return None;
        }

        let raw_bytes = raw.cast::<u8>();
        let advertised_size = ptr::read(raw.cast::<i32>());
        if advertised_size < Self::required_size() {
            return None;
        }

        Some(Self {
            sizeof_exported_functions: advertised_size,
            show_message: Self::read_optional(raw_bytes, advertised_size, Self::SLOT_SHOW_MESSAGE)
                .flatten(),
            register_function: Self::read_optional(
                raw_bytes,
                advertised_size,
                Self::SLOT_REGISTER_FUNCTION,
            )
            .flatten(),
            unregister_function: Self::read_optional(
                raw_bytes,
                advertised_size,
                Self::SLOT_UNREGISTER_FUNCTION,
            )
            .flatten(),
            opened_process_id: Self::read_optional(
                raw_bytes,
                advertised_size,
                Self::SLOT_OPENED_PROCESS_ID,
            )
            .unwrap_or(ptr::null_mut()),
            opened_process_handle: Self::read_optional(
                raw_bytes,
                advertised_size,
                Self::SLOT_OPENED_PROCESS_HANDLE,
            )
            .unwrap_or(ptr::null_mut()),
            get_main_window_handle: Self::read_optional(
                raw_bytes,
                advertised_size,
                Self::SLOT_GET_MAIN_WINDOW_HANDLE,
            )
            .flatten(),
            auto_assemble: Self::read_optional(
                raw_bytes,
                advertised_size,
                Self::SLOT_AUTO_ASSEMBLE,
            )
            .flatten(),
            process_list: Self::read_optional(raw_bytes, advertised_size, Self::SLOT_PROCESS_LIST)
                .flatten(),
            get_lua_state: Self::read_optional(
                raw_bytes,
                advertised_size,
                Self::SLOT_GET_LUA_STATE,
            )
            .flatten(),
        })
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
