mod domain;
mod ffi;
mod http;
mod runtime;
mod tools;

use core::ffi::c_char;

use ffi::plugin_api::{ExportedFunctions, PluginVersion, PLUGIN_VERSION_SDK};

static PLUGIN_NAME: &[u8] = "流云MCP插件\0".as_bytes();

#[no_mangle]
pub extern "system" fn InitializePlugin(
    exported_functions: *mut ExportedFunctions,
    plugin_id: i32,
) -> bool {
    runtime::init_runtime(plugin_id, exported_functions.cast_const());
    true
}

#[no_mangle]
pub extern "system" fn DisablePlugin() {
    runtime::shutdown_runtime();
}

#[no_mangle]
pub extern "system" fn GetVersion(version: *mut PluginVersion, version_size: i32) -> bool {
    if version.is_null() || version_size < core::mem::size_of::<PluginVersion>() as i32 {
        return false;
    }

    unsafe {
        version.write(PluginVersion {
            version: PLUGIN_VERSION_SDK,
            plugin_name: PLUGIN_NAME.as_ptr().cast::<c_char>(),
        });
    }

    true
}
