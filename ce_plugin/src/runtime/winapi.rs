//! Minimal host-side Windows API surface.
//!
//! Primary process/module/memory flows should prefer the embedded CE/Lua backend.
//! This module only keeps the宿主兜底能力 that still cannot be sourced from Lua:
//! - Toolhelp32 module/thread snapshots for fallback metadata
//! - raw ReadProcessMemory / WriteProcessMemory for the few remaining low-level helpers
//! Scan-specific region enumeration/signature/checksum flows are intentionally kept out of here.
//! Avoid reintroducing higher-level business logic here.

use core::ffi::c_void;

type Bool = i32;
type Dword = u32;
type SizeT = usize;
type Handle = *mut c_void;
type Hmodule = *mut c_void;

const TH32CS_SNAPMODULE: Dword = 0x0000_0008;
const TH32CS_SNAPMODULE32: Dword = 0x0000_0010;
const TH32CS_SNAPTHREAD: Dword = 0x0000_0004;
const INVALID_HANDLE_VALUE: isize = -1;

#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(handle: Handle) -> Bool;
    fn CreateToolhelp32Snapshot(flags: Dword, process_id: Dword) -> Handle;
    fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry32W) -> Bool;
    fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry32W) -> Bool;
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> Bool;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> Bool;

    fn ReadProcessMemory(
        process: Handle,
        base_address: *const c_void,
        buffer: *mut c_void,
        size: SizeT,
        number_of_bytes_read: *mut SizeT,
    ) -> Bool;

    fn WriteProcessMemory(
        process: Handle,
        base_address: *mut c_void,
        buffer: *const c_void,
        size: SizeT,
        number_of_bytes_written: *mut SizeT,
    ) -> Bool;
}

#[repr(C)]
struct ModuleEntry32W {
    dw_size: Dword,
    th32_module_id: Dword,
    th32_process_id: Dword,
    glblcnt_usage: Dword,
    proccnt_usage: Dword,
    mod_base_addr: *mut u8,
    mod_base_size: Dword,
    h_module: Hmodule,
    sz_module: [u16; 256],
    sz_exe_path: [u16; 260],
}

#[repr(C)]
struct ThreadEntry32 {
    dw_size: Dword,
    cnt_usage: Dword,
    th32_thread_id: Dword,
    th32_owner_process_id: Dword,
    tp_base_pri: i32,
    tp_delta_pri: i32,
    dw_flags: Dword,
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: usize,
    pub size: u32,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub owner_process_id: u32,
}

pub fn enum_modules(process_id: u32) -> Result<Vec<ModuleInfo>, String> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };
    if snapshot as isize == INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateToolhelp32Snapshot(module) failed for pid {}",
            process_id
        ));
    }

    let mut modules = Vec::new();
    let mut entry = ModuleEntry32W {
        dw_size: core::mem::size_of::<ModuleEntry32W>() as Dword,
        th32_module_id: 0,
        th32_process_id: 0,
        glblcnt_usage: 0,
        proccnt_usage: 0,
        mod_base_addr: core::ptr::null_mut(),
        mod_base_size: 0,
        h_module: core::ptr::null_mut(),
        sz_module: [0; 256],
        sz_exe_path: [0; 260],
    };

    let mut ok = unsafe { Module32FirstW(snapshot, &mut entry) };
    while ok != 0 {
        modules.push(ModuleInfo {
            name: utf16_z_to_string(&entry.sz_module),
            base_address: entry.mod_base_addr as usize,
            size: entry.mod_base_size,
            path: utf16_z_to_string(&entry.sz_exe_path),
        });
        entry.dw_size = core::mem::size_of::<ModuleEntry32W>() as Dword;
        ok = unsafe { Module32NextW(snapshot, &mut entry) };
    }

    unsafe {
        CloseHandle(snapshot);
    }
    Ok(modules)
}

pub fn enum_threads(process_id: u32) -> Result<Vec<ThreadInfo>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot as isize == INVALID_HANDLE_VALUE {
        return Err("CreateToolhelp32Snapshot(thread) failed".to_owned());
    }

    let mut threads = Vec::new();
    let mut entry = ThreadEntry32 {
        dw_size: core::mem::size_of::<ThreadEntry32>() as Dword,
        cnt_usage: 0,
        th32_thread_id: 0,
        th32_owner_process_id: 0,
        tp_base_pri: 0,
        tp_delta_pri: 0,
        dw_flags: 0,
    };

    let mut ok = unsafe { Thread32First(snapshot, &mut entry) };
    while ok != 0 {
        if entry.th32_owner_process_id == process_id {
            threads.push(ThreadInfo {
                thread_id: entry.th32_thread_id,
                owner_process_id: entry.th32_owner_process_id,
            });
        }
        entry.dw_size = core::mem::size_of::<ThreadEntry32>() as Dword;
        ok = unsafe { Thread32Next(snapshot, &mut entry) };
    }

    unsafe {
        CloseHandle(snapshot);
    }
    Ok(threads)
}

pub fn read_process_memory(
    process: Handle,
    address: usize,
    size: usize,
) -> Result<Vec<u8>, String> {
    if process.is_null() {
        return Err("process handle is null".to_owned());
    }
    if address == 0 {
        return Err("address is null".to_owned());
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            buffer.as_mut_ptr().cast::<c_void>(),
            size,
            &mut bytes_read,
        )
    };
    if ok == 0 {
        return Err(format!("ReadProcessMemory failed at 0x{address:X}"));
    }

    buffer.truncate(bytes_read);
    if bytes_read != size {
        return Err(format!(
            "ReadProcessMemory returned {} bytes, expected {}",
            bytes_read, size
        ));
    }

    Ok(buffer)
}

pub fn write_process_memory(process: Handle, address: usize, data: &[u8]) -> Result<(), String> {
    if process.is_null() {
        return Err("process handle is null".to_owned());
    }
    if address == 0 {
        return Err("address is null".to_owned());
    }
    if data.is_empty() {
        return Ok(());
    }

    let mut bytes_written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            address as *mut c_void,
            data.as_ptr().cast::<c_void>(),
            data.len(),
            &mut bytes_written,
        )
    };
    if ok == 0 {
        return Err(format!("WriteProcessMemory failed at 0x{address:X}"));
    }
    if bytes_written != data.len() {
        return Err(format!(
            "WriteProcessMemory wrote {} bytes, expected {}",
            bytes_written,
            data.len()
        ));
    }

    Ok(())
}

fn utf16_z_to_string(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}
