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
pub const MEM_COMMIT: Dword = 0x0000_1000;
pub const MEM_RESERVE: Dword = 0x0000_2000;
pub const MEM_FREE: Dword = 0x0001_0000;
pub const PAGE_NOACCESS: Dword = 0x01;
pub const PAGE_READONLY: Dword = 0x02;
pub const PAGE_READWRITE: Dword = 0x04;
pub const PAGE_WRITECOPY: Dword = 0x08;
pub const PAGE_EXECUTE: Dword = 0x10;
pub const PAGE_EXECUTE_READ: Dword = 0x20;
pub const PAGE_EXECUTE_READWRITE: Dword = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: Dword = 0x80;
pub const PAGE_GUARD: Dword = 0x100;
pub const PAGE_NOCACHE: Dword = 0x200;
pub const PAGE_WRITECOMBINE: Dword = 0x400;
const USER_ADDRESS_LIMIT_X64: usize = 0x0000_7FFF_FFFF_FFFF;
const USER_ADDRESS_LIMIT_X86: usize = 0x7FFE_FFFF;

#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(handle: Handle) -> Bool;
    fn CreateToolhelp32Snapshot(flags: Dword, process_id: Dword) -> Handle;
    fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry32W) -> Bool;
    fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry32W) -> Bool;
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> Bool;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> Bool;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: Dword,
        exe_name: *mut u16,
        size: *mut Dword,
    ) -> Bool;

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
    fn VirtualQueryEx(
        process: Handle,
        address: *const c_void,
        buffer: *mut MemoryBasicInformation,
        length: SizeT,
    ) -> SizeT;
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

#[repr(C)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: Dword,
    partition_id: u16,
    region_size: SizeT,
    state: Dword,
    protect: Dword,
    type_: Dword,
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

#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
}

pub fn query_process_image_name(process: Handle) -> Result<String, String> {
    if process.is_null() {
        return Err("process handle is null".to_owned());
    }

    let mut buffer = vec![0u16; 260];
    let mut size = buffer.len() as Dword;

    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size) };
    if ok == 0 {
        return Err("QueryFullProcessImageNameW failed".to_owned());
    }

    buffer.truncate(size as usize);
    Ok(String::from_utf16_lossy(&buffer))
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

pub fn enum_memory_regions(
    process: Handle,
    max_regions: Option<usize>,
) -> Result<Vec<MemoryRegionInfo>, String> {
    if process.is_null() {
        return Err("process handle is null".to_owned());
    }

    let mut address = 0usize;
    let limit = user_address_limit();
    let mut regions = Vec::new();

    while address < limit {
        if let Some(max_regions) = max_regions {
            if regions.len() >= max_regions {
                break;
            }
        }

        let mut info = MemoryBasicInformation {
            base_address: core::ptr::null_mut(),
            allocation_base: core::ptr::null_mut(),
            allocation_protect: 0,
            partition_id: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            type_: 0,
        };
        let queried = unsafe {
            VirtualQueryEx(
                process,
                address as *const c_void,
                &mut info,
                core::mem::size_of::<MemoryBasicInformation>(),
            )
        };
        if queried == 0 {
            break;
        }

        let base_address = info.base_address as usize;
        let region_size = info.region_size.max(0x1000);
        regions.push(MemoryRegionInfo {
            base_address,
            allocation_base: info.allocation_base as usize,
            allocation_protect: info.allocation_protect,
            region_size,
            state: info.state,
            protect: info.protect,
            type_: info.type_,
        });

        let next_address = base_address.saturating_add(region_size);
        if next_address <= address {
            break;
        }
        address = next_address;
    }

    Ok(regions)
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

pub fn user_address_limit() -> usize {
    if cfg!(target_pointer_width = "64") {
        USER_ADDRESS_LIMIT_X64
    } else {
        USER_ADDRESS_LIMIT_X86
    }
}

pub fn is_region_committed(region: &MemoryRegionInfo) -> bool {
    region.state == MEM_COMMIT
}

pub fn is_region_guarded(region: &MemoryRegionInfo) -> bool {
    region.protect & PAGE_GUARD != 0
}

pub fn is_region_readable(region: &MemoryRegionInfo) -> bool {
    let base = region.protect & 0xFF;
    matches!(
        base,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

pub fn is_region_writable(region: &MemoryRegionInfo) -> bool {
    let base = region.protect & 0xFF;
    matches!(
        base,
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

pub fn is_region_executable(region: &MemoryRegionInfo) -> bool {
    let base = region.protect & 0xFF;
    matches!(
        base,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

pub fn is_region_copy_on_write(region: &MemoryRegionInfo) -> bool {
    let base = region.protect & 0xFF;
    matches!(base, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)
}

pub fn is_region_usable(region: &MemoryRegionInfo) -> bool {
    is_region_committed(region) && !is_region_guarded(region) && region.protect & PAGE_NOACCESS == 0
}

pub fn protection_to_string(protect: u32) -> String {
    let mut text = String::new();
    let base = protect & 0xFF;

    if matches!(
        base,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    ) {
        text.push('R');
    }
    if matches!(
        base,
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    ) {
        text.push('W');
    }
    if matches!(
        base,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    ) {
        text.push('X');
    }
    if matches!(base, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY) {
        text.push('C');
    }
    if protect & PAGE_GUARD != 0 {
        text.push('G');
    }
    if protect & PAGE_NOCACHE != 0 {
        text.push('N');
    }
    if protect & PAGE_WRITECOMBINE != 0 {
        text.push('M');
    }
    if text.is_empty() {
        format!("0x{:X}", protect)
    } else {
        text
    }
}
