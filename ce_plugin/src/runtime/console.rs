#[cfg(windows)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AllocConsole() -> i32;
        fn FreeConsole() -> i32;
        fn GetConsoleWindow() -> *mut core::ffi::c_void;
        fn SetConsoleOutputCP(code_page: u32) -> i32;
        fn SetConsoleCP(code_page: u32) -> i32;
        fn SetConsoleTitleW(title: *const u16) -> i32;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(hwnd: *mut core::ffi::c_void, cmd_show: i32) -> i32;
        fn SetForegroundWindow(hwnd: *mut core::ffi::c_void) -> i32;
    }

    const SW_SHOW: i32 = 5;

    struct ConsoleState {
        enabled: bool,
        owns_console: bool,
        writer: Option<File>,
        debug_writer: Option<File>,
    }

    static CONSOLE: OnceLock<Mutex<ConsoleState>> = OnceLock::new();

    pub fn initialize(enabled: bool, title: &str, debug_log_path: Option<&Path>) {
        let state = CONSOLE.get_or_init(|| {
            Mutex::new(ConsoleState {
                enabled: false,
                owns_console: false,
                writer: None,
                debug_writer: None,
            })
        });

        let Ok(mut guard) = state.lock() else {
            return;
        };

        if !enabled {
            guard.enabled = false;
            guard.debug_writer = open_debug_log(debug_log_path);
            if guard.debug_writer.is_some() {
                write_line_locked(&mut guard, "信息", "调试文件日志已启用");
            }
            return;
        }
        if guard.enabled {
            if guard.debug_writer.is_none() {
                guard.debug_writer = open_debug_log(debug_log_path);
            }
            return;
        }

        let owns_console = unsafe { AllocConsole() != 0 };
        let writer = OpenOptions::new().write(true).open("CONOUT$").ok();
        if writer.is_none() {
            guard.enabled = false;
            guard.owns_console = false;
            guard.debug_writer = open_debug_log(debug_log_path);
            return;
        }

        if !title.trim().is_empty() {
            let wide = to_wide(title);
            unsafe {
                let _ = SetConsoleOutputCP(65001);
                let _ = SetConsoleCP(65001);
                let _ = SetConsoleTitleW(wide.as_ptr());
            }
        }
        unsafe {
            let hwnd = GetConsoleWindow();
            if !hwnd.is_null() {
                let _ = ShowWindow(hwnd, SW_SHOW);
                let _ = SetForegroundWindow(hwnd);
            }
        }

        guard.enabled = true;
        guard.owns_console = owns_console;
        guard.writer = writer;
        guard.debug_writer = open_debug_log(debug_log_path);
        write_line_locked(&mut guard, "信息", "控制台日志已启用，编码已切换到 UTF-8");
        if guard.debug_writer.is_some() {
            write_line_locked(&mut guard, "信息", "调试文件日志已启用");
        }
    }

    pub fn shutdown() {
        let Some(state) = CONSOLE.get() else {
            return;
        };
        let Ok(mut guard) = state.lock() else {
            return;
        };

        if guard.enabled || guard.debug_writer.is_some() {
            write_line_locked(&mut guard, "信息", "日志系统已关闭");
        }

        guard.writer = None;
        guard.debug_writer = None;
        let owns_console = guard.owns_console;
        guard.enabled = false;
        guard.owns_console = false;

        if owns_console {
            unsafe {
                let _ = FreeConsole();
            }
        }
    }

    pub fn info(message: impl AsRef<str>) {
        write_line("信息", message.as_ref());
    }

    pub fn warn(message: impl AsRef<str>) {
        write_line("警告", message.as_ref());
    }

    pub fn error(message: impl AsRef<str>) {
        write_line("错误", message.as_ref());
    }

    fn write_line(level: &str, message: &str) {
        let Some(state) = CONSOLE.get() else {
            return;
        };
        let Ok(mut guard) = state.lock() else {
            return;
        };
        if !guard.enabled && guard.debug_writer.is_none() {
            return;
        }

        write_line_locked(&mut guard, level, message);
    }

    fn write_line_locked(state: &mut ConsoleState, level: &str, message: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or(0);
        let line = format!("[ce_plugin][{}][{}] {}", ts, level, message);

        if let Some(writer) = state.writer.as_mut() {
            let _ = writeln!(writer, "{}", line);
            let _ = writer.flush();
        }
        if let Some(debug_writer) = state.debug_writer.as_mut() {
            let _ = writeln!(debug_writer, "{}", line);
            let _ = debug_writer.flush();
        }
    }

    fn open_debug_log(path: Option<&Path>) -> Option<File> {
        let path = path?;
        OpenOptions::new().create(true).append(true).open(path).ok()
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    pub fn initialize(_enabled: bool, _title: &str, _debug_log_path: Option<&Path>) {}
    pub fn shutdown() {}
    pub fn info(_message: impl AsRef<str>) {}
    pub fn warn(_message: impl AsRef<str>) {}
    pub fn error(_message: impl AsRef<str>) {}
}

pub use imp::{error, info, initialize, shutdown, warn};
