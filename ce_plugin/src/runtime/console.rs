#[cfg(windows)]
mod imp {
    use std::fs::OpenOptions;
    use std::io::Write;
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
        writer: Option<std::fs::File>,
    }

    static CONSOLE: OnceLock<Mutex<ConsoleState>> = OnceLock::new();

    pub fn initialize(enabled: bool, title: &str) {
        let state = CONSOLE.get_or_init(|| {
            Mutex::new(ConsoleState {
                enabled: false,
                owns_console: false,
                writer: None,
            })
        });

        let Ok(mut guard) = state.lock() else {
            return;
        };

        if !enabled {
            guard.enabled = false;
            return;
        }
        if guard.enabled {
            return;
        }

        let owns_console = unsafe { AllocConsole() != 0 };
        let writer = OpenOptions::new().write(true).open("CONOUT$").ok();
        if writer.is_none() {
            guard.enabled = false;
            guard.owns_console = false;
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
        write_line_locked(&mut guard, "信息", "控制台日志已启用，编码已切换到 UTF-8");
    }

    pub fn shutdown() {
        let Some(state) = CONSOLE.get() else {
            return;
        };
        let Ok(mut guard) = state.lock() else {
            return;
        };

        if guard.enabled {
            write_line_locked(&mut guard, "信息", "控制台日志已关闭");
        }

        guard.writer = None;
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
        if !guard.enabled {
            return;
        }

        write_line_locked(&mut guard, level, message);
    }

    fn write_line_locked(state: &mut ConsoleState, level: &str, message: &str) {
        let Some(writer) = state.writer.as_mut() else {
            return;
        };

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or(0);
        let _ = writeln!(writer, "[ce_plugin][{}][{}] {}", ts, level, message);
        let _ = writer.flush();
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn initialize(_enabled: bool, _title: &str) {}
    pub fn shutdown() {}
    pub fn info(_message: impl AsRef<str>) {}
    pub fn warn(_message: impl AsRef<str>) {}
    pub fn error(_message: impl AsRef<str>) {}
}

pub use imp::{error, info, initialize, shutdown, warn};
