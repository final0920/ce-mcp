use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use core::ffi::c_void;

use crate::ffi::plugin_api::ExportedFunctions;
use crate::http::server::StreamableHttpServer;
use crate::tools::{self, ToolResponse};

use super::config::RuntimeConfig;
use super::dispatcher::MainThreadDispatcher;

pub struct AppState {
    plugin_id: i32,
    config: RuntimeConfig,
    exported_functions: ExportedFunctions,
    initialized: AtomicBool,
    dispatcher: MainThreadDispatcher,
    http_server: Mutex<StreamableHttpServer>,
}

impl AppState {
    pub fn new(
        plugin_id: i32,
        config: RuntimeConfig,
        exported_functions: ExportedFunctions,
        dispatcher: MainThreadDispatcher,
        http_server: StreamableHttpServer,
    ) -> Self {
        Self {
            plugin_id,
            config,
            exported_functions,
            initialized: AtomicBool::new(false),
            dispatcher,
            http_server: Mutex::new(http_server),
        }
    }

    pub fn mark_initialized(&self) {
        self.initialized.store(true, Ordering::SeqCst);
    }

    pub fn mark_shutdown(&self) {
        self.initialized.store(false, Ordering::SeqCst);
    }

    pub fn plugin_id(&self) -> i32 {
        self.plugin_id
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn main_window_handle(&self) -> Option<*mut c_void> {
        let callback = self.exported_functions.get_main_window_handle?;
        let handle = unsafe { callback() };
        if handle.is_null() {
            return None;
        }

        Some(handle)
    }

    pub fn lua_state_export_available(&self) -> bool {
        self.exported_functions.get_lua_state.is_some()
    }

    pub fn auto_assemble_export_available(&self) -> bool {
        self.exported_functions.auto_assemble.is_some()
    }

    pub fn script_runtime_ready(&self) -> bool {
        self.dispatcher_mode() == "window-message-hook" && self.lua_state_export_available()
    }

    pub fn start_http_server(&self) -> Result<(), String> {
        let mut server = self
            .http_server
            .lock()
            .map_err(|_| "http server lock poisoned".to_owned())?;
        server.start(self.plugin_id)
    }

    pub fn stop_http_server(&self) -> Result<(), String> {
        let mut server = self
            .http_server
            .lock()
            .map_err(|_| "http server lock poisoned".to_owned())?;
        server.stop()
    }

    pub fn stop_dispatcher(&self) -> Result<(), String> {
        self.dispatcher.stop()
    }

    pub fn dispatch_tool(&self, method: &str, params_json: &str) -> ToolResponse {
        if !tools::requires_serialized_dispatch(method) {
            return tools::dispatch_direct(method, params_json);
        }

        let timeout = Duration::from_millis(self.config.dispatch_timeout_ms);
        match self.dispatcher.execute(method, params_json, timeout) {
            Ok(response) => response,
            Err(error) => ToolResponse {
                success: false,
                body_json: error,
            },
        }
    }

    pub fn dispatcher_mode(&self) -> &'static str {
        self.dispatcher.mode()
    }

    pub fn dispatcher_available(&self) -> bool {
        self.dispatcher.is_available()
    }

    pub fn dispatcher(&self) -> &MainThreadDispatcher {
        &self.dispatcher
    }

    #[allow(dead_code)]
    pub fn exported_functions(&self) -> &ExportedFunctions {
        &self.exported_functions
    }
}
