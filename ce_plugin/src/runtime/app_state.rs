use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use core::ffi::c_void;

use crate::ffi::plugin_api::ExportedFunctions;
use crate::http::server::StreamableHttpServer;
use crate::tools::{self, ToolResponse};

use super::discovery::{InstanceRegistryHandle, InstanceRegistryRecord};
use super::dispatcher::MainThreadDispatcher;
use super::instance::RuntimeInstance;
use super::RuntimeConfig;

pub struct AppState {
    plugin_id: i32,
    config: RuntimeConfig,
    exported_functions: ExportedFunctions,
    initialized: AtomicBool,
    dispatcher: MainThreadDispatcher,
    http_server: Mutex<StreamableHttpServer>,
    instance: RuntimeInstance,
    registry: Mutex<Option<InstanceRegistryHandle>>,
}

impl AppState {
    pub fn new(
        plugin_id: i32,
        config: RuntimeConfig,
        exported_functions: ExportedFunctions,
        dispatcher: MainThreadDispatcher,
        http_server: StreamableHttpServer,
        instance: RuntimeInstance,
    ) -> Self {
        Self {
            plugin_id,
            config,
            exported_functions,
            initialized: AtomicBool::new(false),
            dispatcher,
            http_server: Mutex::new(http_server),
            instance,
            registry: Mutex::new(None),
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

    pub fn instance_id(&self) -> &str {
        self.instance.instance_id()
    }

    pub fn ce_process_id(&self) -> u32 {
        self.instance.ce_process_id()
    }

    pub fn target_process_id(&self) -> u32 {
        if self.exported_functions.opened_process_id.is_null() {
            return 0;
        }

        unsafe { self.exported_functions.opened_process_id.read_volatile() }
    }

    pub fn bind_addr(&self) -> String {
        self.instance.bind_addr()
    }

    pub fn requested_bind_addr(&self) -> &str {
        self.instance.requested_bind_addr()
    }

    pub fn debug_log_path(&self) -> Option<&std::path::Path> {
        self.instance.debug_log_path()
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

    pub fn start_http_server(&self) -> Result<String, String> {
        let mut server = self
            .http_server
            .lock()
            .map_err(|_| "http server lock poisoned".to_owned())?;
        let bind_addr = server.start(self.plugin_id)?;
        self.instance.set_bind_addr(bind_addr.clone());
        Ok(bind_addr)
    }

    pub fn stop_http_server(&self) -> Result<(), String> {
        let mut server = self
            .http_server
            .lock()
            .map_err(|_| "http server lock poisoned".to_owned())?;
        server.stop()
    }

    pub fn start_instance_registry(self: &Arc<Self>) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "instance registry lock poisoned".to_owned())?;
        if registry.is_some() {
            return Ok(());
        }

        let handle = InstanceRegistryHandle::start(Arc::clone(self))?;
        *registry = Some(handle);
        Ok(())
    }

    pub fn stop_instance_registry(&self) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "instance registry lock poisoned".to_owned())?;
        let Some(mut handle) = registry.take() else {
            return Ok(());
        };
        handle.stop()
    }

    pub fn instance_registry_record(&self) -> InstanceRegistryRecord {
        InstanceRegistryRecord {
            schema_version: 1,
            instance_id: self.instance_id().to_owned(),
            ce_pid: self.ce_process_id(),
            target_pid: self.target_process_id(),
            plugin_id: self.instance.plugin_id(),
            bind_addr: self.bind_addr(),
            requested_bind_addr: self.requested_bind_addr().to_owned(),
            dll_path: self
                .instance
                .dll_path()
                .map(|path| path.display().to_string()),
            debug_log_path: self.debug_log_path().map(|path| path.display().to_string()),
            transport: "http".to_owned(),
            server_name: self.config.server_name.clone(),
            server_version: self.config.server_version.clone(),
            started_at_unix_ms: self.instance.started_at_unix_ms(),
            last_heartbeat_unix_ms: current_unix_ms(),
        }
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

fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}
