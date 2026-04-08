mod app_state;
mod config;
pub mod console;
mod dispatcher;

use std::thread;
use std::time::Duration;

use std::sync::{Arc, OnceLock};

use crate::ffi::plugin_api::ExportedFunctions;
use crate::http::server::StreamableHttpServer;
use app_state::AppState;
pub use config::RuntimeConfig;
use dispatcher::MainThreadDispatcher;

#[derive(Debug, Clone)]
pub(crate) struct ModuleInfo {
    pub(crate) name: String,
    pub(crate) base_address: usize,
    pub(crate) size: u32,
    pub(crate) path: String,
}

static APP_STATE: OnceLock<Arc<AppState>> = OnceLock::new();

pub fn build_version() -> String {
    match option_env!("CE_PLUGIN_GIT_SHA") {
        Some(sha) if !sha.is_empty() && sha != "nogit" => {
            format!("{}+{}", env!("CARGO_PKG_VERSION"), sha)
        }
        _ => env!("CARGO_PKG_VERSION").to_owned(),
    }
}

pub fn init_runtime(plugin_id: i32, exported_functions: *const ExportedFunctions) {
    let Some(exported_functions) =
        (unsafe { ExportedFunctions::read_from_ptr(exported_functions) })
    else {
        return;
    };
    if !exported_functions.is_supported_sdk() {
        return;
    }

    let config = RuntimeConfig::load();
    console::initialize(config.console_log_enabled, config.console_title.as_str());
    if let Err(error) = config.validate_startup_policy() {
        console::error(format!("启动策略校验失败: {}", error));
        return;
    }
    console::info(format!(
        "插件启动中: version={} plugin_id={} 监听地址={} allow_remote={} auth_enabled={} 超时={}ms",
        build_version(),
        plugin_id,
        config.bind_addr,
        config.allow_remote,
        config.auth_enabled,
        config.dispatch_timeout_ms
    ));
    let dispatcher = MainThreadDispatcher::new();
    let server = StreamableHttpServer::new(
        config.bind_addr.clone(),
        config.allow_remote,
        config.auth_enabled,
        config.auth_token.clone(),
    );
    let app = Arc::new(AppState::new(
        plugin_id,
        config,
        exported_functions,
        dispatcher,
        server,
    ));

    if APP_STATE.set(Arc::clone(&app)).is_ok() {
        app.mark_initialized();
        if !try_start_window_dispatcher(&app) {
            console::warn("主窗口消息钩子不可用，已回退到串行工作线程调度");
            start_serialized_dispatcher(Arc::clone(&app));
        } else {
            console::info("主窗口消息钩子调度已激活");
        }
        console::info(format!(
            "运行模式: dispatcher_mode={} dispatcher_available={} lua_state_export_available={} auto_assemble_export_available={} script_runtime_ready={}",
            app.dispatcher_mode(),
            app.dispatcher_available(),
            app.lua_state_export_available(),
            app.auto_assemble_export_available(),
            app.script_runtime_ready()
        ));
        match app.start_http_server() {
            Ok(()) => console::info(format!("HTTP 服务已启动，监听 {}", app.config().bind_addr)),
            Err(error) => console::error(format!("HTTP 服务启动失败: {}", error)),
        }
    } else {
        console::warn("运行时已初始化，重复的 InitializePlugin 已忽略");
    }
}

pub fn shutdown_runtime() {
    if let Some(app) = APP_STATE.get() {
        console::info("插件运行时正在关闭");
        if let Err(error) = app.stop_http_server() {
            console::error(format!("HTTP 服务停止失败: {}", error));
        }
        if let Err(error) = app.stop_dispatcher() {
            console::error(format!("调度器停止失败: {}", error));
        }
        app.mark_shutdown();
    }
    console::shutdown();
}

pub fn app_state() -> Option<&'static Arc<AppState>> {
    APP_STATE.get()
}

fn try_start_window_dispatcher(app: &Arc<AppState>) -> bool {
    let Some(main_window) = app.main_window_handle() else {
        console::warn("无法获取主窗口句柄，不能安装调度钩子");
        return false;
    };

    match app.dispatcher().start(main_window) {
        Ok(()) => true,
        Err(error) => {
            console::warn(format!("安装调度钩子失败: {}", error));
            false
        }
    }
}

fn start_serialized_dispatcher(app: Arc<AppState>) {
    let _ = thread::Builder::new()
        .name("ce_plugin_serial_dispatcher".to_owned())
        .spawn(move || {
            if let Err(error) = app.dispatcher().attach_executor() {
                console::error(format!("串行调度器附加失败: {}", error));
                return;
            }
            console::info("串行调度工作线程已附加");

            loop {
                match app.dispatcher().wait_for_job(Duration::from_millis(50)) {
                    Ok(Some(job)) => {
                        let response = crate::tools::dispatch_direct(
                            job.method.as_str(),
                            job.payload.as_str(),
                        );
                        let _ = job.finish(response);
                    }
                    Ok(None) => {
                        if !app.dispatcher_available() {
                            break;
                        }
                    }
                    Err(error) => {
                        console::error(format!("串行调度等待失败: {}", error));
                        break;
                    }
                }
            }

            if let Err(error) = app.dispatcher().detach_executor() {
                console::error(format!("串行调度器分离失败: {}", error));
            }
            console::info("串行调度工作线程已分离");
        });
}
