mod app_state;
mod config;
pub mod console;
mod discovery;
mod dispatcher;
mod instance;

use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use crate::ffi::plugin_api::ExportedFunctions;
use crate::http::server::StreamableHttpServer;
use app_state::AppState;
pub use config::RuntimeConfig;
use dispatcher::MainThreadDispatcher;
use instance::RuntimeInstance;

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
    let instance = RuntimeInstance::new(plugin_id, &config);

    console::initialize(
        config.console_log_enabled,
        config.console_title.as_str(),
        instance.debug_log_path(),
    );
    if let Err(error) = config.validate_startup_policy() {
        console::error(format!("启动策略校验失败: {}", error));
        return;
    }

    let requested_bind_addr = config.requested_bind_addr.clone();
    console::info(format!(
        concat!(
            "插件启动中: version={} plugin_id={} instance_id={} ce_pid={} ",
            "target_pid={} 请求监听={} auto_port={} allow_remote={} ",
            "auth_enabled={} 调试日志={} 超时={}ms"
        ),
        build_version(),
        plugin_id,
        instance.instance_id(),
        instance.ce_process_id(),
        unsafe {
            exported_functions
                .opened_process_id
                .as_ref()
                .copied()
                .unwrap_or(0)
        },
        requested_bind_addr,
        config.uses_auto_port(),
        config.allow_remote,
        config.auth_enabled,
        config.debug_enabled,
        config.dispatch_timeout_ms
    ));
    if let Some(path) = instance.debug_log_path() {
        console::info(format!("实例调试日志文件: {}", path.display()));
    }

    let dispatcher = MainThreadDispatcher::new();
    let server = StreamableHttpServer::new(
        config.requested_bind_addr.clone(),
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
        instance,
    ));

    if APP_STATE.set(Arc::clone(&app)).is_ok() {
        app.mark_initialized();
        if !try_start_window_dispatcher(&app) {
            console::warn("主窗口消息 hook 不可用，已回退到串行工作线程调度");
            start_serialized_dispatcher(Arc::clone(&app));
        } else {
            console::info("主窗口消息 hook 调度已激活");
        }
        console::info(format!(
            concat!(
                "运行模式: dispatcher_mode={} dispatcher_available={} ",
                "lua_state_export_available={} auto_assemble_export_available={} ",
                "script_runtime_ready={}"
            ),
            app.dispatcher_mode(),
            app.dispatcher_available(),
            app.lua_state_export_available(),
            app.auto_assemble_export_available(),
            app.script_runtime_ready()
        ));
        match app.start_http_server() {
            Ok(bind_addr) => {
                console::info(format!(
                    "HTTP 服务已启动，监听 {} (requested={})",
                    bind_addr,
                    app.requested_bind_addr()
                ));
                match app.start_instance_registry() {
                    Ok(()) => console::info("实例 discovery 已注册到本地实例目录"),
                    Err(error) => console::error(format!("实例 discovery 启动失败: {}", error)),
                }
            }
            Err(error) => console::error(format!("HTTP 服务启动失败: {}", error)),
        }
    } else {
        console::warn("运行时已初始化，重复的 InitializePlugin 已忽略");
    }
}

pub fn shutdown_runtime() {
    if let Some(app) = APP_STATE.get() {
        console::info("插件运行时正在关闭");
        if let Err(error) = app.stop_instance_registry() {
            console::error(format!("实例 discovery 停止失败: {}", error));
        }
        if let Err(error) = app.stop_http_server() {
            console::error(format!("HTTP 服务停止失败: {}", error));
        }
        let cleanup_response = if app.dispatcher_available() {
            app.dispatch_tool("__ce_mcp_cleanup_runtime_state", "{}")
        } else {
            crate::tools::cleanup_ce_runtime_state()
        };
        if !cleanup_response.success {
            console::warn(format!(
                "CE 运行时状态清理失败: {}",
                cleanup_response.body_json
            ));
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
        console::warn("无法获取主窗口句柄，不能安装调度 hook");
        return false;
    };

    match app.dispatcher().start(main_window) {
        Ok(()) => true,
        Err(error) => {
            console::warn(format!("安装调度 hook 失败: {}", error));
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
