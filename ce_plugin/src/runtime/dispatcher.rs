#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use core::ffi::c_void;

use crate::tools::ToolResponse;

type Bool = i32;
type Hwnd = *mut c_void;
type Uint = u32;
type Wparam = usize;
type Lparam = isize;
type Lresult = isize;
type LongPtr = isize;

const GWLP_WNDPROC: i32 = -4;
const WM_APP: Uint = 0x8000;
const WM_CE_PLUGIN_DISPATCH: Uint = WM_APP + 0x4CE;

static ACTIVE_DISPATCHER: AtomicUsize = AtomicUsize::new(0);

#[link(name = "user32")]
extern "system" {
    fn SetWindowLongPtrW(hwnd: Hwnd, index: i32, new_long: LongPtr) -> LongPtr;
    fn CallWindowProcW(
        prev_wnd_func: LongPtr,
        hwnd: Hwnd,
        msg: Uint,
        wparam: Wparam,
        lparam: Lparam,
    ) -> Lresult;
    fn DefWindowProcW(hwnd: Hwnd, msg: Uint, wparam: Wparam, lparam: Lparam) -> Lresult;
    fn PostMessageW(hwnd: Hwnd, msg: Uint, wparam: Wparam, lparam: Lparam) -> Bool;
}

#[derive(Clone, Debug)]
pub struct CommandJob {
    pub id: u64,
    pub method: String,
    pub payload: String,
    pub deadline: Instant,
    completion: Arc<JobCompletion>,
}

impl CommandJob {
    fn new(
        id: u64,
        method: impl Into<String>,
        payload: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            id,
            method: method.into(),
            payload: payload.into(),
            deadline: Instant::now() + timeout,
            completion: Arc::new(JobCompletion::default()),
        }
    }

    pub fn finish(&self, response: ToolResponse) -> bool {
        self.completion.finish(response)
    }

    pub fn fail(&self, error: impl Into<String>) -> bool {
        self.completion.fail(error.into())
    }

    pub fn cancel(&self, error: impl Into<String>) -> bool {
        self.completion.fail(error.into())
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn wait_for_result(&self) -> Result<ToolResponse, String> {
        self.completion.wait(self.deadline)
    }
}

#[derive(Debug, Default)]
struct JobCompletion {
    state: Mutex<JobCompletionState>,
    wake: Condvar,
}

#[derive(Debug, Default)]
struct JobCompletionState {
    response: Option<ToolResponse>,
    error: Option<String>,
}

impl JobCompletion {
    fn finish(&self, response: ToolResponse) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        if state.response.is_some() || state.error.is_some() {
            return false;
        }

        state.response = Some(response);
        self.wake.notify_all();
        true
    }

    fn fail(&self, error: String) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        if state.response.is_some() || state.error.is_some() {
            return false;
        }

        state.error = Some(error);
        self.wake.notify_all();
        true
    }

    fn wait(&self, deadline: Instant) -> Result<ToolResponse, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "dispatcher completion lock poisoned".to_owned())?;

        loop {
            if let Some(response) = state.response.take() {
                return Ok(response);
            }
            if let Some(error) = state.error.take() {
                return Err(error);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err("dispatcher timed out waiting for CE main-thread execution".to_owned());
            }

            let wait = deadline.saturating_duration_since(now);
            let (next_state, timeout) = self
                .wake
                .wait_timeout(state, wait)
                .map_err(|_| "dispatcher completion wait poisoned".to_owned())?;
            state = next_state;
            if timeout.timed_out() {
                return Err("dispatcher timed out waiting for CE main-thread execution".to_owned());
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct WindowHookState {
    hwnd: usize,
    prev_wnd_proc: LongPtr,
}

#[derive(Default)]
struct DispatcherState {
    next_id: u64,
    queue: VecDeque<CommandJob>,
    executor_attached: bool,
    shutting_down: bool,
    window_hook: Option<WindowHookState>,
}

pub struct MainThreadDispatcher {
    state: Mutex<DispatcherState>,
    wake: Condvar,
}

impl Default for MainThreadDispatcher {
    fn default() -> Self {
        Self {
            state: Mutex::new(DispatcherState {
                next_id: 1,
                ..DispatcherState::default()
            }),
            wake: Condvar::new(),
        }
    }
}

impl MainThreadDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&self, main_window: *mut c_void) -> Result<(), String> {
        if main_window.is_null() {
            return Err("dispatcher start failed: main window handle is null".to_owned());
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| "dispatcher state lock poisoned".to_owned())?;
        if state.shutting_down {
            return Err("dispatcher is shutting down".to_owned());
        }
        if state.window_hook.is_some() {
            state.executor_attached = true;
            self.wake.notify_all();
            return Ok(());
        }

        let prev_wnd_proc = unsafe {
            SetWindowLongPtrW(
                main_window.cast(),
                GWLP_WNDPROC,
                dispatcher_window_proc as *const () as usize as LongPtr,
            )
        };
        if prev_wnd_proc == 0 {
            return Err("dispatcher start failed: SetWindowLongPtrW returned 0".to_owned());
        }

        state.window_hook = Some(WindowHookState {
            hwnd: main_window as usize,
            prev_wnd_proc,
        });
        state.executor_attached = true;
        ACTIVE_DISPATCHER.store(self as *const Self as usize, Ordering::SeqCst);
        self.wake.notify_all();
        Ok(())
    }

    pub fn attach_executor(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "dispatcher state lock poisoned".to_owned())?;
        if state.shutting_down {
            return Err("dispatcher is shutting down".to_owned());
        }

        state.executor_attached = true;
        self.wake.notify_all();
        Ok(())
    }

    pub fn detach_executor(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "dispatcher state lock poisoned".to_owned())?;
        state.executor_attached = false;
        self.wake.notify_all();
        Ok(())
    }

    pub fn is_executor_attached(&self) -> Result<bool, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "dispatcher state lock poisoned".to_owned())?;
        Ok(state.executor_attached && !state.shutting_down)
    }

    pub fn execute(
        &self,
        method: &str,
        payload: &str,
        timeout: Duration,
    ) -> Result<ToolResponse, String> {
        if timeout.is_zero() {
            return Err("dispatcher timeout must be greater than zero".to_owned());
        }

        let (job, hwnd) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "dispatcher state lock poisoned".to_owned())?;

            if state.shutting_down {
                return Err("dispatcher is shutting down".to_owned());
            }
            if !state.executor_attached {
                return Err(format!(
                    "serialized dispatcher executor unavailable: {}",
                    method
                ));
            }

            let job = CommandJob::new(state.next_id, method, payload, timeout);
            state.next_id += 1;
            state.queue.push_back(job.clone());
            let hwnd = state.window_hook.map(|hook| hook.hwnd as Hwnd);
            self.wake.notify_one();
            (job, hwnd)
        };

        if let Some(hwnd) = hwnd {
            let _ = self.signal_main_thread(hwnd);
        }

        match job.wait_for_result() {
            Ok(response) => Ok(response),
            Err(error) => {
                let _ = self.cancel(job.id, error.clone());
                Err(error)
            }
        }
    }

    pub fn wait_for_job(&self, poll_interval: Duration) -> Result<Option<CommandJob>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "dispatcher state lock poisoned".to_owned())?;

        loop {
            if state.shutting_down {
                return Ok(None);
            }

            if let Some(job) = state.queue.pop_front() {
                if job.is_expired() {
                    let _ = job.cancel(format!(
                        "dispatcher job {} expired before execution",
                        job.id
                    ));
                    continue;
                }
                return Ok(Some(job));
            }

            let (next_state, timeout) = self
                .wake
                .wait_timeout(state, poll_interval)
                .map_err(|_| "dispatcher wait poisoned".to_owned())?;
            state = next_state;
            if timeout.timed_out() {
                return Ok(None);
            }
        }
    }

    pub fn cancel(&self, job_id: u64, reason: String) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "dispatcher state lock poisoned".to_owned())?;

        if let Some(index) = state.queue.iter().position(|job| job.id == job_id) {
            if let Some(job) = state.queue.remove(index) {
                return Ok(job.cancel(reason));
            }
        }

        Ok(false)
    }

    pub fn stop(&self) -> Result<(), String> {
        let (hook, pending_jobs) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "dispatcher state lock poisoned".to_owned())?;
            state.shutting_down = true;
            state.executor_attached = false;
            let hook = state.window_hook.take();
            let pending_jobs = state.queue.drain(..).collect::<Vec<_>>();
            self.wake.notify_all();
            (hook, pending_jobs)
        };

        ACTIVE_DISPATCHER.store(0, Ordering::SeqCst);

        if let Some(hook) = hook {
            let restored =
                unsafe { SetWindowLongPtrW(hook.hwnd as Hwnd, GWLP_WNDPROC, hook.prev_wnd_proc) };
            if restored == 0 {
                return Err("dispatcher stop failed: SetWindowLongPtrW returned 0".to_owned());
            }
        }

        for job in pending_jobs {
            let _ = job.cancel("dispatcher shutting down".to_owned());
        }

        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.is_executor_attached().unwrap_or(false)
    }

    pub fn mode(&self) -> &'static str {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return "poisoned",
        };

        if state.shutting_down || !state.executor_attached {
            return "executor-pending";
        }

        if state.window_hook.is_some() {
            "window-message-hook"
        } else {
            "serialized-worker"
        }
    }

    fn signal_main_thread(&self, hwnd: Hwnd) -> Result<(), String> {
        let ok = unsafe { PostMessageW(hwnd, WM_CE_PLUGIN_DISPATCH, 0, 0) };
        if ok == 0 {
            return Err("dispatcher failed to signal CE main thread".to_owned());
        }
        Ok(())
    }

    fn dequeue_ready_job(&self) -> Result<Option<CommandJob>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "dispatcher state lock poisoned".to_owned())?;
        if state.shutting_down {
            return Ok(None);
        }

        while let Some(job) = state.queue.pop_front() {
            if job.is_expired() {
                let _ = job.cancel(format!(
                    "dispatcher job {} expired before execution",
                    job.id
                ));
                continue;
            }
            return Ok(Some(job));
        }

        Ok(None)
    }

    fn drain_on_main_thread(&self) {
        while let Ok(Some(job)) = self.dequeue_ready_job() {
            let response = crate::tools::dispatch_from_main_thread(&job.method, &job.payload);
            let _ = job.finish(response);
        }
    }

    fn call_previous_window_proc(
        &self,
        hwnd: Hwnd,
        msg: Uint,
        wparam: Wparam,
        lparam: Lparam,
    ) -> Lresult {
        let prev_wnd_proc = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.window_hook.map(|hook| hook.prev_wnd_proc))
            .unwrap_or(0);

        if prev_wnd_proc != 0 {
            unsafe { CallWindowProcW(prev_wnd_proc, hwnd, msg, wparam, lparam) }
        } else {
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

unsafe extern "system" fn dispatcher_window_proc(
    hwnd: Hwnd,
    msg: Uint,
    wparam: Wparam,
    lparam: Lparam,
) -> Lresult {
    if let Some(dispatcher) = active_dispatcher() {
        if msg == WM_CE_PLUGIN_DISPATCH {
            dispatcher.drain_on_main_thread();
            return 0;
        }

        return dispatcher.call_previous_window_proc(hwnd, msg, wparam, lparam);
    }

    DefWindowProcW(hwnd, msg, wparam, lparam)
}

fn active_dispatcher() -> Option<&'static MainThreadDispatcher> {
    let ptr = ACTIVE_DISPATCHER.load(Ordering::SeqCst);
    if ptr == 0 {
        return None;
    }

    Some(unsafe { &*(ptr as *const MainThreadDispatcher) })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use serde_json::json;

    use super::MainThreadDispatcher;
    use crate::tools::ToolResponse;

    #[test]
    fn execute_requires_executor() {
        let dispatcher = MainThreadDispatcher::new();
        let error = dispatcher
            .execute("evaluate_lua", "{}", Duration::from_millis(50))
            .unwrap_err();

        assert!(error.contains("executor unavailable"));
    }

    #[test]
    fn execute_round_trips_when_executor_consumes_queue() {
        let dispatcher = Arc::new(MainThreadDispatcher::new());
        dispatcher.attach_executor().unwrap();

        let submitter = {
            let dispatcher = Arc::clone(&dispatcher);
            thread::spawn(move || dispatcher.execute("evaluate_lua", "{}", Duration::from_secs(1)))
        };

        let job = dispatcher
            .wait_for_job(Duration::from_secs(1))
            .unwrap()
            .expect("job should be available");
        assert_eq!(job.method, "evaluate_lua");
        assert!(job.finish(ToolResponse {
            success: true,
            body_json: json!({"success": true, "engine": "test"}).to_string(),
        }));

        let response = submitter.join().unwrap().unwrap();
        assert!(response.success);
        assert!(response.body_json.contains("\"engine\":\"test\""));
    }

    #[test]
    fn timed_out_job_is_removed_from_queue() {
        let dispatcher = Arc::new(MainThreadDispatcher::new());
        dispatcher.attach_executor().unwrap();

        let submitter = {
            let dispatcher = Arc::clone(&dispatcher);
            thread::spawn(move || {
                dispatcher
                    .execute("auto_assemble", "{}", Duration::from_millis(25))
                    .unwrap_err()
            })
        };

        let error = submitter.join().unwrap();
        assert!(error.contains("timed out"));
        assert!(dispatcher
            .wait_for_job(Duration::from_millis(10))
            .unwrap()
            .is_none());
    }
}
