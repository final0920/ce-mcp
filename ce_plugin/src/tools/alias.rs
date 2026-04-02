pub fn canonical_method(method: &str) -> Option<&'static str> {
    match method {
        "read_bytes" => Some("read_memory"),
        "pattern_scan" => Some("aob_scan"),
        "set_execution_breakpoint" => Some("set_breakpoint"),
        "set_write_breakpoint" => Some("set_data_breakpoint"),
        "find_what_writes_safe" => Some("start_dbvm_watch"),
        "find_what_accesses_safe" => Some("start_dbvm_watch"),
        "get_watch_results" => Some("stop_dbvm_watch"),
        _ => None,
    }
}
