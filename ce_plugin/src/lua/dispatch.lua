-- ce-mcp embedded Lua command dispatch glue
-- Extracted from bridge.lua for the v0.2.0 modular backend layout.

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

local commandHandlers = {
    -- Process & Modules
    get_process_info = cmd_get_process_info,
    enum_modules = cmd_enum_modules,
    get_symbol_address = cmd_get_symbol_address,
    
    -- Memory Read
    read_memory = cmd_read_memory,
    read_bytes = cmd_read_memory,  -- Alias
    read_integer = cmd_read_integer,
    read_string = cmd_read_string,
    read_pointer = cmd_read_pointer,
    
    -- Pattern Scanning
    aob_scan = cmd_aob_scan,
    pattern_scan = cmd_aob_scan,  -- Alias
    scan_all = cmd_scan_all,
    next_scan = cmd_next_scan,
    write_integer = cmd_write_integer,
    write_memory = cmd_write_memory,
    write_string = cmd_write_string,
    get_scan_results = cmd_get_scan_results,
    search_string = cmd_search_string,
    
    -- Disassembly & Analysis
    disassemble = cmd_disassemble,
    get_instruction_info = cmd_get_instruction_info,
    find_function_boundaries = cmd_find_function_boundaries,
    analyze_function = cmd_analyze_function,
    
    -- Reference Finding
    find_references = cmd_find_references,
    find_call_references = cmd_find_call_references,
    
    -- Breakpoints
    set_breakpoint = cmd_set_breakpoint,
    set_execution_breakpoint = cmd_set_breakpoint,  -- Alias
    set_data_breakpoint = cmd_set_data_breakpoint,
    set_write_breakpoint = cmd_set_data_breakpoint,  -- Alias
    remove_breakpoint = cmd_remove_breakpoint,
    get_breakpoint_hits = cmd_get_breakpoint_hits,
    list_breakpoints = cmd_list_breakpoints,
    clear_all_breakpoints = cmd_clear_all_breakpoints,
    
    -- Memory Regions
    get_memory_regions = cmd_get_memory_regions,
    enum_memory_regions_full = cmd_enum_memory_regions_full,  -- CE-native details isolated behind Lua bridge
    
    -- Lua Evaluation
    evaluate_lua = cmd_evaluate_lua,
    
    -- High-Level Analysis Tools
    dissect_structure = cmd_dissect_structure,
    get_thread_list = cmd_get_thread_list,
    auto_assemble = cmd_auto_assemble,
    read_pointer_chain = cmd_read_pointer_chain,
    get_rtti_classname = cmd_get_rtti_classname,
    get_address_info = cmd_get_address_info,
    checksum_memory = cmd_checksum_memory,
    generate_signature = cmd_generate_signature,
    
    -- DBVM Hypervisor Tools (Safe Dynamic Tracing - Ring -1)
    get_physical_address = cmd_get_physical_address,
    start_dbvm_watch = cmd_start_dbvm_watch,
    poll_dbvm_watch = cmd_poll_dbvm_watch,  -- Poll logs without stopping watch
    stop_dbvm_watch = cmd_stop_dbvm_watch,
    -- Semantic aliases for ease of use
    find_what_writes_safe = cmd_start_dbvm_watch,  -- Alias: start watching for writes
    find_what_accesses_safe = cmd_start_dbvm_watch,  -- Alias: start watching for accesses
    get_watch_results = cmd_stop_dbvm_watch,  -- Alias: retrieve results and stop
    
    -- Utility
    ping = cmd_ping,
}


-- Raw command core used by both the current Rust sync path and the future
-- self-driven runtime shell in runtime.lua.
local function dispatch(method, params_json)
    local ok_params, params_or_error = decode_backend_params(params_json)
    if not ok_params then
        return encode_backend_error(params_or_error)
    end

    local handler = commandHandlers[method]
    if not handler then
        return encode_backend_error("method not found: " .. tostring(method))
    end

    local ok_result, result = pcall(handler, params_or_error)
    if not ok_result then
        return encode_backend_error("internal error: " .. tostring(result))
    end

    return encode_backend_result(result)
end

local function createEmbeddedCommandBridge()
    return {
        dispatch = dispatch,
        cleanup = cleanupZombieState,
        handlers = commandHandlers,
    }
end
