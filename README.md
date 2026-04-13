# ce-mcp / ce_plugin

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](#requirements)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org)

Single-DLL Cheat Engine plugin runtime for `ce-mcp`.

The official delivery model remains **one `ce_plugin.dll`**. Version 0.3.0 is a **clean rewrite** that keeps Rust as the formal product surface and removes historical compatibility debt from the official design. Users do **not** manually load a separate bridge or manage a second runtime component.

**Language**: [English](./README.md) | [简体中文](./README.zh-CN.md)

## Fork Notice

- This repository is derived from `miscusi-peek/cheatengine-mcp-bridge`.
- Original project license: MIT.
- Original copyright notice: `Copyright (c) 2025 miscusi-peek`.

## Delivery Model / 0.3.0 Direction

- Product identity: `ce-mcp / ce_plugin`
- External artifact: one `ce_plugin.dll`
- Rust is the only formal product runtime surface
- Historical compatibility debt is not part of the 0.3.0 target
- Legacy Lua materials are reference material only, not a product contract
- External versioning follows `ce_plugin/Cargo.toml` and this README

## Overview

This project turns Cheat Engine into a local MCP tool host.

Instead of asking an AI model to reason blindly about a target process, the model can call structured tools through MCP and collaborate with Cheat Engine as the actual reversing backend:

- inspect modules, threads, and memory regions
- read and write process memory
- resolve pointer chains and scan patterns
- disassemble code and analyze references
- place breakpoints and collect hit data
- run Lua and Auto Assembler scripts inside CE

The result is a practical workflow where:

- Cheat Engine remains the live debugger and memory-analysis engine
- the MCP client provides transport and tool invocation
- Rust provides the plugin envelope and transport surface
- The 0.3.0 target is a clean Windows-focused Rust product surface with explicit MCP, config, and auth boundaries
- the model handles hypothesis generation, planning, correlation, and iterative reverse-engineering tasks

## Reverse Engineering Workflow

Typical AI-assisted workflow with this plugin:

1. Load the plugin in Cheat Engine and attach the target process.
2. Confirm `/health` and `ping` are healthy.
3. Let the model inspect modules, memory regions, symbols, and threads.
4. Use scan, pointer, and memory tools to locate runtime data.
5. Use disassembly and reference tools to map code paths and calling relationships.
6. Use breakpoints or DBVM watch to observe runtime behavior.
7. Use Lua or Auto Assembler to validate patches, hooks, and automation logic.

This is designed for dynamic analysis, game reversing, runtime inspection, memory tooling, and operator-guided debugging sessions.

## Quick Start

### 1. Build

```powershell
cd ce_plugin
cargo build --release
```

Output DLL:

```text
ce_plugin/target/release/ce_plugin.dll
```

### 2. Load in Cheat Engine

1. Open Cheat Engine.
2. Load `ce_plugin.dll` as a plugin.
3. Attach a target process.
4. Confirm the plugin console shows runtime status.
5. Do **not** manually load extra bridge assets; runtime bootstrap is owned by the plugin.

### 3. Connect MCP Client

- Single-instance fixed-port mode: set `server.port=18765`, then connect to `GET http://127.0.0.1:18765/health` and `POST http://127.0.0.1:18765/mcp`
- Multi-instance recommended mode: set `server.port=0`, let the plugin allocate a free port, then read the actual `bind_addr` from the local discovery registry

The exact client config depends on whether the MCP client supports HTTP or Streamable HTTP transport.

## Runtime Notes

- The official backend direction for process / memory / analysis tooling is CE-first execution through the CE-native runtime bridge exposed by `get_lua_state`. Native WinAPI / process-handle paths are no longer the architectural baseline for DMA-oriented scenarios.
- `dispatcher_mode = window-message-hook` means CE main-window dispatch hook is active.
- `script_runtime_ready = true` means script-sensitive tools and backend-bootstrap-dependent CE paths are available.
- If the hook cannot be installed, the plugin may fall back to `serialized-worker`.
- Fallback mode is a degraded compatibility path, not the preferred long-term backend for migrated CE-first tools.
- `/health` and `ping` return `instance_id / ce_pid / target_pid / bind_addr / requested_bind_addr` for multi-instance routing and diagnostics.
- When `runtime.debug_enabled=true`, per-instance debug logs are written as `ce_plugin.<ce_pid>.<instance_id[:8]>.debug.log`.

## Tool Surface

The tool surface is organized around the normal stages of dynamic reverse engineering.

### Process & Symbols

Used to establish context before analysis starts.

- `ping`: Health probe for plugin liveness, instance identity, bind addresses, dispatcher mode, and script runtime state.
- `get_process_info`: Returns the currently attached process summary, architecture, and loaded module count.
- `enum_modules`: Lists loaded modules with base addresses, sizes, and paths.
- `get_thread_list`: Enumerates target-process threads for runtime inspection.
- `get_symbol_address`: Resolves a symbol or module expression into an address.
- `get_address_info`: Resolves an address back into module-relative metadata.
- `normalize_address`: Normalizes a runtime address into `module_name / module_base / va / rva`.
- `get_module_fingerprint`: Returns build-oriented module metadata such as image base, image size, PE timestamp, entry RVA, section hashes, and import hash.
- `get_rtti_classname`: Attempts RTTI-based class name recovery from an object address.

### Memory Read/Write

Used to confirm data layouts, runtime state, object fields, and patch candidates.

- `read_memory`: Reads raw bytes from process memory.
- `read_integer`: Reads numeric values such as `byte`, `word`, `dword`, `qword`, `float`, and `double`.
- `read_string`: Reads ANSI or UTF-16 strings from memory.
- `read_pointer`: Reads a pointer value and can continue through offsets when provided.
- `read_pointer_chain`: Resolves a multi-level pointer chain and reports the traversal path.
- `batch_read_memory`: Reads multiple memory regions in one call.
- `write_memory`: Writes raw bytes into process memory.
- `write_integer`: Writes numeric values into memory.
- `write_string`: Writes ANSI or UTF-16 strings into memory.

### Scan & Search

Used to find candidate values, signatures, regions, and runtime anchors.

- `scan_all`: Starts an initial value scan and creates a scan session.
- `get_scan_results`: Returns the current scan result set.
- `next_scan`: Refines the previous scan result set.
- `aob_scan`: Searches memory for an AOB signature.
- `search_string`: Searches readable memory for text strings.
- `generate_signature`: Builds a signature candidate around a target address.
- `get_memory_regions`: Returns commonly useful committed memory regions.
- `enum_memory_regions_full`: Enumerates the full memory map.
- `checksum_memory`: Computes an MD5 checksum for a memory region.

### Analysis

Used to move from raw addresses to code structure and behavioral understanding.

- `disassemble`: Disassembles instructions from a target address range.
- `batch_disassemble`: Disassembles multiple target ranges in one call.
- `get_instruction_info`: Decodes a single instruction with detailed metadata.
- `find_function_boundaries`: Heuristically locates function start and end boundaries.
- `analyze_function`: Extracts call relationships from a function body.
- `find_references`: Finds instructions that reference a target address.
- `find_call_references`: Finds call sites that target a function address.
- `dissect_structure`: Heuristically infers object or structure field layout from memory.

### Debug / DBVM

Used to observe behavior instead of inferring it statically.

- `set_breakpoint`: Sets an execution hardware breakpoint.
- `set_data_breakpoint`: Sets a data-access or write breakpoint.
- `remove_breakpoint`: Removes a breakpoint by id.
- `list_breakpoints`: Lists active breakpoints.
- `clear_all_breakpoints`: Clears all active breakpoints.
- `get_breakpoint_hits`: Returns captured breakpoint-hit records and structured `evidence` output.
- `get_physical_address`: Translates a virtual address to a physical address.
- `start_dbvm_watch`: Starts a DBVM watch tracing session.
- `poll_dbvm_watch`: Polls intermediate DBVM watch results without stopping the session.
- `stop_dbvm_watch`: Stops a DBVM watch session and returns final results.

### Script

Used to automate CE-side logic, validate ideas quickly, and apply patches during analysis.

- `evaluate_lua`: Executes a Lua snippet inside Cheat Engine.
- `evaluate_lua_file`: Executes a local Lua file inside Cheat Engine.
- `auto_assemble`: Executes an Auto Assembler script.
- `auto_assemble_file`: Executes a local Auto Assembler script file.

## Output Conventions

Recent refactors standardize more runtime results for downstream orchestration:

- address-like results increasingly expose `normalized_address`
- pointer and chain results may also expose normalized pointer targets
- debug and DBVM watch flows now expose structured `evidence`
- batch endpoints are designed so one failing item does not abort the whole batch

### Compatibility Policy

Version 0.3.0 does **not** preserve historical compatibility aliases as part of the formal product surface. The supported entrypoints are the new MCP methods and the canonical tool names exposed by `tools/list`.

## Requirements

- Windows
- Cheat Engine `7.5 x64` or `7.6 x64`
- Rust toolchain for local builds

## Configuration

Version 0.3.0 uses a DLL-side config file as the formal configuration entrypoint.

Supported config filenames:
- `ce_plugin.json`
- `ce_plugin.config.json`

Example config file: [`examples/ce_plugin.example.json`](./examples/ce_plugin.example.json)

Example:
```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 0
  },
  "auth": {
    "enabled": false,
    "token": ""
  },
  "runtime": {
    "dispatch_timeout_ms": 5000,
    "console_log_enabled": true,
    "debug_enabled": false,
    "console_title": "流云MCP插件"
  }
}
```

`0.0.0.0` or public bind targets require `auth.enabled=true` and a non-empty bearer token.

Recommended configuration:

- Single-instance fixed port: set `server.port=18765` or another explicit port and connect directly.
- Multi-instance automatic ports: set `server.port=0` and let the plugin claim a free local port.

Local discovery registry:

- Directory: `%LOCALAPPDATA%\ce-mcp\instances\`
- File model: one live `ce-<ce_pid>.json` per active CE process
- Record fields: `instance_id`, `ce_pid`, `target_pid`, `plugin_id`, `bind_addr`, `requested_bind_addr`, `dll_path`, `debug_log_path`, `server_version`, `last_heartbeat_unix_ms`
- Lifecycle: register on startup, refresh heartbeat while running, remove on clean shutdown, prune stale entries during startup and heartbeat refresh

Client-facing integration follows the MCP HTTP endpoint (`/mcp`) and health endpoint (`/health`) described in this README. Multi-instance clients should enumerate the discovery registry first, then connect to the instance-specific `bind_addr`.

## Project Layout

```text
ce-mcp/
├─ ce_plugin/
│  └─ Cargo.toml
├─ README.md
├─ README.zh-CN.md
└─ LICENSE
```


## License

MIT. See [LICENSE](./LICENSE).

CE-native inline runtime snippets used by the plugin follow the same repository-level `ce-mcp / ce_plugin` product identity and fork notice. They are implementation details, not a separately versioned end-user product.
