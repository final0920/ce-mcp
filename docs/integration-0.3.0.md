# ce-mcp 0.3.0 Integration Guide

This guide is the canonical integration note for the 0.3.0 clean rewrite.

## Scope

- **Windows only** official implementation
- **One artifact**: `ce_plugin.dll`
- **One config entrypoint**: DLL-side JSON config file
- **One MCP surface**: `initialize`, `tools/list`, `tools/call`, `ping`
- Historical `direct-method`, alias tool names, and env-key/value compatibility paths are **not supported**

## Delivery Model

The plugin is delivered as a single Cheat Engine DLL plugin.

You do **not** need to:

- manually load a standalone Lua bridge
- maintain a second runtime package
- keep old alias method names alive
- configure the server through historical env key/value shims

## Build

From Windows:

```powershell
cd ce_plugin
cargo build --release
```

Expected output:

```text
ce_plugin/target/release/ce_plugin.dll
```

If your environment uses an explicit Windows target triple, build the same crate for your installed 64-bit Windows toolchain.

## Files to Place Beside the DLL

Minimum layout:

```text
Cheat Engine/
└─ plugins/
   ├─ ce_plugin.dll
   └─ ce_plugin.json
```

Supported config filenames:

- `ce_plugin.json`
- `ce_plugin.config.json`

The plugin resolves config from the DLL directory first.

## Config Shape

Example:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 18765
  },
  "auth": {
    "enabled": false,
    "token": ""
  },
  "runtime": {
    "dispatch_timeout_ms": 5000,
    "console_log_enabled": true,
    "console_title": "Flowing Cloud MCP Plugin"
  }
}
```

Security rule:

- If `server.host` is `0.0.0.0`, `::`, or another non-loopback/public bind target, startup requires:
  - `auth.enabled = true`
  - non-empty `auth.token`

## Cheat Engine Load Flow

1. Start Cheat Engine x64.
2. Load `ce_plugin.dll` as a plugin.
3. Attach the target process.
4. Confirm the plugin console shows runtime startup logs.
5. Verify `GET /health` returns success.

## MCP HTTP Surface

Base address is controlled by `server.host` + `server.port`.

Routes:

- `GET /health`
- `POST /mcp`

Behavior summary:

- `/health` is a lightweight runtime status endpoint
- `/mcp` accepts JSON-RPC 2.0 style MCP requests
- when auth is enabled, `/mcp` requires `Authorization: Bearer <token>`
- when auth is enabled, the same bearer token should be used by the MCP client for every request

## MCP Handshake

Typical sequence:

1. `initialize`
2. `notifications/initialized`
3. `tools/list`
4. `tools/call`

Example `initialize` request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {}
}
```

Example `tools/list` request:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

Example `tools/call` request:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "read_memory",
    "arguments": {
      "address": "game.exe+123456",
      "size": 32
    }
  }
}
```

## Tool Naming Rules

0.3.0 only accepts canonical tool names exposed by `tools/list`.

Examples:

- `read_memory`
- `enum_modules`
- `disassemble`
- `evaluate_lua`

Not supported in the official 0.3.0 surface:

- old alias names
- legacy direct HTTP method naming conventions
- historical compatibility remaps

## Runtime Semantics

Important health/runtime fields:

- `dispatcher_mode`
- `dispatcher_available`
- `dispatch_timeout_ms`
- `lua_state_export_available`
- `auto_assemble_export_available`
- `script_runtime_ready`

Interpretation:

- `window-message-hook` is the preferred CE-first dispatch mode
- `serialized-worker` is a degraded fallback path
- `script_runtime_ready = true` means script-sensitive CE paths are available

## Suggested Self-Check Commands

For repository-side static validation:

```powershell
cd ce_plugin
cargo check
cargo check --target x86_64-pc-windows-gnu
cargo test --target x86_64-pc-windows-gnu --no-run
```

Notes:

- `cargo check` is useful for host-side syntax/type validation during development
- `cargo check --target x86_64-pc-windows-gnu` validates the official Windows build path
- `cargo test --no-run` only verifies test artifacts compile; it does not execute Windows binaries on a non-Windows host

## Non-Goals of the Clean Rewrite

The following are intentionally outside the 0.3.0 product contract:

- preserving old `direct-method` call shapes
- shipping alias name compatibility layers
- keeping env-key/value configuration shims alive
- documenting a separate legacy Lua bridge as a required user-facing component
