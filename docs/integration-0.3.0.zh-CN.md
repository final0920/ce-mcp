# ce-mcp 0.3.0 新版接入说明

本文是 0.3.0 clean rewrite 的正式接入说明。

## 适用范围

- **只考虑 Windows 正式实现**
- **单交付物**：`ce_plugin.dll`
- **单配置入口**：DLL 同级 JSON 配置文件
- **单 MCP 方法面**：`initialize`、`tools/list`、`tools/call`、`ping`
- 历史 `direct-method`、工具别名、env-key/value 兼容路径 **不再支持**

## 交付模型

插件对外交付为一个 Cheat Engine DLL 插件。

你**不需要**：

- 手动再加载独立 Lua bridge
- 维护第二套运行时包
- 兼容历史 alias 方法名
- 继续使用旧 env key/value 配置旁路

## 编译

在 Windows 上执行：

```powershell
cd ce_plugin
cargo build --release
```

预期产物：

```text
ce_plugin/target/release/ce_plugin.dll
```

如果你的环境使用显式 Windows target triple，则按本机已安装的 64 位 Windows toolchain 构建同一个 crate 即可。

## DLL 同级文件布局

最小部署形态：

```text
Cheat Engine/
└─ plugins/
   ├─ ce_plugin.dll
   └─ ce_plugin.json
```

支持的配置文件名：

- `ce_plugin.json`
- `ce_plugin.config.json`

插件会优先从 DLL 所在目录解析配置文件。

## 配置结构

示例：

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
    "console_title": "流云MCP插件"
  }
}
```

安全规则：

- 当 `server.host` 是 `0.0.0.0`、`::` 或其他非回环/公网监听地址时，启动必须同时满足：
  - `auth.enabled = true`
  - `auth.token` 为非空 Bearer Token

## 在 Cheat Engine 中加载

1. 启动 x64 版 Cheat Engine。
2. 以插件方式加载 `ce_plugin.dll`。
3. 附加目标进程。
4. 确认插件控制台打印运行时启动日志。
5. 访问 `GET /health`，确认健康检查成功。

## MCP HTTP 接口

监听地址由 `server.host` + `server.port` 决定。

路由：

- `GET /health`
- `POST /mcp`

行为说明：

- `/health` 用于轻量运行态探针
- `/mcp` 接收 JSON-RPC 2.0 风格的 MCP 请求
- 启用鉴权后，`/mcp` 必须带 `Authorization: Bearer <token>`
- 开启鉴权后，MCP 客户端的每个请求都应携带同一 Bearer Token

## MCP 握手顺序

典型顺序：

1. `initialize`
2. `notifications/initialized`
3. `tools/list`
4. `tools/call`

`initialize` 示例：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {}
}
```

`tools/list` 示例：

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

`tools/call` 示例：

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

## 工具命名规则

0.3.0 只接受 `tools/list` 暴露出的 canonical tool name。

例如：

- `read_memory`
- `enum_modules`
- `disassemble`
- `evaluate_lua`

以下内容不再属于 0.3.0 正式产品面：

- 历史 alias 名称
- 旧 direct HTTP 方法命名
- 各类兼容重映射

## 运行时语义

重点关注这些字段：

- `dispatcher_mode`
- `dispatcher_available`
- `dispatch_timeout_ms`
- `lua_state_export_available`
- `auto_assemble_export_available`
- `script_runtime_ready`

解释：

- `window-message-hook` 是首选的 CE-first 调度模式
- `serialized-worker` 是降级回退路径
- `script_runtime_ready = true` 表示脚本敏感 CE 路径已经可用

## 建议的静态自检命令

用于仓库侧静态校验：

```powershell
cd ce_plugin
cargo check
cargo check --target x86_64-pc-windows-gnu
cargo test --target x86_64-pc-windows-gnu --no-run
```

说明：

- `cargo check` 适合开发期做宿主机上的语法/类型校验
- `cargo check --target x86_64-pc-windows-gnu` 用于校验正式 Windows 构建路径
- `cargo test --no-run` 只校验测试产物是否能编译，不会在非 Windows 主机上执行 Windows 二进制

## Clean Rewrite 的明确非目标

以下内容被明确排除在 0.3.0 产品契约之外：

- 保留旧 `direct-method` 调用形态
- 继续维持 alias 名称兼容层
- 继续保留 env-key/value 配置兼容垫片
- 把旧独立 Lua bridge 继续当作用户侧必须组件来说明
