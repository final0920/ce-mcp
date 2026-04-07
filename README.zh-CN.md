# Cheat Engine MCP 插件版

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](#环境要求)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org)

原生 Cheat Engine 插件运行时，通过本地 HTTP MCP 端点把 Cheat Engine 变成一个可供大模型调用的逆向分析后端。

**语言**: [English](./README.md) | [简体中文](./README.zh-CN.md)

## Fork 说明

- 本仓库基于 `miscusi-peek/cheatengine-mcp-bridge` 二次改造开发。
- 原项目许可证：MIT。
- 原始版权声明：`Copyright (c) 2025 miscusi-peek`。

## 项目定位

这个项目的目标，不是单纯把 CE 包成一个 HTTP 服务，而是让大模型能够通过 MCP 与 Cheat Engine 协作逆向。

在这条链路里：

- Cheat Engine 负责真实的运行时调试、内存访问、断点、脚本执行与动态观察
- MCP 客户端负责把工具暴露给 AI Agent
- 大模型负责提出假设、规划步骤、关联证据、解释现象、推动逆向分析闭环

也就是说，模型不再只是“纸上谈兵”，而是可以真正调用 CE 去做：

- 模块与线程侦察
- 内存读写与指针链解析
- 数值扫描与 AOB 特征定位
- 反汇编、引用分析、函数边界分析
- 断点追踪与 DBVM 观察
- Lua / Auto Assembler 自动化验证与补丁实验

这适用于动态逆向、游戏分析、运行时内存研究、对象结构推断、行为验证与人工主导的调试分析流程。

## 典型协作流程

一个标准的“大模型 + MCP + CE”协作逆向流程通常如下：

1. 在 Cheat Engine 中加载插件并附加目标进程。
2. 通过 `/health` 或 `ping` 确认插件、调度器和脚本运行态正常。
3. 让模型先枚举模块、线程、内存区域，建立目标全局视图。
4. 用扫描、指针、字符串、签名工具定位关键数据与代码锚点。
5. 用反汇编、引用分析和函数分析工具理解控制流与调用关系。
6. 用断点或 DBVM watch 观察运行时行为，验证模型提出的假设。
7. 用 Lua 或 Auto Assembler 快速做补丁、hook、自动化验证和实验。

## 快速开始

### 1. 编译

```powershell
cd ce_plugin
cargo build --release
```

输出 DLL：

```text
ce_plugin/target/release/ce_plugin.dll
```

### 2. 在 Cheat Engine 中加载

1. 打开 Cheat Engine。
2. 以插件方式加载 `ce_plugin.dll`。
3. 附加目标进程。
4. 查看插件控制台是否打印运行状态。

### 3. 连接 MCP 客户端

- 健康检查：`GET http://127.0.0.1:18765/health`
- MCP 入口：`POST http://127.0.0.1:18765/mcp`

不同 MCP 客户端的配置格式不同，但前提都是该客户端支持 HTTP 或 Streamable HTTP transport。

## 运行说明

- `dispatcher_mode = window-message-hook` 表示已成功挂入 CE 主窗口消息调度链。
- `script_runtime_ready = true` 表示脚本敏感工具已经可用。
- 若安装 hook 失败，插件会自动回退为 `serialized-worker`。
- 回退模式下，纯 Rust 原生工具仍可用，但脚本、断点、DBVM 工具会受限。

## 功能列表

工具面按动态逆向的常见阶段组织。

### 进程与符号

用于建立分析上下文，先知道“目标是谁、代码在哪、线程怎么跑”。

- `ping`: 健康检查，返回插件存活状态、调度模式与脚本运行状态。
- `get_process_info`: 获取当前附加进程的摘要信息、模块数量与架构。
- `enum_modules`: 枚举目标进程已加载模块、基址、大小与路径。
- `get_thread_list`: 枚举目标进程线程列表。
- `get_symbol_address`: 将 symbol 或模块表达式解析为地址。
- `get_address_info`: 将地址反查为模块、段与符号信息。
- `normalize_address`: 将运行时地址标准化为 `module_name / module_base / va / rva`。
- `get_module_fingerprint`: 返回模块构建指纹，包括 image base、image size、PE 时间戳、入口 RVA、section hash 与 import hash。
- `get_rtti_classname`: 尝试根据 RTTI 推断对象类名。

### 内存读写

用于确认对象字段、状态变量、结构布局和补丁点。

- `read_memory`: 读取指定地址的原始字节数据。
- `read_integer`: 读取 `byte/word/dword/qword/float/double` 数值。
- `read_string`: 读取 ANSI 或 UTF-16 字符串。
- `read_pointer`: 读取单层指针，带 offsets 时可继续解析链路。
- `read_pointer_chain`: 解析多级指针链并返回每一层路径。
- `batch_read_memory`: 一次请求批量读取多段内存。
- `write_memory`: 向指定地址写入原始字节。
- `write_integer`: 写入数值类型。
- `write_string`: 写入 ANSI 或 UTF-16 字符串。

### 扫描与搜索

用于从大范围运行时内存里捞出候选值、特征和定位锚点。

- `scan_all`: 发起首次值扫描并建立扫描会话。
- `get_scan_results`: 获取当前扫描结果集。
- `next_scan`: 在前一次结果上继续筛选。
- `aob_scan`: 按 AOB 特征码扫描内存。
- `search_string`: 在内存区域中搜索文本字符串。
- `generate_signature`: 为目标地址生成可用签名字节串。
- `get_memory_regions`: 返回常用、可读写或可执行的有效内存区域。
- `enum_memory_regions_full`: 枚举完整内存映射。
- `checksum_memory`: 计算指定内存区域 MD5 校验值。

### 分析

用于把“地址”推进成“代码逻辑”和“行为理解”。

- `disassemble`: 对目标地址范围执行反汇编。
- `batch_disassemble`: 一次请求批量反汇编多个地址范围。
- `get_instruction_info`: 获取单条指令的详细解码信息。
- `find_function_boundaries`: 启发式定位函数起止边界。
- `analyze_function`: 提取函数内 call 关系与基础分析结果。
- `find_references`: 查找引用目标地址的指令位置。
- `find_call_references`: 查找调用目标函数的 call 点。
- `dissect_structure`: 启发式推断对象或结构体字段布局。

### 调试 / DBVM

用于直接观察运行时行为，而不是只靠静态猜测。

- `set_breakpoint`: 设置执行型硬件断点。
- `set_data_breakpoint`: 设置数据访问断点或写断点。
- `remove_breakpoint`: 按 id 删除断点。
- `list_breakpoints`: 列出当前活动断点。
- `clear_all_breakpoints`: 清空全部断点。
- `get_breakpoint_hits`: 获取断点命中记录，并返回结构化 `evidence`。
- `get_physical_address`: 将虚拟地址转换为物理地址。
- `start_dbvm_watch`: 启动 DBVM watch 追踪会话。
- `poll_dbvm_watch`: 轮询 DBVM watch 中间结果而不停止会话。
- `stop_dbvm_watch`: 停止 DBVM watch 并返回最终结果。

## 输出约定

近期改造后，运行时结果开始逐步统一：

- 地址类结果会尽量返回 `normalized_address`
- 指针/链路类结果会尽量补充标准化后的目标地址
- 断点与 DBVM watch 流程会返回结构化 `evidence`
- batch 接口按单项容错设计，单条失败不会中断整批

### 脚本

用于快速实验、验证思路、自动化 CE 侧逻辑和补丁过程。

- `evaluate_lua`: 在 Cheat Engine 内执行 Lua 代码片段。
- `evaluate_lua_file`: 执行本地 Lua 文件。
- `auto_assemble`: 执行 Auto Assembler 脚本文本。
- `auto_assemble_file`: 执行本地 Auto Assembler 脚本文件。

### 兼容别名

用于兼容旧调用习惯与既有工具命名。

- `read_bytes`: `read_memory` 的兼容别名。
- `pattern_scan`: `aob_scan` 的兼容别名。
- `set_execution_breakpoint`: `set_breakpoint` 的兼容别名。
- `set_write_breakpoint`: `set_data_breakpoint` 的兼容别名。
- `find_what_writes_safe`: `start_dbvm_watch` 的写监控别名。
- `find_what_accesses_safe`: `start_dbvm_watch` 的访问监控别名。
- `get_watch_results`: `stop_dbvm_watch` 的兼容别名。

## 环境要求

- Windows
- Cheat Engine `7.5 x64` 或 `7.6 x64`
- 本地编译时需要 Rust toolchain

## 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `CE_PLUGIN_BIND_ADDR` | 插件 HTTP 监听地址。 | `127.0.0.1:18765` |
| `CE_PLUGIN_ALLOW_REMOTE` | 是否允许非回环地址访问 HTTP 接口。除非你明确通过可信隧道或私网开放联调，否则保持关闭。 | 默认关闭 |
| `CE_PLUGIN_DISPATCH_TIMEOUT_MS` | 主线程调度超时。 | `15000` |
| `CE_PLUGIN_CONSOLE_LOG` | 设为 `0` 时关闭控制台日志。 | 默认开启 |
| `CE_PLUGIN_CONSOLE_TITLE` | 控制台窗口标题。 | `流云MCP插件` |

## 项目结构

```text
ce_plugin/
README.md
README.zh-CN.md
LICENSE
```

## 许可证

MIT，详见 [LICENSE](./LICENSE)。
