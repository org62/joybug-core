# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`joybug-core` is a Windows debugger library and TCP server written in Rust (edition 2024). It provides debugging capabilities including process control, symbol resolution, disassembly (x64/ARM64), and stepping through a JSON-framed protocol.

## Build & Test Commands

**Prerequisites:** The build requires Visual Studio with MSVC and LLVM/Clang components installed.

### One-liner for Claude Code (ARM64)

Use these commands to build/test. LIBCLANG_PATH is set in bash so it's inherited by the child process (avoids `$env:` escaping issues with the VsDevShell script):

```bash
export LIBCLANG_PATH='C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\ARM64\bin' && powershell -Command "& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -SkipAutomaticLocation; cargo build 2>&1"
```

For tests:

```bash
export LIBCLANG_PATH='C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\ARM64\bin' && powershell -Command "& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -SkipAutomaticLocation; cargo test 2>&1"
```

### One-liner for Claude Code (x64)

**IMPORTANT:** On x64 hosts, use x64 LLVM and `-Arch amd64`. Using ARM64 libclang on an x64 host fails with "invalid DLL (ARM64)".

```bash
export LIBCLANG_PATH='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin' && powershell -Command "& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch amd64 -SkipAutomaticLocation; cargo build 2>&1"
```

For tests:

```bash
export LIBCLANG_PATH='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin' && powershell -Command "& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch amd64 -SkipAutomaticLocation; cargo test 2>&1"
```

### Common Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo test                               # Run all tests
cargo test <test_name>                   # Run a specific test
cargo test -- --nocapture                # Show test output
RUST_LOG=trace cargo test -- --nocapture # With full tracing
cargo run                                # Start server on 127.0.0.1:9000
```

**Build requirements:** Rust toolchain, Windows SDK, MSVC compiler, LLVM/Clang (for LIBCLANG_PATH)

## Architecture

```
TCP Clients (DebugSession via protocol_io.rs)
           │ JSON framing (framed_json_stream.rs)
           ▼
Server (server.rs) - routes DebuggerRequest to PlatformAPI
           │
           ▼
PlatformAPI trait (interfaces.rs) - platform abstraction
           │
           ▼
WindowsPlatform (windows_platform/mod.rs)
├── Process control (process.rs, debugged_process.rs)
├── Debug event loop (debug_events.rs) - WaitForDebugEvent thread
├── Memory operations (memory.rs)
├── Module/Thread tracking (module_manager.rs, thread_manager.rs)
├── Symbol resolution (symbol_manager.rs, symbol_provider.rs)
├── Disassembly (disassembler.rs) - Capstone x64/ARM64
├── Stepping (stepper.rs) - Trap Flag/breakpoint based
└── Emulator (emulator/) - Unicorn-based CPU emulation, over an `EmuTarget`
    (a live thread, or a PE file with no process)

Offline (no process, no server): static_pe/ — `PeImage` (a PE file on disk: mapped image,
disassembly, symbols, strings, `find_bytes`, xrefs, function recovery) and `StaticTarget`
(process-less emulation with a synthetic stack and import stubs). Exposed to Lua as the `pe`
global and used by the UI's PE viewer.
```

**Key patterns:**
- Async Tokio server with blocking debug loop in separate thread
- `DebuggedProcess` per-process state with shared `SymbolManager` (Arc<RwLock>)
- `HandleSafe` wrapper for automatic Windows HANDLE cleanup
- `AlignedContext` for 16-byte CONTEXT struct alignment
- Thread-local Capstone engine caching

## Protocol

Requests/responses defined in `protocol.rs`. Client API in `protocol_io.rs` (`DebugSession`).

## Testing

Integration tests in `tests/` use compiled C programs from `tests/test_programs/` (built by build.rs with MSVC). Tests require Windows with debugging privileges.

## Key Files

- `interfaces.rs` - Core trait definitions (PlatformAPI, SymbolProvider, DisassemblerProvider)
- `protocol.rs` - All request/response/event types
- `windows_platform/mod.rs` - Main WindowsPlatform implementation
- `windows_platform/stepper.rs` - Step In/Over/Out implementation
- `emulator/mod.rs` - Unicorn CPU emulator for forward execution (over an `EmuTarget`: `emulator/target.rs`)
- `static_pe/mod.rs` - `PeImage`: offline PE analysis (mapped image, xrefs, functions, process-less emulation)
- `callstack_proposal.md` - Design doc for call stack feature
- `docs/stepping/` - Stepping algorithm analysis
- [docs/jlua-guide.md](docs/jlua-guide.md) - Lua scripting API reference (jlua REPL + `dbg` API)

## Lua Scripting (`src/scripting/`)

Every debugger feature must be accessible from Lua. When adding a new feature:

1. Add the Lua binding method in `src/scripting/bindings.rs` (`dbg:*`), or `src/scripting/pe.rs` for the offline `pe` image object
2. Add a Lua integration test in `tests/lua/` (grouped by topic: basics, breakpoints, disassembly, memory, stepping, modules, emulation)
3. Register the test in `tests/scripting_test.rs` (use `run_lua_test_file()` helper)
4. Update [docs/jlua-guide.md](docs/jlua-guide.md) with the new API

Key files:
- `src/scripting/bindings.rs` - All `dbg:*` method bindings (LuaDebugClient)
- `src/scripting/pe.rs` - The `pe` global (offline PE analysis over `static_pe::PeImage`)
- `src/scripting/debug_client.rs` - DebugClient, event loop, helper converters (instruction_to_lua_table, etc.)
- `src/scripting/lua_helpers.lua` - Built-in Lua helpers (hex, hexdump, regs, disasm, etc.)
- `src/scripting/repl.rs` - Interactive REPL with tab completion
- `tests/lua/` - Lua test scripts organized by topic

## Feature Documentation

- [Emulator Feature](.claude/tasks/EMU.md) - CPU emulation with Unicorn engine
