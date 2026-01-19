# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Joybug2 is a Windows debugger library and TCP server written in Rust (edition 2024). It provides debugging capabilities including process control, symbol resolution, disassembly (x64/ARM64), and stepping through a JSON-framed protocol.

## Build & Test Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo test                               # Run all tests
cargo test <test_name>                   # Run a specific test
cargo test -- --nocapture                # Show test output
RUST_LOG=trace cargo test -- --nocapture # With full tracing
cargo run                                # Start server on 127.0.0.1:9000
```

**Build requirements:** Rust toolchain, Windows SDK, MSVC compiler (cl.exe needed for test program compilation in build.rs)

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
└── Emulator (emulator/) - Unicorn-based CPU emulation
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
- `emulator/mod.rs` - Unicorn CPU emulator for forward execution
- `callstack_proposal.md` - Design doc for call stack feature
- `docs/stepping/` - Stepping algorithm analysis

## Feature Documentation

- [Emulator Feature](.claude/tasks/EMU.md) - CPU emulation with Unicorn engine
