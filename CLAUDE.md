# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`joybug-core` is a debugger library and TCP server written in Rust (edition 2024) for Windows (x64/ARM64, WOW64) and Linux (x86-64, ptrace). It provides debugging capabilities including process control, symbol resolution, disassembly (x64/ARM64), and stepping through a JSON-framed protocol.

## Build & Test Commands

**Prerequisites:** On Windows the build requires Visual Studio with MSVC and LLVM/Clang components installed. On Linux: `build-essential cmake pkg-config clang libclang-dev python3-dev` (clang for the unicorn bindgen, python for keystone's cmake); then plain `cargo build` / `cargo test` work, and `cargo test linux_` runs the ptrace integration tests.

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
cargo run -- --listen 127.0.0.1:9000   # Headless debug server (jlua is the only binary)
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
           ├── WindowsPlatform (windows_platform/) - Win32 debug API
           │     process.rs, debug_events.rs (WaitForDebugEvent thread), memory.rs,
           │     win_ops.rs (`ProcessOps` over a HANDLE), thread_context.rs, ...
           └── LinuxPlatform (linux_platform/, cfg(target_os = "linux")) - ptrace
                 tracer.rs (one thread owns every ptrace call: SEIZE, all-stop,
                 held/deferred threads, TF via PTRACE_SINGLESTEP), ops.rs (`ProcessOps`),
                 launch.rs, procfs.rs, maps.rs, memory.rs (/proc/pid/mem), regs.rs
                 (fills the x64 CONTEXT), loader.rs (_dl_debug_state hook + link_map
                 diff, entry-point hook = InitialBreakpoint), signals.rs (signal →
                 NTSTATUS), unwind*.rs (.eh_frame CFI), elf_symbols.rs (+ .eh_frame
                 function tables), elf_info.rs (ModuleExtraInfo from ELF headers),
                 dwarf.rs (lines), dwarf_types.rs (types), objects.rs (file
                 descriptors / sockets / capabilities = the Handles window),
                 coredump.rs (`write_minidump` = an ELF core file)
           │
           ▼ both are thin layers over
debugger_core/ (OS-neutral) - `DebugBook`: module_manager, thread_table, breakpoints,
  stepping (Step In/Over/Out), coverage, watchpoints, hw_breakpoints, events.rs (the
  breakpoint / single-step dispatch ladder), disasm.rs + disassembler.rs (Capstone),
  dereference, function_args, strings — all generic over `ops::ProcessOps`
symbols/ - `SymbolManager` over a `SymbolBackend` (`PdbBackend` on Windows, `ElfBackend`
  on Linux: .symtab/.dynsym, DWARF lines and types, .eh_frame function tables),
  symbol_provider, type_provider (the PDB TPI parser and the shared type record model),
  module_extra
emulator/ - Unicorn-based CPU emulation, over an `EmuTarget` (a live thread, or a PE
  file with no process)

Offline (no process, no server): static_image/ — `StaticImage`, the format-neutral image (a file
laid out at its load base: mapped image, disassembly, symbols, strings, `find_bytes`, xrefs,
function recovery, `StaticTarget` process-less emulation with a synthetic stack and import stubs);
static_pe/ — `PeImage` (PE headers, PDB discovery, resources) and static_elf/ — `ElfImage` (ELF
headers through `elf/`, symbols from the file or a separate debug file), both `Deref`ing to the
shared image; `StaticFile` (`Pe` | `Elf`) opens by magic for the viewer and Lua. Exposed to Lua as
the `pe` and `elf` globals and used by the UI's image viewer, on both OSes.
```

**Linux: children, signals, dumps.** A wait reports the next stop of *any* traced process, like
`WaitForDebugEvent` (`Tracer::kick` + `wait_any`; `LinuxPlatform::run_until_event` /
`dispatch_stop`). With `debug_children` a `fork` child becomes a debugged process at the fork
(`ProcessCreated`, its modules, an `InitialBreakpoint` where it stands) and a `vfork` child
(`posix_spawn`, `system`) at its exec; without it the child is detached. Either way a fork child
gets the original bytes back under the parent's breakpoints, and a vfork child — which runs in
the parent's memory — has them lifted until `PTRACE_EVENT_VFORK_DONE`. Continuing a child past
its `ProcessExited` releases it. Signals: the fault signals are always reported as their
NTSTATUS; any other signal is delivered unseen unless the client listed it with
`SetReportedSignals`, and then it is an `Exception` with code `posix_signals::signal_exception_code`
(`0x4C53_0000 | signo`, parameters `[signo, si_code, sender pid]`) that the continue delivers
(`pass_exception`) or drops. Passing a signal nobody handles (`SigCgt`/`SigIgn` in
`/proc/pid/status`) first stops once more as a second-chance exception. `inject_syscall` runs one
system call on a stopped thread (`mmap` for `allocate_memory`, `close` for `close_remote_handle`).

**Key patterns:**
- Async Tokio server with blocking debug loop in separate thread
- `DebuggedProcess` per-process state with shared `SymbolManager` (Arc<RwLock>)
- `HandleSafe` wrapper for automatic Windows HANDLE cleanup
- `AlignedContext` for 16-byte CONTEXT struct alignment
- Thread-local Capstone engine caching

## Protocol

Requests/responses defined in `protocol.rs`. Client API in `protocol_io.rs` (`DebugSession`).

## Testing

Integration tests in `tests/` use compiled C programs from `tests/test_programs/` (built by build.rs: MSVC on Windows, `cc` on Linux from `tests/test_programs/linux/`). The Windows tests require Windows with debugging privileges; `tests/linux_*.rs` run on Linux (`cargo test linux_`). The shared `tests/common/mod.rs` finds programs on either OS.

## Key Files

- `interfaces.rs` - Core trait definitions (PlatformAPI, SymbolProvider, DisassemblerProvider)
- `protocol.rs` - All request/response/event types
- `windows_platform/mod.rs` - Main WindowsPlatform implementation
- `linux_platform/mod.rs` - Main LinuxPlatform implementation (ptrace); `tracer.rs` is the one thread allowed to ptrace
- `debugger_core/stepping.rs` - Step In/Over/Out implementation (shared); `debugger_core/events.rs` - breakpoint/single-step ladder (shared)
- `symbols/backend.rs` - `SymbolBackend` (PDB / ELF) behind the shared `SymbolManager`
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
