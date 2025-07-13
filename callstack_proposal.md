# Call Stack Feature Implementation Proposal

This document outlines the plan to implement a call stack retrieval feature for the Joybug debugger on Windows, supporting both x64 and ARM64 architectures.

## 1. Summary

The goal is to provide a function to get the call stack (backtrace) for a specific thread within a debugged process. This will be achieved by using the `StackWalk2` function from the `dbghelp.dll` library on Windows, which is the standard and most robust method available.

The implementation will be designed for long-term maintainability by encapsulating platform-specific logic and exposing the functionality through the existing `PlatformAPI` trait.

## 2. Dependencies

No new external dependencies are required. The existing `windows-sys` crate already includes the necessary bindings for `dbghelp.dll` functions under the `Win32_System_Diagnostics_Debug` feature flag, which is enabled in `Cargo.toml`.

## 3. Data Structure Changes (`src/interfaces.rs`)

A new struct, `CallFrame`, will be defined to represent a single frame in the call stack.

```rust
// In src/interfaces.rs

// ... (existing structs)

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallFrame {
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub symbol: Option<SymbolInfo>,
}
```

This struct will be used across the application, from the platform-specific implementation to the communication protocol.

## 4. Protocol Changes (`src/protocol.rs`)

The debugger communication protocol will be extended to support requesting and receiving call stacks.

```rust
// In src/protocol.rs -> DebuggerRequest enum

pub enum DebuggerRequest {
    // ... existing requests
    GetCallStack { pid: u32, tid: u32 },
}

// In src/protocol.rs -> DebuggerResponse enum

pub enum DebuggerResponse {
    // ... existing responses
    CallStack { frames: Vec<crate::interfaces::CallFrame> },
}
```

## 5. Platform API Changes (`src/interfaces.rs`)

The `PlatformAPI` trait will be updated with a new method for retrieving the call stack.

```rust
// In src/interfaces.rs -> PlatformAPI trait

pub trait PlatformAPI: Send + Sync {
    // ... existing methods
    fn get_call_stack(&mut self, pid: u32, tid: u32) -> Result<Vec<CallFrame>, PlatformError>;
}
```

## 6. Windows Implementation (`src/windows_platform/`)

### New Module: `src/windows_platform/callstack.rs`

To keep the code organized and maintainable, the stack walking logic will be placed in a new file.

This module will contain a function `get_call_stack` that takes a mutable reference to `WindowsPlatform`, a `pid`, and a `tid`.

### `callstack.rs` Implementation Details

1.  **Get Process and Thread Info**: Retrieve the process handle, thread handle, and process architecture from the `WindowsPlatform` struct.
2.  **Get Thread Context**: Fetch the current `CONTEXT` of the target thread using the existing `get_thread_context` method. This is a prerequisite for initializing the stack walker.
3.  **Initialize `STACKFRAME_EX`**: Create and initialize a `STACKFRAME_EX` struct. The initial values for the program counter (`AddrPC`), stack pointer (`AddrStack`), and frame pointer (`AddrFrame`) will be populated from the thread's `CONTEXT` structure.
    *   **x64**: Use `Rip`, `Rsp`, and `Rbp` registers.
    *   **ARM64**: Use `Pc`, `Sp`, and `Fp` (register `X29`) registers.
4.  **Loop with `StackWalk2`**: Call `StackWalk2` in a loop.
    *   The `MachineType` parameter will be set based on the process architecture (`IMAGE_FILE_MACHINE_AMD64` for x64, `IMAGE_FILE_MACHINE_ARM64` for ARM64).
    *   The required callbacks (`ReadMemoryRoutine`, `FunctionTableAccessRoutine`, `GetModuleBaseRoutine`) will be provided. We can leverage existing `read_memory` functionality and use `SymFunctionTableAccess64` and `SymGetModuleBase64` from `dbghelp`.
5.  **Frame Processing**: Inside the loop, for each valid frame returned by `StackWalk2`:
    *   Create a `CallFrame` instance.
    *   The `instruction_pointer` will be the `AddrPC.Offset` from the `STACKFRAME_EX`.
    *   The `resolve_address_to_symbol` method from the `SymbolManager` will be used to resolve the instruction pointer to a symbol.
    *   The populated `CallFrame` is added to a result vector.
6.  The loop continues until `StackWalk2` returns `FALSE`, indicating the end of the stack, or a reasonable frame limit is reached.

### Changes in `src/windows_platform/mod.rs`

1.  **Add `callstack` module**: Add `mod callstack;`
2.  **Implement `get_call_stack`**: Implement the new `get_call_stack` method for `WindowsPlatform`. This will simply delegate the call to the function in the new `callstack.rs` module.
3.  **Determine Process Architecture**: The architecture of the debugged process needs to be determined and stored. This will be done when attaching (`process::attach`) or launching (`process::launch`) a process, for example by inspecting the PE header of the process's main executable file. The `Architecture` enum will be added to the `DebuggedProcess` struct.

```rust
// In src/windows_platform/mod.rs
pub(crate) struct DebuggedProcess {
    pub(crate) process_handle: HandleSafe,
    pub(crate) architecture: Architecture, // <--- NEW FIELD
    pub(crate) module_manager: ModuleManager,
    pub(crate) thread_manager: ThreadManager,
}
```

## 7. Server Integration (`src/server.rs`)

The main server loop in `handle_connection` will be updated to handle the new `DebuggerRequest::GetCallStack` message. It will call `platform.get_call_stack(pid, tid)` and send back either a `DebuggerResponse::CallStack` with the result or a `DebuggerResponse::Error`.

This plan ensures a clean and extensible implementation that integrates well with the existing codebase structure. 