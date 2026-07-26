# VEH Debugging - Design Discussion

## What is VEH Debugging?

Instead of using the Windows Debug API (`WaitForDebugEvent`/`ContinueDebugEvent`), a DLL is injected into the target process. That DLL registers a **Vectored Exception Handler** via `AddVectoredExceptionHandler()`. When exceptions occur (breakpoints, single-step, access violations), the VEH handler captures them *inside* the target process and forwards them to the debugger via IPC (shared memory + events).

**Key difference**: The debugger never calls `DebugActiveProcess()` or `CreateProcess(DEBUG_PROCESS)`. The target process is NOT a "debugee" from the OS perspective. This makes VEH debugging invisible to `IsDebuggerPresent()` and `NtQueryInformationProcess(ProcessDebugPort)`.

---

## How It Maps to Current joybug-core Architecture

### The `PlatformAPI` Trait is the Right Abstraction Boundary

The existing `PlatformAPI` trait (`interfaces.rs:228-378`) already cleanly separates the *what* (attach, continue, set breakpoint, read memory) from the *how* (Windows Debug API). A VEH debugger would be a **second implementation** of `PlatformAPI`:

```
PlatformAPI (trait)
  ├── WindowsPlatform   (current - uses WaitForDebugEvent)
  └── VEHPlatform       (new - uses injected DLL + shared memory)
```

### Components That Stay the Same (Generic)

| Component | Why unchanged |
|-----------|---------------|
| `protocol.rs` / `server.rs` | JSON-framed TCP protocol is transport-agnostic |
| `ModuleManager` / `ThreadManager` | Data structures, no Windows Debug API calls |
| `SymbolManager` / `CapstoneDisassembler` | Symbol resolution and disassembly are independent |
| `DebuggedProcess` (partially) | Breakpoint bookkeeping (original bytes, rearm state) is reusable |
| Emulator (`emulator/`) | Unicorn CPU emulation is independent |
| Callstack walker | Uses register reads + memory reads, both available via VEH |

### Components That Must Be Replaced/Extended

#### 1. Process Attach/Launch (`process.rs`)

**Current**: `CreateProcessW(DEBUG_PROCESS)` or `DebugActiveProcess(pid)`

**VEH approach**:
- **Attach**: Inject VEH DLL into running process via `CreateRemoteThread` + `LoadLibraryA`
- **Launch**: Create process normally (no debug flags), then inject DLL
- DLL initialization registers VEH handler, opens shared memory, starts thread polling

**Cheat Engine reference**: `CEFuncProc.pas:1155-1322` generates x64 shellcode that calls `LoadLibraryA` → `GetProcAddress` → exported init function. Injected via `CreateRemoteThread`.

#### 2. Debug Event Loop (`debug_events.rs`)

**Current**: Blocking `WaitForDebugEvent()` → `handle_debug_event()` → `ContinueDebugEvent()`

**VEH approach**: 
- Debugger side: `WaitForSingleObject(HasDebugEvent)` on a Windows event
- When signaled: read exception info + context from shared memory
- Process exception, potentially modify context in shared memory
- Signal `HasHandledDebugEvent` to resume the target thread

The VEH handler inside the DLL:
1. Enters critical section (only one exception at a time)
2. Copies `EXCEPTION_RECORD` + `CONTEXT` to shared memory
3. Signals `HasDebugEvent`
4. Waits for `HasHandledDebugEvent` (with timeout + heartbeat check)
5. Copies modified `CONTEXT` back from shared memory
6. Returns `EXCEPTION_CONTINUE_EXECUTION`

**Key**: The faulting thread is *suspended inside the VEH handler* while the debugger processes. No `SuspendThread`/`ResumeThread` needed.

#### 3. Software Breakpoints (`mod.rs` set_breakpoint/remove_breakpoint)

**Current**: `WriteProcessMemory` to write `0xCC` (int3) from debugger process.

**VEH approach**: Same mechanism! `WriteProcessMemory` still works from the debugger process (you have a process handle from `OpenProcess`). The int3 fires an exception, which the VEH handler catches instead of the kernel debug port.

Alternatively, the DLL could write breakpoints from *inside* the process (no cross-process memory write needed), but `WriteProcessMemory` is simpler.

#### 4. Hardware Breakpoints (`hardware_breakpoints.rs`)

**Current**: `GetThreadContext` / `SetThreadContext` from debugger process to manipulate DR0-DR7.

**VEH approach**: Two options:
- **Option A (Cheat Engine style)**: Modify debug registers via the `CONTEXT` structure inside the VEH handler. When an exception occurs, the handler receives a `CONTEXT*` — writing to `Dr0-Dr7` there takes effect when the handler returns. The DLL also needs to set DR registers on new threads (via thread polling + `SetThreadContext` from within the process).
- **Option B**: Continue using `GetThreadContext`/`SetThreadContext` from the debugger process. This works but requires the thread to be suspended.

Option A is more elegant because you're already handling the context in the VEH handler.

#### 5. Stepping (`stepper.rs`)

**Current**: Sets trap flag (`EFlags |= 0x100`) via `SetThreadContext`.

**VEH approach**: Same mechanism, but the trap flag is set via the shared `CONTEXT` in the VEH handler. When the handler returns with TF set, the next instruction triggers `STATUS_SINGLE_STEP`, which the VEH handler catches again.

Step-over and step-out use software breakpoints — unchanged.

#### 6. Thread/Module Discovery

**Current**: Kernel sends `CREATE_THREAD_DEBUG_EVENT`, `LOAD_DLL_DEBUG_EVENT` etc.

**VEH approach**: The OS does NOT send these events (no debug port). Solutions:
- **Thread polling** (Cheat Engine approach): A thread in the DLL periodically calls `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` and diffs against known threads. Emits synthetic events for creates/destroys.
- **Module tracking**: Similar polling with `TH32CS_SNAPMODULE`, or hook `LdrLoadDll`/`LdrUnloadDll` for real-time notification.

This is a significant gap — module load events arrive late (polling delay) or require hooking ntdll internals.

#### 7. Memory Access (`memory.rs`)

**Current**: `ReadProcessMemory` / `WriteProcessMemory` from debugger.

**VEH approach**: Identical — these APIs work regardless of debug status. You just need `PROCESS_VM_READ | PROCESS_VM_WRITE` access rights from `OpenProcess`.

#### 8. `ContinueDebugEvent` / Exception Pass-Through

**Current**: `ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED)` passes exception to process.

**VEH approach**: The VEH handler returns `EXCEPTION_CONTINUE_SEARCH` instead of `EXCEPTION_CONTINUE_EXECUTION`. This lets the exception propagate to other handlers (SEH chain, default handler, crash).

---

## DLL Injection Design

The VEH DLL needs to:

### Exports
- `Init(shared_memory_name: *const u16)` — called after injection to set up VEH

### Init Sequence
1. Open named file mapping (created by debugger) → `MapViewOfFile`
2. Read config: event handles (duplicated by debugger), settings
3. `AddVectoredExceptionHandler(1, handler)` — priority 1 = first handler
4. Start thread polling thread
5. Enumerate existing threads/modules → send initial events
6. Signal "ready" to debugger

### VEH Handler
```rust
extern "system" fn handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let shared = get_shared_mem();
    enter_critical_section();  // serialize exceptions
    
    // Copy exception + context to shared memory
    shared.exception = *(*info).ExceptionRecord;
    shared.context = *(*info).ContextRecord;
    shared.thread_id = GetCurrentThreadId();
    
    // Signal debugger
    SetEvent(shared.has_debug_event);
    
    // Wait for debugger response
    WaitForSingleObject(shared.has_handled_event, 5000);
    
    // Apply modified context (debugger may have changed registers, DR regs, etc.)
    *(*info).ContextRecord = shared.context;
    
    leave_critical_section();
    
    if shared.continue_method == HANDLED {
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        EXCEPTION_CONTINUE_SEARCH
    }
}
```

### Shared Memory Layout
```rust
#[repr(C)]
struct VEHSharedMem {
    version: u32,
    has_debug_event: HANDLE,      // DLL → debugger
    has_handled_event: HANDLE,    // debugger → DLL
    heartbeat: u32,               // debugger increments to prove alive
    continue_method: u32,         // HANDLED or SEARCH
    thread_id: u32,
    process_id: u32,
    context: CONTEXT,             // ~1232 bytes on x64
    exception: EXCEPTION_RECORD,
    // Thread poll results
    new_threads: [u32; 64],
    exited_threads: [u32; 64],
}
```

### Injection Flow (debugger side)
1. `OpenProcess(PROCESS_ALL_ACCESS, pid)`
2. Create named file mapping + events
3. Duplicate event handles into target process (`DuplicateHandle`)
4. `VirtualAllocEx` in target for DLL path + init param
5. Write DLL path + shared memory name to allocated memory
6. `CreateRemoteThread` calling `LoadLibraryA` with DLL path
7. Wait for load, then `CreateRemoteThread` calling DLL's `Init` export
8. Wait for "ready" signal

---

## Trade-offs vs Current Debug API Approach

| Aspect | Debug API (current) | VEH |
|--------|---------------------|-----|
| Anti-debug detection | Detectable (`IsDebuggerPresent`, `NtQueryInformationProcess`) | Invisible to standard checks |
| Thread/module events | Real-time from kernel | Polling-based (delayed) or requires ntdll hooks |
| Reliability | Kernel-guaranteed delivery | DLL can be unloaded, VEH can be removed by target |
| Multi-process | `DEBUG_PROCESS` flag cascades to children | Must inject into each child separately |
| Performance | Kernel context switch per event | Shared memory is faster for context exchange |
| Breakpoint int3 | Works the same | Works the same |
| Setup complexity | One API call (`DebugActiveProcess`) | DLL injection + shared memory + event setup |
| Process handle needed | Debug rights | `PROCESS_ALL_ACCESS` for injection |
| Cleanup on debugger crash | Kernel detaches automatically | DLL stays loaded (heartbeat timeout → self-unload) |

---

## Implementation Strategy

If implementing this, I'd suggest:

1. **Build the VEH DLL as a separate Rust cdylib crate** (e.g., `joybug-core-veh-dll/`)
2. **Create `VEHPlatform` implementing `PlatformAPI`** alongside `WindowsPlatform`
3. **Share types** between DLL and debugger via a common crate (`joybug-core-veh-shared/`)
4. **Start with hardware breakpoints only** (no int3 patching initially) — simplest path
5. **Add thread polling** for thread create/exit events
6. **Make the server configurable** to use either `WindowsPlatform` or `VEHPlatform`

The `PlatformAPI` trait is well-designed for this — the protocol layer, symbol resolution, and disassembly are all reusable without changes.
