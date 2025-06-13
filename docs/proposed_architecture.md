# Proposed Debugger Architecture

## 1. Overview
- Modular, maintainable, and extensible design
- Initially targets Windows (x64/arm64), extensible to Linux
- Client/server architecture: server can run remotely, communicates over network
- Each debug session runs its event loop on a dedicated thread

## 2. High-Level Modules
- **Network Layer**: Handles async client/server communication (e.g., with `tokio`, `serde`)
- **Session Manager**: Manages debug sessions, each on its own thread
- **Debug Session**: Orchestrates the debug loop for a single process
- **Platform Abstraction**: Trait-based interface for OS-specific debugging APIs
    - Implementations: `WindowsAPI`, `LinuxAPI`, etc.
- **Breakpoint Manager**: Manages breakpoints
- **Memory Manager**: Handles memory read/write
- **Thread Manager**: Controls thread operations

## 3. Interfaces & Extensibility
- Use Rust traits for all major interfaces (e.g., `PlatformAPI`)
- Add new platforms by implementing the trait and using conditional compilation (`#[cfg(windows)]`, etc.)
- Clear separation of protocol, platform code, and business logic

## 4. Technologies & Methods
- **Async/await**: For networking and event-driven logic
- **Serde**: For protocol serialization
- **Tokio**: Async runtime and networking
- **Error Handling**: `thiserror` or `anyhow`
- **Testing**: Rust's built-in test framework, integration tests for protocol

## 5. Example Trait (Platform Abstraction)
```rust
trait PlatformAPI {
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn continue_exec(&mut self) -> Result<()>;
    fn set_breakpoint(&mut self, addr: u64) -> Result<()>;
    // ...
}
```

## 6. Summary Table

| Module             | Responsibility                | Extensible? | Example Tech      |
|--------------------|------------------------------|-------------|-------------------|
| Network Layer      | Client/server comms           | Yes         | tokio, serde      |
| Session Manager    | Session lifecycle             | Yes         | std, tokio        |
| Debug Session      | Debug loop, orchestration     | Yes         | std, traits       |
| PlatformAPI        | OS-specific debug operations  | Yes         | traits, cfg       |
| BreakpointManager  | Breakpoint logic              | Yes         | std               |
| MemoryManager      | Memory read/write             | Yes         | std               |
| ThreadManager      | Thread control                | Yes         | std               |

## 7. Next Steps
- Define the network protocol (e.g., JSON, protobuf)
- Sketch out `PlatformAPI` and its Windows implementation
- Set up async network layer
- Build minimal session manager and debug loop
