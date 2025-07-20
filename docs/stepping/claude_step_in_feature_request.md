# Feature Request: Single Stepper Interface Implementation

## Overview

Implement a comprehensive stepping interface for the joybug2 debugger that supports single-step debugging operations (Step Into, Step Over, Step Out) for both x64 and ARM64 architectures.

## Background

Based on analysis of TitanEngine, koidbg, and GleeBug implementations, stepping is achieved through:
- **x64**: Setting Trap Flag (TF) in EFlags register to trigger `STATUS_SINGLE_STEP` exception
- **ARM64**: Setting SS bit (bit 21) in MDSCR_EL1 register to enable single-step mode

## Proposed Interface Design

### 1. Protocol Extensions

Add new request/response types to `protocol.rs`:

```rust
// New stepping requests
StepInto { pid: u32, tid: u32 },
StepOver { pid: u32, tid: u32 },
StepOut { pid: u32, tid: u32 },

// New stepping responses
StepCompleted { pid: u32, tid: u32, stopped_address: u64 },
```

### 2. Platform API Extensions

Add stepping methods to the `PlatformAPI` trait in `interfaces.rs`:

```rust
// Core stepping operations
fn step_into(&mut self, pid: u32, tid: u32) -> Result<Option<DebugEvent>, PlatformError>;
fn step_over(&mut self, pid: u32, tid: u32) -> Result<Option<DebugEvent>, PlatformError>;
fn step_out(&mut self, pid: u32, tid: u32) -> Result<Option<DebugEvent>, PlatformError>;
```

### 3. Architecture-Specific Implementation

Create a new `stepping` module in `windows_platform/`:

```rust
// windows_platform/stepping.rs
pub struct Stepper {
    arch: Architecture,
    // State tracking for step operations
    active_steps: HashMap<(u32, u32), StepState>, // (pid, tid) -> state
}

#[derive(Debug, Clone)]
pub enum StepType {
    Into,
    Over,
    Out,
}

#[derive(Debug, Clone)]
pub struct StepState {
    step_type: StepType,
    original_context: ThreadContext,
    breakpoint_addresses: Vec<u64>, // For step over/out
}
```

### 4. Error Types

Add stepping-specific errors to `interfaces.rs`:

```rust
#[derive(Debug, Error)]
pub enum SteppingError {
    #[error("Architecture not supported: {0:?}")]
    UnsupportedArchitecture(Architecture),
    #[error("Thread context manipulation failed: {0}")]
    ContextError(String),
    #[error("Single step already active for thread {0}")]
    StepAlreadyActive(u32),
    #[error("No active step for thread {0}")]
    NoActiveStep(u32),
    #[error("Disassembly required for step over/out failed: {0}")]
    DisassemblyFailed(String),
}
```

## Implementation Requirements

### Phase 1: Step Into (Current Focus)

1. **Context Manipulation**:
   - x64: Set/clear Trap Flag (bit 8) in EFlags register
   - ARM64: Set/clear SS bit (bit 21) in MDSCR_EL1 register

2. **Exception Handling**:
   - Handle `STATUS_SINGLE_STEP` exceptions on Windows
   - Distinguish between internal stepping and external single-step events

3. **State Management**:
   - Track which threads have active stepping
   - Store original context for restoration if needed

### Phase 2: Step Over (Future)

1. **Instruction Analysis**:
   - Integrate with existing disassembler (Capstone)
   - Identify CALL, REP, PUSHF instructions that need special handling
   - Calculate next instruction address after calls

2. **Breakpoint Management**:
   - Set temporary breakpoints at instruction following calls
   - Clean up breakpoints after step completion

3. **Special Cases**:
   - Handle PUSHF instruction (clear TF from stack after execution)
   - Handle segment manipulation instructions

### Phase 3: Step Out (Future)

1. **Stack Analysis**:
   - Scan forward for RET instructions
   - Handle multiple return paths
   - Set breakpoints at return addresses

2. **Function Boundary Detection**:
   - Use symbol information when available
   - Fall back to disassembly-based detection

## Architecture-Specific Details

### x64 Implementation

```rust
// Trap Flag manipulation in EFlags
const EFLAGS_TF_BIT: u32 = 0x100; // Bit 8

fn set_trap_flag_x64(context: &mut CONTEXT) {
    context.EFlags |= EFLAGS_TF_BIT;
}

fn clear_trap_flag_x64(context: &mut CONTEXT) {
    context.EFlags &= !EFLAGS_TF_BIT;
}
```

### ARM64 Implementation

```rust
// Single Step bit in MDSCR_EL1
const MDSCR_EL1_SS_BIT: u64 = 1 << 21; // Bit 21

// Note: ARM64 context manipulation will require platform-specific code
// and proper handling of system registers
```

## Integration Points

### 1. Server Request Handling

Update `server.rs` to handle new stepping requests:

```rust
Ok(DebuggerRequest::StepInto { pid, tid }) => {
    match platform.step_into(pid, tid) {
        Ok(Some(event)) => DebuggerResponse::Event { event },
        Ok(None) => DebuggerResponse::StepCompleted { 
            pid, 
            tid, 
            stopped_address: /* get from context */ 
        },
        Err(e) => DebuggerResponse::Error { message: e.to_string() },
    }
}
```

### 2. Debug Event Processing

Enhance debug event handling to recognize and process single-step exceptions as stepping completions rather than regular exceptions.

### 3. Thread Safety

Ensure stepping operations are thread-safe when multiple clients are connected, with proper synchronization of step state.

## Testing Strategy

1. **Unit Tests**:
   - Context manipulation functions
   - Step state management
   - Error conditions

2. **Integration Tests**:
   - Step through simple programs
   - Test with various instruction types
   - Multi-threaded stepping scenarios

3. **Architecture Tests**:
   - Verify correct behavior on both x64 and ARM64
   - Test special instruction handling

## Dependencies

1. **Existing Components**:
   - Thread context management (already implemented)
   - Disassembler integration (Capstone, already available)
   - Debug event handling system

2. **New Components Needed**:
   - Architecture-specific context flag manipulation
   - Step state tracking and management
   - Enhanced exception filtering for single-step events

## Future Enhancements

1. **Conditional Stepping**: Step until condition is met
2. **Step Count**: Step N instructions
3. **Step with Callbacks**: Custom logic during stepping
4. **Safe Stepping**: Suspend other threads during step operations
5. **Step Tracing**: Record step history for analysis

## Implementation Priority

1. **High Priority**: Step Into for x64
2. **Medium Priority**: Step Into for ARM64
3. **Low Priority**: Step Over and Step Out (can be built on Step Into foundation)

This design provides a solid foundation for implementing stepping functionality while maintaining consistency with the existing codebase architecture and following proven patterns from other debugging engines.
