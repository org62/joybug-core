# Emulator Feature Documentation

## Overview

The emulator module provides CPU emulation capabilities using the Unicorn engine. It enables forward emulation from debugger state with configurable hook modes for different use cases: basic block tracking, instruction tracing, module transition detection, and syscall interception.

## Architecture

```
src/emulator/
├── mod.rs       # Main Emulator struct and emulation logic
├── error.rs     # EmulatorError types
└── registers.rs # Register read/write helpers for x64 and ARM64
```

## Emulation Modes

The emulator supports 5 distinct modes, each installing only the hooks needed for maximum performance:

| Mode | Hook Type | Description | Performance |
|------|-----------|-------------|-------------|
| `Basic` | None | Run instructions with no per-instruction hooks | Fastest |
| `InstructionTrace` | CODE | Record every instruction (addr, size) | Slowest |
| `BasicBlock` | BLOCK | Track basic block boundaries only | Fast |
| `ModuleTransition` | Memory fault | Stop when execution moves to different module | Fast |
| `Syscall` | INSN_SYS | Stop on first syscall instruction | Fast |

### Mode Details

**Basic Mode**: No per-instruction hooks installed. Memory fault hook handles lazy loading. The `basic_blocks` vector contains only the start address. Best for fast forward emulation when no detailed tracking is needed.

**InstructionTrace Mode**: CODE hook fires on every instruction, recording `(address, size)` pairs. Also tracks basic blocks via non-sequential jump detection. Use when you need full instruction-level trace.

**BasicBlock Mode**: BLOCK hook fires at translation block boundaries (Unicorn's internal basic blocks). More efficient than InstructionTrace for basic block discovery.

**ModuleTransition Mode**: Detects when execution fetches from a page belonging to a different module. No per-instruction hook - detection happens on memory fault when loading new code pages.

**Syscall Mode**: Installs x86 SYSCALL instruction hook. Stops emulation when first syscall is encountered, recording the address in `StopReason::Syscall { address }`. Currently x64 only.

## Key Components

### Emulator Struct (`src/emulator/mod.rs`)

The main `Emulator<'a>` struct wraps a Unicorn instance and provides:

- **Lazy memory loading**: Memory is loaded on-demand from the debugged process
- **Configurable page size**: Default 64KB max chunks, clamped to Windows region boundaries
- **TEB/GS segment setup**: For x64, GS_BASE is set to the Thread Environment Block address
- **Mode-specific hooks**: Hooks installed dynamically per emulation call

### Creation

```rust
// Default 64KB max chunk size
let mut emu = Emulator::from_debugger_state(platform, pid, tid)?;

// Custom page size
let mut emu = Emulator::from_debugger_state_with_page_size(platform, pid, tid, 0x1000)?;
```

### Emulation Methods

| Method | Description |
|--------|-------------|
| `emulate_with_mode(platform, max, mode)` | Emulate with specific mode |
| `emulate_instructions(platform, max)` | Emulate up to N instructions (Basic mode) |
| `emulate_until(platform, max, condition)` | Emulate until closure returns true |
| `emulate_until_register_equals(platform, reg, val, max)` | Emulate until register equals value |
| `emulate_until_address(platform, addr, max)` | Emulate until PC reaches address |

### EmulationResult

```rust
pub struct EmulationResult {
    pub final_pc: u64,              // Final instruction pointer
    pub instructions_executed: usize,
    pub stop_reason: StopReason,    // Why emulation stopped
    pub emulation_time_us: u64,     // Execution time in microseconds
    pub pages_loaded: usize,        // Memory pages loaded during emulation
    pub basic_blocks: Vec<u64>,     // Basic block start addresses visited
    pub instruction_trace: Vec<(u64, usize)>, // (addr, size) if InstructionTrace mode
}
```

### StopReason

```rust
pub enum StopReason {
    InstructionLimit,           // Hit max_instructions
    UnmappedMemory(u64),        // Memory couldn't be loaded
    Error(String),              // Unicorn error
    ConditionMet,               // User condition satisfied
    ModuleTransition { from, to, address },
    EndOfBasicBlock,
    Syscall { address },        // Syscall instruction hit
    Stopped,                    // Explicit stop requested
}
```

## Protocol Integration

### EmulationMode Enum (`src/protocol.rs`)

```rust
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum EmulationMode {
    #[default]
    Basic,          // No per-instruction hooks (fastest)
    InstructionTrace, // CODE hook records every instruction
    BasicBlock,     // BLOCK hook records basic block starts
    ModuleTransition, // Stop when execution moves to different module
    Syscall,        // Stop on first syscall instruction
}
```

### Request Types

```rust
EmulateInstructions { pid, tid, max_instructions, mode: EmulationMode }
EmulateUntilRegister { pid, tid, register, value, max_instructions }
EmulateUntilAddress { pid, tid, target_address, max_instructions }
```

### Response Type

```rust
EmulationResult { final_pc, instructions_executed, stop_reason,
                  emulation_time_us, pages_loaded, basic_blocks, instruction_trace }
```

## Memory Loading Strategy

### Page Granularity

The emulator uses configurable chunk sizes (default 64KB) for lazy memory loading:

1. When a memory fault occurs, query the Windows memory region at that address
2. Calculate chunk size: `min(max_chunk_size, region_end - aligned_addr)`
3. Check for overlaps with existing Unicorn mappings and truncate if needed
4. Map the chunk with permissions derived from Windows PAGE_* flags
5. Read content from debugged process and write to Unicorn memory

### Performance Comparison

| Chunk Size | Instructions/s | Pages Loaded | Notes |
|------------|---------------|--------------|-------|
| 4KB        | ~65k          | More         | Matches Windows page size exactly |
| 64KB       | ~77k          | Fewer        | Better performance, region-aware clamping |

### TEB Setup (x64)

For x64 Windows, the GS segment must point to the Thread Environment Block:

```rust
// In setup_x64_segments()
let teb_addr = platform.get_teb_address(pid, tid)?;
emu.reg_write(RegisterX86::GS_BASE, teb_addr)?;
// Pre-load TEB memory region
```

This enables code using `gs:[offset]` (like `gs:[0x30]` for TEB self-pointer) to work correctly.

## Server Handling (`src/server.rs`)

The server creates a fresh emulator for each request (one-shot model):

```rust
DebuggerRequest::EmulateInstructions { pid, tid, max_instructions, mode } => {
    let mut emu = Emulator::from_debugger_state(&platform, pid, tid)?;
    let result = emu.emulate_with_mode(&platform, max_instructions, mode)?;
    // Return EmulationResult response
}
```

## Testing

Integration test: `tests/emulator_test.rs`

```bash
cargo test test_emulator_integration -- --nocapture
```

Tests all 5 emulation modes and 2 conditional emulation types at cmd.exe entry point:

1. **Basic mode**: Fastest, no per-instruction hooks
2. **InstructionTrace mode**: Full instruction trace with (addr, size) pairs
3. **BasicBlock mode**: BLOCK hook for efficient block discovery
4. **ModuleTransition mode**: Detects cross-module execution
5. **Syscall mode**: Stops at first syscall instruction
6. **EmulateUntilRegister**: Condition-based register value matching
7. **EmulateUntilAddress**: Condition-based PC address matching

## Known Limitations

1. **No syscall emulation**: System calls stop emulation; only detection supported
2. **No exception handling**: CPU exceptions stop emulation
3. **One-shot model**: Each request creates a new emulator; no persistent sessions
4. **x64/ARM64 only**: No 32-bit support
5. **Syscall mode x64 only**: ARM64 SVC not yet implemented

## Future Improvements

- Persistent emulator sessions for multi-step emulation
- Syscall hooks for common Windows APIs (NtReadFile, etc.)
- Snapshot/restore for branching execution paths
- ARM64 syscall (SVC) support
- Symbolic execution integration
