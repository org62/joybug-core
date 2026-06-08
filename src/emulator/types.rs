//! Emulator type definitions and helpers

use std::collections::HashMap;

use unicorn_engine::Unicorn;

#[cfg(target_arch = "x86_64")]
use unicorn_engine::RegisterX86;

#[cfg(target_arch = "aarch64")]
use unicorn_engine::RegisterARM64;

use crate::interfaces::ModuleSymbol;
use crate::protocol::{RegisterSnapshot, MemoryAccess};

#[cfg(target_arch = "x86_64")]
use crate::protocol::X64RegisterSnapshot;

#[cfg(target_arch = "aarch64")]
use crate::protocol::Arm64RegisterSnapshot;

/// Memory region info for lazy loading
#[derive(Debug, Clone)]
pub(super) struct MappedRegion {
    pub base: u64,
    pub size: u64,
}

/// Module boundary info for transition detection
#[derive(Debug, Clone)]
pub(super) struct ModuleBoundary {
    pub name: String,
    pub base: u64,
    pub end: u64,
}

/// Result of emulation
#[derive(Debug, Clone)]
pub struct EmulationResult {
    /// Final instruction pointer
    pub final_pc: u64,
    /// Number of instructions executed
    pub instructions_executed: usize,
    /// Why emulation stopped
    pub stop_reason: StopReason,
    /// Time taken for emulation in microseconds
    pub emulation_time_us: u64,
    /// Number of pages loaded during emulation
    pub pages_loaded: usize,
    /// Basic blocks visited (start addresses)
    pub basic_blocks: Vec<u64>,
    /// Instruction trace: (address, size) pairs
    pub instruction_trace: Vec<(u64, usize)>,
    /// Register trace: full register state at each step (only populated in InstructionTrace mode)
    pub register_trace: Vec<RegisterSnapshot>,
    /// Memory trace: memory accesses at each step (only populated in InstructionTrace mode)
    pub memory_trace: Vec<Vec<MemoryAccess>>,
    /// Detailed timing breakdown
    pub stats_text: String,
    /// Memory snapshots read from emulator state after execution
    pub memory_snapshots: Vec<(u64, Vec<u8>)>,
}

/// Why emulation stopped
#[derive(Debug, Clone, PartialEq)]
pub enum StopReason {
    /// Reached instruction limit
    InstructionLimit,
    /// Hit unmapped memory that couldn't be loaded
    UnmappedMemory(u64),
    /// Hit an error during emulation
    Error(String),
    /// Condition was met
    ConditionMet,
    /// Module transition detected
    ModuleTransition { from: String, to: String, address: u64, symbol: Option<String> },
    /// End of basic block (branch/jump/call/ret)
    EndOfBasicBlock,
    /// Syscall instruction executed
    Syscall { address: u64 },
    /// Explicit stop requested
    Stopped,
    /// Reached specified exit address
    ReachedAddress(u64),
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::InstructionLimit => write!(f, "InstructionLimit"),
            StopReason::UnmappedMemory(addr) => write!(f, "UnmappedMemory(0x{:X})", addr),
            StopReason::Error(msg) => write!(f, "Error({})", msg),
            StopReason::ConditionMet => write!(f, "ConditionMet"),
            StopReason::ModuleTransition { from, to, address, symbol } => {
                match symbol {
                    Some(sym) => write!(f, "ModuleTransition({}->{}@{})", from, to, sym),
                    None => write!(f, "ModuleTransition({}->{}@0x{:X})", from, to, address),
                }
            }
            StopReason::EndOfBasicBlock => write!(f, "EndOfBasicBlock"),
            StopReason::Syscall { address } => write!(f, "Syscall(0x{:X})", address),
            StopReason::Stopped => write!(f, "Stopped"),
            StopReason::ReachedAddress(addr) => write!(f, "ReachedAddress(0x{:X})", addr),
        }
    }
}

/// Shared state for memory hook callbacks
pub(super) struct EmulatorSharedState {
    pub mapped_regions: HashMap<u64, MappedRegion>,
    pub modules: Vec<ModuleBoundary>,
    pub pending_memory_fault: Option<u64>,
    pub basic_blocks: Vec<u64>,
    pub current_module: Option<String>,
    pub module_transition: Option<(String, String, u64)>,
    pub stop_requested: bool,
    /// Instruction trace (address, size) for InstructionTrace mode
    pub instruction_trace: Vec<(u64, usize)>,
    /// Register trace (full register state at each step) for InstructionTrace mode
    pub register_trace: Vec<RegisterSnapshot>,
    /// Memory trace: memory accesses at each step for InstructionTrace mode
    pub memory_trace: Vec<Vec<MemoryAccess>>,
    /// Pending write operations: (address, size) to capture after instruction executes
    pub pending_write_ops: Vec<(u64, usize)>,
    /// Last instruction address for basic block detection
    pub last_instruction_addr: Option<u64>,
    /// Last instruction size (from CODE hook) for basic block detection
    pub last_instruction_size: Option<u32>,
    /// Syscall address (set by syscall hook)
    pub syscall_address: Option<u64>,
    /// Unhandled exception interrupt number (set by interrupt hook for non-SVC interrupts)
    pub exception_intno: Option<u32>,
    /// Exit address (stop when this address is reached)
    pub exit_address: Option<u64>,
    /// Set after a memory fault in InstructionTrace mode; tells the CODE hook
    /// to pop the stale trace entry that was recorded before the fault.
    pub retrying_after_fault: bool,
}

impl EmulatorSharedState {
    pub fn new(modules: Vec<ModuleBoundary>) -> Self {
        Self {
            mapped_regions: HashMap::new(),
            modules,
            pending_memory_fault: None,
            basic_blocks: Vec::new(),
            current_module: None,
            module_transition: None,
            stop_requested: false,
            instruction_trace: Vec::new(),
            register_trace: Vec::new(),
            memory_trace: Vec::new(),
            pending_write_ops: Vec::new(),
            last_instruction_addr: None,
            last_instruction_size: None,
            syscall_address: None,
            exception_intno: None,
            exit_address: None,
            retrying_after_fault: false,
        }
    }
}

/// Format a symbol with optional offset as a string
pub(super) fn format_symbol_with_offset(sym: ModuleSymbol, offset: u64) -> String {
    if offset == 0 {
        sym.name
    } else {
        format!("{}+0x{:x}", sym.name, offset)
    }
}

/// Create RegisterSnapshot from Unicorn x64 emulator state
#[cfg(target_arch = "x86_64")]
pub(super) fn snapshot_from_unicorn<D>(emu: &Unicorn<'_, D>, pc: u64) -> RegisterSnapshot {
    RegisterSnapshot::X64(X64RegisterSnapshot {
        rax: emu.reg_read(RegisterX86::RAX).unwrap_or(0),
        rbx: emu.reg_read(RegisterX86::RBX).unwrap_or(0),
        rcx: emu.reg_read(RegisterX86::RCX).unwrap_or(0),
        rdx: emu.reg_read(RegisterX86::RDX).unwrap_or(0),
        rsi: emu.reg_read(RegisterX86::RSI).unwrap_or(0),
        rdi: emu.reg_read(RegisterX86::RDI).unwrap_or(0),
        rbp: emu.reg_read(RegisterX86::RBP).unwrap_or(0),
        rsp: emu.reg_read(RegisterX86::RSP).unwrap_or(0),
        r8: emu.reg_read(RegisterX86::R8).unwrap_or(0),
        r9: emu.reg_read(RegisterX86::R9).unwrap_or(0),
        r10: emu.reg_read(RegisterX86::R10).unwrap_or(0),
        r11: emu.reg_read(RegisterX86::R11).unwrap_or(0),
        r12: emu.reg_read(RegisterX86::R12).unwrap_or(0),
        r13: emu.reg_read(RegisterX86::R13).unwrap_or(0),
        r14: emu.reg_read(RegisterX86::R14).unwrap_or(0),
        r15: emu.reg_read(RegisterX86::R15).unwrap_or(0),
        rip: pc,
        rflags: emu.reg_read(RegisterX86::RFLAGS).unwrap_or(0),
    })
}

/// Create RegisterSnapshot from Unicorn ARM64 emulator state
#[cfg(target_arch = "aarch64")]
pub(super) fn snapshot_from_unicorn<D>(emu: &Unicorn<'_, D>, pc: u64) -> RegisterSnapshot {
    RegisterSnapshot::Arm64(Arm64RegisterSnapshot {
        x: [
            emu.reg_read(RegisterARM64::X0).unwrap_or(0),
            emu.reg_read(RegisterARM64::X1).unwrap_or(0),
            emu.reg_read(RegisterARM64::X2).unwrap_or(0),
            emu.reg_read(RegisterARM64::X3).unwrap_or(0),
            emu.reg_read(RegisterARM64::X4).unwrap_or(0),
            emu.reg_read(RegisterARM64::X5).unwrap_or(0),
            emu.reg_read(RegisterARM64::X6).unwrap_or(0),
            emu.reg_read(RegisterARM64::X7).unwrap_or(0),
            emu.reg_read(RegisterARM64::X8).unwrap_or(0),
            emu.reg_read(RegisterARM64::X9).unwrap_or(0),
            emu.reg_read(RegisterARM64::X10).unwrap_or(0),
            emu.reg_read(RegisterARM64::X11).unwrap_or(0),
            emu.reg_read(RegisterARM64::X12).unwrap_or(0),
            emu.reg_read(RegisterARM64::X13).unwrap_or(0),
            emu.reg_read(RegisterARM64::X14).unwrap_or(0),
            emu.reg_read(RegisterARM64::X15).unwrap_or(0),
            emu.reg_read(RegisterARM64::X16).unwrap_or(0),
            emu.reg_read(RegisterARM64::X17).unwrap_or(0),
            emu.reg_read(RegisterARM64::X18).unwrap_or(0),
            emu.reg_read(RegisterARM64::X19).unwrap_or(0),
            emu.reg_read(RegisterARM64::X20).unwrap_or(0),
            emu.reg_read(RegisterARM64::X21).unwrap_or(0),
            emu.reg_read(RegisterARM64::X22).unwrap_or(0),
            emu.reg_read(RegisterARM64::X23).unwrap_or(0),
            emu.reg_read(RegisterARM64::X24).unwrap_or(0),
            emu.reg_read(RegisterARM64::X25).unwrap_or(0),
            emu.reg_read(RegisterARM64::X26).unwrap_or(0),
            emu.reg_read(RegisterARM64::X27).unwrap_or(0),
            emu.reg_read(RegisterARM64::X28).unwrap_or(0),
        ],
        fp: emu.reg_read(RegisterARM64::X29).unwrap_or(0),
        lr: emu.reg_read(RegisterARM64::X30).unwrap_or(0),
        sp: emu.reg_read(RegisterARM64::SP).unwrap_or(0),
        pc,
        cpsr: emu.reg_read(RegisterARM64::NZCV).unwrap_or(0),
    })
}
