//! CPU Emulator module using Unicorn engine
//!
//! Provides forward emulation from debugger state for:
//! - Basic block prediction
//! - Module transition detection
//! - Condition-based search

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use unicorn_engine::{
    unicorn_const::{Arch, Mode, uc_error, Prot, HookType, X86Insn},
    Unicorn, RegisterX86, RegisterARM64,
};

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

use crate::interfaces::{Architecture, PlatformAPI};
use crate::protocol::{ThreadContext, EmulationMode, RegisterSnapshot, MemoryAccess};

mod error;
mod registers;

pub use error::EmulatorError;
use registers::{write_x64_registers, write_arm64_registers, read_x64_registers, read_arm64_registers};

/// Memory region info for lazy loading
#[derive(Debug, Clone)]
struct MappedRegion {
    base: u64,
    size: u64,
}

/// Module boundary info for transition detection
#[derive(Debug, Clone)]
struct ModuleBoundary {
    name: String,
    base: u64,
    end: u64,
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

use crate::interfaces::ModuleSymbol;

/// Format a symbol with optional offset as a string
fn format_symbol_with_offset(sym: ModuleSymbol, offset: u64) -> String {
    if offset == 0 {
        sym.name
    } else {
        format!("{}+0x{:x}", sym.name, offset)
    }
}

/// Create RegisterSnapshot from Unicorn x64 emulator state
#[cfg(target_arch = "x86_64")]
fn snapshot_from_unicorn<D>(emu: &Unicorn<'_, D>, rip: u64) -> RegisterSnapshot {
    RegisterSnapshot {
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
        rip,
        rflags: emu.reg_read(RegisterX86::RFLAGS).unwrap_or(0),
    }
}

/// Shared state for memory hook callbacks
struct EmulatorSharedState {
    mapped_regions: HashMap<u64, MappedRegion>,
    modules: Vec<ModuleBoundary>,
    pending_memory_fault: Option<u64>,
    basic_blocks: Vec<u64>,
    current_module: Option<String>,
    module_transition: Option<(String, String, u64)>,
    stop_requested: bool,
    /// Instruction trace (address, size) for InstructionTrace mode
    instruction_trace: Vec<(u64, usize)>,
    /// Register trace (full register state at each step) for InstructionTrace mode
    register_trace: Vec<RegisterSnapshot>,
    /// Memory trace: memory accesses at each step for InstructionTrace mode
    memory_trace: Vec<Vec<MemoryAccess>>,
    /// Pending write operations: (address, size) to capture after instruction executes
    pending_write_ops: Vec<(u64, usize)>,
    /// Last instruction address for basic block detection
    last_instruction_addr: Option<u64>,
    /// Last instruction size (from CODE hook) for basic block detection
    last_instruction_size: Option<u32>,
    /// Syscall address (set by syscall hook)
    syscall_address: Option<u64>,
    /// Exit address (stop when this address is reached)
    exit_address: Option<u64>,
}

/// CPU Emulator that initializes from debugger state
pub struct Emulator<'a> {
    emu: Unicorn<'a, Arc<RwLock<EmulatorSharedState>>>,
    architecture: Architecture,
    pid: u32,
    shared_state: Arc<RwLock<EmulatorSharedState>>,
}

impl<'a> Emulator<'a> {
    /// Create a new emulator from debugger state
    pub fn from_debugger_state<P: PlatformAPI>(
        platform: &P,
        pid: u32,
        tid: u32,
    ) -> Result<Self, EmulatorError> {
        // Get thread context
        let context = platform.get_thread_context(pid, tid)
            .map_err(|e| EmulatorError::PlatformError(e.to_string()))?;

        // Determine architecture
        let architecture = Self::detect_architecture(&context);

        // Get module list for boundary detection
        let modules_info = platform.list_modules(pid)
            .map_err(|e| EmulatorError::PlatformError(e.to_string()))?;

        let modules: Vec<ModuleBoundary> = modules_info
            .iter()
            .map(|m| ModuleBoundary {
                name: m.name.clone(),
                base: m.base,
                end: m.base + m.size.unwrap_or(0x1000),
            })
            .collect();

        // Create shared state
        let shared_state = Arc::new(RwLock::new(EmulatorSharedState {
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
            exit_address: None,
        }));

        // Create Unicorn instance
        let (arch, mode) = match architecture {
            Architecture::X64 => (Arch::X86, Mode::MODE_64),
            Architecture::Arm64 => (Arch::ARM64, Mode::LITTLE_ENDIAN),
        };

        let mut emu = Unicorn::new_with_data(arch, mode, shared_state.clone())
            .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))?;

        // Add memory fault hook to capture the actual fault address
        let hook_state = shared_state.clone();
        emu.add_mem_hook(
            HookType::MEM_READ_UNMAPPED | HookType::MEM_WRITE_UNMAPPED | HookType::MEM_FETCH_UNMAPPED,
            0,
            u64::MAX,
            move |_emu, mem_type, address, size, _value| {
                let mut state = hook_state.write().unwrap();
                tracing::trace!(
                    "Memory fault hook: type={:?} address=0x{:X} size={}",
                    mem_type, address, size
                );
                state.pending_memory_fault = Some(address);
                // Return false to indicate we didn't handle it - let emulation stop
                false
            }
        ).map_err(|e| EmulatorError::UnicornError(format!("mem hook failed: {:?}", e)))?;

        // NOTE: Mode-specific hooks (CODE, BLOCK, SYSCALL) are installed dynamically
        // in emulate_with_mode() to avoid overhead when not needed.

        // For x64, set up scratch stack for reliable emulation
        #[cfg(target_arch = "x86_64")]
        if matches!(architecture, Architecture::X64) {
            Self::setup_x64_segments(&mut emu, platform, pid, tid)?;
        }

        // Write registers from context
        match architecture {
            Architecture::X64 => write_x64_registers(&mut emu, &context)?,
            Architecture::Arm64 => write_arm64_registers(&mut emu, &context)?,
        }

        // Set current module based on PC
        let pc = context.get_pc();
        {
            let mut state = shared_state.write().unwrap();
            state.current_module = state.modules.iter()
                .find(|m| pc >= m.base && pc < m.end)
                .map(|m| m.name.clone());
        }

        Ok(Self {
            emu,
            architecture,
            pid,
            shared_state,
        })
    }

    fn detect_architecture(_context: &ThreadContext) -> Architecture {
        // For now, use compile-time detection
        // In future, could inspect context structure
        #[cfg(target_arch = "x86_64")]
        { Architecture::X64 }
        #[cfg(target_arch = "aarch64")]
        { Architecture::Arm64 }
    }

    /// Set up x64 segment bases (GS for TEB, FS for PEB)
    #[cfg(target_arch = "x86_64")]
    fn setup_x64_segments<D, P: PlatformAPI>(
        emu: &mut Unicorn<'_, D>,
        platform: &P,
        pid: u32,
        tid: u32,
    ) -> Result<(), EmulatorError> {
        // In x64 long mode on Windows:
        // - GS segment base points to the TEB (Thread Environment Block)
        // - FS segment base is typically 0 (unused in x64 Windows)
        //
        // Get TEB address from the debugger and set GS_BASE so code using
        // gs:[offset] (like gs:[0x30] for TEB self-pointer) works correctly.

        match platform.get_teb_address(pid, tid) {
            Ok(teb_address) => {
                tracing::debug!("Setting GS_BASE to TEB address: 0x{:016X}", teb_address);
                emu.reg_write(RegisterX86::GS_BASE, teb_address)
                    .map_err(|e| EmulatorError::UnicornError(format!("GS_BASE write failed: {:?}", e)))?;

                // Pre-load the TEB memory region so gs:[offset] accesses work
                if let Ok(region) = platform.query_memory_region(pid, teb_address) {
                    let size = Self::align_size(region.region_size);
                    let prot = Self::windows_protect_to_unicorn(region.protect);

                    if emu.mem_map(region.base_address, size, prot).is_ok() {
                        tracing::trace!(
                            "Unicorn mem_map (TEB): base=0x{:X} size=0x{:X} prot={}",
                            region.base_address, size, Self::prot_to_str(prot)
                        );
                        // Read and write TEB content
                        if region.state == MEM_COMMIT {
                            if let Ok(data) = platform.read_memory(pid, region.base_address, region.region_size as usize) {
                                let _ = emu.mem_write(region.base_address, &data);
                                tracing::debug!("Pre-loaded TEB region: 0x{:016X} - 0x{:016X} ({} bytes)",
                                    region.base_address, region.base_address + region.region_size, region.region_size);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Could not get TEB address: {}. GS segment access will fail.", e);
            }
        }

        Ok(())
    }

    /// Load a single 4KB page from debugger on demand
    ///
    /// Maps only the page containing the faulting address with 0x1000 granularity.
    pub fn load_memory_region<P: PlatformAPI>(
        &mut self,
        platform: &P,
        address: u64,
    ) -> Result<(), EmulatorError> {
        const PAGE_SIZE: u64 = 0x1000;

        // Align address down to page boundary
        let page_base = address & !(PAGE_SIZE - 1);

        // Check if page is already mapped
        {
            let state = self.shared_state.read().unwrap();
            if state.mapped_regions.contains_key(&page_base) {
                return Ok(());
            }
        }

        // Query the region to get permissions and state
        let region = platform.query_memory_region(self.pid, address)
            .map_err(|e| {
                tracing::warn!("query_memory_region failed for 0x{:X}: {}", address, e);
                EmulatorError::PlatformError(e.to_string())
            })?;

        // Can't map free memory
        if region.state == MEM_FREE {
            return Err(EmulatorError::PlatformError("cannot map free memory".into()));
        }

        let prot = Self::windows_protect_to_unicorn(region.protect);

        // Map the single page
        self.emu.mem_map(page_base, PAGE_SIZE, prot)
            .map_err(|e| {
                tracing::warn!("mem_map failed for page 0x{:X}: {:?}", page_base, e);
                EmulatorError::UnicornError(format!("mem_map failed: {:?}", e))
            })?;

        tracing::trace!(
            "Unicorn mem_map: base=0x{:X} size=0x{:X} prot={} state={}",
            page_base, PAGE_SIZE, Self::prot_to_str(prot), Self::state_to_str(region.state)
        );

        // Read and write page content if committed
        if region.state == MEM_COMMIT {
            match platform.read_memory(self.pid, page_base, PAGE_SIZE as usize) {
                Ok(data) => {
                    if let Err(e) = self.emu.mem_write(page_base, &data) {
                        tracing::warn!("mem_write failed for page 0x{:X}: {:?}", page_base, e);
                    }
                }
                Err(_) => {
                    tracing::warn!("Failed to read memory for page 0x{:X}, leaving as zeros", page_base);
                    // Page not readable, leave as zeros
                }
            }
        } else {
            tracing::warn!(
                "Page 0x{:X} not committed (state={}), leaving as zeros",
                page_base,
                Self::state_to_str(region.state)
            );
        }

        // Track the mapped page
        {
            let mut state = self.shared_state.write().unwrap();
            state.mapped_regions.insert(page_base, MappedRegion {
                base: page_base,
                size: PAGE_SIZE,
            });
        }

        Ok(())
    }

    fn windows_protect_to_unicorn(protect: u32) -> Prot {
        let mut prot = Prot::NONE;

        // Check for execute permission
        if protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
            prot |= Prot::EXEC;
        }

        // Check for read permission
        if protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
            prot |= Prot::READ;
        }

        // Check for write permission
        if protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
            prot |= Prot::WRITE;
        }

        if prot == Prot::NONE {
            prot = Prot::READ; // Default to readable
        }

        prot
    }

    fn prot_to_str(prot: Prot) -> &'static str {
        let r = (prot & Prot::READ) != Prot::NONE;
        let w = (prot & Prot::WRITE) != Prot::NONE;
        let x = (prot & Prot::EXEC) != Prot::NONE;
        match (r, w, x) {
            (true, true, true) => "RWX",
            (true, true, false) => "RW",
            (true, false, true) => "RX",
            (true, false, false) => "R",
            (false, true, true) => "WX",
            (false, true, false) => "W",
            (false, false, true) => "X",
            (false, false, false) => "NONE",
        }
    }

    fn state_to_str(state: u32) -> &'static str {
        match state {
            MEM_COMMIT => "MEM_COMMIT",
            MEM_FREE => "MEM_FREE",
            MEM_RESERVE => "MEM_RESERVE",
            _ => "UNKNOWN",
        }
    }

    fn align_size(size: u64) -> u64 {
        // Unicorn requires page-aligned sizes (4KB)
        const PAGE_SIZE: u64 = 0x1000;
        (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }

    /// Get current instruction pointer
    pub fn get_pc(&self) -> Result<u64, EmulatorError> {
        match self.architecture {
            Architecture::X64 => {
                self.emu.reg_read(RegisterX86::RIP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::Arm64 => {
                self.emu.reg_read(RegisterARM64::PC)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
        }
    }

    /// Get stack pointer
    pub fn get_sp(&self) -> Result<u64, EmulatorError> {
        match self.architecture {
            Architecture::X64 => {
                self.emu.reg_read(RegisterX86::RSP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::Arm64 => {
                self.emu.reg_read(RegisterARM64::SP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
        }
    }

    /// Read a register by name (for condition checking)
    pub fn read_register(&self, name: &str) -> Result<u64, EmulatorError> {
        match self.architecture {
            Architecture::X64 => read_x64_registers(&self.emu, name),
            Architecture::Arm64 => read_arm64_registers(&self.emu, name),
        }
    }

    /// Build EmulationResult from current state
    fn build_result(
        &self,
        instructions_executed: usize,
        stop_reason: StopReason,
        emulation_time_us: u64,
        pages_before: usize,
    ) -> Result<EmulationResult, EmulatorError> {
        let final_pc = self.get_pc()?;
        let state = self.shared_state.read().unwrap();
        let pages_loaded = state.mapped_regions.len() - pages_before;

        Ok(EmulationResult {
            final_pc,
            instructions_executed,
            stop_reason,
            emulation_time_us,
            pages_loaded,
            basic_blocks: state.basic_blocks.clone(),
            instruction_trace: state.instruction_trace.clone(),
            register_trace: state.register_trace.clone(),
            memory_trace: state.memory_trace.clone(),
        })
    }

    /// Emulate up to max_instructions
    pub fn emulate_instructions<P: PlatformAPI>(
        &mut self,
        platform: &P,
        max_instructions: usize,
    ) -> Result<EmulationResult, EmulatorError> {
        use std::time::Instant;
        let start_time = Instant::now();

        let start_pc = self.get_pc()?;
        let mut instructions_executed = 0;
        let mut stop_reason = StopReason::InstructionLimit;

        // Track pages loaded before emulation
        let pages_before = {
            let state = self.shared_state.read().unwrap();
            state.mapped_regions.len()
        };

        // Clear previous state
        {
            let mut state = self.shared_state.write().unwrap();
            state.basic_blocks.clear();
            state.basic_blocks.push(start_pc);
            state.pending_memory_fault = None;
            state.module_transition = None;
            state.stop_requested = false;
            state.last_instruction_addr = None;
            state.last_instruction_size = None;
            state.instruction_trace.clear();
            state.register_trace.clear();
            state.memory_trace.clear();
            state.pending_write_ops.clear();
        }

        // Pre-load initial code region (loads entire region containing PC)
        self.load_memory_region(platform, start_pc)?;

        // Pre-load stack region (loads entire region containing SP)
        let sp = self.get_sp()?;
        let _ = self.load_memory_region(platform, sp);

        for _ in 0..max_instructions {
            let pc_before = self.get_pc()?;

            // Clear pending fault before each instruction so we get fresh fault addresses
            {
                let mut state = self.shared_state.write().unwrap();
                state.pending_memory_fault = None;
            }

            // Try to execute one instruction
            match self.emu.emu_start(pc_before, u64::MAX, 0, 1) {
                Ok(()) => {
                    instructions_executed += 1;
                }
                Err(uc_error::READ_UNMAPPED) | Err(uc_error::FETCH_UNMAPPED) | Err(uc_error::WRITE_UNMAPPED) => {
                    // Check if PC moved (instruction partially executed before fault)
                    let pc_after = self.get_pc().unwrap_or(pc_before);
                    if pc_after != pc_before {
                        instructions_executed += 1;
                    }

                    // Try to load the faulting region using address from memory hook
                    let fault_addr = {
                        let state = self.shared_state.read().unwrap();
                        state.pending_memory_fault
                    };

                    if let Some(addr) = fault_addr {
                        match self.load_memory_region(platform, addr) {
                            Ok(()) => {
                                // Retry (or continue if instruction already executed)
                                if pc_after != pc_before {
                                    // Instruction executed, continue to next
                                    continue;
                                }
                                // Retry the same instruction
                                continue;
                            }
                            Err(_) => {
                                stop_reason = StopReason::UnmappedMemory(addr);
                                break;
                            }
                        }
                    } else {
                        // Can't determine fault address, try to load around PC and stack
                        let sp = self.get_sp().unwrap_or(0);
                        let _ = self.load_memory_region(platform, pc_after);
                        if sp > 0 {
                            let _ = self.load_memory_region(platform, sp);
                            if sp >= 0x1000 {
                                let _ = self.load_memory_region(platform, sp - 0x1000);
                            }
                        }
                        // If PC already moved, continue to next iteration
                        if pc_after != pc_before {
                            continue;
                        }
                        // Try once more at same PC
                        match self.emu.emu_start(pc_before, u64::MAX, 0, 1) {
                            Ok(()) => {
                                instructions_executed += 1;
                            }
                            Err(_e) => {
                                stop_reason = StopReason::UnmappedMemory(pc_before);
                                break;
                            }
                        }
                    }
                }
                Err(uc_error::EXCEPTION) => {
                    // CPU exception - check if instruction executed before the exception
                    let pc_after = self.get_pc().unwrap_or(pc_before);
                    if pc_after != pc_before {
                        // Instruction executed, PC moved - count it
                        instructions_executed += 1;
                        // Try loading more memory for the next instruction and continue
                        let _ = self.load_memory_region(platform, pc_after);
                        let sp = self.get_sp().unwrap_or(0);
                        if sp >= 0x1000 {
                            let _ = self.load_memory_region(platform, sp - 0x1000);
                        }
                        continue;
                    }
                    // PC didn't move - try loading more memory and retry once
                    let sp = self.get_sp().unwrap_or(0);
                    if sp >= 0x1000 {
                        let _ = self.load_memory_region(platform, sp - 0x1000);
                    }
                    match self.emu.emu_start(pc_before, u64::MAX, 0, 1) {
                        Ok(()) => {
                            instructions_executed += 1;
                        }
                        Err(e) => {
                            stop_reason = StopReason::Error(format!("{:?}", e));
                            break;
                        }
                    }
                }
                Err(e) => {
                    // Check if PC moved despite the error
                    let pc_after = self.get_pc().unwrap_or(pc_before);
                    if pc_after != pc_before {
                        instructions_executed += 1;
                    }
                    stop_reason = StopReason::Error(format!("{:?}", e));
                    break;
                }
            }

            // Check for module transition
            {
                let state = self.shared_state.read().unwrap();
                if let Some((from, to, addr)) = &state.module_transition {
                    let symbol = platform.resolve_address_to_symbol(self.pid, *addr)
                        .ok()
                        .flatten()
                        .map(|(_, sym, offset)| format_symbol_with_offset(sym, offset));
                    stop_reason = StopReason::ModuleTransition {
                        from: from.clone(),
                        to: to.clone(),
                        address: *addr,
                        symbol,
                    };
                    break;
                }
                if state.stop_requested {
                    stop_reason = StopReason::Stopped;
                    break;
                }
            }
        }

        let emulation_time_us = start_time.elapsed().as_micros() as u64;
        self.build_result(instructions_executed, stop_reason, emulation_time_us, pages_before)
    }

    /// Emulate with a specific mode that determines which hooks are installed
    ///
    /// Modes:
    /// - Basic: No per-instruction hooks (fastest)
    /// - InstructionTrace: CODE hook records every instruction (addr, size)
    /// - BasicBlock: BLOCK hook records basic block starts
    /// - ModuleTransition: Stop when execution moves to a different module
    /// - Syscall: Stop on first syscall instruction
    pub fn emulate_with_mode<P: PlatformAPI>(
        &mut self,
        platform: &P,
        max_instructions: usize,
        mode: EmulationMode,
        exit_condition: Option<crate::protocol::TraceExitCondition>,
    ) -> Result<EmulationResult, EmulatorError> {
        use std::time::Instant;
        use crate::protocol::TraceExitCondition;

        let start_time = Instant::now();

        let start_pc = self.get_pc()?;
        let mut instructions_executed = 0;
        let mut stop_reason = StopReason::InstructionLimit;

        // Extract exit address from exit condition
        let exit_address = match &exit_condition {
            Some(TraceExitCondition::ReachAddress(addr)) => Some(*addr),
            _ => None,
        };

        // Track pages loaded before emulation
        let pages_before = {
            let state = self.shared_state.read().unwrap();
            state.mapped_regions.len()
        };

        // Clear previous state
        {
            let mut state = self.shared_state.write().unwrap();
            state.basic_blocks.clear();
            state.basic_blocks.push(start_pc);
            state.pending_memory_fault = None;
            state.module_transition = None;
            state.stop_requested = false;
            state.last_instruction_addr = None;
            state.last_instruction_size = None;
            state.instruction_trace.clear();
            state.register_trace.clear();
            state.memory_trace.clear();
            state.pending_write_ops.clear();
            state.syscall_address = None;
            state.exit_address = exit_address;

            // Set current module for ModuleTransition mode
            if mode == EmulationMode::ModuleTransition {
                state.current_module = state.modules.iter()
                    .find(|m| start_pc >= m.base && start_pc < m.end)
                    .map(|m| m.name.clone());
            }
        }

        // Pre-load initial code region (loads entire region containing PC)
        self.load_memory_region(platform, start_pc)?;

        // Pre-load stack region (loads entire region containing SP)
        let sp = self.get_sp()?;
        let _ = self.load_memory_region(platform, sp);

        // Install mode-specific hooks
        let hook_handle = match mode {
            EmulationMode::Basic => None,

            EmulationMode::InstructionTrace => {
                // CODE hook: fires on every instruction
                let shared = self.shared_state.clone();
                let arch = self.architecture;
                let hook = self.emu.add_code_hook(0, u64::MAX, move |emu, addr, size| {
                    use crate::memory_operand::analyze_memory_operands;
                    use crate::protocol::{MemoryAccess, MemoryAccessType};

                    let mut state = shared.write().unwrap();

                    // Step 1: Capture pending write data from previous instruction
                    // (previous instruction has now completed execution)
                    if !state.pending_write_ops.is_empty() && !state.memory_trace.is_empty() {
                        // Drain pending writes into a local vector to avoid borrow conflicts
                        let pending: Vec<_> = state.pending_write_ops.drain(..).collect();
                        let last_mem = state.memory_trace.last_mut().unwrap();
                        for (write_addr, write_size) in pending {
                            if let Ok(data) = emu.mem_read_as_vec(write_addr, write_size) {
                                last_mem.push(MemoryAccess {
                                    access_type: MemoryAccessType::Write,
                                    address: write_addr,
                                    data,
                                });
                            }
                        }
                    } else {
                        state.pending_write_ops.clear();
                    }

                    // Record instruction trace
                    state.instruction_trace.push((addr, size as usize));
                    let step = state.instruction_trace.len();

                    // Capture full register snapshot
                    let snapshot = snapshot_from_unicorn(emu, addr);
                    state.register_trace.push(snapshot.clone());

                    tracing::trace!("step {} RIP=0x{:X} RFLAGS=0x{:X} size={}", step, addr,
                        emu.reg_read(RegisterX86::RFLAGS).unwrap_or(0), size);

                    // Step 2: Analyze current instruction for memory operands
                    let mut current_mem_accesses: Vec<MemoryAccess> = Vec::new();

                    // Read instruction bytes from emulator memory
                    if let Ok(insn_bytes) = emu.mem_read_as_vec(addr, size as usize) {
                        let operands = analyze_memory_operands(&insn_bytes, addr, &snapshot, arch);

                        for op in operands {
                            if op.is_read {
                                // For reads, capture data immediately (before execution)
                                if let Ok(data) = emu.mem_read_as_vec(op.address, op.size) {
                                    let access_type = if op.is_write {
                                        MemoryAccessType::ReadWrite
                                    } else {
                                        MemoryAccessType::Read
                                    };
                                    current_mem_accesses.push(MemoryAccess {
                                        access_type,
                                        address: op.address,
                                        data,
                                    });
                                }
                            }
                            if op.is_write && !op.is_read {
                                // For write-only, queue for capture after execution
                                state.pending_write_ops.push((op.address, op.size));
                            } else if op.is_write && op.is_read {
                                // For read-write, we already captured the read data
                                // but also need to capture write data after execution
                                // The write will update the data in-place
                                state.pending_write_ops.push((op.address, op.size));
                            }
                        }
                    }

                    state.memory_trace.push(current_mem_accesses);

                    // Check for exit address
                    if let Some(exit_addr) = state.exit_address {
                        if addr == exit_addr {
                            state.stop_requested = true;
                            emu.emu_stop().ok();
                            return;
                        }
                    }

                    // Track basic blocks via non-sequential jumps
                    if let (Some(last_addr), Some(last_size)) = (state.last_instruction_addr, state.last_instruction_size) {
                        // If this instruction isn't immediately after the previous one,
                        // it's a new basic block
                        if addr != last_addr + last_size as u64 {
                            state.basic_blocks.push(addr);
                        }
                    }
                    state.last_instruction_addr = Some(addr);
                    state.last_instruction_size = Some(size);
                }).map_err(|e| EmulatorError::UnicornError(format!("code hook failed: {:?}", e)))?;
                Some(hook)
            }

            EmulationMode::BasicBlock => {
                // BLOCK hook: fires at translation block boundaries (more efficient)
                let shared = self.shared_state.clone();
                let hook = self.emu.add_block_hook(0, u64::MAX, move |_emu, addr, _size| {
                    let mut state = shared.write().unwrap();
                    state.basic_blocks.push(addr);
                }).map_err(|e| EmulatorError::UnicornError(format!("block hook failed: {:?}", e)))?;
                Some(hook)
            }

            EmulationMode::ModuleTransition => {
                // For module transition, we detect it via memory fetch faults
                // when loading new pages - check in the emulation loop
                None
            }

            EmulationMode::Syscall => {
                // Use Unicorn's instruction-level syscall hook (no per-instruction overhead)
                if self.architecture != Architecture::X64 {
                    return Err(EmulatorError::UnicornError("Syscall mode not yet supported for ARM64".into()));
                }
                let shared = self.shared_state.clone();
                let hook = self.emu.add_insn_sys_hook(
                    X86Insn::SYSCALL,
                    0, u64::MAX,
                    move |emu| {
                        // Get RIP at syscall instruction
                        let rip = emu.reg_read(RegisterX86::RIP).unwrap_or(0);
                        let mut state = shared.write().unwrap();
                        state.syscall_address = Some(rip);
                        state.stop_requested = true;
                    }
                ).map_err(|e| EmulatorError::UnicornError(format!("syscall hook failed: {:?}", e)))?;
                Some(hook)
            }
        };

        // Batch size for modes with hooks - run multiple instructions at once
        // For modes without hooks (Basic, ModuleTransition), we single-step
        let batch_size = match mode {
            EmulationMode::Syscall | EmulationMode::InstructionTrace | EmulationMode::BasicBlock => 1000,
            EmulationMode::Basic | EmulationMode::ModuleTransition => 1,
        };

        // Main emulation loop
        let mut remaining = max_instructions;
        while remaining > 0 {
            let pc_before = self.get_pc()?;

            // Clear pending fault
            {
                let mut state = self.shared_state.write().unwrap();
                state.pending_memory_fault = None;
            }

            // Execute instructions - batch for hooked modes, single for others
            let count = batch_size.min(remaining);
            match self.emu.emu_start(pc_before, u64::MAX, 0, count) {
                Ok(()) => {
                    // For modes with CODE hooks, get count from instruction_trace
                    // For other modes, assume 'count' instructions ran (or PC changed = 1)
                    let executed = if mode == EmulationMode::InstructionTrace {
                        let state = self.shared_state.read().unwrap();
                        state.instruction_trace.len().saturating_sub(instructions_executed)
                    } else if batch_size > 1 {
                        // For batch modes without per-instruction tracking, estimate from PC delta
                        // This is imprecise but better than nothing
                        count
                    } else {
                        1
                    };
                    instructions_executed += executed;
                    remaining = remaining.saturating_sub(executed);

                    // Check for stop_requested (e.g., exit address reached)
                    {
                        let state = self.shared_state.read().unwrap();
                        if state.stop_requested {
                            if let Some(addr) = state.exit_address {
                                stop_reason = StopReason::ReachedAddress(addr);
                            } else {
                                stop_reason = StopReason::Stopped;
                            }
                            break;
                        }
                    }
                    continue;
                }
                Err(uc_error::READ_UNMAPPED) | Err(uc_error::FETCH_UNMAPPED) | Err(uc_error::WRITE_UNMAPPED) => {
                    let pc_after = self.get_pc().unwrap_or(pc_before);
                    if pc_after != pc_before {
                        instructions_executed += 1;
                        remaining = remaining.saturating_sub(1);
                    }

                    let fault_addr = {
                        let state = self.shared_state.read().unwrap();
                        state.pending_memory_fault
                    };

                    if let Some(addr) = fault_addr {
                        // For ModuleTransition mode, check if we're loading from a different module
                        if mode == EmulationMode::ModuleTransition {
                            let transition = {
                                let state = self.shared_state.read().unwrap();
                                let target_module = state.modules.iter()
                                    .find(|m| addr >= m.base && addr < m.end)
                                    .map(|m| m.name.clone());

                                if let (Some(current), Some(target)) = (&state.current_module, &target_module) {
                                    if current != target {
                                        Some((current.clone(), target.clone(), addr))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            };

                            if let Some((from, to, at_addr)) = transition {
                                let symbol = platform.resolve_address_to_symbol(self.pid, at_addr)
                                    .ok()
                                    .flatten()
                                    .map(|(_, sym, offset)| format_symbol_with_offset(sym, offset));
                                stop_reason = StopReason::ModuleTransition { from, to, address: at_addr, symbol };
                                break;
                            }
                        }

                        match self.load_memory_region(platform, addr) {
                            Ok(()) => continue,
                            Err(_) => {
                                stop_reason = StopReason::UnmappedMemory(addr);
                                break;
                            }
                        }
                    } else {
                        let sp = self.get_sp().unwrap_or(0);
                        let _ = self.load_memory_region(platform, pc_after);
                        if sp > 0 && sp >= 0x1000 {
                            let _ = self.load_memory_region(platform, sp - 0x1000);
                        }
                        if pc_after != pc_before {
                            continue;
                        }
                        match self.emu.emu_start(pc_before, u64::MAX, 0, 1) {
                            Ok(()) => {
                                instructions_executed += 1;
                                remaining = remaining.saturating_sub(1);
                            }
                            Err(_) => {
                                stop_reason = StopReason::UnmappedMemory(pc_before);
                                break;
                            }
                        }
                    }
                }
                Err(uc_error::EXCEPTION) => {
                    // CPU exception - check if instruction executed before the exception
                    let pc_after = self.get_pc().unwrap_or(pc_before);

                    if pc_after != pc_before {
                        // Instruction executed successfully, PC moved - continue
                        // Note: Unicorn often returns EXCEPTION when single-stepping
                        // even though the instruction succeeded
                        instructions_executed += 1;
                        remaining = remaining.saturating_sub(1);
                        let _ = self.load_memory_region(platform, pc_after);
                        continue;
                    }

                    // PC didn't move - this is a real exception, log details
                    let fault_addr = {
                        let state = self.shared_state.read().unwrap();
                        state.pending_memory_fault
                    };

                    // Read all registers for context
                    let rax = self.emu.reg_read(RegisterX86::RAX).unwrap_or(0);
                    let rbx = self.emu.reg_read(RegisterX86::RBX).unwrap_or(0);
                    let rcx = self.emu.reg_read(RegisterX86::RCX).unwrap_or(0);
                    let rdx = self.emu.reg_read(RegisterX86::RDX).unwrap_or(0);
                    let rsi = self.emu.reg_read(RegisterX86::RSI).unwrap_or(0);
                    let rdi = self.emu.reg_read(RegisterX86::RDI).unwrap_or(0);
                    let rbp = self.emu.reg_read(RegisterX86::RBP).unwrap_or(0);
                    let rsp = self.emu.reg_read(RegisterX86::RSP).unwrap_or(0);
                    let r8 = self.emu.reg_read(RegisterX86::R8).unwrap_or(0);
                    let r9 = self.emu.reg_read(RegisterX86::R9).unwrap_or(0);
                    let r10 = self.emu.reg_read(RegisterX86::R10).unwrap_or(0);
                    let r11 = self.emu.reg_read(RegisterX86::R11).unwrap_or(0);
                    let r12 = self.emu.reg_read(RegisterX86::R12).unwrap_or(0);
                    let r13 = self.emu.reg_read(RegisterX86::R13).unwrap_or(0);
                    let r14 = self.emu.reg_read(RegisterX86::R14).unwrap_or(0);
                    let r15 = self.emu.reg_read(RegisterX86::R15).unwrap_or(0);
                    let rflags = self.emu.reg_read(RegisterX86::RFLAGS).unwrap_or(0);

                    tracing::warn!(
                        "EXCEPTION at RIP=0x{:X}, fault_addr={:?}\n\
                         RAX={:016X} RBX={:016X} RCX={:016X} RDX={:016X}\n\
                         RSI={:016X} RDI={:016X} RBP={:016X} RSP={:016X}\n\
                         R8 ={:016X} R9 ={:016X} R10={:016X} R11={:016X}\n\
                         R12={:016X} R13={:016X} R14={:016X} R15={:016X}\n\
                         RFLAGS={:016X}",
                        pc_before, fault_addr,
                        rax, rbx, rcx, rdx,
                        rsi, rdi, rbp, rsp,
                        r8, r9, r10, r11,
                        r12, r13, r14, r15,
                        rflags
                    );

                    // Disassemble the faulting instruction
                    if let Ok(insns) = platform.disassemble_memory(self.pid, pc_before, 1, self.architecture) {
                        if let Some(insn) = insns.first() {
                            tracing::warn!(
                                "Faulting instruction: {} {}",
                                insn.mnemonic, insn.op_str
                            );
                        }
                    }

                    // Check if RDI points to a mapped region
                    let rdi_page = rdi & !0xFFF;
                    {
                        let state = self.shared_state.read().unwrap();
                        if let Some(region) = state.mapped_regions.get(&rdi_page) {
                            tracing::warn!(
                                "RDI 0x{:X} -> mapped region: base=0x{:X} size=0x{:X}",
                                rdi, region.base, region.size
                            );
                        } else {
                            tracing::warn!("RDI 0x{:X} -> NOT MAPPED in emulator", rdi);
                        }
                    }

                    // Query real process memory for RDI
                    if rdi != 0 {
                        match platform.query_memory_region(self.pid, rdi) {
                            Ok(region) => {
                                tracing::warn!(
                                    "RDI 0x{:X} in real process: base=0x{:X} size=0x{:X} prot={} state={}",
                                    rdi, region.base_address, region.region_size,
                                    Self::prot_to_str(Self::windows_protect_to_unicorn(region.protect)),
                                    Self::state_to_str(region.state)
                                );
                            }
                            Err(e) => {
                                tracing::warn!("RDI 0x{:X} query failed: {}", rdi, e);
                            }
                        }
                    }

                    stop_reason = StopReason::Error("EXCEPTION".into());
                    break;
                }
                Err(e) => {
                    let pc_after = self.get_pc().unwrap_or(pc_before);
                    if pc_after != pc_before {
                        instructions_executed += 1;
                    }
                    stop_reason = StopReason::Error(format!("{:?}", e));
                    break;
                }
            }

            // Check for stop conditions
            {
                let state = self.shared_state.read().unwrap();

                // Check for syscall
                if let Some(addr) = state.syscall_address {
                    stop_reason = StopReason::Syscall { address: addr };
                    break;
                }

                // Check for module transition (from CODE hook path)
                if let Some((from, to, addr)) = &state.module_transition {
                    let symbol = platform.resolve_address_to_symbol(self.pid, *addr)
                        .ok()
                        .flatten()
                        .map(|(_, sym, offset)| format_symbol_with_offset(sym, offset));
                    stop_reason = StopReason::ModuleTransition {
                        from: from.clone(),
                        to: to.clone(),
                        address: *addr,
                        symbol,
                    };
                    break;
                }

                if state.stop_requested {
                    // Check if it was a syscall
                    if let Some(addr) = state.syscall_address {
                        stop_reason = StopReason::Syscall { address: addr };
                    } else if let Some(addr) = state.exit_address {
                        // Reached exit address
                        stop_reason = StopReason::ReachedAddress(addr);
                    } else {
                        stop_reason = StopReason::Stopped;
                    }
                    break;
                }
            }
        }

        // Remove hook if installed
        if let Some(hook) = hook_handle {
            let _ = self.emu.remove_hook(hook);
        }

        // Capture any final pending writes from the last instruction
        // (only relevant for InstructionTrace mode)
        if mode == EmulationMode::InstructionTrace {
            use crate::protocol::{MemoryAccess, MemoryAccessType};
            let mut state = self.shared_state.write().unwrap();
            if !state.pending_write_ops.is_empty() && !state.memory_trace.is_empty() {
                let pending_ops: Vec<_> = state.pending_write_ops.drain(..).collect();
                let last_mem = state.memory_trace.last_mut().unwrap();
                for (write_addr, write_size) in pending_ops {
                    if let Ok(data) = self.emu.mem_read_as_vec(write_addr, write_size) {
                        last_mem.push(MemoryAccess {
                            access_type: MemoryAccessType::Write,
                            address: write_addr,
                            data,
                        });
                    }
                }
            }
        }

        let emulation_time_us = start_time.elapsed().as_micros() as u64;
        self.build_result(instructions_executed, stop_reason, emulation_time_us, pages_before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicorn_engine::unicorn_const::Prot;

    #[test]
    fn test_emulator_x64_creates() {
        let shared = Arc::new(RwLock::new(EmulatorSharedState {
            mapped_regions: HashMap::new(),
            modules: Vec::new(),
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
            exit_address: None,
        }));

        let emu = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, shared);
        assert!(emu.is_ok());
    }

    #[test]
    fn test_memory_operations() {
        let shared = Arc::new(RwLock::new(EmulatorSharedState {
            mapped_regions: HashMap::new(),
            modules: Vec::new(),
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
            exit_address: None,
        }));

        let mut emu = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, shared).unwrap();

        // Map a page
        emu.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();

        // Write some code: NOP NOP NOP RET
        let code = [0x90u8, 0x90, 0x90, 0xC3];
        emu.mem_write(0x1000, &code).unwrap();

        // Read it back
        let read_back = emu.mem_read_as_vec(0x1000, 4).unwrap();
        assert_eq!(read_back, code);
    }

    #[test]
    fn test_simple_emulation() {
        let shared = Arc::new(RwLock::new(EmulatorSharedState {
            mapped_regions: HashMap::new(),
            modules: Vec::new(),
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
            exit_address: None,
        }));

        let mut emu = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, shared).unwrap();

        // Map code region
        emu.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();

        // mov rax, 0x1234
        // ret
        let code: [u8; 12] = [
            0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,  // mov rax, 0x1234
            0xC3, 0x90, 0x90, 0x90, 0x90,              // ret + padding
        ];
        emu.mem_write(0x1000, &code).unwrap();

        // Map stack
        emu.mem_map(0x7FFF0000, 0x1000, Prot::ALL).unwrap();

        // Set RSP and write return address
        emu.reg_write(RegisterX86::RSP, 0x7FFF0FF0u64).unwrap();
        emu.mem_write(0x7FFF0FF0, &0x1100u64.to_le_bytes()).unwrap();

        // Execute until ret
        let result = emu.emu_start(0x1000, 0x1100, 0, 10);
        assert!(result.is_ok());

        // Check RAX
        let rax: u64 = emu.reg_read(RegisterX86::RAX).unwrap();
        assert_eq!(rax, 0x1234);
    }
}
