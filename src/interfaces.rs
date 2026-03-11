use thiserror::Error;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo};

pub type Address = u64;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("OS error: {0}")]
    OsError(String),
    #[error("Not implemented")]
    NotImplemented,
    #[error("Other: {0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum SymbolError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("PE parsing failed: {0}")]
    PeParsingFailed(String),
    #[error("PDB parsing failed: {0}")]
    PdbParsingFailed(String),
    #[error("PDB not found: {0}")]
    PdbNotFound(String),
    #[error("Symbols not found: {0}")]
    SymbolsNotFound(String),
    #[error("SymSrv error: {0}")]
    SymSrvError(String),
    #[error("Module not loaded: {0}")]
    ModuleNotLoaded(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleSymbol {
    pub name: String,
    pub rva: u32, // Relative Virtual Address
    pub is_function: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSymbol {
    pub name: String,
    pub module_name: String,
    pub rva: u32, // Relative Virtual Address
    pub va: u64,  // Virtual Address (module_base + rva)
    pub is_function: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Architecture {
    X64,
    Arm64,
}

impl Architecture {
    pub fn from_native() -> Self {
        if cfg!(target_arch = "x86_64") { Architecture::X64 } else { Architecture::Arm64 }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    pub size: usize,
    pub symbol_info: Option<SymbolInfo>,
    pub symbolized_op_str: Option<String>, // Operands with symbolized addresses
    pub is_jump: bool,           // jmp, jcc instructions (conditional/unconditional jumps)
    pub is_call: bool,           // call instruction
    pub is_ret: bool,            // ret instruction
    pub jump_target: Option<u64>, // Target address if resolvable (for jumps/calls)
    pub addresses_to_symbolize: Vec<u64>, // Addresses extracted from operands for symbolization
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolInfo {
    pub module_name: String,
    pub symbol_name: String,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallFrame {
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub symbol: Option<SymbolInfo>,
}

pub trait InstructionFormatter {
    fn format_disassembly(&self) -> String;
}

impl InstructionFormatter for Vec<Instruction> {
    fn format_disassembly(&self) -> String {
        if self.is_empty() {
            return "No instructions".to_string();
        }
        
        let mut result = String::new();
        result.push_str("Disassembly:\n");
        
        for instruction in self {
            result.push_str(&format!("{}\n", instruction));
        }
        
        result
    }
}

impl InstructionFormatter for &[Instruction] {
    fn format_disassembly(&self) -> String {
        self.to_vec().format_disassembly()
    }
}

#[derive(Debug, Error)]
pub enum DisassemblerError {
    #[error("Capstone error: {0}")]
    CapstoneError(String),
    #[error("Unsupported architecture: {0:?}")]
    UnsupportedArchitecture(Architecture),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub trait SymbolProvider: Send + Sync {
    fn load_symbols_for_module(
        &mut self,
        module_path: &str,
        module_base: Address,
        module_size: Option<usize>,
    ) -> Result<(), SymbolError>;

    fn find_symbol(
        &self,
        symbol_name: &str,
        max_results: usize,
    ) -> Result<Vec<ResolvedSymbol>, SymbolError>;

    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError>;

    fn resolve_rva_to_symbol(
        &self,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<ModuleSymbol>, SymbolError>;
}

pub trait DisassemblerProvider: Send + Sync {
    fn disassemble(
        &self,
        arch: Architecture,
        data: &[u8],
        address: u64,
        count: usize,
    ) -> Result<Vec<Instruction>, DisassemblerError>;

    fn disassemble_single(
        &self,
        arch: Architecture,
        data: &[u8],
        address: u64,
    ) -> Result<Option<Instruction>, DisassemblerError> {
        let instructions = self.disassemble(arch, data, address, 1)?;
        Ok(instructions.into_iter().next())
    }
    
    fn disassemble_with_symbols<F>(
        &self,
        arch: Architecture,
        data: &[u8],
        address: u64,
        count: usize,
        symbol_resolver: F,
    ) -> Result<Vec<Instruction>, DisassemblerError>
    where
        F: Fn(u64) -> Option<SymbolInfo>,
    {
        let mut instructions = self.disassemble(arch, data, address, count)?;
        for instruction in &mut instructions {
            instruction.symbol_info = symbol_resolver(instruction.address);

            // Symbolize operand addresses using pre-extracted address list (no regex)
            if !instruction.addresses_to_symbolize.is_empty() {
                let mut op_str = instruction.op_str.clone();
                for addr in &instruction.addresses_to_symbolize {
                    if let Some(symbol) = symbol_resolver(*addr) {
                        let symbol_str = symbol.format_symbol();
                        // Try direct hex replacement first (for absolute addresses)
                        let hex_lower = format!("0x{:x}", addr);
                        let hex_upper = format!("0x{:X}", addr);
                        let before = op_str.clone();
                        op_str = op_str.replace(&hex_lower, &symbol_str);
                        op_str = op_str.replace(&hex_upper, &symbol_str);

                        // Fallback: RIP-relative pattern replacement
                        // Capstone outputs [rip + 0xNNNN] but the resolved address isn't in the text
                        if op_str == before {
                            let disp = (*addr).wrapping_sub(instruction.address + instruction.size as u64) as i64;
                            let (pattern, replacement) = if disp >= 0 {
                                (format!("[rip + 0x{:x}]", disp), format!("[{}]", symbol_str))
                            } else {
                                (format!("[rip - 0x{:x}]", disp.unsigned_abs()), format!("[{}]", symbol_str))
                            };
                            op_str = op_str.replace(&pattern, &replacement);
                        }
                    }
                }
                if op_str != instruction.op_str {
                    instruction.symbolized_op_str = Some(op_str);
                }
            }
        }
        Ok(instructions)
    }
}

pub trait Stepper: Send + Sync {
    fn step(&mut self, pid: u32, tid: u32, kind: crate::protocol::StepKind) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
}

pub trait PlatformAPI: Send + Sync {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn detach(&mut self, pid: u32) -> Result<(), PlatformError>;
    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn set_breakpoint(&mut self, pid: u32, addr: u64, tid: Option<u32>) -> Result<(), PlatformError>;
    fn remove_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError>;
    fn set_single_shot_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError>;
    fn set_hardware_breakpoint(&mut self, pid: u32, addr: u64, bp_type: crate::protocol::HardwareBreakpointType, size: crate::protocol::HardwareBreakpointSize) -> Result<u8, PlatformError>;
    fn remove_hardware_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError>;
    fn launch(&mut self, command: &str, debug_children: bool) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn read_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError>;
    fn write_memory(&self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError>;
    fn read_wide_string(&self, pid: u32, address: u64, max_len: Option<usize>) -> Result<String, PlatformError>;
    fn get_thread_context(&self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError>;
    fn set_thread_context(&self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError>;
    fn get_function_arguments(&self, pid: u32, tid: u32, count: usize) -> Result<Vec<u64>, PlatformError>;
    fn list_modules(&self, pid: u32) -> Result<Vec<ModuleInfo>, PlatformError>;
    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError>;
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError>;
    
    // Symbol-related methods
    fn find_symbol(&self, symbol_name: &str, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError>;
    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError>;
    fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<ModuleSymbol>, SymbolError>;
    fn resolve_address_to_symbol(&self, pid: u32, address: u64) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError>; // Returns (module_path, symbol, offset_from_symbol)
    
    // Symbolized disassembly methods
    fn disassemble_memory(&self, pid: u32, address: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError>;
    
    // Call stack methods
    fn get_call_stack(&self, pid: u32, tid: u32) -> Result<Vec<CallFrame>, PlatformError>;
    // Process control
    fn terminate_process(&self, pid: u32) -> Result<(), PlatformError>;
    // Break into a running, debugged process (fire-and-forget)
    fn break_into(&self, pid: u32) -> Result<(), PlatformError>;
    
    // Module extra info
    fn get_module_extra_info(&self, pid: u32, module_base: u64) -> Result<crate::pe_types::ModuleExtraInfo, PlatformError>;

    // Memory region queries
    fn query_memory_region(&self, pid: u32, address: u64) -> Result<crate::protocol::MemoryRegionInfo, PlatformError>;
    fn enumerate_memory_regions(&self, pid: u32) -> Result<Vec<crate::protocol::MemoryRegionInfo>, PlatformError>;

    // Dereference/telescope
    fn dereference(
        &self,
        pid: u32,
        address: u64,
        count: usize,
        reference_base: Option<u64>,
    ) -> Result<Vec<crate::protocol::DereferenceEntry>, PlatformError>;

    // Thread Environment Block (TEB) address - used for emulator GS segment setup
    fn get_teb_address(&self, _pid: u32, _tid: u32) -> Result<u64, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// Search process memory for a byte pattern, returning matching addresses.
    /// Scans all committed, readable memory regions in 1MB chunks with overlap
    /// for cross-boundary matches. Uses rayon to parallelize across regions.
    /// Returns up to `max_results` addresses sorted by address.
    fn search_memory(&self, pid: u32, pattern: &[u8], max_results: usize) -> Result<(Vec<u64>, bool), PlatformError>
    where
        Self: Sync,
    {
        if pattern.is_empty() {
            return Err(PlatformError::Other("Search pattern must not be empty".into()));
        }

        let regions = self.enumerate_memory_regions(pid)?;
        let chunk_size: usize = 1024 * 1024; // 1MB

        const PAGE_NOACCESS: u32 = 0x01;
        const PAGE_GUARD: u32 = 0x100;
        const MEM_COMMIT: u32 = 0x1000;

        // Filter to searchable regions
        let searchable_regions: Vec<_> = regions
            .iter()
            .filter(|r| {
                r.state == MEM_COMMIT
                    && r.protect != 0
                    && (r.protect & PAGE_NOACCESS) == 0
                    && (r.protect & PAGE_GUARD) == 0
            })
            .collect();

        let total_found = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);

        let all_results: Vec<Vec<u64>> = searchable_regions
            .par_iter()
            .map(|region| {
                if stop.load(Ordering::Relaxed) {
                    return Vec::new();
                }

                let region_base = region.base_address;
                let region_size = region.region_size as usize;
                let overlap = if pattern.len() > 1 { pattern.len() - 1 } else { 0 };
                let mut offset: usize = 0;
                let mut local_results = Vec::new();

                while offset < region_size {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let read_size = (chunk_size + overlap).min(region_size - offset);
                    let read_addr = region_base + offset as u64;

                    match self.read_memory(pid, read_addr, read_size) {
                        Ok(data) => {
                            if data.len() >= pattern.len() {
                                let mut i = 0;
                                while i <= data.len() - pattern.len() {
                                    if data[i..i + pattern.len()] == *pattern {
                                        local_results.push(read_addr + i as u64);
                                        let prev = total_found.fetch_add(1, Ordering::Relaxed);
                                        if prev + 1 >= max_results * 2 {
                                            stop.store(true, Ordering::Relaxed);
                                            return local_results;
                                        }
                                    }
                                    i += 1;
                                }
                            }
                        }
                        Err(_) => {
                            // Skip unreadable chunks silently
                        }
                    }

                    if read_size <= overlap {
                        break;
                    }
                    offset += read_size - overlap;
                }

                local_results
            })
            .collect();

        let mut addresses: Vec<u64> = all_results.into_iter().flatten().collect();
        addresses.sort_unstable();
        let capped = addresses.len() > max_results;
        addresses.truncate(max_results);

        Ok((addresses, capped))
    }
}

impl SymbolInfo {
    pub fn format_symbol(&self) -> String {
        if self.offset == 0 {
            format!("{}!{}", self.module_name, self.symbol_name)
        } else {
            format!("{}!{}+0x{:x}", self.module_name, self.symbol_name, self.offset)
        }
    }
}
