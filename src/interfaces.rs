use thiserror::Error;
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo};
use regex;

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
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSymbol {
    pub name: String,
    pub module_name: String,
    pub rva: u32, // Relative Virtual Address  
    pub va: u64,  // Virtual Address (module_base + rva)
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
            
            // Also symbolize operands
            if !instruction.op_str.is_empty() {
                let symbolized_ops = symbolize_operands(&instruction.op_str, &symbol_resolver);
                if symbolized_ops != instruction.op_str {
                    instruction.symbolized_op_str = Some(symbolized_ops);
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
    fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
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
    
    // ... add more as needed
}

impl SymbolInfo {
    pub fn format_symbol(&self) -> String {
        format!("{}!{}+0x{:x}", self.module_name, self.symbol_name, self.offset)
    }
}

/// Symbolizes addresses in instruction operands
pub fn symbolize_operands<F>(op_str: &str, symbol_resolver: F) -> String
where
    F: Fn(u64) -> Option<SymbolInfo>,
{
    // Regex to find hexadecimal addresses in operands
    // Matches patterns like 0x1234567890abcdef, 0x1234, etc.
    let re = regex::Regex::new(r"0x([0-9a-fA-F]+)").unwrap();
    
    let result = re.replace_all(op_str, |caps: &regex::Captures| {
        if let Ok(addr) = u64::from_str_radix(&caps[1], 16) {
            // Only symbolize addresses that look like code addresses (not small constants)
            if addr > 0x10000 {
                if let Some(symbol_info) = symbol_resolver(addr) {
                    return symbol_info.format_symbol();
                }
            }
        }
        caps[0].to_string() // Return original if no symbol found
    });
    
    result.to_string()
}

 