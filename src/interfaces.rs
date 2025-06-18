#![allow(dead_code)]
use thiserror::Error;
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo};
use async_trait::async_trait;

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
pub struct Symbol {
    pub name: String,
    pub rva: u32, // Relative Virtual Address
}

#[async_trait]
pub trait SymbolProvider: Send + Sync {
    async fn load_symbols_for_module(
        &mut self,
        module_path: &str,
        module_base: Address,
        module_size: Option<usize>,
    ) -> Result<(), SymbolError>;

    async fn find_symbol(
        &self,
        module_path: &str,
        symbol_name: &str,
    ) -> Result<Option<Symbol>, SymbolError>;

    async fn list_symbols(&self, module_path: &str) -> Result<Vec<Symbol>, SymbolError>;

    async fn resolve_rva_to_symbol(
        &self,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<Symbol>, SymbolError>;
}

pub trait PlatformAPI: Send + Sync {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn set_breakpoint(&mut self, addr: u64) -> Result<(), PlatformError>;
    fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError>;
    fn write_memory(&mut self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError>;
    fn get_thread_context(&mut self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError>;
    fn set_thread_context(&mut self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError>;
    fn list_modules(&self, pid: u32) -> Result<Vec<ModuleInfo>, PlatformError>;
    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError>;
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError>;
    
    // Symbol-related methods
    fn find_symbol(&self, module_path: &str, symbol_name: &str) -> Result<Option<Symbol>, SymbolError>;
    fn list_symbols(&self, module_path: &str) -> Result<Vec<Symbol>, SymbolError>;
    fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<Symbol>, SymbolError>;
    fn resolve_address_to_symbol(&self, pid: u32, address: u64) -> Result<Option<(String, Symbol, u64)>, SymbolError>; // Returns (module_path, symbol, offset_from_symbol)
    
    // ... add more as needed
} 