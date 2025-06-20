mod utils;
mod module_manager;
mod thread_manager;
mod process;
mod debug_events;
mod memory;
mod thread_context;
mod symbol_manager;
mod symbol_provider;
pub mod disassembler;

use crate::interfaces::{PlatformAPI, PlatformError, Symbol, SymbolError, Architecture, DisassemblerError, Instruction, DisassemblerProvider};
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo};
use module_manager::ModuleManager;
use thread_manager::ThreadManager;
use symbol_manager::SymbolManager;
use disassembler::CapstoneDisassembler;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use tracing::{trace};

// Safe wrapper for HANDLE that automatically closes it
#[derive(Debug)]
pub(crate) struct HandleSafe(pub HANDLE);
unsafe impl Send for HandleSafe {}
unsafe impl Sync for HandleSafe {}

impl Drop for HandleSafe {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 as isize != -1 {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// Aligned wrapper for CONTEXT structure
#[repr(align(16))]
struct AlignedContext {
    context: CONTEXT,
}

pub struct WindowsPlatform {
    pub(crate) pid: Option<u32>,
    pub(crate) process_handle: Option<HandleSafe>,
    pub(crate) module_manager: ModuleManager,
    pub(crate) thread_manager: ThreadManager,
    pub(crate) symbol_manager: Option<SymbolManager>,
    pub(crate) disassembler: Option<CapstoneDisassembler>,
}

impl WindowsPlatform {
    pub fn new() -> Self {
        let symbol_manager = SymbolManager::new().ok(); // Log error but don't fail initialization
        let disassembler = CapstoneDisassembler::new().ok(); // Log error but don't fail initialization
        Self { 
            pid: None, 
            process_handle: None, 
            module_manager: ModuleManager::new(), 
            thread_manager: ThreadManager::new(),
            symbol_manager,
            disassembler,
        }
    }
}

impl PlatformAPI for WindowsPlatform {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::attach(self, pid)
    }

    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        debug_events::continue_exec(self, pid, tid)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<(), PlatformError> {
        trace!(addr, "WindowsPlatform::set_breakpoint called");
        Err(PlatformError::NotImplemented)
    }

    fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::launch(self, command)
    }

    fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError> {
        memory::read_memory(self, pid, address, size)
    }

    fn write_memory(&mut self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        memory::write_memory(self, pid, address, data)
    }

    fn get_thread_context(&mut self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError> {
        thread_context::get_thread_context(self, pid, tid)
    }

    fn set_thread_context(&mut self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError> {
        thread_context::set_thread_context(self, pid, tid, context)
    }

    fn list_modules(&self, _pid: u32) -> Result<Vec<ModuleInfo>, PlatformError> {
        Ok(self.module_manager.list_modules())
    }

    fn list_threads(&self, _pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
        Ok(self.thread_manager.list_threads())
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        process::list_processes()
    }

    // Symbol-related methods
    fn find_symbol(&self, module_path: &str, symbol_name: &str) -> Result<Option<Symbol>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            symbol_manager.find_symbol(module_path, symbol_name)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }

    fn list_symbols(&self, module_path: &str) -> Result<Vec<Symbol>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            symbol_manager.list_symbols(module_path)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }

    fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<Symbol>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            symbol_manager.resolve_rva_to_symbol(module_path, rva)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }

    fn resolve_address_to_symbol(&self, _pid: u32, address: u64) -> Result<Option<(String, Symbol, u64)>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            let modules = self.module_manager.list_modules();
            symbol_manager.resolve_address_to_symbol(&modules, address)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }
    
    // Symbolized disassembly methods
    fn disassemble_memory(&mut self, pid: u32, address: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        if self.disassembler.is_none() {
            return Err(DisassemblerError::CapstoneError("Disassembler not initialized".to_string()));
        }
        
        // First read memory from the process
        let data = self.read_memory(pid, address, count * 16) // Read up to 16 bytes per instruction estimate
            .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;
        
        // Create a symbol resolver closure
        let symbol_resolver = |addr: u64| -> Option<crate::interfaces::SymbolInfo> {
            if let Ok(Some((module_path, symbol, offset))) = self.resolve_address_to_symbol(pid, addr) {
                // Extract module name from path
                let module_name = std::path::Path::new(&module_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&module_path)
                    .to_string();
                
                Some(crate::interfaces::SymbolInfo {
                    module_name,
                    symbol_name: symbol.name,
                    offset,
                })
            } else {
                None
            }
        };
        
        // Now safely access the disassembler with symbol resolution
        self.disassembler.as_ref().unwrap().disassemble_with_symbols(arch, &data, address, count, symbol_resolver)
    }
} 