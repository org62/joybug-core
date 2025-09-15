mod utils;
mod module_manager;
mod thread_manager;
pub mod process;
pub mod debug_events;
mod memory;
mod thread_context;
mod symbol_manager;
mod symbol_provider;
pub mod disassembler;
mod callstack;
mod stepper;
mod debugged_process;

use crate::interfaces::{PlatformAPI, PlatformError, ModuleSymbol, ResolvedSymbol, SymbolError, Architecture, DisassemblerError, Instruction, DisassemblerProvider, Stepper};
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo, StepKind};
use symbol_manager::SymbolManager;
use disassembler::CapstoneDisassembler;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use tracing::{trace, info};
use std::collections::HashMap;

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

// Stepping state tracking
#[derive(Debug, Clone)]
pub(crate) struct StepState {
    pub(crate) kind: StepKind,
}

pub(crate) use debugged_process::DebuggedProcess;

pub struct WindowsPlatform {
    /// Map of PID to DebuggedProcess for managing multiple processes
    processes: HashMap<u32, DebuggedProcess>,
    /// Shared symbol manager for all processes
    symbol_manager: Option<SymbolManager>,
    /// Shared disassembler for all processes
    disassembler: Option<CapstoneDisassembler>,
}

impl WindowsPlatform {
    pub fn new() -> Self {
        let symbol_manager = SymbolManager::new().ok(); // Log error but don't fail initialization
        let disassembler = CapstoneDisassembler::new().ok(); // Log error but don't fail initialization
        Self { 
            processes: HashMap::new(),
            symbol_manager,
            disassembler,
        }
    }
    
    /// Get a reference to a debugged process by PID
    fn get_process(&self, pid: u32) -> Result<&DebuggedProcess, PlatformError> {
        self.processes.get(&pid)
            .ok_or_else(|| PlatformError::Other(format!("Process {} not found", pid)))
    }
    
    /// Get a mutable reference to a debugged process by PID
    fn get_process_mut(&mut self, pid: u32) -> Result<&mut DebuggedProcess, PlatformError> {
        self.processes.get_mut(&pid)
            .ok_or_else(|| PlatformError::Other(format!("Process {} not found", pid)))
    }
    
    /// Add a new debugged process
    fn add_process(&mut self, pid: u32, process_handle: HANDLE, architecture: Architecture) -> Result<(), PlatformError> {
        let process = DebuggedProcess::new(pid, process_handle, architecture)?;
        self.processes.insert(pid, process);
        Ok(())
    }
    
    /// Remove a debugged process
    fn remove_process(&mut self, pid: u32) {
        self.processes.remove(&pid);
    }

    /// Cleanup all step-related breakpoint state for a process
    fn cleanup_step_state_for_process(&mut self, pid: u32) -> (usize, usize) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            let removed_over = proc.clear_step_over_breakpoints();
            let removed_out = proc.clear_step_out_breakpoints();

            if removed_over > 0 || removed_out > 0 {
                trace!(pid, removed_over, removed_out, "Cleaned up step breakpoint state for process");
            }
            (removed_over, removed_out)
        } else {
            (0, 0)
        }
    }

    /// Cleanup all step-related breakpoint state for a specific thread
    fn cleanup_step_state_for_thread(&mut self, pid: u32, tid: u32) -> (usize, usize) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            let removed_over = proc.retain_step_over_breakpoints_excluding_tid(tid);
            let removed_out = proc.retain_step_out_breakpoints_excluding_tid(tid);

            if removed_over > 0 || removed_out > 0 {
                trace!(pid, tid, removed_over, removed_out, "Cleaned up step breakpoint state for thread");
            }
            (removed_over, removed_out)
        } else {
            (0, 0)
        }
    }
}

impl PlatformAPI for WindowsPlatform {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::attach(self, pid)
    }

    fn detach(&mut self, pid: u32) -> Result<(), PlatformError> {
        trace!(pid, "WindowsPlatform::detach called");
        if self.processes.contains_key(&pid) {
            self.remove_process(pid);
            Ok(())
        } else {
            Err(PlatformError::Other(format!("Process {} not found", pid)))
        }
    }

    fn set_single_shot_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        let process = self.get_process_mut(pid)?;
        let process_handle = process.handle();
        let arch = process.architecture();

        let (breakpoint_bytes, original_bytes) = match arch {
            Architecture::X64 => {
                let original_byte = memory::read_memory_internal(process_handle, addr, 1)?;
                (vec![0xCC], original_byte)
            }
            Architecture::Arm64 => {
                // ARM64 BRK instruction (BRK #0)
                let original_bytes = memory::read_memory_internal(process_handle, addr, 4)?;
                (vec![0x00, 0x00, 0x3e, 0xD4], original_bytes)
            }
        };
        
        // Store the original bytes
        process.insert_single_shot_breakpoint(addr, original_bytes);
        
        // Write the breakpoint instruction
        memory::write_memory_internal(process_handle, addr, &breakpoint_bytes)
    }

    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        // Blocking variant retained for direct callers; server uses non-locking helpers
        debug_events::continue_only(pid, tid)?;
        let debug_event = debug_events::wait_for_debug_event_blocking()?;
        debug_events::handle_debug_event(self, &debug_event)
    }

    fn set_breakpoint(&mut self, pid: u32, addr: u64, tid: Option<u32>) -> Result<(), PlatformError> {
        trace!(pid, addr, "WindowsPlatform::set_breakpoint called");
        let process = self.get_process_mut(pid)?;
        let process_handle = process.handle();
        let arch = process.architecture();

        if process.is_persistent_breakpoint(addr) {
            return Ok(());
        }

        let (breakpoint_bytes, original_bytes) = match arch {
            Architecture::X64 => {
                let original_byte = memory::read_memory_internal(process_handle, addr, 1)?;
                (vec![0xCC], original_byte)
            }
            Architecture::Arm64 => {
                let original_bytes = memory::read_memory_internal(process_handle, addr, 4)?;
                (vec![0x00, 0x00, 0x3e, 0xD4], original_bytes)
            }
        };

        process.insert_persistent_breakpoint(addr, original_bytes, tid);
        memory::write_memory_internal(process_handle, addr, &breakpoint_bytes)
    }

    fn remove_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        trace!(pid, addr, "WindowsPlatform::remove_breakpoint called");
        let process = self.get_process_mut(pid)?;
        process.remove_breakpoint(addr)
    }

    fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::launch(self, command)
    }

    fn read_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError> {
        memory::read_memory_unlocked(pid, address, size)
    }

    fn write_memory(&self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        memory::write_memory(self, pid, address, data)
    }

    fn read_wide_string(&self, pid: u32, address: u64, max_len: Option<usize>) -> Result<String, PlatformError> {
        memory::read_wide_string(self, pid, address, max_len)
    }

    fn get_thread_context(&self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError> {
        // Only read access to process state is needed here
        thread_context::get_thread_context(self.get_process(pid)?, pid, tid)
    }

    fn set_thread_context(&self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError> {
        thread_context::set_thread_context(self.get_process(pid)?, pid, tid, context)
    }

    fn get_function_arguments(&self, pid: u32, tid: u32, count: usize) -> Result<Vec<u64>, PlatformError> {
        let process = self.get_process(pid)?;
        let arch = process.architecture();
        let context = self.get_thread_context(pid, tid)?;

        let mut arguments = Vec::with_capacity(count);

        match (arch, context) {
            #[cfg(all(windows, target_arch = "x86_64"))]
            (Architecture::X64, crate::protocol::ThreadContext::Win32RawContext(ctx)) => {
                // First 4 arguments are in registers: RCX, RDX, R8, R9
                if count > 0 { arguments.push(ctx.Rcx); }
                if count > 1 { arguments.push(ctx.Rdx); }
                if count > 2 { arguments.push(ctx.R8); }
                if count > 3 { arguments.push(ctx.R9); }

                // Subsequent arguments are on the stack
                if count > 4 {
                    let stack_ptr = ctx.Rsp;
                    // The first stack argument is at RSP+0x28 (after return address and space for register args)
                    let stack_args_ptr = stack_ptr + 0x28;
                    let num_stack_args = count - 4;
                    let stack_data = self.read_memory(pid, stack_args_ptr, num_stack_args * 8)?;
                    
                    for chunk in stack_data.chunks_exact(8) {
                        arguments.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                    }
                }
            }
            #[cfg(all(windows, target_arch = "aarch64"))]
            (Architecture::Arm64, crate::protocol::ThreadContext::Win32RawContext(ctx)) => {
                // First 8 arguments are in registers X0-X7
                for i in 0..std::cmp::min(count, 8) {
                    arguments.push(unsafe { ctx.Anonymous.X[i] });
                }

                // Subsequent arguments are on the stack
                if count > 8 {
                    let stack_ptr = ctx.Sp;
                    let num_stack_args = count - 8;
                    let stack_data = self.read_memory(pid, stack_ptr, num_stack_args * 8)?;

                    for chunk in stack_data.chunks_exact(8) {
                        arguments.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                    }
                }
            }
            _ => return Err(PlatformError::NotImplemented),
        }

        Ok(arguments)
    }

    fn list_modules(&self, pid: u32) -> Result<Vec<ModuleInfo>, PlatformError> {
        let process = self.get_process(pid)?;
        Ok(process.module_manager().list_modules())
    }

    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
        let process = self.get_process(pid)?;
        Ok(process.thread_manager().list_threads())
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        process::list_processes()
    }

    // Symbol-related methods
    fn find_symbol(&self, symbol_name: &str, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            symbol_manager.find_symbol_across_all_modules(symbol_name, max_results)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }

    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            // Get the raw ModuleSymbol objects without VA calculation
            symbol_manager.list_symbols_raw(module_path)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }

    fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<ModuleSymbol>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            // Get the raw ModuleSymbol without VA calculation
            symbol_manager.resolve_rva_to_symbol_raw(module_path, rva)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }

    fn resolve_address_to_symbol(&self, pid: u32, address: u64) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError> {
        if let Some(ref symbol_manager) = self.symbol_manager {
            let modules = self.get_process(pid).map_err(|e| SymbolError::SymbolsNotFound(e.to_string()))?
                .module_manager()
                .list_modules();
            symbol_manager.resolve_address_to_symbol_raw(&modules, address)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }
    
    // Symbolized disassembly methods
    fn disassemble_memory(&self, pid: u32, address: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        if self.disassembler.is_none() {
            return Err(DisassemblerError::CapstoneError("Disassembler not initialized".to_string()));
        }

        let data = memory::read_memory_unlocked(pid, address, count * 16)
            .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;

        let modules = self.get_process(pid)
            .map_err(|e| DisassemblerError::InvalidData(format!("Process not found: {}", e)))?
            .module_manager()
            .list_modules();

        let symbol_manager = self.symbol_manager.as_ref();
        let symbol_resolver = move |addr: u64| -> Option<crate::interfaces::SymbolInfo> {
            if let Some(symbol_manager) = symbol_manager {
                if let Ok(Some((module_path, symbol, offset))) = symbol_manager.resolve_address_to_symbol(&modules, addr) {
                    let module_name = std::path::Path::new(&module_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&module_path)
                        .to_string();
                    Some(crate::interfaces::SymbolInfo { module_name, symbol_name: symbol.name, offset })
                } else { None }
            } else { None }
        };

        self.disassembler.as_ref().unwrap().disassemble_with_symbols(arch, &data, address, count, symbol_resolver)
    }
    
    fn get_call_stack(&self, pid: u32, tid: u32) -> Result<Vec<crate::interfaces::CallFrame>, PlatformError> {
        callstack::get_call_stack(self, pid, tid)
    }

    fn terminate_process(&self, pid: u32) -> Result<(), PlatformError> {
        // Avoid holding internal mutex/state that the debug loop uses.
        // Delegate to an unlocked helper that uses OpenProcess/TerminateProcess directly.
        info!(pid, "WindowsPlatform::terminate_process invoked");
        process::terminate_process_unlocked(pid)
    }

}

impl Stepper for WindowsPlatform {
    fn step(&mut self, pid: u32, tid: u32, kind: StepKind) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        stepper::step(self, pid, tid, kind)
    }
} 