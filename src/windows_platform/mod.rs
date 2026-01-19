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
mod module_extra;
mod dbghelp;
mod dereference;

use crate::interfaces::{PlatformAPI, PlatformError, ModuleSymbol, ResolvedSymbol, SymbolError, Architecture, DisassemblerError, Instruction, DisassemblerProvider, Stepper};
// no-op
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo, StepKind};
use crate::emulator::{Emulator, EmulationResult};
use symbol_manager::SymbolManager;
use disassembler::CapstoneDisassembler;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use tracing::{trace, info, error};
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
    
    /// Public accessor to retrieve a raw process handle for a PID
    pub fn process_handle(&self, pid: u32) -> Result<HANDLE, PlatformError> {
        Ok(self.get_process(pid)?.handle())
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

    // ==================== Emulator Methods (One-Shot) ====================
    // Note: Emulators are created, used, and destroyed in a single call
    // because Unicorn is not Send+Sync and can't be stored across threads.

    /// Emulate with a specific mode (one-shot)
    pub fn emulate_with_mode(&self, pid: u32, tid: u32, max_instructions: usize, mode: crate::protocol::EmulationMode) -> Result<EmulationResult, PlatformError> {
        let mut emulator = Emulator::from_debugger_state(self, pid, tid)
            .map_err(|e| PlatformError::Other(e.to_string()))?;

        emulator.emulate_with_mode(self, max_instructions, mode)
            .map_err(|e| PlatformError::Other(e.to_string()))
    }

    /// Get the TEB (Thread Environment Block) address for a thread
    pub fn get_teb_address(&self, pid: u32, tid: u32) -> Result<u64, PlatformError> {
        let process = self.get_process(pid)?;
        let thread_handle = process.thread_manager().get_thread_handle(tid)
            .ok_or_else(|| PlatformError::Other(format!("Thread {} not found", tid)))?;

        // Use NtQueryInformationThread to get THREAD_BASIC_INFORMATION
        #[repr(C)]
        struct ThreadBasicInformation {
            exit_status: i32,
            teb_base_address: *mut std::ffi::c_void,
            client_id_unique_process: usize,
            client_id_unique_thread: usize,
            affinity_mask: usize,
            priority: i32,
            base_priority: i32,
        }

        // Link to ntdll
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationThread(
                thread_handle: HANDLE,
                thread_information_class: u32,
                thread_information: *mut std::ffi::c_void,
                thread_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        const THREAD_BASIC_INFORMATION: u32 = 0;

        let mut info: ThreadBasicInformation = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;

        let status = unsafe {
            NtQueryInformationThread(
                thread_handle,
                THREAD_BASIC_INFORMATION,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ThreadBasicInformation>() as u32,
                &mut return_length,
            )
        };

        if status >= 0 {
            Ok(info.teb_base_address as u64)
        } else {
            Err(PlatformError::Other(format!("NtQueryInformationThread failed: 0x{:08X}", status)))
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
        use std::time::Instant;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::cell::Cell;

        // Thread-local timing accumulators
        thread_local! {
            static MEMORY_READ_US: Cell<u64> = const { Cell::new(0) };
            static MODULE_LIST_US: Cell<u64> = const { Cell::new(0) };
            static DISASM_US: Cell<u64> = const { Cell::new(0) };
            static SYMBOL_US: Cell<u64> = const { Cell::new(0) };
            static CALL_COUNT: Cell<u64> = const { Cell::new(0) };
            static SYMBOL_CALLS: Cell<u64> = const { Cell::new(0) };
        }

        if self.disassembler.is_none() {
            return Err(DisassemblerError::CapstoneError("Disassembler not initialized".to_string()));
        }

        // Time memory read
        let t0 = Instant::now();
        let data = memory::read_memory_unlocked(pid, address, count * 16)
            .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;
        let memory_time = t0.elapsed();

        // Time module list fetch
        let t1 = Instant::now();
        let mut modules = self.get_process(pid)
            .map_err(|e| DisassemblerError::InvalidData(format!("Process not found: {}", e)))?
            .module_manager()
            .list_modules();
        // Sort modules by base address for binary search
        modules.sort_by_key(|m| m.base);
        let module_time = t1.elapsed();

        let symbol_manager = self.symbol_manager.as_ref();

        // Track symbol resolution time
        let symbol_time_us = std::sync::Arc::new(AtomicU64::new(0));
        let symbol_call_count = std::sync::Arc::new(AtomicU64::new(0));
        let symbol_time_clone = symbol_time_us.clone();
        let symbol_count_clone = symbol_call_count.clone();

        let symbol_resolver = move |addr: u64| -> Option<crate::interfaces::SymbolInfo> {
            let t = Instant::now();
            let result = if let Some(symbol_manager) = symbol_manager {
                if let Ok(Some((module_path, symbol, offset))) = symbol_manager.resolve_address_to_symbol(&modules, addr) {
                    let module_name = std::path::Path::new(&module_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&module_path)
                        .to_string();
                    Some(crate::interfaces::SymbolInfo { module_name, symbol_name: symbol.name, offset })
                } else { None }
            } else { None };
            symbol_time_clone.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
            symbol_count_clone.fetch_add(1, Ordering::Relaxed);
            result
        };

        // Time disassembly
        let t2 = Instant::now();
        let result = self.disassembler.as_ref().unwrap().disassemble_with_symbols(arch, &data, address, count, symbol_resolver);
        let disasm_time = t2.elapsed();

        // Accumulate timing stats
        MEMORY_READ_US.with(|c| c.set(c.get() + memory_time.as_micros() as u64));
        MODULE_LIST_US.with(|c| c.set(c.get() + module_time.as_micros() as u64));
        DISASM_US.with(|c| c.set(c.get() + disasm_time.as_micros() as u64));
        SYMBOL_US.with(|c| c.set(c.get() + symbol_time_us.load(Ordering::Relaxed)));
        SYMBOL_CALLS.with(|c| c.set(c.get() + symbol_call_count.load(Ordering::Relaxed)));
        let call_count = CALL_COUNT.with(|c| { c.set(c.get() + 1); c.get() });

        // Print stats every 1000 calls
        if call_count % 1000 == 0 {
            let mem_ms = MEMORY_READ_US.with(|c| c.get()) as f64 / 1000.0;
            let mod_ms = MODULE_LIST_US.with(|c| c.get()) as f64 / 1000.0;
            let dis_ms = DISASM_US.with(|c| c.get()) as f64 / 1000.0;
            let sym_ms = SYMBOL_US.with(|c| c.get()) as f64 / 1000.0;
            let sym_calls = SYMBOL_CALLS.with(|c| c.get());
            println!("\n=== TIMING STATS after {} calls ===", call_count);
            println!("  Memory read:    {:8.2} ms", mem_ms);
            println!("  Module list:    {:8.2} ms", mod_ms);
            println!("  Disassembly:    {:8.2} ms (includes symbol resolution)", dis_ms);
            println!("  Symbol resolve: {:8.2} ms ({} calls, {:.3} ms/call avg)",
                sym_ms, sym_calls, if sym_calls > 0 { sym_ms / sym_calls as f64 } else { 0.0 });
            println!("=====================================\n");
        }

        result
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

    fn break_into(&self, pid: u32) -> Result<(), PlatformError> {
        // Trigger a breakpoint in the target without holding internal locks; do not wait.
        info!(pid, "WindowsPlatform::break_into invoked");
        process::debug_break_process_unlocked(pid)
    }

    fn get_module_extra_info(&self, pid: u32, module_base: u64) -> Result<crate::pe_types::ModuleExtraInfo, PlatformError> {
        // Try cached info first
        if let Ok(process) = self.get_process(pid) {
            if let Some(info) = process.module_manager().get_extra_info(module_base) {
                return Ok(info);
            }
        }
        // Fallback: parse from file
        error!(pid, module_base, "Parsing module extra info from file");
        self.parse_module_extra_info(pid, module_base)
    }

    fn query_memory_region(&self, pid: u32, address: u64) -> Result<crate::protocol::MemoryRegionInfo, PlatformError> {
        memory::query_memory_region_unlocked(pid, address)
    }

    fn enumerate_memory_regions(&self, pid: u32) -> Result<Vec<crate::protocol::MemoryRegionInfo>, PlatformError> {
        memory::enumerate_memory_regions_unlocked(pid)
    }

    fn dereference(
        &self,
        pid: u32,
        address: u64,
        count: usize,
        reference_base: Option<u64>,
    ) -> Result<Vec<crate::protocol::DereferenceEntry>, PlatformError> {
        // Get process - required for module list and architecture
        let process = self.get_process(pid)?;
        let arch = process.architecture();

        // Build symbol resolver for instruction operand symbolization
        let mut modules = process.module_manager().list_modules();
        // Sort modules by base address for binary search in symbol resolution
        modules.sort_by_key(|m| m.base);
        let symbol_manager = self.symbol_manager.as_ref();
        let symbol_resolver = move |addr: u64| -> Option<crate::interfaces::SymbolInfo> {
            if let Some(sm) = symbol_manager {
                if let Ok(Some((module_path, symbol, offset))) = sm.resolve_address_to_symbol(&modules, addr) {
                    let module_name = std::path::Path::new(&module_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&module_path)
                        .to_string();
                    return Some(crate::interfaces::SymbolInfo { module_name, symbol_name: symbol.name, offset });
                }
            }
            None
        };

        dereference::dereference(pid, address, count, reference_base, arch, Some(symbol_resolver))
    }

    fn get_teb_address(&self, pid: u32, tid: u32) -> Result<u64, PlatformError> {
        // Call the method we defined on WindowsPlatform
        WindowsPlatform::get_teb_address(self, pid, tid)
    }
}

impl Stepper for WindowsPlatform {
    fn step(&mut self, pid: u32, tid: u32, kind: StepKind) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        stepper::step(self, pid, tid, kind)
    }
}

impl WindowsPlatform {
    /// Find function boundaries for an address using the exception directory (RuntimeFunction).
    /// Returns (function_start_va, function_end_va, function_name) if found.
    pub fn find_function_bounds(&self, pid: u32, address: u64) -> Result<Option<(u64, u64, Option<String>)>, PlatformError> {
        let process = self.get_process(pid)?;
        let modules = process.module_manager().list_modules();

        // Find which module contains this address
        let containing_module = modules.iter().find(|m| {
            let end = m.base + m.size.unwrap_or(0);
            address >= m.base && address < end
        });

        let module = match containing_module {
            Some(m) => m,
            None => return Ok(None),
        };

        // Get module extra info (which contains runtime_functions)
        let extra_info = match self.get_module_extra_info(pid, module.base) {
            Ok(info) => info,
            Err(_) => return Ok(None),
        };

        let runtime_functions = match &extra_info.runtime_functions {
            Some(funcs) if !funcs.is_empty() => funcs,
            _ => return Ok(None),
        };

        // Convert address to RVA
        let rva = (address - module.base) as u32;

        // Binary search for the function containing this RVA
        let result = runtime_functions.binary_search_by(|rf| {
            if rva < rf.BeginAddress {
                std::cmp::Ordering::Greater
            } else if rva >= rf.EndAddress {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });

        match result {
            Ok(idx) => {
                let rf = &runtime_functions[idx];
                let func_start = module.base + rf.BeginAddress as u64;
                let func_end = module.base + rf.EndAddress as u64;

                // Try to get function name from symbol
                let func_name = if let Some(ref symbol_manager) = self.symbol_manager {
                    symbol_manager
                        .resolve_address_to_symbol_raw(&modules, func_start)
                        .ok()
                        .flatten()
                        .map(|(module_path, symbol, _offset)| {
                            let module_name = std::path::Path::new(&module_path)
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or(&module_path)
                                .to_string();
                            format!("{}!{}", module_name, symbol.name)
                        })
                } else {
                    None
                };

                Ok(Some((func_start, func_end, func_name)))
            }
            Err(_) => Ok(None),
        }
    }

    /// Disassemble a function with bounds detection.
    /// Returns (instructions, function_start, function_end, function_name).
    pub fn disassemble_function(
        &self,
        pid: u32,
        address: u64,
        max_instructions: usize,
        arch: Architecture,
    ) -> Result<(Vec<Instruction>, Option<u64>, Option<u64>, Option<String>), crate::interfaces::DisassemblerError> {
        // Try to find function bounds
        let bounds = self.find_function_bounds(pid, address)
            .ok()
            .flatten();

        let (disasm_start, disasm_count, func_start, func_end, func_name) = match bounds {
            Some((start, end, name)) => {
                // Calculate how many instructions we might need based on function size
                // Assume average instruction size of ~2 bytes for a conservative estimate
                // Don't cap by max_instructions here - we want the full function
                let func_size = (end - start) as usize;
                let estimated_count = (func_size / 2).max(1);
                (start, estimated_count, Some(start), Some(end), name)
            }
            None => {
                // No bounds found, just disassemble from the address with limit
                (address, max_instructions, None, None, None)
            }
        };

        // Disassemble the function
        let instructions = self.disassemble_memory(pid, disasm_start, disasm_count, arch)?;

        // If we have bounds, filter to only instructions within the function (no cap)
        // If no bounds, use max_instructions as a safety limit
        let filtered_instructions = if let (Some(start), Some(end)) = (func_start, func_end) {
            instructions
                .into_iter()
                .filter(|i| i.address >= start && i.address < end)
                .collect()
        } else {
            instructions.into_iter().take(max_instructions).collect()
        };

        Ok((filtered_instructions, func_start, func_end, func_name))
    }
}