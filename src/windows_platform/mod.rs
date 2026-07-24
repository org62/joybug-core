mod utils;
mod module_manager;
mod thread_manager;
pub mod process;
pub mod debug_events;
mod memory;
mod thread_context;
mod symbol_manager;
mod symbol_provider;
mod type_provider;
pub mod disassembler;
mod callstack;
mod stepper;
mod debugged_process;
mod module_extra;
pub use module_extra::parse_module_extra_info_from_bytes;
pub use symbol_provider::{WindowsSymbolProvider, parse_pdb_matching_pe};
mod dbghelp;
mod dereference;
mod tracer;
mod hardware_breakpoints;

use crate::interfaces::{PlatformAPI, PlatformError, ModuleSymbol, ResolvedSymbol, SymbolError, Architecture, DisassemblerError, Instruction, DisassemblerProvider, Stepper};
// no-op
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo, StepKind};
use crate::emulator::{Emulator, EmulationResult};
use symbol_manager::SymbolManager;
pub use crate::interfaces::SymbolConfig;
use disassembler::CapstoneDisassembler;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use tracing::{trace, info, warn, error};
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
    /// If set, a hardware breakpoint DR index that needs re-arming after the step completes.
    /// Only read on x86_64 (DR-register based HW breakpoints).
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) deferred_hw_bp_rearm: Option<u8>,
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
        Self::new_with_config(SymbolConfig::default())
    }

    pub fn new_with_config(symbol_config: SymbolConfig) -> Self {
        let symbol_manager = SymbolManager::new_with_config(symbol_config).ok(); // Log error but don't fail initialization
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

    /// Module list for symbolization/PE parsing: the debug-event-populated cache
    /// when the process is attached, otherwise a Toolhelp snapshot so it works
    /// non-invasively (no `DebugActiveProcess`).
    fn modules_for(&self, pid: u32) -> Vec<ModuleInfo> {
        match self.get_process(pid) {
            Ok(p) => p.module_manager().list_modules(),
            Err(_) => utils::get_modules(pid).unwrap_or_default(),
        }
    }

    /// The symbol manager, or the uniform error when it failed to initialize.
    fn symbols(&self) -> Result<&SymbolManager, SymbolError> {
        self.symbol_manager.as_ref()
            .ok_or_else(|| SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
    }

    /// Attribute a watchpoint trap instruction pointer to the accessing
    /// instruction. On x86 the hardware traps *after* the access, so the accessor
    /// is the instruction ending exactly at `raw_rip`. Uses the shared backward
    /// disassembler (self-resynchronizing decode) to find the instruction ending at
    /// `raw_rip`. ARM64 reports the exact faulting PC. Falls back to `raw_rip` when
    /// no instruction ends exactly there (misaligned/undecodable window).
    fn attribute_watchpoint_accessor(&self, pid: u32, raw_rip: u64) -> u64 {
        if cfg!(target_arch = "aarch64") || raw_rip < 16 {
            return raw_rip;
        }
        // Use the cheap self-resync decode, not the anchored `disassemble_backward`
        // override: this runs on every watchpoint trap in an auto-continue trace
        // loop, and the anchored path can decode kilobytes from the function start
        // (with symbol/line enrichment) just to yield one instruction.
        match self.disassemble_backward_resync(pid, raw_rip, 1, Architecture::X64) {
            Ok(ins) => ins
                .last()
                .filter(|i| i.address + i.size as u64 == raw_rip)
                .map(|i| i.address)
                .unwrap_or(raw_rip),
            Err(_) => raw_rip,
        }
    }

    /// Find a module by base address in `pid`'s module list.
    fn module_at(&self, pid: u32, module_base: u64) -> Result<ModuleInfo, SymbolError> {
        self.modules_for(pid).into_iter()
            .find(|m| m.base == module_base)
            .ok_or_else(|| SymbolError::ModuleNotLoaded(format!("No module at base 0x{:X}", module_base)))
    }

    /// Modules to search for a type query: just the one at `module_base`, or the
    /// full list sorted by base address.
    fn type_query_modules(&self, pid: u32, module_base: Option<u64>) -> Vec<ModuleInfo> {
        let mut modules = self.modules_for(pid);
        match module_base {
            Some(base) => modules.retain(|m| m.base == base),
            None => modules.sort_by_key(|m| m.base),
        }
        modules
    }

    /// Target architecture: the attached process's arch, else the host arch. A
    /// non-invasive session has no attached process to query, so we assume the
    /// host arch (correct for same-arch targets; WOW64 is not distinguished here).
    fn arch_for(&self, pid: u32) -> Architecture {
        if let Ok(p) = self.get_process(pid) {
            return p.architecture();
        }
        if cfg!(target_arch = "aarch64") { Architecture::Arm64 } else { Architecture::X64 }
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
            proc.resume_all_step_over_suspensions();
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
            // If the exiting thread was mid step-over, drop it and lift its freeze.
            proc.forget_thread_step_over(tid);
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
    pub fn emulate_with_mode(
        &self,
        pid: u32,
        tid: u32,
        max_instructions: usize,
        mode: crate::protocol::EmulationMode,
        exit_condition: Option<crate::protocol::TraceExitCondition>,
        memory_reads: &[(u64, usize)],
    ) -> Result<EmulationResult, PlatformError> {
        let mut emulator = Emulator::from_debugger_state(self, pid, tid)
            .map_err(|e| PlatformError::Other(e.to_string()))?;

        emulator.emulate_with_mode(self, max_instructions, mode, exit_condition, memory_reads)
            .map_err(|e| PlatformError::Other(e.to_string()))
    }

    /// Trace instructions using trap flag, capturing register state at each step
    pub fn trace_instructions(
        &mut self,
        pid: u32,
        tid: u32,
        exit_condition: crate::protocol::TraceExitCondition,
        max_instructions: usize,
    ) -> Result<(Vec<crate::protocol::TraceEntry>, String, u64), PlatformError> {
        let result = tracer::trace_instructions(self, pid, tid, exit_condition, max_instructions)?;
        Ok((result.entries, result.stop_reason, result.trace_time_us))
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

    /// Get the PEB (Process Environment Block) base address for a process.
    pub fn get_peb_address(&self, pid: u32) -> Result<u64, PlatformError> {
        let process_handle = self.get_process(pid)?.handle();

        // PROCESS_BASIC_INFORMATION layout — see `winternl.h`.
        #[repr(C)]
        struct ProcessBasicInformation {
            exit_status: i32,
            peb_base_address: *mut std::ffi::c_void,
            affinity_mask: usize,
            base_priority: i32,
            unique_process_id: usize,
            inherited_from_unique_process_id: usize,
        }

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process_handle: HANDLE,
                process_information_class: u32,
                process_information: *mut std::ffi::c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

        let mut info: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                process_handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            )
        };

        if status >= 0 {
            Ok(info.peb_base_address as u64)
        } else {
            Err(PlatformError::Other(format!(
                "NtQueryInformationProcess(ProcessBasicInformation) failed: 0x{:08X}",
                status
            )))
        }
    }

    /// True if the target process is WOW64 (32-bit on 64-bit Windows).
    pub fn is_wow64_process(&self, pid: u32) -> Result<bool, PlatformError> {
        let process_handle = self.get_process(pid)?.handle();

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process_handle: HANDLE,
                process_information_class: u32,
                process_information: *mut std::ffi::c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        // ProcessWow64Information returns the WOW64 PEB pointer; non-NULL = WOW64.
        const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;

        let mut wow64_peb: usize = 0;
        let mut return_length: u32 = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                process_handle,
                PROCESS_WOW64_INFORMATION_CLASS,
                &mut wow64_peb as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                &mut return_length,
            )
        };

        if status >= 0 {
            Ok(wow64_peb != 0)
        } else {
            Err(PlatformError::Other(format!(
                "NtQueryInformationProcess(ProcessWow64Information) failed: 0x{:08X}",
                status
            )))
        }
    }
}

impl PlatformAPI for WindowsPlatform {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::attach(self, pid)
    }

    fn detach(&mut self, pid: u32) -> Result<(), PlatformError> {
        process::detach(self, pid)
    }

    fn open_process(&mut self, pid: u32) -> Result<(), PlatformError> {
        process::open_non_invasive(self, pid)
    }

    fn close_process(&mut self, pid: u32) -> Result<(), PlatformError> {
        process::close_non_invasive(self, pid)
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

    fn start_code_coverage(&mut self, pid: u32, addrs: &[u64], limit: u64) -> Result<(), PlatformError> {
        trace!(pid, count = addrs.len(), limit, "WindowsPlatform::start_code_coverage called");
        let process = self.get_process_mut(pid)?;
        let process_handle = process.handle();
        let bp_bytes = process.breakpoint_instruction_bytes();
        let bp_len = bp_bytes.len();
        let mut armed = 0usize;
        for &addr in addrs {
            // Skip addresses already covered by a user/persistent breakpoint so we
            // never collide with (or double-handle) an existing INT3.
            if process.is_persistent_breakpoint(addr) {
                continue;
            }
            let original_bytes = match memory::read_memory_internal(process_handle, addr, bp_len) {
                Ok(b) => b,
                Err(e) => {
                    warn!(pid, addr, error = %e, "Skipping coverage breakpoint: failed to read original bytes");
                    continue;
                }
            };
            if let Err(e) = memory::write_memory_internal(process_handle, addr, &bp_bytes) {
                warn!(pid, addr, error = %e, "Failed to write coverage breakpoint byte");
                continue;
            }
            process.arm_coverage(addr, original_bytes, limit);
            armed += 1;
        }
        trace!(pid, armed, requested = addrs.len(), "Coverage breakpoints armed");
        Ok(())
    }

    fn get_code_coverage(&self, pid: u32) -> Result<Vec<crate::protocol::CoverageHit>, PlatformError> {
        let process = self.get_process(pid)?;
        Ok(process.coverage_snapshot())
    }

    fn stop_code_coverage(&mut self, pid: u32) -> Result<(), PlatformError> {
        trace!(pid, "WindowsPlatform::stop_code_coverage called");
        let process = self.get_process_mut(pid)?;
        process.clear_coverage();
        Ok(())
    }

    fn start_watchpoint_trace(&mut self, pid: u32, addr: u64, bp_type: crate::protocol::HardwareBreakpointType, size: crate::protocol::HardwareBreakpointSize) -> Result<(), PlatformError> {
        trace!(pid, addr, ?bp_type, ?size, "WindowsPlatform::start_watchpoint_trace called");
        // Arm the underlying hardware watchpoint (allocates a DR slot, applies to
        // all threads), then mark it as a silent access trace.
        self.set_hardware_breakpoint(pid, addr, bp_type, size)?;
        self.get_process_mut(pid)?.arm_watchpoint_trace(addr);
        info!(pid, addr, "Hardware access trace started");
        Ok(())
    }

    fn get_watchpoint_accesses(&self, pid: u32, addr: u64) -> Result<Vec<crate::protocol::WatchpointAccess>, PlatformError> {
        let mut accesses = self.get_process(pid)?.watchpoint_snapshot(addr);
        for a in &mut accesses {
            a.accessor = self.attribute_watchpoint_accessor(pid, a.accessor_raw_rip);
        }
        Ok(accesses)
    }

    fn stop_watchpoint_trace(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        trace!(pid, addr, "WindowsPlatform::stop_watchpoint_trace called");
        // Remove the hardware watchpoint; ignore "no breakpoint" so stop is
        // idempotent even if it was already cleared (e.g. module unload).
        if let Err(e) = self.remove_hardware_breakpoint(pid, addr) {
            warn!(pid, addr, error = %e, "stop_watchpoint_trace: hardware watchpoint already gone");
        }
        self.get_process_mut(pid)?.clear_watchpoint_trace(addr);
        Ok(())
    }

    fn set_hardware_breakpoint(
        &mut self,
        pid: u32,
        addr: u64,
        bp_type: crate::protocol::HardwareBreakpointType,
        size: crate::protocol::HardwareBreakpointSize,
    ) -> Result<u8, PlatformError> {
        trace!(pid, addr, ?bp_type, ?size, "WindowsPlatform::set_hardware_breakpoint called");
        let process = self.get_process_mut(pid)?;

        // Check for duplicate
        if process.has_hardware_breakpoint_at(addr) {
            return Err(PlatformError::Other(format!(
                "Hardware breakpoint already exists at 0x{:X}", addr
            )));
        }

        // Allocate a free debug register slot from the appropriate bank
        let dr_index = process.find_free_debug_register(bp_type)
            .ok_or_else(|| PlatformError::Other(
                "No free hardware debug register slot available for this breakpoint type".to_string()
            ))?;

        // Apply to all threads (skip threads that fail — they may be exiting or
        // in a kernel transition where GetThreadContext returns ERROR_GEN_FAILURE)
        let thread_handles = process.thread_manager().all_thread_handles();
        let mut applied_count = 0u32;
        for (tid, handle) in &thread_handles {
            match hardware_breakpoints::apply_single_hw_bp_to_thread(*handle, dr_index, addr, bp_type, size) {
                Ok(()) => applied_count += 1,
                Err(e) => {
                    warn!(tid, addr, error = %e, "Failed to apply HW BP to thread (may have exited or be in kernel transition)");
                }
            }
        }
        if applied_count == 0 && !thread_handles.is_empty() {
            return Err(PlatformError::Other(format!(
                "Failed to set hardware breakpoint: could not apply to any of {} threads", thread_handles.len()
            )));
        }

        // Store in process state
        process.add_hardware_breakpoint(debugged_process::InternalHardwareBreakpoint {
            address: addr,
            bp_type,
            size,
            dr_index,
            is_active: true,
        });

        info!(pid, addr, dr_index, "Hardware breakpoint set");
        Ok(dr_index)
    }

    fn remove_hardware_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        trace!(pid, addr, "WindowsPlatform::remove_hardware_breakpoint called");
        let process = self.get_process_mut(pid)?;

        let bp = process.remove_hardware_breakpoint_by_addr(addr)
            .ok_or_else(|| PlatformError::Other(format!(
                "No hardware breakpoint at 0x{:X}", addr
            )))?;

        // Clear from all threads
        let thread_handles = process.thread_manager().all_thread_handles();
        for (_tid, handle) in &thread_handles {
            let _ = hardware_breakpoints::clear_hw_bp_from_thread(*handle, bp.dr_index, bp.bp_type);
        }

        info!(pid, addr, dr_index = bp.dr_index, "Hardware breakpoint removed");
        Ok(())
    }

    fn launch(&mut self, command: &str, debug_children: bool, working_directory: Option<&str>) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::launch(self, command, debug_children, working_directory)
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
        match self.get_process(pid) {
            Ok(process) => Ok(process.module_manager().list_modules()),
            Err(_) => utils::get_modules(pid).map_err(PlatformError::Other),
        }
    }

    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
        match self.get_process(pid) {
            Ok(process) => Ok(process.thread_manager().list_threads()),
            Err(_) => utils::list_threads_toolhelp(pid),
        }
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
            let modules = self.modules_for(pid);

            // Try chain-aware resolution first (handles PGO-split function fragments)
            if let Ok(Some(result)) = symbol_manager.resolve_address_with_chain(&modules, address) {
                return Ok(Some(result));
            }

            // Fall back to nearest-below symbol resolution
            symbol_manager.resolve_address_to_symbol_raw(&modules, address)
        } else {
            Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
        }
    }

    fn try_resolve_addresses_to_symbols(&self, pid: u32, addresses: &[u64]) -> Result<Vec<Option<(String, ModuleSymbol, u64)>>, SymbolError> {
        let Some(ref symbol_manager) = self.symbol_manager else {
            return Err(SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()));
        };
        let mut modules = self.modules_for(pid);
        modules.sort_by_key(|m| m.base);
        Ok(symbol_manager.try_resolve_addresses_to_symbols_raw(&modules, addresses))
    }

    fn get_symbol_status(&self, pid: u32) -> Result<Vec<crate::protocol::ModuleSymbolStatus>, SymbolError> {
        Ok(self.symbols()?.get_symbol_status(self.modules_for(pid)))
    }

    fn load_pdb_from_path(&self, pid: u32, module_base: u64, pdb_path: &str, force: bool) -> Result<crate::protocol::PdbLoadOutcome, SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.load_pdb_from_path(&module, std::path::Path::new(pdb_path), force)
    }

    fn retry_symbol_load(&self, pid: u32, module_base: u64) -> Result<(), SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.retry_loading_symbols(&module);
        Ok(())
    }

    fn unload_module_symbols(&self, pid: u32, module_base: u64) -> Result<(), SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.unload_module_symbols(&module.name);
        Ok(())
    }

    fn set_symbol_deny_list(&self, modules: Vec<String>) -> Result<(), SymbolError> {
        self.symbols()?.set_deny_list(modules);
        Ok(())
    }

    fn resolve_address_to_line(&self, pid: u32, address: u64) -> Result<Option<crate::protocol::AddressLineInfo>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let mut modules = self.modules_for(pid);
        modules.sort_by_key(|m| m.base);
        let Some(module) = SymbolManager::find_module_binary_search(&modules, address) else {
            return Ok(None);
        };
        let rva = (address - module.base) as u32;
        Ok(symbol_manager.resolve_rva_to_line(&module.name, rva)?.map(|(file, line_entry)| {
            crate::protocol::AddressLineInfo {
                module_path: module.name.clone(),
                module_base: module.base,
                rva,
                file,
                line_entry,
            }
        }))
    }

    fn get_source_file_line_map(&self, pid: u32, module_base: u64, file_path: &str, start_line: Option<u32>, end_line: Option<u32>) -> Result<(Option<crate::interfaces::SourceFileEntry>, Vec<crate::interfaces::LineEntry>), SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.file_line_map(&module.name, file_path, start_line, end_line)
    }

    fn list_source_files(&self, pid: u32, module_base: u64) -> Result<Vec<crate::interfaces::SourceFileEntry>, SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.list_source_files(&module.name)
    }

    // Type system methods (PDB TPI stream)
    fn list_types(&self, pid: u32, module_base: Option<u64>, filter: Option<&str>, max_results: usize) -> Result<Vec<crate::protocol::TypeSummary>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let modules = self.type_query_modules(pid, module_base);
        Ok(symbol_manager.list_types(&modules, filter, max_results))
    }

    fn get_type(&self, pid: u32, module_base: Option<u64>, name: &str) -> Result<Option<crate::protocol::TypeLayout>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let modules = self.type_query_modules(pid, module_base);
        symbol_manager.get_type(&modules, name)
    }

    fn get_type_by_index(&self, pid: u32, module_base: u64, index: u32) -> Result<Option<crate::protocol::TypeLayout>, SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.get_type_by_index(&module, index)
    }

    // Symbolized disassembly methods
    fn disassemble_memory(&self, pid: u32, address: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        self.disassemble_memory_impl(pid, address, count * 16, count, arch)
    }

    fn disassemble_memory_bytes(&self, pid: u32, address: u64, byte_len: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        // Reading and decoding exactly `byte_len` bytes means the decode cannot
        // produce an instruction extending past the window (Capstone stops at
        // the buffer end), so no post-trim is needed.
        self.disassemble_memory_impl(pid, address, byte_len, byte_len, arch)
    }

    /// Backward disassembly, anchored on known-good instruction boundaries.
    ///
    /// The trait default (interfaces.rs) blindly starts a forward decode at
    /// `target - back` and trusts x86 self-resynchronization. Here we instead
    /// seed the decode from a *guaranteed* boundary when one is available — the
    /// containing function's start from the PE exception directory (`.pdata`),
    /// or the nearest symbol start — so the forward decode is exactly aligned all
    /// the way to `target` with no guessing. We probe near `target - back` first
    /// (to preserve full backward reach); if that byte sits in an uncovered gap
    /// we fall back to the boundary containing the byte just before `target`
    /// (aligning at least the rows nearest `target`), and finally to the plain
    /// self-resync window when no boundary is known (leaf/JIT code, no symbols).
    fn disassemble_backward(&self, pid: u32, target: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        if count == 0 || target == 0 {
            return Ok(Vec::new());
        }
        let back = crate::interfaces::backward_resync_window(arch, count);
        let fallback_start = target.saturating_sub(back);
        // Never anchor an anchored decode more than this far before `target`, so a
        // huge function can't turn each scroll-up tick into a massive re-decode.
        const MAX_ANCHOR_SPAN: u64 = 8192;
        let min_anchor = target.saturating_sub(MAX_ANCHOR_SPAN.max(back));

        // Largest guaranteed instruction boundary <= `probe`, within
        // [min_anchor, target): `.pdata` function start first, then nearest symbol.
        let modules = self.modules_for(pid);
        let boundary_before = |probe: u64| -> Option<u64> {
            let mut best: Option<u64> = None;
            if let Ok(Some((func_start, _, _))) = self.find_function_bounds(pid, probe) {
                if func_start >= min_anchor && func_start < target {
                    best = Some(func_start);
                }
            }
            if let Some(ref symbol_manager) = self.symbol_manager {
                if let Ok(Some((_, _, offset))) = symbol_manager.try_resolve_address_to_symbol(&modules, probe) {
                    let sym_start = probe.saturating_sub(offset);
                    if sym_start >= min_anchor && sym_start < target {
                        best = Some(best.map_or(sym_start, |b| b.max(sym_start)));
                    }
                }
            }
            best
        };

        // No known boundary (leaf/JIT code, no symbols) — plain self-resync
        // fallback, provided by the trait. An anchor needs no region clamp: it
        // is already inside a mapped module and `boundary_before` guarantees
        // min_anchor <= start < target.
        let Some(start) = boundary_before(fallback_start).or_else(|| boundary_before(target - 1)) else {
            return self.disassemble_backward_resync(pid, target, count, arch);
        };
        let window = (target - start) as usize;
        let instructions = self.disassemble_memory_bytes(pid, start, window, arch)?;
        Ok(crate::interfaces::align_backward_instructions(instructions, target, count))
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
        let arch = self.arch_for(pid);
        let symbol_resolver = self.nonblocking_symbol_resolver(pid);
        dereference::dereference(pid, address, count, reference_base, arch, Some(symbol_resolver))
    }

    fn dereference_batch(
        &self,
        pid: u32,
        addresses: &[u64],
        count: usize,
        reference_base: Option<u64>,
    ) -> Result<Vec<Vec<crate::protocol::DereferenceEntry>>, PlatformError> {
        let arch = self.arch_for(pid);

        // One resolver for the whole batch. `dereference::dereference_batch`
        // enumerates the process's memory regions ONCE and reuses that snapshot
        // across every address — the per-address `dereference` would otherwise
        // re-walk the whole address space for each register, the dominant
        // per-step cost on large targets.
        let symbol_resolver = self.nonblocking_symbol_resolver(pid);
        dereference::dereference_batch(pid, addresses, count, reference_base, arch, Some(symbol_resolver))
    }

    fn get_teb_address(&self, pid: u32, tid: u32) -> Result<u64, PlatformError> {
        // Call the method we defined on WindowsPlatform
        WindowsPlatform::get_teb_address(self, pid, tid)
    }

    fn get_peb_address(&self, pid: u32) -> Result<u64, PlatformError> {
        WindowsPlatform::get_peb_address(self, pid)
    }

    fn is_wow64(&self, pid: u32) -> Result<bool, PlatformError> {
        WindowsPlatform::is_wow64_process(self, pid)
    }

    // ---------------------- Server-side fast paths ----------------------
    //
    // These bypass the platform lock for OS calls that don't need shared
    // state, so concurrent read-only requests aren't starved while a
    // Continue is parked in WaitForDebugEvent.

    fn server_continue(
        platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
        tid: u32,
        pass_exception: bool,
    ) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        let mut cont_pid = pid;
        let mut cont_tid = tid;
        let mut cont_pass = pass_exception;
        let mut cont_reply_later = false;
        loop {
            if cont_reply_later {
                crate::windows_platform::debug_events::continue_reply_later(cont_pid, cont_tid)?;
            } else {
                crate::windows_platform::debug_events::continue_debug_event(
                    cont_pid, cont_tid, cont_pass,
                )?;
            }

            let debug_event =
                crate::windows_platform::debug_events::wait_for_debug_event_blocking()?;

            let mut p = platform.write().unwrap();

            // Multi-threaded software-breakpoint safety: while one thread is
            // stepping over a temporarily-removed INT3, defer any OTHER thread's
            // exception via DBG_REPLY_LATER instead of processing it. Windows
            // re-queues the event and keeps that thread suspended until the
            // step-over completes and the breakpoint is re-armed. Combined with
            // suspending the other threads when the step-over begins, this closes
            // the race (a thread sailing through the disarmed address) and — by
            // ensuring only one step-over is ever in flight — avoids the
            // double-hit that concurrent step-overs would cause. Same approach as
            // x64dbg/TitanEngine's "safe step".
            if crate::windows_platform::debug_events::should_defer_event(&p, &debug_event) {
                drop(p);
                cont_pid = debug_event.dwProcessId;
                cont_tid = debug_event.dwThreadId;
                cont_reply_later = true;
                continue;
            }

            cont_reply_later = false;
            match crate::windows_platform::debug_events::handle_debug_event(&mut *p, &debug_event)?
            {
                Some(event) => return Ok(Some(event)),
                None => {
                    // Internal event (e.g., breakpoint rearm) — auto-continue.
                    cont_pid = debug_event.dwProcessId;
                    cont_tid = debug_event.dwThreadId;
                    cont_pass = false;
                }
            }
        }
    }

    fn server_terminate(
        _platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
    ) -> Result<(), PlatformError> {
        crate::windows_platform::process::terminate_process_unlocked(pid)
    }

    fn server_break_into(
        _platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
    ) -> Result<(), PlatformError> {
        crate::windows_platform::process::debug_break_process_unlocked(pid)
    }

    // ------------------ Optional features (forwarders) ------------------

    fn emulate_with_mode(
        &self,
        pid: u32,
        tid: u32,
        max_instructions: usize,
        mode: crate::protocol::EmulationMode,
        exit_condition: Option<crate::protocol::TraceExitCondition>,
        memory_reads: &[(u64, usize)],
    ) -> Result<crate::emulator::EmulationResult, PlatformError> {
        WindowsPlatform::emulate_with_mode(
            self,
            pid,
            tid,
            max_instructions,
            mode,
            exit_condition,
            memory_reads,
        )
    }

    fn trace_instructions(
        &mut self,
        pid: u32,
        tid: u32,
        exit_condition: crate::protocol::TraceExitCondition,
        max_instructions: usize,
    ) -> Result<(Vec<crate::protocol::TraceEntry>, String, u64), PlatformError> {
        WindowsPlatform::trace_instructions(self, pid, tid, exit_condition, max_instructions)
    }

    fn disassemble_function(
        &self,
        pid: u32,
        address: u64,
        max_instructions: usize,
        arch: Architecture,
    ) -> Result<(Vec<Instruction>, Option<u64>, Option<u64>, Option<String>), DisassemblerError> {
        WindowsPlatform::disassemble_function(self, pid, address, max_instructions, arch)
    }
}

impl Stepper for WindowsPlatform {
    fn step(&mut self, pid: u32, tid: u32, kind: StepKind) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        stepper::step(self, pid, tid, kind)
    }
}

/// Binary-search a module's `.pdata` runtime functions for the entry containing
/// `rva`. Returns `(BeginAddress, EndAddress)` RVAs.
fn runtime_function_bounds(info: &crate::pe_types::ModuleExtraInfo, rva: u32) -> Option<(u32, u32)> {
    let funcs = info.runtime_functions.as_ref().filter(|f| !f.is_empty())?;
    let idx = funcs
        .binary_search_by(|rf| {
            if rva < rf.BeginAddress {
                std::cmp::Ordering::Greater
            } else if rva >= rf.EndAddress {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()?;
    Some((funcs[idx].BeginAddress, funcs[idx].EndAddress))
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

        // Convert address to RVA
        let rva = (address - module.base) as u32;

        // Search the cached extra info by reference — this runs per backward-
        // disassembly boundary probe, and `get_extra_info`'s deep clone of the
        // whole ModuleExtraInfo just to binary-search `.pdata` is wasteful.
        // Fall back to a file parse only when nothing is cached yet.
        let bounds = match process
            .module_manager()
            .with_extra_info(module.base, |info| runtime_function_bounds(info, rva))
        {
            Some(b) => b,
            None => match self.parse_module_extra_info(pid, module.base) {
                Ok(info) => runtime_function_bounds(&info, rva),
                Err(_) => return Ok(None),
            },
        };
        let Some((begin_rva, end_rva)) = bounds else {
            return Ok(None);
        };
        let func_start = module.base + begin_rva as u64;
        let func_end = module.base + end_rva as u64;

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

        // `trim = Some` = decode the WHOLE function from its start and trim to
        // [start, end). That's ideal for normal functions, but a large or
        // MALFORMED bound (e.g. a corrupt `.pdata` reporting a multi-MB "function")
        // would decode millions of instructions — tens of MB read, seconds of CPU
        // on the paused command channel, and a payload the UI can't render (the
        // observed multi-second freeze). It can also start so far below the PC that
        // the requested address isn't even in the result. So: only take the
        // whole-function path when it fits `max_instructions` AND actually contains
        // the address; otherwise decode a bounded window anchored at the requested
        // address (a known instruction boundary, always included) and let the UI
        // scroll-extension pull in the rest.
        let (disasm_start, disasm_count, func_start, func_end, func_name, trim) = match bounds {
            Some((start, end, name)) => {
                let func_size = end.saturating_sub(start) as usize;
                let estimated_count = (func_size / 2).max(1);
                let contains = address >= start && address < end;
                if estimated_count <= max_instructions && contains {
                    (start, estimated_count, Some(start), Some(end), name, Some((start, end)))
                } else {
                    (address, max_instructions, Some(start), Some(end), name, None)
                }
            }
            None => (address, max_instructions, None, None, None, None),
        };

        // Disassemble the chosen window
        let instructions = self.disassemble_memory(pid, disasm_start, disasm_count, arch)?;

        let filtered_instructions = if let Some((start, end)) = trim {
            instructions
                .into_iter()
                .filter(|i| i.address >= start && i.address < end)
                .collect()
        } else {
            // Windowed decode from the requested address: cap the count, don't
            // trim by bounds (the head is the requested address by construction).
            instructions.into_iter().take(max_instructions).collect()
        };

        Ok((filtered_instructions, func_start, func_end, func_name))
    }

    /// Non-blocking symbol resolver over a snapshot of the process's module
    /// list: returns `None` immediately for a module whose symbols are still
    /// loading rather than waiting (up to seconds) for the PDB parse — callers
    /// stay instant even for large PDBs, and re-resolve once symbols land.
    fn nonblocking_symbol_resolver(&self, pid: u32) -> impl Fn(u64) -> Option<crate::interfaces::SymbolInfo> + '_ {
        let mut modules = self.modules_for(pid);
        // Sort by base address for binary search in symbol resolution
        modules.sort_by_key(|m| m.base);
        let symbol_manager = self.symbol_manager.as_ref();
        move |addr: u64| -> Option<crate::interfaces::SymbolInfo> {
            let sm = symbol_manager?;
            if let Ok(Some((module_path, symbol, offset))) = sm.try_resolve_address_to_symbol(&modules, addr) {
                let module_name = std::path::Path::new(&module_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&module_path)
                    .to_string();
                return Some(crate::interfaces::SymbolInfo { module_name, symbol_name: symbol.name, offset });
            }
            None
        }
    }

    /// Disassemble a SINGLE instruction from target memory WITHOUT symbolization.
    /// Used by the stepper, which needs only the instruction's size and mnemonic
    /// (call/branch classification). The symbolizing decode path does per-
    /// instruction symbol/pdata/line lookups and a module-list snapshot — all
    /// wasted work here, and all contending with the symbol loader's locks while
    /// a large PDB (millions of symbols) is being parsed, which showed up as
    /// step hitches during symbol loading. This raw path never touches symbols.
    /// Breakpoint bytes are still restored so the real opcode is decoded.
    pub(crate) fn disassemble_instruction_raw(&self, pid: u32, address: u64, arch: Architecture) -> Result<Option<Instruction>, DisassemblerError> {
        let Some(disasm) = self.disassembler.as_ref() else {
            return Err(DisassemblerError::CapstoneError("Disassembler not initialized".to_string()));
        };
        // 16 bytes covers the longest x86 instruction (15) with slack.
        let mut data = memory::read_memory_unlocked(pid, address, 16)
            .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;
        if let Ok(process) = self.get_process(pid) {
            process.patch_breakpoint_bytes(address, &mut data);
        }
        Ok(disasm.disassemble(arch, &data, address, 1)?.into_iter().next())
    }

    /// Shared body of `disassemble_memory` / `disassemble_memory_bytes`:
    /// reads `read_len` bytes and decodes up to `count` instructions.
    fn disassemble_memory_impl(&self, pid: u32, address: u64, read_len: usize, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
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
        let mut data = memory::read_memory_unlocked(pid, address, read_len)
            .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;

        // Patch breakpoint bytes with originals so disassembly shows real instructions
        if let Ok(process) = self.get_process(pid) {
            process.patch_breakpoint_bytes(address, &mut data);
        }
        let memory_time = t0.elapsed();

        // Time module list fetch
        let t1 = Instant::now();
        let mut modules = self.modules_for(pid);
        // Sort modules by base address for binary search
        modules.sort_by_key(|m| m.base);
        let module_time = t1.elapsed();
        // The symbol resolver closure consumes `modules`; keep a copy for line annotation.
        let modules_for_lines = modules.clone();

        let symbol_manager = self.symbol_manager.as_ref();

        // Track symbol resolution time
        let symbol_time_us = std::sync::Arc::new(AtomicU64::new(0));
        let symbol_call_count = std::sync::Arc::new(AtomicU64::new(0));
        let symbol_time_clone = symbol_time_us.clone();
        let symbol_count_clone = symbol_call_count.clone();

        let symbol_resolver = move |addr: u64| -> Option<crate::interfaces::SymbolInfo> {
            let t = Instant::now();
            let result = if let Some(symbol_manager) = symbol_manager {
                // Non-blocking: skip symbolization while PDBs are still loading rather
                // than stalling the disassembly response behind symbol downloads.
                // The UI re-requests disassembly once symbols finish loading.
                if let Ok(Some((module_path, symbol, offset))) = symbol_manager.try_resolve_address_to_symbol(&modules, addr) {
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

        // Resolve indirect jump/call targets (e.g., `call qword ptr [IAT_slot]`)
        // by reading the pointer value so clicking navigates to the actual
        // function. This is best-effort and speculative: for misdecoded data the
        // target is garbage/unmapped, so use the fast pointer read (no partial-
        // read fallback, no error log) — otherwise each such instruction spends a
        // wasted VirtualQueryEx and spams an ERROR line. One VM_READ handle is
        // shared by every read in the batch (IAT-heavy code has hundreds).
        let mut instructions = result?;
        let is_indirect = |i: &Instruction| (i.is_call || i.is_jump) && i.jump_target.is_some() && i.op_str.contains('[');
        let ptr_handle = instructions.iter().any(is_indirect)
            .then(|| memory::open_vm_read_handle(pid))
            .flatten();
        if let Some(ref handle) = ptr_handle {
            for instr in &mut instructions {
                if is_indirect(instr) {
                    let ptr_addr = instr.jump_target.unwrap();
                    if let Some(actual_target) = memory::try_read_pointer(handle.0, ptr_addr) {
                        instr.jump_target = Some(actual_target);
                    }
                }
            }
        }

        // Annotate with source lines from already-cached line tables only.
        // The first source-view request triggers the parse; until then this is a no-op,
        // so bulk disassembly never stalls behind a PDB line-table parse.
        if let Some(symbol_manager) = self.symbol_manager.as_ref() {
            for instr in &mut instructions {
                instr.line_info = symbol_manager.try_resolve_address_to_line_cached(&modules_for_lines, instr.address);
                // At a symbol start, collect every name sharing this address (aliases
                // like NtClose/ZwClose) so the UI can show all labels, not just the
                // one `symbol_info` picked. Gated on offset == 0 to avoid a lookup for
                // the vast majority of instructions that sit mid-symbol.
                if instr.symbol_info.as_ref().is_some_and(|s| s.offset == 0) {
                    let all = symbol_manager.resolve_all_at_exact_address(&modules_for_lines, instr.address);
                    // Keep the trait-default seed (the single resolved symbol) if
                    // the alias lookup unexpectedly comes back empty.
                    if !all.is_empty() {
                        instr.symbols_at_address = all;
                    }
                }
            }
        }
        Ok(instructions)
    }
}
