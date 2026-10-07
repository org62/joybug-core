//! The Windows debugger backend. The module is compiled on every OS: the
//! pure-Rust parts (Capstone disassembler, PDB/PE symbol parsing, module
//! header parsing, coverage-target naming) are shared with the offline
//! `static_pe` analysis and the UI, which exist on Linux too. Only the parts
//! that touch Win32 process/thread/memory APIs - and `WindowsPlatform` itself -
//! are `cfg(windows)`.

#[cfg(windows)]
mod utils;
#[cfg(windows)]
mod thread_manager;
#[cfg(windows)]
mod thread_control;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod debug_events;
#[cfg(windows)]
mod memory;
#[cfg(windows)]
mod thread_context;
// Live in `crate::symbols`; aliased so the `symbol_manager::` paths below and the
// re-exports `static_pe` and the UI import keep resolving.
#[cfg_attr(not(windows), allow(unused_imports))]
pub(crate) use crate::symbols::{symbol_manager, symbol_provider, type_provider};
/// Compiled in `debugger_core`; the path is kept for `static_pe` and the UI.
pub use crate::debugger_core::disassembler;
#[cfg(windows)]
mod callstack;
#[cfg(windows)]
mod stepper;
#[cfg(windows)]
mod debugged_process;
#[cfg(windows)]
mod win_ops;
pub(crate) use crate::symbols::module_extra;
pub use module_extra::parse_module_extra_info_from_bytes;
pub use symbol_provider::{WindowsSymbolProvider, parse_pdb_matching_pe, extract_pdb_identifier_from_file, PdbIdentifier};
#[cfg(windows)]
mod dbghelp;
#[cfg(windows)]
mod tracer;
#[cfg(windows)]
mod hardware_breakpoints;
#[cfg(windows)]
mod process_objects;

#[cfg(windows)]
use crate::interfaces::{PlatformAPI, PlatformError, ModuleSymbol, ResolvedSymbol, SymbolError, Architecture, DisassemblerError, Instruction, DisassemblerProvider, Stepper};
// no-op
#[cfg(windows)]
use crate::protocol::{MinidumpKind, ModuleInfo, ProcessInfo, ProcessObjects, ThreadInfo, StepKind};
#[cfg(windows)]
use crate::emulator::{Emulator, EmulationResult};
#[cfg(windows)]
use symbol_manager::SymbolManager;
pub use crate::interfaces::SymbolConfig;
#[cfg(windows)]
use disassembler::CapstoneDisassembler;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use tracing::{trace, info, error};
#[cfg(windows)]
use std::collections::HashMap;

// Safe wrapper for HANDLE that automatically closes it
#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct HandleSafe(pub HANDLE);
#[cfg(windows)]
unsafe impl Send for HandleSafe {}
#[cfg(windows)]
unsafe impl Sync for HandleSafe {}

#[cfg(windows)]
impl Drop for HandleSafe {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 as isize != -1 {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// Aligned wrapper for CONTEXT structure
#[cfg(windows)]
#[repr(align(16))]
struct AlignedContext {
    context: CONTEXT,
}

// Stepping state tracking
// Stepping state tracking lives in the shared core; re-exported for the
// `super::StepState` paths in this module.
#[cfg(windows)]
pub(crate) use crate::debugger_core::stepping::StepState;

#[cfg(windows)]
pub(crate) use debugged_process::DebuggedProcess;
// Shared with the offline `static_pe` analysis, which has no platform.
pub(crate) use crate::debugger_core::coverage_targets::name_for as symbol_name_at;
pub(crate) use crate::debugger_core::strings::decode_wide_until_nul;
pub(crate) use symbol_manager::{matches_tokens, query_tokens};

#[cfg(windows)]
pub struct WindowsPlatform {
    /// Map of PID to DebuggedProcess for managing multiple processes
    processes: HashMap<u32, DebuggedProcess>,
    /// Shared symbol manager for all processes
    symbol_manager: Option<SymbolManager>,
    /// Shared disassembler for all processes
    disassembler: Option<CapstoneDisassembler>,
}


#[cfg(windows)]
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
        let target = crate::emulator::LiveTarget::new(self, pid, tid)
            .map_err(|e| PlatformError::Other(e.to_string()))?;
        let mut emulator = Emulator::from_context(&target, &target.context)
            .map_err(|e| PlatformError::Other(e.to_string()))?;

        emulator.emulate_with_mode(&target, max_instructions, mode, exit_condition, memory_reads)
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

        use utils::NtQueryInformationThread;

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

        if status < 0 {
            return Err(PlatformError::Other(format!("NtQueryInformationThread failed: 0x{:08X}", status)));
        }
        let teb = info.teb_base_address as u64;
        // A WOW64 thread has two TEBs. The 32-bit one — what its code reaches
        // through `fs:` and what the 32-bit ntdll's `_TEB` describes — sits at
        // TEB64.WowTebOffset (normally +0x2000). Report that for x86 targets.
        if process.architecture() == Architecture::X86 {
            if let Some(teb32) = self.wow64_teb32(pid, teb) {
                return Ok(teb32);
            }
        }
        Ok(teb)
    }

    /// `TEB64.WowTebOffset` applied to `teb64`, when set.
    fn wow64_teb32(&self, pid: u32, teb64: u64) -> Option<u64> {
        const TEB64_WOW_TEB_OFFSET: u64 = 0x180C;
        let bytes = memory::read_memory_unlocked(pid, teb64 + TEB64_WOW_TEB_OFFSET, 4).ok()?;
        let offset = i32::from_le_bytes(bytes.first_chunk::<4>().copied()?);
        (offset != 0).then(|| teb64.wrapping_add(offset as i64 as u64))
    }

    /// The PEB the target's own code uses: the 32-bit PEB of a WOW64 process,
    /// otherwise the native one. See [`Self::get_native_peb_address`].
    pub fn get_peb_address(&self, pid: u32) -> Result<u64, PlatformError> {
        if self.get_process(pid)?.architecture() == Architecture::X86 {
            let peb32 = self.get_wow64_peb_address(pid)?;
            if peb32 != 0 {
                return Ok(peb32);
            }
        }
        self.get_native_peb_address(pid)
    }

    /// The native (64-bit) PEB of a process — a WOW64 process has this one too,
    /// read by the 64-bit ntdll on its behalf.
    pub fn get_native_peb_address(&self, pid: u32) -> Result<u64, PlatformError> {
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

    /// True if the target process is WOW64 (32-bit x86 on 64-bit Windows).
    pub fn is_wow64_process(&self, pid: u32) -> Result<bool, PlatformError> {
        Ok(self.get_process(pid)?.architecture() == Architecture::X86)
    }

    /// The 32-bit PEB of a WOW64 process (`ProcessWow64Information`); 0 for a
    /// native process.
    pub fn get_wow64_peb_address(&self, pid: u32) -> Result<u64, PlatformError> {
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
            Ok(wow64_peb as u64)
        } else {
            Err(PlatformError::Other(format!(
                "NtQueryInformationProcess(ProcessWow64Information) failed: 0x{:08X}",
                status
            )))
        }
    }
}

#[cfg(windows)]
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
        crate::debugger_core::breakpoints::arm_single_shot(&mut process.book.bps, &process.os, pid, addr)
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
        crate::debugger_core::breakpoints::arm_persistent(&mut process.book.bps, &process.os, pid, addr, tid)
    }

    fn remove_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        trace!(pid, addr, "WindowsPlatform::remove_breakpoint called");
        let process = self.get_process_mut(pid)?;
        process.remove_breakpoint(addr)
    }

    fn enumerate_coverage_targets(&self, pid: u32, module_path: &str, sources: &[crate::protocol::CoverageTargetSource]) -> Result<Vec<crate::protocol::CoverageTarget>, PlatformError> {
        let arch = self.get_process(pid)?.architecture();
        let symbol_manager = self.symbol_manager.as_ref().ok_or_else(|| PlatformError::Other("Symbol manager unavailable".to_string()))?;
        let disassembler = self.disassembler.as_ref().ok_or_else(|| PlatformError::Other("Disassembler unavailable".to_string()))?;
        crate::debugger_core::coverage_targets::enumerate_coverage_targets(self, symbol_manager, disassembler, arch, pid, module_path, sources)
    }

    fn start_code_coverage(&mut self, pid: u32, addrs: &[u64], limit: u64) -> Result<(), PlatformError> {
        let process = self.get_process_mut(pid)?;
        crate::debugger_core::coverage::start_code_coverage(&mut process.book, &process.os, pid, addrs, limit)
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
        let process = self.get_process_mut(pid)?;
        crate::debugger_core::watchpoints::start_trace(&mut process.book, &process.os, pid, addr, bp_type, size)
    }

    fn get_watchpoint_accesses(&self, pid: u32, addr: u64) -> Result<Vec<crate::protocol::WatchpointAccess>, PlatformError> {
        let mut accesses = self.get_process(pid)?.watchpoint_snapshot(addr);
        for a in &mut accesses {
            a.accessor = crate::debugger_core::watchpoints::attribute_accessor(self, pid, a.accessor_raw_rip);
        }
        Ok(accesses)
    }

    fn stop_watchpoint_trace(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        let process = self.get_process_mut(pid)?;
        crate::debugger_core::watchpoints::stop_trace(&mut process.book, &process.os, pid, addr)
    }

    fn set_hardware_breakpoint(
        &mut self,
        pid: u32,
        addr: u64,
        bp_type: crate::protocol::HardwareBreakpointType,
        size: crate::protocol::HardwareBreakpointSize,
    ) -> Result<u8, PlatformError> {
        let process = self.get_process_mut(pid)?;
        crate::debugger_core::hw_breakpoints::set_hardware_breakpoint(&mut process.book, &process.os, pid, addr, bp_type, size)
    }

    fn remove_hardware_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        let process = self.get_process_mut(pid)?;
        crate::debugger_core::hw_breakpoints::remove_hardware_breakpoint(&mut process.book, &process.os, pid, addr)
    }

    fn launch(&mut self, command: &str, debug_children: bool, working_directory: Option<&str>, environment: Option<&[(String, String)]>) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::launch(self, command, debug_children, working_directory, environment)
    }

    fn read_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError> {
        memory::read_memory_unlocked(pid, address, size)
    }

    fn write_memory(&self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        memory::write_memory(self, pid, address, data)
    }

    fn allocate_memory(&self, pid: u32, size: usize, executable: bool) -> Result<u64, PlatformError> {
        memory::allocate_memory(self, pid, size, executable)
    }

    fn read_wide_string(&self, pid: u32, address: u64, max_len: Option<usize>) -> Result<String, PlatformError> {
        crate::debugger_core::strings::read_wide_string(|a, n| self.read_memory(pid, a, n), address, max_len)
    }

    fn get_thread_context(&self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError> {
        // Only read access to process state is needed here
        thread_context::get_thread_context(self.get_process(pid)?, pid, tid)
    }

    fn set_thread_context(&self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError> {
        thread_context::set_thread_context(self.get_process(pid)?, pid, tid, context)
    }

    fn get_function_arguments(&self, pid: u32, tid: u32, count: usize) -> Result<Vec<u64>, PlatformError> {
        use crate::debugger_core::function_args::{function_arguments, CallingConvention};
        let process = self.get_process(pid)?;
        let cc = match process.architecture() {
            Architecture::X64 => CallingConvention::Win64,
            Architecture::X86 => CallingConvention::Cdecl32,
            Architecture::Arm64 => CallingConvention::Aapcs64,
        };
        let context = self.get_thread_context(pid, tid)?;
        function_arguments(cc, &context, count, |a, n| self.read_memory(pid, a, n))
    }

    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
        let (mut threads, count_of): (Vec<ThreadInfo>, fn(u32) -> Option<u32>) = match self.get_process(pid) {
            Ok(process) => (process.thread_manager().list_threads(), thread_control::debugged_suspend_count),
            Err(_) => (utils::list_threads_toolhelp(pid)?, thread_control::queried_suspend_count),
        };
        for t in &mut threads {
            t.suspend_count = count_of(t.tid).unwrap_or(0);
        }
        Ok(threads)
    }

    fn suspend_thread(&self, _pid: u32, tid: u32) -> Result<u32, PlatformError> {
        thread_control::suspend_thread_unlocked(tid)
    }

    fn resume_thread(&self, _pid: u32, tid: u32) -> Result<u32, PlatformError> {
        thread_control::resume_thread_unlocked(tid)
    }

    fn terminate_thread(&self, _pid: u32, tid: u32, exit_code: u32) -> Result<(), PlatformError> {
        thread_control::terminate_thread_unlocked(tid, exit_code)
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

    fn symbols_in_range(&self, pid: u32, start: u64, len: u64, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let mut modules = self.modules_for(pid);
        modules.sort_by_key(|m| m.base);
        Ok(symbol_manager.symbols_in_range(&modules, start, start.saturating_add(len), max_results))
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
        let modules = self.modules_for(pid);
        let bounds = |probe: u64| self.find_function_bounds(pid, probe).ok().flatten();
        crate::debugger_core::disasm::disassemble_backward_anchored(
            self, pid, target, count, arch, self.symbol_manager.as_ref(), &modules, &bounds,
        )
    }

    fn get_call_stack(&self, pid: u32, tid: u32) -> Result<Vec<crate::interfaces::CallFrame>, PlatformError> {
        callstack::get_call_stack(self, pid, tid)
    }

    fn list_process_objects(&self, pid: u32) -> Result<ProcessObjects, PlatformError> {
        Ok(process_objects::list_process_objects(self.process_handle(pid)?, pid))
    }

    fn close_remote_handle(&self, pid: u32, handle: u64) -> Result<(), PlatformError> {
        info!(pid, handle = format!("{:#x}", handle), "Closing remote handle");
        process_objects::close_remote_handle(self.process_handle(pid)?, handle)
    }

    fn set_privilege(&self, pid: u32, name: &str, enable: bool) -> Result<(), PlatformError> {
        info!(pid, name, enable, "Adjusting privilege");
        process_objects::set_privilege(self.process_handle(pid)?, name, enable)
    }

    fn set_window_enabled(&self, pid: u32, hwnd: u64, enabled: bool) -> Result<(), PlatformError> {
        process_objects::set_window_enabled(pid, hwnd, enabled)
    }

    fn write_minidump(&self, pid: u32, path: &str, kind: MinidumpKind) -> Result<u64, PlatformError> {
        info!(pid, path, ?kind, "Writing minidump");
        dbghelp::write_minidump(self.process_handle(pid)?, pid, path, kind)
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
        probe_start: bool,
    ) -> Result<Vec<crate::protocol::DereferenceEntry>, PlatformError> {
        let arch = self.arch_for(pid);
        let symbol_resolver = self.nonblocking_symbol_resolver(pid);
        crate::debugger_core::dereference::dereference(&(self, pid), address, count, reference_base, probe_start, arch, Some(symbol_resolver))
    }

    fn dereference_batch(
        &self,
        pid: u32,
        addresses: &[u64],
        count: usize,
        reference_base: Option<u64>,
        probe_start: bool,
    ) -> Result<Vec<Vec<crate::protocol::DereferenceEntry>>, PlatformError> {
        let arch = self.arch_for(pid);

        // One resolver for the whole batch. `dereference::dereference_batch`
        // enumerates the process's memory regions ONCE and reuses that snapshot
        // across every address — the per-address `dereference` would otherwise
        // re-walk the whole address space for each register, the dominant
        // per-step cost on large targets.
        let symbol_resolver = self.nonblocking_symbol_resolver(pid);
        crate::debugger_core::dereference::dereference_batch(&(self, pid), addresses, count, reference_base, probe_start, arch, Some(symbol_resolver))
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

    fn get_native_peb_address(&self, pid: u32) -> Result<u64, PlatformError> {
        WindowsPlatform::get_native_peb_address(self, pid)
    }

    fn process_architecture(&self, pid: u32) -> Result<Architecture, PlatformError> {
        Ok(self.arch_for(pid))
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

    /// `EXIT_PROCESS_DEBUG_EVENT` is the last event a process ever reports, and
    /// Windows keeps the process object (address space included) alive until the
    /// debugger acknowledges it — which is precisely what lets a client pause and
    /// inspect the corpse. Nothing acknowledges it implicitly, so without this the
    /// target lingers as a zombie for as long as the server holds its handles.
    ///
    /// Deliberately not routed through `server_continue`: that one blocks in
    /// `WaitForDebugEvent` for the next event, and for a dead process there is no
    /// next event — the connection's thread would park forever.
    ///
    /// `ContinueDebugEvent` is thread-affine, so this must run on the same
    /// connection thread that launched/attached the target and has been pumping
    /// its events. It does.
    fn server_finalize_exited_process(
        platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
        tid: u32,
    ) -> Result<(), PlatformError> {
        let cont = crate::windows_platform::debug_events::continue_debug_event(pid, tid, false);

        // Drop our handles either way: on a failed continue the process is still
        // gone, and holding them would only keep the zombie around longer.
        platform.write().unwrap().remove_process(pid);
        cont
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

#[cfg(windows)]
impl Stepper for WindowsPlatform {
    fn step(&mut self, pid: u32, tid: u32, kind: StepKind) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        // Step-out needs the caller frame; the stack walk borrows the whole
        // platform, so it runs before the process book is taken mutably.
        let call_stack = if kind == StepKind::Out {
            Some(callstack::get_call_stack(self, pid, tid)
                .map_err(|e| PlatformError::Other(format!("Failed to get call stack for step-out: {}", e)))?)
        } else {
            None
        };
        let disasm = self
            .disassembler
            .as_ref()
            .ok_or_else(|| PlatformError::Other("Disassembler not initialized".to_string()))?;
        let process = self
            .processes
            .get_mut(&pid)
            .ok_or_else(|| PlatformError::Other(format!("Process {} not found", pid)))?;
        crate::debugger_core::stepping::step(&mut process.book, &process.os, disasm, pid, tid, kind, call_stack)
    }
}
#[cfg(windows)]
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
            .with_extra_info(module.base, |info| info.runtime_function_bounds(rva))
        {
            Some(b) => b,
            None => match self.parse_module_extra_info(pid, module.base) {
                Ok(info) => info.runtime_function_bounds(rva),
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
                    let module_name = crate::formatting::module_stem(&module_path);
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
        let bounds = self.find_function_bounds(pid, address).ok().flatten();
        crate::debugger_core::disasm::disassemble_function(self, pid, address, max_instructions, arch, bounds)
    }

    /// Non-blocking symbol resolver over a snapshot of the process's module
    /// list (see `debugger_core::disasm::nonblocking_symbol_resolver`).
    fn nonblocking_symbol_resolver(&self, pid: u32) -> impl Fn(u64) -> Option<crate::interfaces::SymbolInfo> + '_ {
        crate::debugger_core::disasm::nonblocking_symbol_resolver(self.symbol_manager.as_ref(), self.modules_for(pid))
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
        let Some(disasm) = self.disassembler.as_ref() else {
            return Err(DisassemblerError::CapstoneError("Disassembler not initialized".to_string()));
        };
        let process = self.get_process(pid).ok();
        let listing = crate::debugger_core::disasm::Listing {
            reader: &(self, pid),
            bps: process.map(|p| &p.book.bps),
            disasm,
            symbol_manager: self.symbol_manager.as_ref(),
            modules: self.modules_for(pid),
        };
        // One VM_READ handle shared by every speculative pointer read in the
        // batch; `try_read_pointer` has no partial-read fallback and no error log.
        crate::debugger_core::disasm::decode_listing(listing, address, read_len, count, arch, || {
            memory::open_vm_read_handle(pid).map(|handle| {
                Box::new(move |addr: u64| memory::try_read_pointer(handle.0, addr)) as Box<dyn Fn(u64) -> Option<u64>>
            })
        })
    }
}
