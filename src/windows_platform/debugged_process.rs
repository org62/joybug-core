//! One debugged process: its Win32 handles ([`WinProcess`]) plus the shared,
//! OS-neutral bookkeeping ([`DebugBook`]). Every method here is a thin
//! forwarder so the rest of the Windows backend reads as before; the logic
//! lives in `crate::debugger_core`.

use crate::debugger_core::{breakpoints, coverage, stepping, DebugBook};
// Re-exported: `debug_events.rs` and `mod.rs` name it through this module.
pub(crate) use crate::debugger_core::hw_breakpoints::InternalHardwareBreakpoint;
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::{HardwareBreakpointType, StepKind};
use tracing::{error, warn};
use windows_sys::Win32::Foundation::{FALSE, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{SymCleanup, SymInitialize};

pub(super) use super::win_ops::WinProcess;

/// Represents a single debugged process with its associated state.
#[derive(Debug)]
pub(crate) struct DebuggedProcess {
    pub(super) os: WinProcess,
    pub(super) book: DebugBook,
}

impl DebuggedProcess {
    pub(super) fn new(pid: u32, process_handle: HANDLE, architecture: Architecture) -> Result<Self, PlatformError> {
        {
            let _lock = super::dbghelp::DBGHELP_LOCK.lock().unwrap();
            if unsafe { SymInitialize(process_handle, std::ptr::null(), FALSE) } == FALSE {
                let error = unsafe { GetLastError() };
                error!(pid, "Failed to initialize symbol handler, error code: 0x{:x}", error);
                return Err(PlatformError::OsError(format!(
                    "SymInitialize failed for pid {}: {}",
                    pid,
                    super::utils::error_message(error)
                )));
            }
        }
        Ok(Self {
            os: WinProcess::new(pid, process_handle, architecture),
            book: DebugBook::new(architecture),
        })
    }

    fn pid(&self) -> u32 { self.os.pid() }
}

impl DebuggedProcess {
    pub(super) fn handle(&self) -> HANDLE { self.os.handle() }
    pub(super) fn architecture(&self) -> Architecture { self.os.architecture() }
    pub(super) fn insert_single_shot_breakpoint(&mut self, address: u64, original_bytes: Vec<u8>) {
        self.book.bps.insert_single_shot(address, original_bytes);
    }

    pub(super) fn insert_persistent_breakpoint(&mut self, address: u64, original_bytes: Vec<u8>, tid: Option<u32>) {
        self.book.bps.insert_persistent(address, original_bytes, tid);
    }
    /// Remove and return original bytes for a single-shot breakpoint at `address` if present.
    pub(super) fn remove_single_shot_breakpoint(&mut self, address: u64) -> Option<Vec<u8>> {
        self.book.bps.remove_single_shot(address)
    }

    /// Restore original instruction bytes at `address` using this process' handle.
    pub(super) fn restore_original_bytes(&self, address: u64, original_bytes: &[u8]) -> Result<(), PlatformError> {
        super::memory::write_memory_internal(self.os.handle(), address, original_bytes)
    }

    /// Check whether a persistent breakpoint exists at `address`.
    pub(super) fn is_persistent_breakpoint(&self, address: u64) -> bool {
        self.book.bps.is_persistent(address)
    }

    /// Determine if the persistent breakpoint at `address` is allowed for `tid` (filter passes).
    pub(super) fn persistent_allowed_for_tid(&self, address: u64, tid: u32) -> bool {
        self.book.bps.persistent_allowed_for_tid(address, tid)
    }

    /// Restore the original instruction bytes for the persistent breakpoint at
    /// `address`, if one exists.
    pub(super) fn restore_persistent_original(&self, address: u64) -> Result<(), PlatformError> {
        breakpoints::restore_persistent_original(&self.book.bps, &self.os, self.pid(), address)
    }

    /// Remove and return an active step-over breakpoint at `address`, if any.
    pub(super) fn remove_step_over_breakpoint(&mut self, address: u64) -> Option<(u32, StepKind)> {
        self.book.bps.remove_step_over(address)
    }

    /// Insert a step-over breakpoint mapping for `address`.
    pub(super) fn insert_step_over_breakpoint(&mut self, address: u64, tid: u32, kind: StepKind) {
        self.book.bps.insert_step_over(address, tid, kind);
    }

    /// Clear all step-over breakpoints. Returns how many were removed.
    pub(super) fn clear_step_over_breakpoints(&mut self) -> usize {
        self.book.bps.clear_step_over()
    }

    /// Retain only step-over breakpoints not owned by `tid`. Returns number removed.
    pub(super) fn retain_step_over_breakpoints_excluding_tid(&mut self, tid: u32) -> usize {
        self.book.bps.retain_step_over_excluding_tid(tid)
    }

    /// Query whether a step-out breakpoint exists at `address`.
    pub(super) fn has_step_out_breakpoint(&self, address: u64) -> bool {
        self.book.bps.has_step_out(address)
    }

    /// Remove and return a step-out breakpoint at `address`, if present.
    pub(super) fn remove_step_out_breakpoint(&mut self, address: u64) -> Option<(u32, u64)> {
        self.book.bps.remove_step_out(address)
    }

    /// Insert a step-out breakpoint mapping.
    pub(super) fn insert_step_out_breakpoint(&mut self, address: u64, tid: u32, original_return_address: u64) {
        self.book.bps.insert_step_out(address, tid, original_return_address);
    }

    /// Clear all step-out breakpoints. Returns how many were removed.
    pub(super) fn clear_step_out_breakpoints(&mut self) -> usize {
        self.book.bps.clear_step_out()
    }

    /// Retain only step-out breakpoints not owned by `tid`. Returns number removed.
    pub(super) fn retain_step_out_breakpoints_excluding_tid(&mut self, tid: u32) -> usize {
        self.book.bps.retain_step_out_excluding_tid(tid)
    }

    /// Schedule a single-step rearm for (tid -> address).
    pub(super) fn schedule_rearm_after_single_step(&mut self, tid: u32, address: u64, is_single_shot: bool) {
        self.book.steps.schedule_rearm_after_single_step(tid, address, is_single_shot);
    }

    /// Remove and return a pending rearm entry for a thread, if any.
    pub(super) fn take_pending_rearm_for_tid(&mut self, tid: u32) -> Option<(u64, bool)> {
        self.book.steps.take_pending_rearm_for_tid(tid)
    }

    /// See [`stepping::begin_step_over`].
    pub(super) fn begin_step_over(&mut self, pid: u32, tid: u32, address: u64, context: &'static str) {
        stepping::begin_step_over(&mut self.book, &self.os, pid, tid, address, context);
    }

    /// See [`stepping::StepBook::is_stepping_over_other_thread`].
    pub(super) fn is_stepping_over_other_thread(&self, tid: u32) -> bool {
        self.book.steps.is_stepping_over_other_thread(tid)
    }

    /// See [`stepping::complete_step_over`].
    pub(super) fn complete_step_over(&mut self, tid: u32) -> usize {
        stepping::complete_step_over(&mut self.book, &self.os, self.os.pid(), tid)
    }

    /// Resume every thread frozen for a step-over. Returns the number resumed.
    pub(super) fn resume_frozen_threads(&mut self) -> usize {
        stepping::resume_frozen_threads(&mut self.book.steps, &self.os, self.os.pid())
    }

    /// See [`stepping::forget_thread_step_over`].
    pub(super) fn forget_thread_step_over(&mut self, tid: u32) {
        stepping::forget_thread_step_over(&mut self.book.steps, &self.os, self.os.pid(), tid);
    }

    /// Resume every frozen thread and clear step-over state (safety net on
    /// process cleanup).
    pub(super) fn resume_all_step_over_suspensions(&mut self) {
        stepping::resume_all_step_over_suspensions(&mut self.book.steps, &self.os, self.os.pid());
    }

    /// Record that a thread is in an active single-step operation. Returns true if an existing
    /// record for this thread was replaced.
    pub(super) fn record_active_single_step(&mut self, tid: u32, kind: StepKind, deferred_hw_bp_rearm: Option<u8>) -> bool {
        self.book.steps.record_active_single_step(tid, kind, deferred_hw_bp_rearm)
    }

    /// Take and remove the active single-step state for a thread, if any.
    pub(super) fn take_active_single_step(&mut self, tid: u32) -> Option<super::StepState> {
        self.book.steps.take_active_single_step(tid)
    }

    /// Return the architecture-appropriate bytes for a breakpoint instruction.
    pub(super) fn breakpoint_instruction_bytes(&self) -> Vec<u8> {
        breakpoints::breakpoint_bytes(self.architecture())
    }

    /// If current memory matches the original instruction bytes for a persistent breakpoint at
    /// `address`, re-arm the breakpoint by writing the breakpoint instruction back.
    pub(super) fn rearm_persistent_breakpoint_if_matches_original(&self, address: u64) -> Result<(), PlatformError> {
        breakpoints::rearm_if_matches_original(&self.book.bps, &self.os, self.pid(), address)
    }

    /// Mark that the process has passed the initial breakpoint.
    pub(super) fn mark_initial_breakpoint_hit(&mut self) {
        self.book.has_hit_initial_breakpoint = true;
    }

    /// Query whether the initial breakpoint was already observed.
    pub(super) fn has_initial_breakpoint_been_hit(&self) -> bool {
        self.book.has_hit_initial_breakpoint
    }

    pub(super) fn set_created_by_launch(&mut self, launched: bool) {
        self.book.created_by_launch = launched;
    }

    pub(super) fn created_by_launch(&self) -> bool {
        self.book.created_by_launch
    }

    /// See [`breakpoints::remove_breakpoint`].
    pub(super) fn remove_breakpoint(&mut self, address: u64) -> Result<(), PlatformError> {
        breakpoints::remove_breakpoint(&mut self.book.bps, &self.os, self.os.pid(), address)
    }

    /// See [`breakpoints::is_stale_hit`].
    pub(super) fn is_stale_sw_breakpoint_hit(&self, address: u64) -> bool {
        breakpoints::is_stale_hit(&self.book.bps, &self.os, self.pid(), address)
    }

    // --- Code-coverage breakpoints -------------------------------------------

    /// Register a coverage breakpoint at `address`: store its original bytes as a
    /// persistent breakpoint (no tid filter) and start a counter with `limit`.
    pub(super) fn arm_coverage(&mut self, address: u64, original_bytes: Vec<u8>, limit: u64) {
        let DebugBook { bps, coverage, .. } = &mut self.book;
        coverage.arm(bps, address, original_bytes, limit);
    }

    /// See [`coverage::CoverageBook::record_hit`].
    pub(super) fn record_coverage_hit(&mut self, address: u64, tid: u32) -> Option<(u64, u64)> {
        self.book.coverage.record_hit(address, tid)
    }

    /// See [`coverage::deactivate_coverage`].
    pub(super) fn deactivate_coverage(&mut self, address: u64) {
        coverage::deactivate_coverage(&mut self.book, &self.os, self.os.pid(), address);
    }

    /// See [`coverage::CoverageBook::snapshot`].
    pub(super) fn coverage_snapshot(&self) -> Vec<crate::protocol::CoverageHit> {
        self.book.coverage.snapshot()
    }

    /// See [`coverage::clear_coverage`].
    pub(super) fn clear_coverage(&mut self) {
        coverage::clear_coverage(&mut self.book, &self.os, self.os.pid());
    }

    // --- Hardware access traces ----------------------------------------------

    /// Mark the watched `address` as an active access trace (idempotent).
    pub(super) fn arm_watchpoint_trace(&mut self, address: u64) {
        self.book.watch.arm_trace(address);
    }

    /// See [`crate::debugger_core::watchpoints::WatchBook::record_access`].
    pub(super) fn record_watchpoint_access(&mut self, watched_addr: u64, raw_rip: u64, tid: u32) -> bool {
        self.book.watch.record_access(watched_addr, raw_rip, tid)
    }

    /// See [`crate::debugger_core::watchpoints::WatchBook::snapshot`].
    pub(super) fn watchpoint_snapshot(&self, address: u64) -> Vec<crate::protocol::WatchpointAccess> {
        self.book.watch.snapshot(address)
    }

    /// Stop tracing `address`: drop the accumulated accessors. Removing the
    /// underlying hardware watchpoint is the caller's job.
    pub(super) fn clear_watchpoint_trace(&mut self, address: u64) {
        self.book.watch.clear(address);
    }

    /// Restore the original bytes for every software breakpoint (persistent and
    /// single-shot) and forget them. Used on detach so the target keeps running
    /// without executing leftover int3/brk instructions.
    pub(super) fn restore_all_software_breakpoints(&mut self) {
        breakpoints::restore_all(&mut self.book.bps, &self.os, self.os.pid());
        self.book.coverage.forget();
    }

    /// See [`breakpoints::BreakpointTable::patch_breakpoint_bytes`].
    pub(super) fn patch_breakpoint_bytes(&self, base_address: u64, data: &mut [u8]) {
        self.book.bps.patch_breakpoint_bytes(base_address, data);
    }

    pub(super) fn module_manager(&self) -> &crate::debugger_core::module_manager::ModuleManager { &self.book.modules }
    pub(super) fn module_manager_mut(&mut self) -> &mut crate::debugger_core::module_manager::ModuleManager { &mut self.book.modules }
    pub(super) fn thread_manager(&self) -> &super::thread_manager::ThreadManager { self.os.threads() }
    pub(super) fn thread_manager_mut(&mut self) -> &mut super::thread_manager::ThreadManager { self.os.threads_mut() }

    // Hardware breakpoint methods

    /// See [`crate::debugger_core::hw_breakpoints::HwBpTable::find_free_slot`].
    pub(super) fn find_free_debug_register(&self, bp_type: HardwareBreakpointType) -> Option<u8> {
        self.book.hw.find_free_slot(self.architecture(), bp_type)
    }

    /// Add a hardware breakpoint to the internal tracking.
    pub(super) fn add_hardware_breakpoint(&mut self, bp: InternalHardwareBreakpoint) {
        self.book.hw.add(bp);
    }

    /// Remove a hardware breakpoint by address. Returns the removed BP if found.
    pub(super) fn remove_hardware_breakpoint_by_addr(&mut self, addr: u64) -> Option<InternalHardwareBreakpoint> {
        self.book.hw.remove_by_addr(addr)
    }

    /// Find a hardware breakpoint by DR index.
    pub(super) fn find_hardware_breakpoint_by_dr_index(&self, dr_index: u8) -> Option<&InternalHardwareBreakpoint> {
        self.book.hw.find_by_dr_index(dr_index)
    }

    /// Check if a hardware breakpoint exists at the given address.
    pub(super) fn has_hardware_breakpoint_at(&self, addr: u64) -> bool {
        self.book.hw.has_at(addr)
    }

    /// Whether a software single-shot breakpoint is registered at `addr`.
    #[cfg(target_arch = "aarch64")]
    pub(super) fn has_single_shot_breakpoint(&self, addr: u64) -> bool {
        self.book.bps.has_single_shot(addr)
    }

    /// See [`crate::debugger_core::hw_breakpoints::HwBpTable::active_for_access`].
    #[cfg(target_arch = "aarch64")]
    pub(super) fn active_hw_bp_for_access(&self, addr: u64, is_watchpoint: bool) -> Option<InternalHardwareBreakpoint> {
        self.book.hw.active_for_access(addr, is_watchpoint)
    }

    /// Return all active hardware breakpoints.
    pub(super) fn active_hardware_breakpoints(&self) -> Vec<InternalHardwareBreakpoint> {
        self.book.hw.active()
    }

    /// Schedule a HW BP re-arm after a single-step for the given thread.
    pub(super) fn schedule_hw_bp_rearm(&mut self, tid: u32, dr_index: u8) {
        self.book.steps.schedule_hw_bp_rearm(tid, dr_index);
    }

    /// Take and remove a pending HW BP re-arm for a thread.
    pub(super) fn take_pending_hw_bp_rearm(&mut self, tid: u32) -> Option<u8> {
        self.book.steps.take_pending_hw_bp_rearm(tid)
    }
}

impl Drop for DebuggedProcess {
    fn drop(&mut self) {
        let _lock = super::dbghelp::DBGHELP_LOCK.lock().unwrap();
        if unsafe { SymCleanup(self.os.handle()) } == FALSE {
            let error = unsafe { GetLastError() };
            warn!("Failed to cleanup symbol handler for process, error code: {}", error);
        }
    }
}
