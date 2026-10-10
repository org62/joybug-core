//! One debugged process: its Win32 handles ([`WinProcess`]) plus the shared,
//! OS-neutral bookkeeping ([`DebugBook`]). The methods here are thin
//! forwarders so the rest of the Windows backend reads as before; the logic
//! lives in `crate::debugger_core`, and a one-off caller reaches `book`
//! directly.

use crate::debugger_core::{breakpoints, coverage, stepping, DebugBook};
// Re-exported: `debug_events.rs` and `mod.rs` name it through this module.
pub(crate) use crate::debugger_core::hw_breakpoints::InternalHardwareBreakpoint;
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::StepKind;
use tracing::{error, warn};
use windows_sys::Win32::Foundation::{FALSE, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{EXCEPTION_RECORD, SymCleanup, SymInitialize};

pub(super) use super::win_ops::WinProcess;

/// The exception a process is stopped on: what a dump written during that stop
/// records as its exception stream.
#[derive(Clone, Copy)]
pub(super) struct LastException {
    pub(super) tid: u32,
    pub(super) record: EXCEPTION_RECORD,
}

// SAFETY: the record's pointer fields (the faulting address, the link to a
// nested record) are addresses in the *target* process, kept as plain values
// and never dereferenced here.
unsafe impl Send for LastException {}
unsafe impl Sync for LastException {}

impl std::fmt::Debug for LastException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LastException")
            .field("tid", &self.tid)
            .field("code", &format_args!("0x{:X}", self.record.ExceptionCode as u32))
            .field("address", &format_args!("0x{:X}", self.record.ExceptionAddress as u64))
            .finish()
    }
}

/// Represents a single debugged process with its associated state.
#[derive(Debug)]
pub(crate) struct DebuggedProcess {
    pub(super) os: WinProcess,
    pub(super) book: DebugBook,
    /// Set when a stop is reported as `DebugEvent::Exception`, dropped when the
    /// client continues. Breakpoint and step stops are the debugger's own and
    /// never land here: a dump taken at a breakpoint is not a crash dump.
    pub(super) last_exception: Option<LastException>,
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
            last_exception: None,
        })
    }

}

impl DebuggedProcess {
    pub(super) fn handle(&self) -> HANDLE { self.os.handle() }
    pub(super) fn architecture(&self) -> Architecture { self.os.architecture() }

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

    /// Clear all step-out breakpoints. Returns how many were removed.
    pub(super) fn clear_step_out_breakpoints(&mut self) -> usize {
        self.book.bps.clear_step_out()
    }

    /// Retain only step-out breakpoints not owned by `tid`. Returns number removed.
    pub(super) fn retain_step_out_breakpoints_excluding_tid(&mut self, tid: u32) -> usize {
        self.book.bps.retain_step_out_excluding_tid(tid)
    }

    /// See [`stepping::StepBook::is_stepping_over_other_thread`].
    pub(super) fn is_stepping_over_other_thread(&self, tid: u32) -> bool {
        self.book.steps.is_stepping_over_other_thread(tid)
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

    /// Take and remove the active single-step state for a thread, if any.
    pub(super) fn take_active_single_step(&mut self, tid: u32) -> Option<super::StepState> {
        self.book.steps.take_active_single_step(tid)
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

    // --- Code-coverage breakpoints -------------------------------------------

    /// See [`coverage::CoverageBook::snapshot`].
    pub(super) fn coverage_snapshot(&self) -> Vec<crate::protocol::CoverageHit> {
        self.book.coverage.snapshot()
    }

    /// See [`coverage::clear_coverage`].
    pub(super) fn clear_coverage(&mut self) {
        coverage::clear_coverage(&mut self.book, &self.os, self.os.pid());
    }

    // --- Hardware access traces ----------------------------------------------

    /// See [`crate::debugger_core::watchpoints::WatchBook::snapshot`].
    pub(super) fn watchpoint_snapshot(&self, address: u64) -> Vec<crate::protocol::WatchpointAccess> {
        self.book.watch.snapshot(address)
    }

    /// Restore the original bytes for every software breakpoint (persistent and
    /// single-shot) and forget them. Used on detach so the target keeps running
    /// without executing leftover int3/brk instructions.
    pub(super) fn restore_all_software_breakpoints(&mut self) {
        breakpoints::restore_all(&mut self.book.bps, &self.os, self.os.pid());
        self.book.coverage.forget();
    }

    pub(super) fn module_manager(&self) -> &crate::debugger_core::module_manager::ModuleManager { &self.book.modules }
    pub(super) fn module_manager_mut(&mut self) -> &mut crate::debugger_core::module_manager::ModuleManager { &mut self.book.modules }
    pub(super) fn thread_manager(&self) -> &super::thread_manager::ThreadManager { self.os.threads() }
    pub(super) fn thread_manager_mut(&mut self) -> &mut super::thread_manager::ThreadManager { self.os.threads_mut() }

    // Hardware breakpoint methods

    /// Return all active hardware breakpoints.
    pub(super) fn active_hardware_breakpoints(&self) -> Vec<InternalHardwareBreakpoint> {
        self.book.hw.active()
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
