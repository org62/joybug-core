use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::{HardwareBreakpointType, HardwareBreakpointSize};
use tracing::{error, trace, warn};
use windows_sys::Win32::Foundation::{FALSE, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{SymCleanup, SymInitialize};
use windows_sys::Win32::System::Threading::{ResumeThread, SuspendThread};

#[derive(Debug, Clone)]
pub(crate) struct InternalHardwareBreakpoint {
    pub address: u64,
    pub bp_type: HardwareBreakpointType,
    pub size: HardwareBreakpointSize,
    pub dr_index: u8,
    pub is_active: bool,
}

/// A single code-coverage breakpoint's counter. The INT3 byte itself lives in
/// `persistent_breakpoints` so it reuses the existing restore/re-arm/step-over
/// machinery; this entry only tracks how many times the address has been hit and
/// the auto-remove limit. `limit == 0` means never auto-remove; `1` removes on the
/// first hit (pure coverage). `active` goes false once the INT3 has been removed
/// (limit reached), while the final `hit_count` is kept for reporting.
#[derive(Debug, Clone)]
pub(crate) struct CoverageEntry {
    pub hit_count: u64,
    pub limit: u64,
    pub active: bool,
    /// 1-based first-execution order across the coverage run (0 = never hit).
    /// Assigned once when `hit_count` transitions 0 -> 1.
    pub first_hit_seq: u64,
    /// Distinct thread ids that hit this address, in first-hit order.
    pub thread_ids: Vec<u32>,
}

/// One distinct accessor of a watched address, keyed by raw trap instruction
/// pointer, and how often it hit. On x86 the trap fires *after* the accessing
/// instruction, so the raw RIP points at the following instruction (the platform
/// back-steps to attribute it when snapshotting); on ARM64 it is the exact
/// faulting PC.
#[derive(Debug, Clone)]
pub(crate) struct WatchpointAccessEntry {
    pub hit_count: u64,
    pub first_seq: u64,
    pub thread_ids: Vec<u32>,
}

/// One active hardware access trace. Presence of an entry for a watched address
/// means the hardware watchpoint there is in silent "collect accessors" mode: on a
/// hit the server records the accessor and auto-continues instead of forwarding a
/// `HardwareBreakpoint` event. The watchpoint's DR/register state itself lives in
/// `hardware_breakpoints`; this only accumulates who touched it.
#[derive(Debug, Clone, Default)]
pub(crate) struct WatchpointTraceEntry {
    pub accessors: std::collections::HashMap<u64 /*raw rip*/, WatchpointAccessEntry>,
}

/// Represents a single debugged process with its associated state
#[derive(Debug)]
pub(crate) struct DebuggedProcess {
    process_handle: super::HandleSafe,
    architecture: Architecture,
    module_manager: super::module_manager::ModuleManager,
    thread_manager: super::thread_manager::ThreadManager,
    single_shot_breakpoints: std::collections::HashMap<u64, Vec<u8>>,
    persistent_breakpoints: std::collections::HashMap<u64, Vec<u8>>,
    persistent_bp_tid_filters: std::collections::HashMap<u64, Option<u32>>,
    /// Track whether this process has hit its initial breakpoint
    has_hit_initial_breakpoint: bool,
    /// Track active stepping operations by (tid)
    active_single_steps: std::collections::HashMap<u32, super::StepState>,
    /// Track step-over breakpoints by address
    step_over_breakpoints: std::collections::HashMap<u64, (u32, crate::protocol::StepKind)>,
    /// Track step-out breakpoints by fake address
    step_out_breakpoints: std::collections::HashMap<u64, (u32, u64)>, // (tid, original_return_address)
    /// Track threads that need re-arming after a single-step: tid -> (address, is_single_shot)
    pending_rearm_breakpoints: std::collections::HashMap<u32, (u64, bool)>,
    /// Threads currently stepping over a temporarily-removed software breakpoint
    /// (INT3 removed, awaiting the single-step that re-arms it), mapped to the
    /// breakpoint address they are stepping over. Such a thread must be allowed to
    /// run and must never be frozen by another thread's step-over.
    stepping_over_threads: std::collections::HashMap<u32, u64>,
    /// Threads we have `SuspendThread`'d (exactly once each) to keep them out of
    /// a software breakpoint while its INT3 is removed. Resumed once no step-over
    /// remains in flight.
    frozen_threads: std::collections::HashSet<u32>,
    /// Hardware breakpoints (DR0-DR3, max 4)
    hardware_breakpoints: Vec<InternalHardwareBreakpoint>,
    /// Pending HW BP re-arm after single-step: tid -> dr_index
    pending_hw_bp_rearm: std::collections::HashMap<u32, u8>,
    /// Code-coverage breakpoints by address. The INT3 bytes are stored in
    /// `persistent_breakpoints`; this map holds the hit counter + auto-remove limit.
    coverage_breakpoints: std::collections::HashMap<u64, CoverageEntry>,
    /// Monotonic first-hit counter backing `CoverageEntry::first_hit_seq`.
    /// Reset (with the map) by `forget_coverage_state`, not by re-arming mid-run.
    coverage_seq: u64,
    /// Active hardware access traces by watched address. An entry marks the
    /// hardware watchpoint at that address as silent "collect accessors" mode.
    watchpoint_traces: std::collections::HashMap<u64, WatchpointTraceEntry>,
    /// Monotonic first-access counter backing `WatchpointAccessEntry::first_seq`.
    watchpoint_seq: u64,
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
            process_handle: super::HandleSafe(process_handle),
            architecture,
            module_manager: super::module_manager::ModuleManager::new(),
            thread_manager: super::thread_manager::ThreadManager::new(),
            single_shot_breakpoints: std::collections::HashMap::new(),
            persistent_breakpoints: std::collections::HashMap::new(),
            persistent_bp_tid_filters: std::collections::HashMap::new(),
            has_hit_initial_breakpoint: false,
            active_single_steps: std::collections::HashMap::new(),
            step_over_breakpoints: std::collections::HashMap::new(),
            step_out_breakpoints: std::collections::HashMap::new(),
            pending_rearm_breakpoints: std::collections::HashMap::new(),
            stepping_over_threads: std::collections::HashMap::new(),
            frozen_threads: std::collections::HashSet::new(),
            hardware_breakpoints: Vec::new(),
            pending_hw_bp_rearm: std::collections::HashMap::new(),
            coverage_breakpoints: std::collections::HashMap::new(),
            coverage_seq: 0,
            watchpoint_traces: std::collections::HashMap::new(),
            watchpoint_seq: 0,
        })
    }
}

impl DebuggedProcess {
    pub(super) fn handle(&self) -> HANDLE { self.process_handle.0 }
    pub(super) fn architecture(&self) -> Architecture { self.architecture }
    pub(super) fn insert_single_shot_breakpoint(&mut self, address: u64, original_bytes: Vec<u8>) {
        self.single_shot_breakpoints.insert(address, original_bytes);
    }

    pub(super) fn insert_persistent_breakpoint(&mut self, address: u64, original_bytes: Vec<u8>, tid: Option<u32>) {
        self.persistent_breakpoints.insert(address, original_bytes);
        self.persistent_bp_tid_filters.insert(address, tid);
    }
    /// Remove and return original bytes for a single-shot breakpoint at `address` if present.
    pub(super) fn remove_single_shot_breakpoint(&mut self, address: u64) -> Option<Vec<u8>> {
        self.single_shot_breakpoints.remove(&address)
    }

    /// Restore original instruction bytes at `address` using this process' handle.
    pub(super) fn restore_original_bytes(&self, address: u64, original_bytes: &[u8]) -> Result<(), PlatformError> {
        super::memory::write_memory_internal(self.process_handle.0, address, original_bytes)
    }

    /// Check whether a persistent breakpoint exists at `address`.
    pub(super) fn is_persistent_breakpoint(&self, address: u64) -> bool {
        self.persistent_breakpoints.contains_key(&address)
    }

    /// Determine if the persistent breakpoint at `address` is allowed for `tid` (filter passes).
    pub(super) fn persistent_allowed_for_tid(&self, address: u64, tid: u32) -> bool {
        if let Some(filter_opt) = self.persistent_bp_tid_filters.get(&address) {
            if let Some(filter_tid) = *filter_opt {
                return filter_tid == tid;
            }
        }
        true
    }

    /// Restore the original instruction bytes for the persistent breakpoint at
    /// `address`, if one exists. Borrows the stored bytes directly (no clone) —
    /// this runs on the silent coverage auto-continue hot path.
    pub(super) fn restore_persistent_original(&self, address: u64) -> Result<(), PlatformError> {
        if let Some(original) = self.persistent_breakpoints.get(&address) {
            self.restore_original_bytes(address, original)?;
        }
        Ok(())
    }

    /// Remove and return an active step-over breakpoint at `address`, if any.
    pub(super) fn remove_step_over_breakpoint(&mut self, address: u64) -> Option<(u32, crate::protocol::StepKind)> {
        self.step_over_breakpoints.remove(&address)
    }

    /// Insert a step-over breakpoint mapping for `address`.
    pub(super) fn insert_step_over_breakpoint(&mut self, address: u64, tid: u32, kind: crate::protocol::StepKind) {
        self.step_over_breakpoints.insert(address, (tid, kind));
    }

    /// Clear all step-over breakpoints. Returns how many were removed.
    pub(super) fn clear_step_over_breakpoints(&mut self) -> usize {
        let before = self.step_over_breakpoints.len();
        self.step_over_breakpoints.clear();
        before
    }

    /// Retain only step-over breakpoints not owned by `tid`. Returns number removed.
    pub(super) fn retain_step_over_breakpoints_excluding_tid(&mut self, tid: u32) -> usize {
        let before = self.step_over_breakpoints.len();
        self.step_over_breakpoints.retain(|_, (t, _)| *t != tid);
        before - self.step_over_breakpoints.len()
    }

    /// Query whether a step-out breakpoint exists at `address`.
    pub(super) fn has_step_out_breakpoint(&self, address: u64) -> bool {
        self.step_out_breakpoints.contains_key(&address)
    }

    /// Remove and return a step-out breakpoint at `address`, if present.
    pub(super) fn remove_step_out_breakpoint(&mut self, address: u64) -> Option<(u32, u64)> {
        self.step_out_breakpoints.remove(&address)
    }

    /// Insert a step-out breakpoint mapping.
    pub(super) fn insert_step_out_breakpoint(&mut self, address: u64, tid: u32, original_return_address: u64) {
        self.step_out_breakpoints.insert(address, (tid, original_return_address));
    }

    /// Clear all step-out breakpoints. Returns how many were removed.
    pub(super) fn clear_step_out_breakpoints(&mut self) -> usize {
        let before = self.step_out_breakpoints.len();
        self.step_out_breakpoints.clear();
        before
    }

    /// Retain only step-out breakpoints not owned by `tid`. Returns number removed.
    pub(super) fn retain_step_out_breakpoints_excluding_tid(&mut self, tid: u32) -> usize {
        let before = self.step_out_breakpoints.len();
        self.step_out_breakpoints.retain(|_, (t, _)| *t != tid);
        before - self.step_out_breakpoints.len()
    }

    /// Schedule a single-step rearm for (tid -> address).
    pub(super) fn schedule_rearm_after_single_step(&mut self, tid: u32, address: u64, is_single_shot: bool) {
        self.pending_rearm_breakpoints.insert(tid, (address, is_single_shot));
    }

    /// Remove and return a pending rearm entry for a thread, if any.
    pub(super) fn take_pending_rearm_for_tid(&mut self, tid: u32) -> Option<(u64, bool)> {
        self.pending_rearm_breakpoints.remove(&tid)
    }

    /// Begin a software-breakpoint step-over for `tid` at `address`: freeze every
    /// other thread so none can execute through `address` while its INT3 is
    /// temporarily removed (the multi-threaded software-breakpoint race).
    ///
    /// `ContinueDebugEvent` resumes the *entire* process, not just the stepping
    /// thread, so without this freeze another thread could run straight through
    /// the now-INT3-less address and its hit would be silently lost.
    ///
    /// Only one step-over is ever in flight at a time: the debug loop defers any
    /// other thread's exception with `DBG_REPLY_LATER` (see `server_continue`)
    /// until the step-over completes, so a second thread that also hit the same
    /// breakpoint is not processed concurrently. The stepping thread itself is
    /// never frozen (it must run to deliver its single-step); a defensive thaw is
    /// kept in case an earlier step-over had frozen it.
    ///
    /// Returns the number of threads newly frozen.
    pub(super) fn begin_step_over(&mut self, tid: u32, address: u64) -> usize {
        self.stepping_over_threads.insert(tid, address);

        // The stepping thread must run; thaw it if an earlier step-over froze it.
        if self.frozen_threads.remove(&tid) {
            if let Some(handle) = self.thread_manager.get_thread_handle(tid) {
                unsafe { ResumeThread(handle); }
            }
        }

        let mut newly_frozen = 0;
        for (other, handle) in self.thread_manager.iter_handles() {
            if other == tid
                || self.stepping_over_threads.contains_key(&other)
                || self.frozen_threads.contains(&other)
            {
                continue;
            }
            // SuspendThread returns the previous suspend count, or (DWORD)-1 on failure.
            let prev = unsafe { SuspendThread(handle) };
            if prev == u32::MAX {
                // Typically a thread that has already exited (the thread manager
                // keeps handles across exit); such a thread cannot run through the
                // breakpoint anyway, so this is not a correctness concern.
                let err = unsafe { GetLastError() };
                trace!(tid = other, err, "SuspendThread skipped during breakpoint step-over (thread may have exited)");
            } else {
                self.frozen_threads.insert(other);
                newly_frozen += 1;
            }
        }
        newly_frozen
    }

    /// Whether some *other* thread is currently mid software-breakpoint step-over
    /// (INT3 removed) — i.e. an event for `tid` should be deferred via
    /// `DBG_REPLY_LATER` rather than processed now. False for the stepping thread's
    /// own single-step event.
    pub(super) fn is_stepping_over_other_thread(&self, tid: u32) -> bool {
        self.stepping_over_threads.keys().any(|&stepper| stepper != tid)
    }

    /// Complete the step-over for `tid` (its single-step has delivered): re-arm
    /// the INT3 it was stepping over and, once no step-over remains in flight,
    /// resume the threads frozen by [`begin_step_over`]. The order is the safety
    /// contract — frozen threads may only run again after the INT3 is back in
    /// place.
    ///
    /// `DBG_REPLY_LATER` guarantees at most one thread is ever mid-step-over at a
    /// time (another thread's breakpoint event is deferred, not processed
    /// concurrently), so no per-address deferral is needed here.
    ///
    /// No-op returning 0 if `tid` was not mid-step-over. Returns the number of
    /// threads resumed.
    pub(super) fn complete_step_over(&mut self, tid: u32) -> usize {
        let Some(addr) = self.stepping_over_threads.remove(&tid) else {
            return 0;
        };
        let _ = self.rearm_persistent_breakpoint_if_matches_original(addr);
        if self.stepping_over_threads.is_empty() {
            self.resume_frozen_threads()
        } else {
            0
        }
    }

    /// Resume every thread frozen for a step-over. Returns the number resumed.
    pub(super) fn resume_frozen_threads(&mut self) -> usize {
        let mut resumed = 0;
        for other in std::mem::take(&mut self.frozen_threads) {
            if let Some(handle) = self.thread_manager.get_thread_handle(other) {
                let prev = unsafe { ResumeThread(handle) };
                if prev == u32::MAX {
                    let err = unsafe { GetLastError() };
                    trace!(tid = other, err, "ResumeThread skipped after breakpoint step-over (thread may have exited)");
                } else {
                    resumed += 1;
                }
            }
        }
        resumed
    }

    /// Drop `tid` from all step-over bookkeeping (used when a thread exits). If it
    /// was the last stepper in flight, remaining frozen threads are resumed.
    pub(super) fn forget_thread_step_over(&mut self, tid: u32) {
        self.frozen_threads.remove(&tid);
        self.stepping_over_threads.remove(&tid);
        if self.stepping_over_threads.is_empty() {
            self.resume_frozen_threads();
        }
    }

    /// Resume every frozen thread and clear step-over state (safety net on
    /// process cleanup).
    pub(super) fn resume_all_step_over_suspensions(&mut self) {
        self.stepping_over_threads.clear();
        self.resume_frozen_threads();
    }

    /// Record that a thread is in an active single-step operation. Returns true if an existing
    /// record for this thread was replaced.
    pub(super) fn record_active_single_step(&mut self, tid: u32, kind: crate::protocol::StepKind, deferred_hw_bp_rearm: Option<u8>) -> bool {
        self.active_single_steps
            .insert(tid, super::StepState { kind, deferred_hw_bp_rearm })
            .is_some()
    }

    /// Take and remove the active single-step state for a thread, if any.
    pub(super) fn take_active_single_step(&mut self, tid: u32) -> Option<super::StepState> {
        self.active_single_steps.remove(&tid)
    }

    /// Return the architecture-appropriate bytes for a breakpoint instruction.
    pub(super) fn breakpoint_instruction_bytes(&self) -> Vec<u8> {
        match self.architecture {
            Architecture::X64 => vec![0xCC],
            Architecture::Arm64 => vec![0x00, 0x00, 0x3e, 0xD4],
        }
    }

    /// If current memory matches the original instruction bytes for a persistent breakpoint at
    /// `address`, re-arm the breakpoint by writing the breakpoint instruction back.
    pub(super) fn rearm_persistent_breakpoint_if_matches_original(&self, address: u64) -> Result<(), PlatformError> {
        if let Some(original) = self.persistent_breakpoints.get(&address) {
            let process_handle = self.process_handle.0;
            let current = super::memory::read_memory_internal(process_handle, address, original.len()).unwrap_or_default();
            if current == *original {
                let bp_bytes = self.breakpoint_instruction_bytes();
                let _ = super::memory::write_memory_internal(process_handle, address, &bp_bytes);
            }
        }
        Ok(())
    }

    /// Mark that the process has passed the initial breakpoint.
    pub(super) fn mark_initial_breakpoint_hit(&mut self) {
        self.has_hit_initial_breakpoint = true;
    }

    /// Query whether the initial breakpoint was already observed.
    pub(super) fn has_initial_breakpoint_been_hit(&self) -> bool {
        self.has_hit_initial_breakpoint
    }

    /// Remove a persistent breakpoint
    pub(super) fn remove_breakpoint(&mut self, address: u64) -> Result<(), PlatformError> {
        if let Some(original) = self.persistent_breakpoints.remove(&address) {
            self.persistent_bp_tid_filters.remove(&address);
            let process_handle = self.process_handle.0;
            super::memory::write_memory_internal(process_handle, address, &original)
        } else {
            warn!(address, "Breakpoint not found");
            Ok(())
        }
    }

    // --- Code-coverage breakpoints -------------------------------------------
    // Coverage INT3s are stored in `persistent_breakpoints` (so they reuse the
    // restore / re-arm / step-over / patch machinery); `coverage_breakpoints`
    // adds the per-address hit counter + auto-remove limit.

    /// Register a coverage breakpoint at `address`: store its original bytes as a
    /// persistent breakpoint (no tid filter) and start a counter with `limit`.
    pub(super) fn arm_coverage(&mut self, address: u64, original_bytes: Vec<u8>, limit: u64) {
        self.insert_persistent_breakpoint(address, original_bytes, None);
        self.coverage_breakpoints.insert(
            address,
            CoverageEntry { hit_count: 0, limit, active: true, first_hit_seq: 0, thread_ids: Vec::new() },
        );
    }

    /// If an *active* coverage breakpoint exists at `address`, increment its hit
    /// counter (recording first-hit order and the hitting thread) and return
    /// `(new_hit_count, limit)`; `None` otherwise. One map lookup for both the
    /// "is this a coverage hit?" test and the count — this runs on the silent
    /// auto-continue hot path.
    pub(super) fn record_coverage_hit(&mut self, address: u64, tid: u32) -> Option<(u64, u64)> {
        let entry = self.coverage_breakpoints.get_mut(&address).filter(|e| e.active)?;
        if entry.hit_count == 0 {
            self.coverage_seq += 1;
            entry.first_hit_seq = self.coverage_seq;
        }
        entry.hit_count += 1;
        if !entry.thread_ids.contains(&tid) {
            entry.thread_ids.push(tid);
        }
        Some((entry.hit_count, entry.limit))
    }

    /// Permanently remove the INT3 for a coverage breakpoint (limit reached) but
    /// keep the entry (now `active == false`) so its final count is still reported.
    pub(super) fn deactivate_coverage(&mut self, address: u64) {
        if let Err(e) = self.remove_breakpoint(address) {
            warn!(address, error = %e, "Failed to remove coverage breakpoint at limit");
        }
        if let Some(entry) = self.coverage_breakpoints.get_mut(&address) {
            entry.active = false;
        }
    }

    /// Snapshot of every coverage breakpoint hit at least once (active or
    /// already auto-removed). Never-hit addresses are omitted — the client
    /// knows the armed set and fills zeros — so a poll doesn't serialize
    /// thousands of zero entries.
    pub(super) fn coverage_snapshot(&self) -> Vec<crate::protocol::CoverageHit> {
        self.coverage_breakpoints
            .iter()
            .filter(|(_, e)| e.hit_count > 0)
            .map(|(addr, e)| crate::protocol::CoverageHit {
                address: *addr,
                hit_count: e.hit_count,
                first_hit_seq: e.first_hit_seq,
                thread_ids: e.thread_ids.clone(),
            })
            .collect()
    }

    /// Remove all coverage breakpoints (restoring original bytes for any still
    /// active) and clear the coverage map.
    pub(super) fn clear_coverage(&mut self) {
        let active: Vec<u64> = self
            .coverage_breakpoints
            .iter()
            .filter(|(_, e)| e.active)
            .map(|(addr, _)| *addr)
            .collect();
        for addr in active {
            if let Err(e) = self.remove_breakpoint(addr) {
                warn!(address = addr, error = %e, "Failed to remove coverage breakpoint on clear");
            }
        }
        self.forget_coverage_state();
    }

    /// Forget all coverage bookkeeping (counters and the first-hit sequence).
    /// Restoring the INT3 bytes is the caller's job — the single owner of what
    /// "coverage state" consists of, shared by `clear_coverage` and detach.
    fn forget_coverage_state(&mut self) {
        self.coverage_breakpoints.clear();
        self.coverage_seq = 0;
    }

    // --- Hardware access traces ----------------------------------------------
    // The watchpoint's DR/register state lives in `hardware_breakpoints` (armed by
    // `set_hardware_breakpoint`); an entry here just puts it in silent
    // "collect accessors" mode.

    /// Mark the watched `address` as an active access trace (idempotent).
    pub(super) fn arm_watchpoint_trace(&mut self, address: u64) {
        self.watchpoint_traces.entry(address).or_default();
    }

    /// If an access trace is active for `watched_addr`, record an access from
    /// `raw_rip` by thread `tid` and return `true` (the caller then silently
    /// auto-continues); return `false` if the address is not being traced (a normal
    /// hardware breakpoint that should break into the client). Runs on the silent
    /// auto-continue hot path.
    pub(super) fn record_watchpoint_access(&mut self, watched_addr: u64, raw_rip: u64, tid: u32) -> bool {
        let Some(trace) = self.watchpoint_traces.get_mut(&watched_addr) else { return false; };
        let entry = trace.accessors.entry(raw_rip).or_insert(WatchpointAccessEntry {
            hit_count: 0,
            first_seq: 0,
            thread_ids: Vec::new(),
        });
        if entry.hit_count == 0 {
            self.watchpoint_seq += 1;
            entry.first_seq = self.watchpoint_seq;
        }
        entry.hit_count += 1;
        if !entry.thread_ids.contains(&tid) {
            entry.thread_ids.push(tid);
        }
        true
    }

    /// Snapshot of every distinct instruction that accessed `address` at least once.
    /// Empty if no trace is (or was) active for that address. `accessor` is filled
    /// with the raw trap RIP; the platform layer attributes it (x86 back-step).
    pub(super) fn watchpoint_snapshot(&self, address: u64) -> Vec<crate::protocol::WatchpointAccess> {
        let Some(trace) = self.watchpoint_traces.get(&address) else { return Vec::new(); };
        trace
            .accessors
            .iter()
            .map(|(rip, e)| crate::protocol::WatchpointAccess {
                accessor: *rip,
                accessor_raw_rip: *rip,
                hit_count: e.hit_count,
                first_seq: e.first_seq,
                thread_ids: e.thread_ids.clone(),
            })
            .collect()
    }

    /// Stop tracing `address`: drop the accumulated accessors. Removing the
    /// underlying hardware watchpoint is the caller's job.
    pub(super) fn clear_watchpoint_trace(&mut self, address: u64) {
        self.watchpoint_traces.remove(&address);
    }

    /// Restore the original bytes for every software breakpoint (persistent and
    /// single-shot) and forget them. Used on detach so the target keeps running
    /// without executing leftover int3/brk instructions.
    pub(super) fn restore_all_software_breakpoints(&mut self) {
        for (addr, original) in self
            .persistent_breakpoints
            .iter()
            .chain(self.single_shot_breakpoints.iter())
        {
            if let Err(e) = self.restore_original_bytes(*addr, original) {
                warn!(address = *addr, error = %e, "Failed to restore breakpoint byte on detach");
            }
        }
        self.persistent_breakpoints.clear();
        self.persistent_bp_tid_filters.clear();
        self.single_shot_breakpoints.clear();
        self.forget_coverage_state();
    }

    /// Patch a memory buffer to replace breakpoint instruction bytes with the
    /// original bytes that were saved when each breakpoint was set.
    /// This should be used before disassembling memory so the user sees
    /// original instructions rather than int3/brk.
    pub(super) fn patch_breakpoint_bytes(&self, base_address: u64, data: &mut [u8]) {
        let range_end = base_address + data.len() as u64;
        for (bp_addr, original) in self.persistent_breakpoints.iter()
            .chain(self.single_shot_breakpoints.iter())
        {
            let bp_start = *bp_addr;
            let bp_end = bp_start + original.len() as u64;
            // Check for overlap with buffer range
            if bp_start < range_end && bp_end > base_address {
                let copy_start = bp_start.max(base_address);
                let copy_end = bp_end.min(range_end);
                let buf_offset = (copy_start - base_address) as usize;
                let src_offset = (copy_start - bp_start) as usize;
                let len = (copy_end - copy_start) as usize;
                data[buf_offset..buf_offset + len]
                    .copy_from_slice(&original[src_offset..src_offset + len]);
            }
        }
    }

    pub(super) fn module_manager(&self) -> &super::module_manager::ModuleManager { &self.module_manager }
    pub(super) fn module_manager_mut(&mut self) -> &mut super::module_manager::ModuleManager { &mut self.module_manager }
    pub(super) fn thread_manager(&self) -> &super::thread_manager::ThreadManager { &self.thread_manager }
    pub(super) fn thread_manager_mut(&mut self) -> &mut super::thread_manager::ThreadManager { &mut self.thread_manager }

    // Hardware breakpoint methods

    /// Find a free debug-register slot for a breakpoint of the given type.
    ///
    /// x86: a single shared bank of 4 registers (DR0-DR3) serves every type.
    /// ARM64: two independent banks — 8 breakpoint slots (Bvr/Bcr, Execute) and
    /// 2 watchpoint slots (Wvr/Wcr, Write/ReadWrite). Returns the slot index
    /// within the relevant bank, or None if that bank is full.
    pub(super) fn find_free_debug_register(&self, bp_type: HardwareBreakpointType) -> Option<u8> {
        match self.architecture {
            Architecture::X64 => {
                let used: std::collections::HashSet<u8> =
                    self.hardware_breakpoints.iter().map(|bp| bp.dr_index).collect();
                (0..4u8).find(|i| !used.contains(i))
            }
            Architecture::Arm64 => {
                let is_exec = matches!(bp_type, HardwareBreakpointType::Execute);
                let max = if is_exec { 8u8 } else { 2u8 };
                let used: std::collections::HashSet<u8> = self
                    .hardware_breakpoints
                    .iter()
                    .filter(|bp| matches!(bp.bp_type, HardwareBreakpointType::Execute) == is_exec)
                    .map(|bp| bp.dr_index)
                    .collect();
                (0..max).find(|i| !used.contains(i))
            }
        }
    }

    /// Add a hardware breakpoint to the internal tracking.
    pub(super) fn add_hardware_breakpoint(&mut self, bp: InternalHardwareBreakpoint) {
        self.hardware_breakpoints.push(bp);
    }

    /// Remove a hardware breakpoint by address. Returns the removed BP if found.
    pub(super) fn remove_hardware_breakpoint_by_addr(&mut self, addr: u64) -> Option<InternalHardwareBreakpoint> {
        if let Some(pos) = self.hardware_breakpoints.iter().position(|bp| bp.address == addr) {
            Some(self.hardware_breakpoints.remove(pos))
        } else {
            None
        }
    }

    /// Find a hardware breakpoint by DR index.
    #[cfg(target_arch = "x86_64")]
    pub(super) fn find_hardware_breakpoint_by_dr_index(&self, dr_index: u8) -> Option<&InternalHardwareBreakpoint> {
        self.hardware_breakpoints.iter().find(|bp| bp.dr_index == dr_index)
    }

    /// Check if a hardware breakpoint exists at the given address.
    pub(super) fn has_hardware_breakpoint_at(&self, addr: u64) -> bool {
        self.hardware_breakpoints.iter().any(|bp| bp.address == addr)
    }

    /// Whether a software single-shot breakpoint is registered at `addr`.
    #[cfg(target_arch = "aarch64")]
    pub(super) fn has_single_shot_breakpoint(&self, addr: u64) -> bool {
        self.single_shot_breakpoints.contains_key(&addr)
    }

    /// Find the active hardware breakpoint/watchpoint responsible for an access
    /// at `addr` (ARM64 hit detection).
    ///
    /// For watchpoints (`is_watchpoint`), Windows reports the accessed data
    /// address; match it to the watched variable's doubleword-aligned window.
    /// For execute breakpoints, match the instruction address exactly.
    #[cfg(target_arch = "aarch64")]
    pub(super) fn active_hw_bp_for_access(
        &self,
        addr: u64,
        is_watchpoint: bool,
    ) -> Option<InternalHardwareBreakpoint> {
        self.hardware_breakpoints
            .iter()
            .filter(|bp| bp.is_active)
            .find(|bp| {
                let is_exec = matches!(bp.bp_type, HardwareBreakpointType::Execute);
                if is_watchpoint {
                    !is_exec && (addr & !0x7) == (bp.address & !0x7)
                } else {
                    is_exec && bp.address == addr
                }
            })
            .cloned()
    }

    /// Return all active hardware breakpoints.
    pub(super) fn active_hardware_breakpoints(&self) -> Vec<InternalHardwareBreakpoint> {
        self.hardware_breakpoints.iter().filter(|bp| bp.is_active).cloned().collect()
    }

    /// Schedule a HW BP re-arm after a single-step for the given thread.
    pub(super) fn schedule_hw_bp_rearm(&mut self, tid: u32, dr_index: u8) {
        self.pending_hw_bp_rearm.insert(tid, dr_index);
    }

    /// Take and remove a pending HW BP re-arm for a thread.
    pub(super) fn take_pending_hw_bp_rearm(&mut self, tid: u32) -> Option<u8> {
        self.pending_hw_bp_rearm.remove(&tid)
    }

}

impl Drop for DebuggedProcess {
    fn drop(&mut self) {
        let _lock = super::dbghelp::DBGHELP_LOCK.lock().unwrap();
        if unsafe { SymCleanup(self.process_handle.0) } == FALSE {
            let error = unsafe { GetLastError() };
            warn!("Failed to cleanup symbol handler for process, error code: {}", error);
        }
    }
}


