use crate::interfaces::{Architecture, PlatformError};
use tracing::{error, warn};
use windows_sys::Win32::Foundation::{FALSE, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{SymCleanup, SymInitialize};

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
}

impl DebuggedProcess {
    pub(super) fn new(pid: u32, process_handle: HANDLE, architecture: Architecture) -> Result<Self, PlatformError> {
        if unsafe { SymInitialize(process_handle, std::ptr::null(), FALSE) } == FALSE {
            let error = unsafe { GetLastError() };
            error!(pid, "Failed to initialize symbol handler, error code: 0x{:x}", error);
            return Err(PlatformError::OsError(format!(
                "SymInitialize failed for pid {}: {}",
                pid,
                super::utils::error_message(error)
            )));
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

    /// Get a clone of the original bytes for a persistent breakpoint.
    pub(super) fn persistent_original_bytes(&self, address: u64) -> Option<Vec<u8>> {
        self.persistent_breakpoints.get(&address).cloned()
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

    /// Record that a thread is in an active single-step operation. Returns true if an existing
    /// record for this thread was replaced.
    pub(super) fn record_active_single_step(&mut self, tid: u32, kind: crate::protocol::StepKind) -> bool {
        self.active_single_steps
            .insert(tid, super::StepState { kind })
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

    pub(super) fn module_manager(&self) -> &super::module_manager::ModuleManager { &self.module_manager }
    pub(super) fn module_manager_mut(&mut self) -> &mut super::module_manager::ModuleManager { &mut self.module_manager }
    pub(super) fn thread_manager(&self) -> &super::thread_manager::ThreadManager { &self.thread_manager }
    pub(super) fn thread_manager_mut(&mut self) -> &mut super::thread_manager::ThreadManager { &mut self.thread_manager }
}

impl Drop for DebuggedProcess {
    fn drop(&mut self) {
        if unsafe { SymCleanup(self.process_handle.0) } == FALSE {
            let error = unsafe { GetLastError() };
            warn!("Failed to cleanup symbol handler for process, error code: {}", error);
        }
    }
}


