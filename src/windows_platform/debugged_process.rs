use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::{HardwareBreakpointType, HardwareBreakpointSize};
use tracing::{error, warn};
use windows_sys::Win32::Foundation::{FALSE, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{SymCleanup, SymInitialize};

#[derive(Debug, Clone)]
pub(crate) struct InternalHardwareBreakpoint {
    pub address: u64,
    pub bp_type: HardwareBreakpointType,
    pub size: HardwareBreakpointSize,
    pub dr_index: u8,
    pub is_active: bool,
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
    /// Hardware breakpoints (DR0-DR3, max 4)
    hardware_breakpoints: Vec<InternalHardwareBreakpoint>,
    /// Pending HW BP re-arm after single-step: tid -> dr_index
    pending_hw_bp_rearm: std::collections::HashMap<u32, u8>,
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
            hardware_breakpoints: Vec::new(),
            pending_hw_bp_rearm: std::collections::HashMap::new(),
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


