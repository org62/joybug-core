//! Platform-neutral debugger bookkeeping shared by every backend.
//!
//! A backend (`windows_platform`, `linux_platform`) owns the OS primitives -
//! how to read a tracee's memory, get a thread's registers, keep a thread from
//! running - and everything else lives here: the module and thread tables, the
//! breakpoint/step/coverage/watchpoint books, the hardware-breakpoint register
//! math, the trap dispatch that turns a stop into a `DebugEvent`, and the
//! read-side helpers (dereference, disassembly, calling conventions). Nothing in
//! this module is `cfg(windows)`; only `cfg(target_arch)` where a register
//! field is touched.

pub mod breakpoints;
pub mod coverage;
pub mod coverage_targets;
pub mod dereference;
pub mod disasm;
pub mod disassembler;
pub mod events;
pub mod function_args;
pub mod hw_breakpoints;
pub mod module_manager;
pub mod ops;
pub mod stepping;
pub mod strings;
pub mod thread_table;
pub mod watchpoints;

use crate::interfaces::Architecture;

/// Everything the debugger knows about one process that is not an OS handle.
#[derive(Debug)]
pub struct DebugBook {
    pub arch: Architecture,
    pub modules: module_manager::ModuleManager,
    pub bps: breakpoints::BreakpointTable,
    pub steps: stepping::StepBook,
    pub hw: hw_breakpoints::HwBpTable,
    pub coverage: coverage::CoverageBook,
    pub watch: watchpoints::WatchBook,
    /// Whether this process has hit its initial breakpoint.
    pub has_hit_initial_breakpoint: bool,
    /// Created by our launch (or a debugged child of one), as opposed to
    /// attached/opened. Only a launched WOW64 process delivers the 64-bit
    /// loader break *and* the 32-bit one; an attach break-in is native only.
    pub created_by_launch: bool,
}

impl DebugBook {
    pub fn new(arch: Architecture) -> Self {
        Self {
            arch,
            modules: module_manager::ModuleManager::new(),
            bps: Default::default(),
            steps: Default::default(),
            hw: Default::default(),
            coverage: Default::default(),
            watch: Default::default(),
            has_hit_initial_breakpoint: false,
            created_by_launch: false,
        }
    }

    /// Called under the platform lock, with `mapped_code` checking the live
    /// memory mapping using the same backend/process as the trap write.
    pub(crate) fn change_module_breakpoint(
        &mut self,
        ops: &impl ops::ProcessOps,
        pid: u32,
        base: u64,
        mapping_id: u64,
        addr: u64,
        arm: bool,
        mapped_code: impl FnOnce(u64) -> Result<Option<bool>, crate::interfaces::PlatformError>,
    ) -> Result<bool, crate::interfaces::PlatformError> {
        let Some(executable) = self.module_trap_location(base, mapping_id, addr, mapped_code)? else { return Ok(false) };
        if arm && !executable {
            return Err(crate::interfaces::PlatformError::Other("Breakpoint is not in executable mapped memory".into()));
        }
        breakpoints::change_module_trap(&mut self.bps, ops, pid, addr, mapping_id, arm)
    }

    /// The eligibility check shared by exact-name lookup and trap mutation.
    pub(crate) fn module_trap_location(
        &self,
        base: u64,
        mapping_id: u64,
        addr: u64,
        mapped_code: impl FnOnce(u64) -> Result<Option<bool>, crate::interfaces::PlatformError>,
    ) -> Result<Option<bool>, crate::interfaces::PlatformError> {
        let Some((module, current_id)) = self.modules.mapping_at(base) else { return Ok(None) };
        if current_id != mapping_id {
            return Ok(None);
        }
        let end = breakpoints::module_trap_end(module, self.arch, addr)?;
        mapped_code(end)
    }

    /// The loader has unmapped the image. Forget all its live software trap
    /// bookkeeping, never writing saved instruction bytes back to its VAs.
    pub(crate) fn unload_module(&mut self, ops: &impl ops::ProcessOps, pid: u32, base: u64) {
        let Some(module) = self.modules.remove_module(base) else { return };
        let gone = |addr: u64| addr.checked_sub(base).is_some_and(|rva| rva < module.size.unwrap_or(1));
        self.bps.forget_range(gone);
        self.coverage.deactivate_range(gone);
        if self.steps.forget_step_overs_in_range(gone) {
            stepping::resume_frozen_threads(&mut self.steps, ops, pid);
        }
    }
}
