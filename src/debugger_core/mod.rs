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
}
