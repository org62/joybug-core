//! The boundary between the shared bookkeeping and an OS backend.
//!
//! Everything the shared code needs from a tracee goes through [`ProcessOps`]:
//! memory, which threads exist, and keeping a thread from running. A backend
//! implements it over its own handles (Win32 `HANDLE`s, a ptrace tracer
//! thread) and the breakpoint, stepping and coverage logic is written once.

use super::hw_breakpoints::{InternalHardwareBreakpoint, X86DebugRegs};
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::{DebugEvent, ThreadContext};

/// What becomes of an internal hook after it fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookDisposition {
    /// Re-arm it (single-step past the restored instruction, then put the
    /// breakpoint byte back).
    Keep,
    /// Forget it; the original instruction stays in place.
    Remove,
}

/// How a process's `InitialBreakpoint` event is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialBpPolicy {
    /// The first breakpoint trap the debugger does not own is the initial
    /// breakpoint (Windows: the loader's `DbgBreakPoint`).
    FirstUnownedTrap,
    /// The backend reports it from an internal hook (Linux: the entry-point
    /// hook); an unowned trap is always the debuggee's own.
    InternalHook,
}

pub trait ProcessOps {
    /// The debuggee's architecture (a WOW64 process reports `X86`).
    fn arch(&self) -> Architecture;

    /// Read `len` bytes of the tracee's memory. May return a shorter prefix
    /// when the range runs into unmapped memory.
    fn read(&self, pid: u32, address: u64, len: usize) -> Result<Vec<u8>, PlatformError>;

    /// Write into the tracee's memory, including read-only code pages (that
    /// is how breakpoint bytes are planted).
    fn write(&self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError>;

    /// Every thread that has not exited. The exiting thread stays reachable by
    /// tid through `freeze_thread`/`thaw_thread`, just not listed here.
    fn live_threads(&self, pid: u32) -> Vec<u32>;

    /// Keep `tid` from running on the next resume (Windows: `SuspendThread`;
    /// ptrace: leave it stopped). `Err` when the thread is gone, in which case
    /// the caller does not count it as frozen.
    fn freeze_thread(&self, pid: u32, tid: u32) -> Result<(), PlatformError>;

    /// Undo one [`freeze_thread`](Self::freeze_thread). `Err` when the thread is gone.
    fn thaw_thread(&self, pid: u32, tid: u32) -> Result<(), PlatformError>;

    /// The thread's full register file.
    fn get_context(&self, pid: u32, tid: u32) -> Result<ThreadContext, PlatformError>;

    /// Write a thread's full register file back.
    fn set_context(&self, pid: u32, tid: u32, context: ThreadContext) -> Result<(), PlatformError>;

    /// Read-modify-write a thread's context in one round trip.
    fn modify_context(
        &self,
        pid: u32,
        tid: u32,
        f: &mut dyn FnMut(&mut ThreadContext) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        let mut context = self.get_context(pid, tid)?;
        f(&mut context)?;
        self.set_context(pid, tid, context)
    }

    /// Read-modify-write a thread's x86 debug-register block, plus the control
    /// block (instruction pointer, flags) when `with_control`. `f` returns
    /// whether to write the block back. Only called for x86-family targets.
    fn modify_debug_regs(
        &self,
        pid: u32,
        tid: u32,
        with_control: bool,
        f: &mut dyn FnMut(&mut dyn X86DebugRegs) -> bool,
    ) -> Result<(), PlatformError>;

    /// Program one breakpoint into one thread's debug registers.
    fn apply_hw_bp(
        &self,
        pid: u32,
        tid: u32,
        dr_index: u8,
        address: u64,
        bp_type: crate::protocol::HardwareBreakpointType,
        size: crate::protocol::HardwareBreakpointSize,
    ) -> Result<(), PlatformError>;

    /// Clear one breakpoint from one thread's debug registers.
    fn clear_hw_bp(&self, pid: u32, tid: u32, dr_index: u8, bp_type: crate::protocol::HardwareBreakpointType) -> Result<(), PlatformError>;

    /// Program every active hardware breakpoint on one thread (a new thread,
    /// or re-arming after a step).
    fn apply_all_hw_bps(&self, pid: u32, tid: u32, bps: &[InternalHardwareBreakpoint]) -> Result<(), PlatformError>;

    /// One of the backend's internal hooks fired (see
    /// `BreakpointTable::insert_internal`). The original bytes are already
    /// restored; return what the client should see, if anything, and whether
    /// the hook stays armed.
    fn on_internal_hook(&self, _pid: u32, _tid: u32, _hook_id: u32) -> Result<(Option<DebugEvent>, HookDisposition), PlatformError> {
        Ok((None, HookDisposition::Keep))
    }

    fn initial_breakpoint_policy(&self) -> InitialBpPolicy {
        InitialBpPolicy::FirstUnownedTrap
    }
}
