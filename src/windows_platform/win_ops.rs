//! The Win32 side of the shared bookkeeping: [`WinProcess`] holds the process
//! and thread handles and implements [`ProcessOps`] over them.

use crate::debugger_core::hw_breakpoints::{InternalHardwareBreakpoint, X86DebugRegs};
use crate::debugger_core::ops::ProcessOps;
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::ThreadContext;
use super::thread_manager::ThreadManager;
use super::HandleSafe;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{ResumeThread, SuspendThread};

#[derive(Debug)]
pub(crate) struct WinProcess {
    pid: u32,
    process_handle: HandleSafe,
    architecture: Architecture,
    thread_manager: ThreadManager,
}

impl WinProcess {
    pub(super) fn new(pid: u32, process_handle: HANDLE, architecture: Architecture) -> Self {
        Self {
            pid,
            process_handle: HandleSafe(process_handle),
            architecture,
            thread_manager: ThreadManager::new(),
        }
    }

    pub(super) fn pid(&self) -> u32 { self.pid }
    pub(super) fn handle(&self) -> HANDLE { self.process_handle.0 }
    pub(super) fn architecture(&self) -> Architecture { self.architecture }
    pub(super) fn threads(&self) -> &ThreadManager { &self.thread_manager }
    pub(super) fn threads_mut(&mut self) -> &mut ThreadManager { &mut self.thread_manager }
}

impl ProcessOps for WinProcess {
    fn arch(&self) -> Architecture { self.architecture }

    fn read(&self, _pid: u32, address: u64, len: usize) -> Result<Vec<u8>, PlatformError> {
        super::memory::read_memory_internal(self.process_handle.0, address, len)
    }

    fn write(&self, _pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        super::memory::write_memory_internal(self.process_handle.0, address, data)
    }

    fn live_threads(&self, _pid: u32) -> Vec<u32> {
        self.thread_manager.live_tids()
    }

    /// `SuspendThread`. Returns the previous suspend count on success, or
    /// `(DWORD)-1` on failure - typically a thread that has already exited
    /// (the thread table keeps handles across exit).
    fn freeze_thread(&self, _pid: u32, tid: u32) -> Result<(), PlatformError> {
        let handle = self
            .thread_manager
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::Other(format!("no handle for thread {tid}")))?;
        let prev = unsafe { SuspendThread(handle) };
        if prev == u32::MAX {
            let err = unsafe { GetLastError() };
            return Err(PlatformError::OsError(format!("SuspendThread failed: {err}")));
        }
        Ok(())
    }

    fn thaw_thread(&self, _pid: u32, tid: u32) -> Result<(), PlatformError> {
        let handle = self
            .thread_manager
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::Other(format!("no handle for thread {tid}")))?;
        let prev = unsafe { ResumeThread(handle) };
        if prev == u32::MAX {
            let err = unsafe { GetLastError() };
            return Err(PlatformError::OsError(format!("ResumeThread failed: {err}")));
        }
        Ok(())
    }

    fn get_context(&self, pid: u32, tid: u32) -> Result<ThreadContext, PlatformError> {
        super::thread_context::get_thread_context_os(self, pid, tid)
    }

    fn set_context(&self, pid: u32, tid: u32, context: ThreadContext) -> Result<(), PlatformError> {
        super::thread_context::set_thread_context_os(self, pid, tid, context)
    }

    fn modify_debug_regs(
        &self,
        _pid: u32,
        tid: u32,
        with_control: bool,
        f: &mut dyn FnMut(&mut dyn X86DebugRegs) -> bool,
    ) -> Result<(), PlatformError> {
        let handle = self
            .thread_manager
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))?;
        let mut dctx = super::hardware_breakpoints::X86DebugCtx::read(handle, self.architecture, with_control)?;
        if f(dctx.regs()) {
            dctx.write(handle)?;
        }
        Ok(())
    }

    fn apply_hw_bp(
        &self,
        _pid: u32,
        tid: u32,
        dr_index: u8,
        address: u64,
        bp_type: crate::protocol::HardwareBreakpointType,
        size: crate::protocol::HardwareBreakpointSize,
    ) -> Result<(), PlatformError> {
        let handle = self
            .thread_manager
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))?;
        super::hardware_breakpoints::apply_single_hw_bp_to_thread_for(self.architecture, handle, dr_index, address, bp_type, size)
    }

    fn clear_hw_bp(&self, _pid: u32, tid: u32, dr_index: u8, bp_type: crate::protocol::HardwareBreakpointType) -> Result<(), PlatformError> {
        let handle = self
            .thread_manager
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))?;
        super::hardware_breakpoints::clear_hw_bp_from_thread_for(self.architecture, handle, dr_index, bp_type)
    }

    fn apply_all_hw_bps(&self, _pid: u32, tid: u32, bps: &[InternalHardwareBreakpoint]) -> Result<(), PlatformError> {
        let handle = self
            .thread_manager
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))?;
        super::hardware_breakpoints::apply_all_hw_bps_to_thread_for(self.architecture, handle, bps)
    }
}
