mod utils;
mod module_manager;
mod thread_manager;
mod process;
mod debug_events;
mod memory;
mod thread_context;

use crate::interfaces::{PlatformAPI, PlatformError};
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo};
use module_manager::ModuleManager;
use thread_manager::ThreadManager;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use tracing::{trace};

// Safe wrapper for HANDLE that automatically closes it
#[derive(Debug)]
pub(crate) struct HandleSafe(pub HANDLE);
unsafe impl Send for HandleSafe {}
unsafe impl Sync for HandleSafe {}

impl Drop for HandleSafe {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 as isize != -1 {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// Aligned wrapper for CONTEXT structure
#[repr(align(16))]
struct AlignedContext {
    context: CONTEXT,
}

pub struct WindowsPlatform {
    pub(crate) pid: Option<u32>,
    pub(crate) process_handle: Option<HandleSafe>,
    pub(crate) module_manager: ModuleManager,
    pub(crate) thread_manager: ThreadManager,
}

impl WindowsPlatform {
    pub fn new() -> Self {
        Self { pid: None, process_handle: None, module_manager: ModuleManager::new(), thread_manager: ThreadManager::new() }
    }
}

impl PlatformAPI for WindowsPlatform {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::attach(self, pid)
    }

    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        debug_events::continue_exec(self, pid, tid)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<(), PlatformError> {
        trace!(addr, "WindowsPlatform::set_breakpoint called");
        Err(PlatformError::NotImplemented)
    }

    fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        process::launch(self, command)
    }

    fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError> {
        memory::read_memory(self, pid, address, size)
    }

    fn write_memory(&mut self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        memory::write_memory(self, pid, address, data)
    }

    fn get_thread_context(&mut self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError> {
        thread_context::get_thread_context(self, pid, tid)
    }

    fn set_thread_context(&mut self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError> {
        thread_context::set_thread_context(self, pid, tid, context)
    }

    fn list_modules(&self, _pid: u32) -> Result<Vec<ModuleInfo>, PlatformError> {
        Ok(self.module_manager.list_modules())
    }

    fn list_threads(&self, _pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
        Ok(self.thread_manager.list_threads())
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        process::list_processes()
    }
} 