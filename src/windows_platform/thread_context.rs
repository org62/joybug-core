use super::{utils, AlignedContext};
use crate::interfaces::PlatformError;
use crate::protocol::ThreadContext;
use crate::windows_platform::DebuggedProcess;
use tracing::{error, trace};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT
};

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;

#[cfg(target_arch = "aarch64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_ARM64;

pub(super) fn get_thread_context(
    process: &mut DebuggedProcess,
    pid: u32,
    tid: u32,
) -> Result<ThreadContext, PlatformError> {
    trace!(pid, tid, "WindowsPlatform::get_thread_context called");
    #[cfg(windows)]
    {
        let thread_handle = process
            .thread_manager()
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))?;

        let mut aligned_context = AlignedContext {
            context: unsafe { std::mem::zeroed() },
        };

        #[cfg(target_arch = "aarch64")]
        {
            aligned_context.context.ContextFlags = CONTEXT_ALL_ARM64;
        }
        #[cfg(target_arch = "x86_64")]
        {
            aligned_context.context.ContextFlags = CONTEXT_ALL_AMD64;
        }

        let ok = unsafe { GetThreadContext(thread_handle, &mut aligned_context.context) };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            let error_str = utils::error_message(error);
            error!(error, error_str, "GetThreadContext failed");
            return Err(PlatformError::OsError(format!(
                "GetThreadContext failed: {} ({})",
                error, error_str
            )));
        }
        trace!("GetThreadContext succeeded");
        Ok(crate::protocol::ThreadContext::Win32RawContext(
            aligned_context.context,
        ))
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::NotImplemented)
    }
}

pub(super) fn set_thread_context(
    process: &mut DebuggedProcess,
    pid: u32,
    tid: u32,
    context: ThreadContext,
) -> Result<(), PlatformError> {
    trace!(pid, tid, "WindowsPlatform::set_thread_context called");
    #[cfg(windows)]
    unsafe {
        let thread_handle = process
            .thread_manager()
            .get_thread_handle(tid)
            .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))?;

        match context {
            crate::protocol::ThreadContext::Win32RawContext(ctx) => {
                // Use aligned memory for CONTEXT
                let mut aligned_context = AlignedContext {
                    context: std::mem::zeroed(),
                };
                std::ptr::copy_nonoverlapping(
                    &ctx as *const _ as *const u8,
                    &mut aligned_context.context as *mut _ as *mut u8,
                    std::mem::size_of::<CONTEXT>(),
                );
                let ok = SetThreadContext(thread_handle, &aligned_context.context);
                if ok == 0 {
                    let error = GetLastError();
                    let error_str = utils::error_message(error);
                    error!(error, error_str, "SetThreadContext failed");
                    return Err(PlatformError::OsError(format!(
                        "SetThreadContext failed: {} ({})",
                        error, error_str
                    )));
                }
                trace!("SetThreadContext succeeded");
                Ok(())
            }
        }
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::NotImplemented)
    }
} 