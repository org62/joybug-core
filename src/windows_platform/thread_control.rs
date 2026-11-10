//! User-initiated thread control: suspend / resume / terminate, plus the live
//! suspend count shown in thread lists.
//!
//! Each explicit control opens its own [`HandleSafe`] thread handle rather than
//! reusing the debugger's cached ones: the non-invasive (`open_non_invasive`)
//! handles are opened with only `THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION`,
//! so the same code serves debugged and merely-opened processes alike.
//!
//! Suspend counts nest with the step-over freezer in `debugged_process.rs`
//! (both are plain `SuspendThread` calls on the same thread), so a user suspend
//! survives a step-over and vice versa. Server-side resume holds the platform
//! write lock, excluding stopped-context samples in listings. A user resume
//! during the in-flight single-instruction step-over window can still release
//! the step-over freezer's suspension.

use tracing::{error, trace};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, TerminateThread,
    THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
};

use super::utils::{self, NtQueryInformationThread};
use super::HandleSafe;
use crate::interfaces::PlatformError;

/// `THREADINFOCLASS::ThreadSuspendCount` — the thread's suspend count as a
/// `ULONG` (Windows 8.1+).
const THREAD_SUSPEND_COUNT: u32 = 35;

/// Open a thread handle for a user-requested action. Failure is reported: the
/// user picked this thread, so they need to know why nothing happened.
fn open(tid: u32, access: u32, what: &str) -> Result<HandleSafe, PlatformError> {
    let h = unsafe { OpenThread(access, 0, tid) };
    if h.is_null() {
        let e = unsafe { GetLastError() };
        let err = utils::error_message(e);
        error!(tid, code = e, err, "OpenThread failed for {}", what);
        return Err(PlatformError::OsError(format!(
            "OpenThread({}) failed for thread {}: {} ({})",
            what, tid, e, err
        )));
    }
    Ok(HandleSafe(h))
}

fn os_err(what: &str, tid: u32) -> PlatformError {
    let e = unsafe { GetLastError() };
    let err = utils::error_message(e);
    error!(tid, code = e, err, "{} failed", what);
    PlatformError::OsError(format!("{} failed for thread {}: {} ({})", what, tid, e, err))
}

/// Previous suspend count on success.
pub fn suspend_thread_unlocked(tid: u32) -> Result<u32, PlatformError> {
    let h = open(tid, THREAD_SUSPEND_RESUME, "SuspendThread")?;
    let prev = unsafe { SuspendThread(h.0) };
    if prev == u32::MAX {
        return Err(os_err("SuspendThread", tid));
    }
    trace!(tid, prev, "SuspendThread");
    Ok(prev)
}

/// Previous suspend count on success (0 means the thread was not suspended;
/// the call is then a no-op, not an error).
pub fn resume_thread_unlocked(tid: u32) -> Result<u32, PlatformError> {
    let h = open(tid, THREAD_SUSPEND_RESUME, "ResumeThread")?;
    let prev = unsafe { ResumeThread(h.0) };
    if prev == u32::MAX {
        return Err(os_err("ResumeThread", tid));
    }
    trace!(tid, prev, "ResumeThread");
    Ok(prev)
}

pub fn terminate_thread_unlocked(tid: u32, exit_code: u32) -> Result<(), PlatformError> {
    let h = open(tid, THREAD_TERMINATE, "TerminateThread")?;
    if unsafe { TerminateThread(h.0, exit_code) } == 0 {
        return Err(os_err("TerminateThread", tid));
    }
    trace!(tid, exit_code, "TerminateThread");
    Ok(())
}

/// Passive kernel suspend count, including a debug-event freeze. `None` when the
/// query fails (e.g. the thread has exited). Listings reuse their query-capable
/// handle and use this same count to decide whether context sampling is safe.
pub(super) fn queried_suspend_count_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u32> {
    let mut count: u32 = 0;
    let mut ret: u32 = 0;
    let status = unsafe {
        NtQueryInformationThread(
            handle,
            THREAD_SUSPEND_COUNT,
            &mut count as *mut u32 as *mut std::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
            &mut ret,
        )
    };
    if status < 0 {
        return None;
    }
    Some(count)
}
