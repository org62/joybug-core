//! User-initiated thread control: suspend / resume / terminate, plus the live
//! suspend count shown in thread lists.
//!
//! Every call opens its own [`HandleSafe`] thread handle rather than reusing
//! the debugger's cached ones: the non-invasive (`open_non_invasive`) handles
//! are opened with only `THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION`, and a
//! fresh handle needs no platform lock, so the same code serves debugged and
//! merely-opened processes alike.
//!
//! Suspend counts nest with the step-over freezer in `debugged_process.rs`
//! (both are plain `SuspendThread` calls on the same thread), so a user suspend
//! survives a step-over and vice versa. The one unguarded hazard is a user
//! *resume* landing inside an in-flight step-over window; that window is a
//! single instruction long.

use tracing::{error, trace};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, TerminateThread, THREAD_QUERY_INFORMATION,
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

/// Open a thread handle for a suspend-count probe. Unlike [`open`] this stays
/// silent on failure: `list_threads` probes every tid it knows about on every
/// poll, and a tid that has exited (the debugged `ThreadManager` never evicts
/// them) fails every time — formatting an OS message and logging an error for
/// that, once per thread per poll, is pure noise and allocation.
fn open_quiet(tid: u32, access: u32) -> Option<HandleSafe> {
    let h = unsafe { OpenThread(access, 0, tid) };
    if h.is_null() {
        trace!(tid, code = unsafe { GetLastError() }, "OpenThread failed for suspend-count probe");
        return None;
    }
    Some(HandleSafe(h))
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

/// Suspend count of a thread in a process we are debugging, read through a
/// `SuspendThread`/`ResumeThread` round-trip: `SuspendThread` returns the
/// previous *user* suspend count, which is what the UI wants. The
/// `ThreadSuspendCount` query in [`queried_suspend_count`] cannot be used here
/// because it also counts the kernel's debug freeze — every thread of a process
/// halted at a debug event reads one too high. While halted the round-trip is
/// invisible (the threads are frozen anyway); on a running target it is a
/// microsecond hiccup per poll. `None` when the thread cannot be opened or has
/// exited.
pub fn debugged_suspend_count(tid: u32) -> Option<u32> {
    let h = open_quiet(tid, THREAD_SUSPEND_RESUME)?;
    let prev = unsafe { SuspendThread(h.0) };
    if prev == u32::MAX {
        return None;
    }
    unsafe { ResumeThread(h.0) };
    Some(prev)
}

/// Non-intrusive suspend count for a process we are *not* debugging. Includes
/// any debug freeze another debugger may hold, which is why the debugged path
/// uses [`debugged_suspend_count`] instead. `None` when the thread cannot be
/// opened or queried (e.g. it has exited).
pub fn queried_suspend_count(tid: u32) -> Option<u32> {
    let h = open_quiet(tid, THREAD_QUERY_INFORMATION)?;
    let mut count: u32 = 0;
    let mut ret: u32 = 0;
    let status = unsafe {
        NtQueryInformationThread(
            h.0,
            THREAD_SUSPEND_COUNT,
            &mut count as *mut u32 as *mut std::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
            &mut ret,
        )
    };
    if status < 0 {
        trace!(tid, status, "NtQueryInformationThread(ThreadSuspendCount) failed");
        return None;
    }
    Some(count)
}
