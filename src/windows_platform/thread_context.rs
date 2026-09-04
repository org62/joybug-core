//! Thread register access, dispatched on the debuggee's architecture.
//!
//! A native (x64 / ARM64) thread uses `GetThreadContext` / `SetThreadContext`
//! and yields the host `CONTEXT`. A 32-bit (WOW64) thread uses
//! `Wow64GetThreadContext` / `Wow64SetThreadContext` and yields a
//! `WOW64_CONTEXT`, on either 64-bit host — on x64 the native context of a
//! WOW64 thread happens to mirror the 32-bit registers, on ARM64 (xtajit) it is
//! the emulator's own state and useless for the debuggee.

use super::{utils, AlignedContext};
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::ThreadContext;
use crate::windows_platform::DebuggedProcess;
use tracing::{debug, error, trace};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, Wow64GetThreadContext, Wow64SetThreadContext, CONTEXT,
    WOW64_CONTEXT, WOW64_CONTEXT_ALL,
};

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64 as CONTEXT_ALL_NATIVE;

#[cfg(target_arch = "aarch64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_ARM64 as CONTEXT_ALL_NATIVE;

fn last_os_error(what: &str) -> PlatformError {
    let error = unsafe { GetLastError() };
    let error_str = utils::error_message(error);
    error!(error, error_str, "{} failed", what);
    PlatformError::OsError(format!("{} failed: {} ({})", what, error, error_str))
}

fn thread_handle(process: &DebuggedProcess, tid: u32) -> Result<HANDLE, PlatformError> {
    process
        .thread_manager()
        .get_thread_handle(tid)
        .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))
}

/// The host-native `CONTEXT` of a thread, whatever the debuggee's architecture.
pub(super) fn get_native_context(thread_handle: HANDLE) -> Result<CONTEXT, PlatformError> {
    let mut aligned = AlignedContext { context: unsafe { std::mem::zeroed() } };
    aligned.context.ContextFlags = CONTEXT_ALL_NATIVE;
    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        return Err(last_os_error("GetThreadContext"));
    }
    Ok(aligned.context)
}

pub(super) fn set_native_context(thread_handle: HANDLE, ctx: &CONTEXT) -> Result<(), PlatformError> {
    // CONTEXT must be 16-byte aligned for SetThreadContext; copy into the wrapper.
    let mut aligned = AlignedContext { context: unsafe { std::mem::zeroed() } };
    unsafe {
        std::ptr::copy_nonoverlapping(
            ctx as *const _ as *const u8,
            &mut aligned.context as *mut _ as *mut u8,
            std::mem::size_of::<CONTEXT>(),
        );
    }
    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        return Err(last_os_error("SetThreadContext"));
    }
    Ok(())
}

fn get_wow64_context(thread_handle: HANDLE) -> Result<WOW64_CONTEXT, PlatformError> {
    let mut ctx: WOW64_CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = WOW64_CONTEXT_ALL;
    if unsafe { Wow64GetThreadContext(thread_handle, &mut ctx) } == 0 {
        return Err(last_os_error("Wow64GetThreadContext"));
    }
    Ok(ctx)
}

pub(super) fn get_thread_context(
    process: &DebuggedProcess,
    pid: u32,
    tid: u32,
) -> Result<ThreadContext, PlatformError> {
    trace!(pid, tid, "WindowsPlatform::get_thread_context called");
    let handle = thread_handle(process, tid)?;
    match process.architecture() {
        Architecture::X86 => match get_wow64_context(handle) {
            Ok(ctx) => Ok(ThreadContext::Wow64RawContext(ctx)),
            // A thread with no 32-bit half — the 64-bit break-in thread that
            // `DebugBreakProcess`/attach inject into a WOW64 process — has no
            // WOW64 context. Report its native one so the event can still be
            // shown rather than failing the whole stop.
            Err(e) => {
                debug!(pid, tid, error = %e, "No WOW64 context for thread; falling back to the native context");
                Ok(ThreadContext::Win32RawContext(get_native_context(handle)?))
            }
        },
        Architecture::X64 | Architecture::Arm64 => {
            Ok(ThreadContext::Win32RawContext(get_native_context(handle)?))
        }
    }
}

pub(super) fn set_thread_context(
    process: &DebuggedProcess,
    pid: u32,
    tid: u32,
    context: ThreadContext,
) -> Result<(), PlatformError> {
    trace!(pid, tid, "WindowsPlatform::set_thread_context called");
    let handle = thread_handle(process, tid)?;
    match context {
        ThreadContext::Win32RawContext(ctx) => set_native_context(handle, &ctx),
        ThreadContext::Wow64RawContext(ctx) => {
            if unsafe { Wow64SetThreadContext(handle, &ctx) } == 0 {
                return Err(last_os_error("Wow64SetThreadContext"));
            }
            Ok(())
        }
    }
}

/// Read-modify-write a thread's context in one round trip: every caller that
/// used to destructure `Win32RawContext`, poke a field and write it back goes
/// through here, so the WOW64 arm is handled once.
pub(super) fn modify_thread_context(
    process: &DebuggedProcess,
    pid: u32,
    tid: u32,
    f: impl FnOnce(&mut ThreadContext) -> Result<(), PlatformError>,
) -> Result<(), PlatformError> {
    let mut context = get_thread_context(process, pid, tid)?;
    f(&mut context)?;
    set_thread_context(process, pid, tid, context)
}

/// Clear the single-step flag in a thread's *native* context. Used when a
/// WOW64 thread traps with a native `STATUS_SINGLE_STEP` (a 32-bit trap flag
/// carried through the 32→64 gate), which `Wow64SetThreadContext` cannot clear.
pub(super) fn clear_native_single_step(
    process: &DebuggedProcess,
    tid: u32,
) -> Result<(), PlatformError> {
    let handle = thread_handle(process, tid)?;
    let mut ctx = ThreadContext::Win32RawContext(get_native_context(handle)?);
    ctx.set_single_step(false);
    match ctx {
        ThreadContext::Win32RawContext(native) => set_native_context(handle, &native),
        ThreadContext::Wow64RawContext(_) => unreachable!("built as a native context"),
    }
}
