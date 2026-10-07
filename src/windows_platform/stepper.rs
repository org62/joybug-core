//! Stepping lives in `crate::debugger_core::stepping`; this keeps the
//! `stepper::clear_single_step_flag(platform, ..)` entry the event loop uses.

use super::WindowsPlatform;
use crate::interfaces::PlatformError;

/// Clear the single-step flag of `tid` (one context round trip).
pub fn clear_single_step_flag(platform: &mut WindowsPlatform, pid: u32, tid: u32) -> Result<(), PlatformError> {
    let process = platform.get_process(pid)?;
    crate::debugger_core::stepping::clear_single_step_flag(&process.os, pid, tid)
}
