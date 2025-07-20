use super::{utils, WindowsPlatform, AlignedContext};
use crate::interfaces::{PlatformError, Architecture};
use crate::protocol::{StepKind, DebugEvent};
use tracing::{error, trace, debug};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_CONTROL_X86, CONTEXT_INTEGER_X86,
    CONTEXT_CONTROL_ARM64, CONTEXT_INTEGER_ARM64
};

// x64 EFlags register Trap Flag bit
#[cfg(target_arch = "x86_64")]
const X64_TRAP_FLAG: u32 = 0x100;

// ARM64 PSTATE Single Step bit (bit 21 in PSTATE)
#[cfg(target_arch = "aarch64")]
const ARM64_PSTATE_SS_BIT: u64 = 1 << 21;

pub(super) fn step(
    platform: &mut WindowsPlatform, 
    pid: u32, 
    tid: u32, 
    kind: StepKind
) -> Result<Option<DebugEvent>, PlatformError> {
    trace!(pid, tid, kind = ?kind, "WindowsPlatform::step called");
    
    // For now, only implement Step Into
    if kind != StepKind::Into {
        return Err(PlatformError::NotImplemented);
    }

    let process = platform.get_process(pid)?;
    let thread_handle = process
        .thread_manager
        .get_thread_handle(tid)
        .ok_or_else(|| PlatformError::OsError(format!("No handle for thread {}", tid)))?;

    // Get current thread context
    let mut aligned_context = AlignedContext {
        context: unsafe { std::mem::zeroed() },
    };
    
    // Set context flags based on architecture
    match process.architecture {
        Architecture::X64 => {
            aligned_context.context.ContextFlags = CONTEXT_CONTROL_X86 | CONTEXT_INTEGER_X86;
        }
        Architecture::Arm64 => {
            aligned_context.context.ContextFlags = CONTEXT_CONTROL_ARM64 | CONTEXT_INTEGER_ARM64;
        }
    }
    
    let ok = unsafe { GetThreadContext(thread_handle, &mut aligned_context.context) };
    if ok == 0 {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "GetThreadContext failed in step");
        return Err(PlatformError::OsError(format!(
            "GetThreadContext failed: {} ({})",
            error, error_str
        )));
    }

    // Set single-step flag based on architecture
    set_single_step_flag_native(&mut aligned_context.context)?;

    // Set the modified context back
    let ok = unsafe { SetThreadContext(thread_handle, &aligned_context.context) };
    if ok == 0 {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "SetThreadContext failed in step");
        return Err(PlatformError::OsError(format!(
            "SetThreadContext failed: {} ({})",
            error, error_str
        )));
    }

    debug!(pid, tid, "Single-step flag set, continuing execution");
    
    // Track this stepping operation
    platform.active_steppers.insert((pid, tid), super::StepState { kind });
    
    // Stepping is set up - execution will be continued by the caller
    Ok(None)
}

fn set_single_step_flag_native(context: &mut CONTEXT) -> Result<(), PlatformError> {
    #[cfg(target_arch = "x86_64")]
    {
        set_x64_single_step_flag(context)?;
    }
    #[cfg(target_arch = "aarch64")]
    {
        set_arm64_single_step_flag(context)?;
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn set_x64_single_step_flag(context: &mut CONTEXT) -> Result<(), PlatformError> {
    // For x64, set the Trap Flag (TF) in the EFLAGS register
    context.EFlags |= X64_TRAP_FLAG;
    trace!("Set x64 Trap Flag in EFLAGS register");
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub(super) fn clear_x64_single_step_flag(context: &mut CONTEXT) -> Result<(), PlatformError> {
    // Clear the Trap Flag (TF) in the EFLAGS register
    context.EFlags &= !X64_TRAP_FLAG;
    trace!("Cleared x64 Trap Flag in EFLAGS register");
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn set_arm64_single_step_flag(context: &mut CONTEXT) -> Result<(), PlatformError> {
    // For ARM64, set the SS (Single-Step) bit in the CPSR register
    // The CONTEXT structure has a direct Cpsr field we can access
    context.Cpsr |= ARM64_PSTATE_SS_BIT as u32;
    trace!("Set ARM64 SS bit in CPSR: 0x{:08x}", context.Cpsr);
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub(super) fn clear_arm64_single_step_flag(context: &mut CONTEXT) -> Result<(), PlatformError> {
    // Clear the SS (Single-Step) bit from the CPSR register
    context.Cpsr &= !(ARM64_PSTATE_SS_BIT as u32);
    trace!("Cleared ARM64 SS bit in CPSR: 0x{:08x}", context.Cpsr);
    Ok(())
} 