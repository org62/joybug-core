use super::{WindowsPlatform};
use crate::interfaces::PlatformError;
use crate::protocol::{StepKind, DebugEvent, ThreadContext};
use tracing::{trace, debug};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT
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

    // Get current thread context using platform function
    let thread_context = super::thread_context::get_thread_context(platform, pid, tid)?;
    
    let mut context = match thread_context {
        ThreadContext::Win32RawContext(ctx) => ctx,
    };

    // Set single-step flag based on architecture
    set_single_step_flag_native(&mut context)?;

    // Set the modified context back using platform function
    let updated_context = ThreadContext::Win32RawContext(context);
    super::thread_context::set_thread_context(platform, pid, tid, updated_context)?;

    debug!(pid, tid, "Single-step flag set, continuing execution");
    
    // Track this stepping operation
    platform.active_steppers.insert((pid, tid), super::StepState { kind });
    
    // Stepping is set up - execution will be continued by the caller
    Ok(None)
}

pub fn clear_single_step_flag_native2(platform: &mut WindowsPlatform, pid: u32, tid: u32) -> Result<(), PlatformError> {
    trace!(pid, tid, "Clearing single-step flag");
    
    // Get current thread context using platform function
    let thread_context = super::thread_context::get_thread_context(platform, pid, tid)?;
    
    let mut context = match thread_context {
        ThreadContext::Win32RawContext(ctx) => ctx,
    };

    // Clear single-step flag based on architecture
    clear_single_step_flag_native(&mut context)?;

    // Set the modified context back using platform function
    let updated_context = ThreadContext::Win32RawContext(context);
    super::thread_context::set_thread_context(platform, pid, tid, updated_context)?;

    debug!(pid, tid, "Single-step flag cleared");
    Ok(())
}

pub fn set_single_step_flag_native(context: &mut CONTEXT) -> Result<(), PlatformError> {
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

pub fn clear_single_step_flag_native(context: &mut CONTEXT) -> Result<(), PlatformError> {
    #[cfg(target_arch = "x86_64")]
    {
        clear_x64_single_step_flag(context)?;
    }
    #[cfg(target_arch = "aarch64")]
    {
        clear_arm64_single_step_flag(context)?;
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