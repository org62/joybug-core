use super::{WindowsPlatform};
use crate::interfaces::{PlatformAPI, PlatformError};
use crate::protocol::{StepKind, DebugEvent, ThreadContext};
use crate::interfaces::Architecture;
use tracing::{trace, debug, warn};
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

    // Get current thread context using platform function
    let thread_context = super::thread_context::get_thread_context(platform.get_process(pid)?, pid, tid)?;
    
    let mut context = match thread_context {
        ThreadContext::Win32RawContext(ctx) => ctx,
    };

    // Set single-step flag based on architecture
    match kind {
        StepKind::Into => {

            // TODO: Special cases:
            // - If the current instruction is `PUSHF`, it delegates to `StepOver` because stepping into `PUSHF` can cause confusion with TF on the stack.
            // - If the instruction is `POP SS` or `MOV SS`, it sets a one-shot breakpoint at the instruction after.

            set_single_step_flag_native(&mut context)?;
            // Set the modified context back using platform function
            let updated_context = ThreadContext::Win32RawContext(context);
            super::thread_context::set_thread_context(platform.get_process(pid)?, pid, tid, updated_context)?;
            // Track this stepping operation
            // Remove any pending re-arm for this thread to avoid misrouting the next SS
            {
                let proc = platform.get_process_mut(pid)?;
                let _ = proc.take_pending_rearm_for_tid(tid);
                let replaced = proc.record_active_single_step(tid, kind);
                if replaced {
                    debug!(pid, tid, "Single-step flag set (replaced existing step record for this thread)");
                } else {
                    debug!(pid, tid, "Single-step flag set");
                }
            }
        }
        StepKind::Over => {
            // Read and disassemble the current instruction.
            // If it's a `CALL`, `REP`, or `PUSHF`, set a one-shot (single-use) breakpoint at the instruction immediately following.
            // Otherwise, perform a `StepInto`.
            let arch = Architecture::from_native();
            let instructions = platform.disassemble_memory(pid, thread_context.get_pc(), 1, arch)
                .map_err(|e| PlatformError::Other(format!("Failed to disassemble instruction: {}", e)))?;
            
            let instruction = instructions.first().ok_or_else(|| PlatformError::Other("No instructions returned from disassembler".to_string()))?;
            let next_instruction_addr = instruction.address + instruction.size as u64;

            // Check if this is a CALL-like instruction
            let needs_breakpoint = if matches!(arch, Architecture::Arm64) {
                // On ARM64, treat BL-family instructions as calls
                instruction.mnemonic.starts_with("bl")
            } else {
                // On x64, match call/rep/pushf variants
                instruction.mnemonic.starts_with("call") ||
                instruction.mnemonic.starts_with("rep") ||
                instruction.mnemonic == "pushf" ||
                instruction.mnemonic == "pushfq"
            };

            if needs_breakpoint {
                // Set a one-shot breakpoint at the next instruction
                platform.set_single_shot_breakpoint(pid, next_instruction_addr)?;
                // Track this as a step-over breakpoint
                {
                    let proc = platform.get_process_mut(pid)?;
                    proc.insert_step_over_breakpoint(next_instruction_addr, tid, kind);
                }
                debug!(pid, tid, "Set one-shot breakpoint for step-over at 0x{:X}", next_instruction_addr);
            } else {
                // For other instructions, just do a step-into
                set_single_step_flag_native(&mut context)?;
                // Set the modified context back using platform function
                let updated_context = ThreadContext::Win32RawContext(context);
                super::thread_context::set_thread_context(platform.get_process(pid)?, pid, tid, updated_context)?;
                // Track this stepping operation
                // Remove any pending re-arm for this thread to avoid misrouting the next SS
                {
                    let proc = platform.get_process_mut(pid)?;
                    let _ = proc.take_pending_rearm_for_tid(tid);
                    let replaced = proc.record_active_single_step(tid, kind);
                    if replaced {
                        debug!(pid, tid, "Step-into is used for step-over (replaced existing step record for this thread)");
                    } else {
                        debug!(pid, tid, "Step-into is used for step-over");
                    }
                }
            }
        }
        StepKind::Out => {
            #[cfg(target_arch = "x86_64")]
            {
                // On x64, use the same technique as ARM64: set a persistent breakpoint at the caller's IP
                // filtered to the current thread, instead of patching the return address.
                let call_stack = platform.get_call_stack(pid, tid)
                    .map_err(|e| PlatformError::Other(format!("Failed to get call stack for step-out: {}", e)))?;

                if let (Some(_current_frame), Some(caller_frame)) = (call_stack.get(0), call_stack.get(1)) {
                    let return_address = caller_frame.instruction_pointer;

                    // Install a persistent, thread-filtered breakpoint at the caller's IP
                    platform.set_breakpoint(pid, return_address, Some(tid))?;

                    // Track this so the breakpoint handler can emit StepComplete::Out and clean up
                    {
                        let proc = platform.get_process_mut(pid)?;
                        proc.insert_step_out_breakpoint(return_address, tid, return_address);
                    }
                    debug!(
                        pid,
                        tid,
                        "Set step-out breakpoint at caller IP 0x{:X} (x64)",
                        return_address
                    );
                } else {
                    // We are in the top-most frame, so we can't "step out".
                    warn!(pid, tid, "Cannot step out, no caller frame on the stack.");
                    return Err(PlatformError::Other(
                        "Cannot step out, no caller frame on the stack.".to_string(),
                    ));
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                // On ARM64, set a persistent breakpoint at the caller frame's instruction pointer,
                // filtered to the current thread so other threads ignore it.
                let call_stack = platform.get_call_stack(pid, tid)
                    .map_err(|e| PlatformError::Other(format!("Failed to get call stack for step-out: {}", e)))?;

                if let (Some(_current_frame), Some(caller_frame)) = (call_stack.get(0), call_stack.get(1)) {
                    let return_address = caller_frame.instruction_pointer;

                    // Install a persistent, thread-filtered breakpoint at the caller's IP
                    platform.set_breakpoint(pid, return_address, Some(tid))?;

                    // Track this so the breakpoint handler can emit StepComplete::Out and clean up
                    {
                        let proc = platform.get_process_mut(pid)?;
                        proc.insert_step_out_breakpoint(return_address, tid, return_address);
                    }
                    debug!(
                        pid,
                        tid,
                        "Set step-out breakpoint at caller IP 0x{:X} (ARM64)",
                        return_address
                    );
                } else {
                    warn!(pid, tid, "Cannot step out, no caller frame on the stack.");
                    return Err(PlatformError::Other(
                        "Cannot step out, no caller frame on the stack.".to_string(),
                    ));
                }
            }
        }
    }
    
    // Stepping is set up - execution will be continued by the caller
    Ok(None)
}

pub fn clear_single_step_flag_native2(platform: &mut WindowsPlatform, pid: u32, tid: u32) -> Result<(), PlatformError> {
    trace!(pid, tid, "Clearing single-step flag");
    
    // Get current thread context using platform function
    let thread_context = super::thread_context::get_thread_context(platform.get_process_mut(pid)?, pid, tid)?;
    
    let mut context = match thread_context {
        ThreadContext::Win32RawContext(ctx) => ctx,
    };

    // Clear single-step flag based on architecture
    clear_single_step_flag_native(&mut context)?;

    // Set the modified context back using platform function
    let updated_context = ThreadContext::Win32RawContext(context);
    super::thread_context::set_thread_context(platform.get_process_mut(pid)?, pid, tid, updated_context)?;

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