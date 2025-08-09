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
    let thread_context = super::thread_context::get_thread_context(platform, pid, tid)?;
    
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
            super::thread_context::set_thread_context(platform, pid, tid, updated_context)?;
            // Track this stepping operation
            platform.active_single_steps.insert((pid, tid), super::StepState { kind });
            debug!(pid, tid, "Single-step flag set");
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

            // Check if this is a CALL, REP, or PUSHF instruction
            // TODO: arm64 analogues
            let needs_breakpoint = instruction.mnemonic.starts_with("call") ||
                                 instruction.mnemonic.starts_with("rep") ||
                                 instruction.mnemonic == "pushf" ||
                                 instruction.mnemonic == "pushfq";

            if needs_breakpoint {
                // Set a one-shot breakpoint at the next instruction
                platform.set_single_shot_breakpoint(pid, next_instruction_addr)?;
                // Track this as a step-over breakpoint
                platform.step_over_breakpoints.insert(next_instruction_addr, (pid, tid, kind));
                debug!(pid, tid, "Set one-shot breakpoint for step-over at 0x{:X}", next_instruction_addr);
            } else {
                // For other instructions, just do a step-into
                set_single_step_flag_native(&mut context)?;
                // Set the modified context back using platform function
                let updated_context = ThreadContext::Win32RawContext(context);
                super::thread_context::set_thread_context(platform, pid, tid, updated_context)?;
                // Track this stepping operation
                platform.active_single_steps.insert((pid, tid), super::StepState { kind });
                debug!(pid, tid, "Step-into is used for step-over");
            }
        }
        StepKind::Out => {
            // Get the call stack to find the return address and where it's stored on the stack.
            let call_stack = platform.get_call_stack(pid, tid)
                .map_err(|e| PlatformError::Other(format!("Failed to get call stack for step-out: {}", e)))?;

            if let (Some(_current_frame), Some(caller_frame)) = (call_stack.get(0), call_stack.get(1)) {
                let stack_patch_addr = caller_frame.stack_pointer - 8;
                let original_return_address = caller_frame.instruction_pointer;
    
                if stack_patch_addr == 0 {
                    return Err(PlatformError::Other("Stack pointer is zero in call frame, cannot step out.".to_string()));
                }

                // Generate a unique fake address.
                let fake_address = 0x13370000 + platform.step_out_breakpoints.len() as u64;

                // Write the fake address to the location of the return address on the stack.
                platform.write_memory(pid, stack_patch_addr, &fake_address.to_le_bytes())?;

                // Store the mapping of fake address to the original for later restoration.
                platform.step_out_breakpoints.insert(fake_address, (pid, tid, original_return_address));
                debug!(
                    pid,
                    tid,
                    "Patched return address 0x{:X} at stack address 0x{:X} with fake address 0x{:X} for step-out.",
                    original_return_address,
                    stack_patch_addr,
                    fake_address
                );
            } else {
                // We are in the top-most frame, so we can't "step out".
                // We'll treat this as a "continue" and let the debugger run.
                warn!(pid, tid, "Cannot step out, no caller frame on the stack.");
            }
        }
    }
    
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