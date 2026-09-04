use super::WindowsPlatform;
use crate::interfaces::{Architecture, PlatformAPI, PlatformError};
use crate::protocol::{DebugEvent, StepKind, ThreadContext};
use tracing::{debug, trace, warn};

pub(super) fn step(
    platform: &mut WindowsPlatform,
    pid: u32,
    tid: u32,
    kind: StepKind
) -> Result<Option<DebugEvent>, PlatformError> {
    trace!(pid, tid, kind = ?kind, "WindowsPlatform::step called");

    // Per-process architecture, never the host's: a WOW64 target steps its
    // 32-bit register file (trap flag in the WOW64 context) and decodes as x86.
    let arch = platform.get_process(pid)?.architecture();
    let context = super::thread_context::get_thread_context(platform.get_process(pid)?, pid, tid)?;

    match kind {
        StepKind::Into => {
            // TODO: Special cases:
            // - If the current instruction is `PUSHF`, it delegates to `StepOver` because stepping into `PUSHF` can cause confusion with TF on the stack.
            // - If the instruction is `POP SS` or `MOV SS`, it sets a one-shot breakpoint at the instruction after.

            // WOW64 heaven's gate: the far jump into the 64-bit side of the
            // syscall stub. A 32-bit trap flag carried through it traps in
            // wow64cpu/xtajit, where the 32-bit context is meaningless, so run
            // to the 32-bit return address instead (see `x86_far_jump_return`).
            if let Some(resume_at) = x86_far_jump_return(platform, pid, arch, &context)? {
                set_step_breakpoint(platform, pid, tid, kind, resume_at)?;
            } else {
                execute_single_step(platform, pid, tid, kind, context)?;
            }
        }
        StepKind::Over => {
            // Read and disassemble the current instruction.
            // If it's a `CALL`, `REP`, or `PUSHF`, set a one-shot (single-use) breakpoint at the instruction immediately following.
            // Otherwise, perform a `StepInto`.
            //
            // Raw (non-symbolizing) disassembly: the step only needs size +
            // mnemonic, and must not contend with the symbol machinery while a
            // large PDB is parsed (that caused ~second-long step hitches).
            let instruction = platform.disassemble_instruction_raw(pid, context.pc(), arch)
                .map_err(|e| PlatformError::Other(format!("Failed to disassemble instruction: {}", e)))?
                .ok_or_else(|| PlatformError::Other("No instructions returned from disassembler".to_string()))?;
            let next_instruction_addr = instruction.address + instruction.size as u64;

            // Check if this is a CALL-like instruction
            let needs_breakpoint = match arch {
                // On ARM64, treat BL-family instructions as calls
                Architecture::Arm64 => instruction.mnemonic.starts_with("bl"),
                // On x86/x64, match call/rep/pushf variants
                Architecture::X86 | Architecture::X64 => {
                    instruction.mnemonic.starts_with("call") ||
                    instruction.mnemonic.starts_with("rep") ||
                    matches!(instruction.mnemonic.as_str(), "pushf" | "pushfq" | "pushfd")
                }
            };

            if let Some(resume_at) = x86_far_jump_return(platform, pid, arch, &context)? {
                set_step_breakpoint(platform, pid, tid, kind, resume_at)?;
            } else if needs_breakpoint {
                set_step_breakpoint(platform, pid, tid, kind, next_instruction_addr)?;
            } else {
                // For other instructions, just do a step-into
                execute_single_step(platform, pid, tid, kind, context)?;
            }
        }
        StepKind::Out => {
            // Set a persistent breakpoint at the caller's IP, filtered to the
            // current thread, instead of patching the return address. The same
            // technique on every architecture: the stack walk supplies the frame.
            let call_stack = platform.get_call_stack(pid, tid)
                .map_err(|e| PlatformError::Other(format!("Failed to get call stack for step-out: {}", e)))?;

            if let (Some(_current_frame), Some(caller_frame)) = (call_stack.first(), call_stack.get(1)) {
                let return_address = caller_frame.instruction_pointer;

                // Install a persistent, thread-filtered breakpoint at the caller's IP
                platform.set_breakpoint(pid, return_address, Some(tid))?;

                // Track this so the breakpoint handler can emit StepComplete::Out and clean up
                {
                    let proc = platform.get_process_mut(pid)?;
                    proc.insert_step_out_breakpoint(return_address, tid, return_address);
                }
                debug!(pid, tid, ?arch, "Set step-out breakpoint at caller IP 0x{:X}", return_address);
            } else {
                // We are in the top-most frame, so we can't "step out".
                warn!(pid, tid, "Cannot step out, no caller frame on the stack.");
                return Err(PlatformError::Other(
                    "Cannot step out, no caller frame on the stack.".to_string(),
                ));
            }
        }
    }

    // Stepping is set up - execution will be continued by the caller
    Ok(None)
}

/// A one-shot breakpoint that completes a step of `kind` when reached.
fn set_step_breakpoint(
    platform: &mut WindowsPlatform,
    pid: u32,
    tid: u32,
    kind: StepKind,
    address: u64,
) -> Result<(), PlatformError> {
    platform.set_single_shot_breakpoint(pid, address)?;
    platform.get_process_mut(pid)?.insert_step_over_breakpoint(address, tid, kind);
    debug!(pid, tid, ?kind, "Set one-shot breakpoint for step at 0x{:X}", address);
    Ok(())
}

/// For a 32-bit (WOW64) thread sitting on a far `jmp` — the `wow64cpu!
/// KiFastSystemCall2` / xtajit gate that the `call [ntdll!Wow64Transition]` in
/// every 32-bit syscall stub lands on — the 32-bit address execution returns
/// to: the return address the `call` pushed, at `[esp]`. `None` for any other
/// instruction or architecture.
fn x86_far_jump_return(
    platform: &WindowsPlatform,
    pid: u32,
    arch: Architecture,
    context: &ThreadContext,
) -> Result<Option<u64>, PlatformError> {
    if arch != Architecture::X86 {
        return Ok(None);
    }
    let Some(instruction) = platform.disassemble_instruction_raw(pid, context.pc(), arch)
        .map_err(|e| PlatformError::Other(format!("Failed to disassemble instruction: {}", e)))?
    else {
        return Ok(None);
    };
    if instruction.mnemonic != "ljmp" {
        return Ok(None);
    }
    let slot = platform.read_memory(pid, context.sp(), 4)?;
    let return_address = u32::from_le_bytes(slot[..4].try_into().unwrap()) as u64;
    debug!(pid, pc = %format!("0x{:X}", context.pc()), return_address = %format!("0x{:X}", return_address),
        "Far jump (WOW64 gate) — stepping to the 32-bit return address");
    Ok(Some(return_address))
}

/// Sets the single-step flag, handles any deferred hardware breakpoint state,
/// writes the context back, and records the active step.
fn execute_single_step(
    platform: &mut WindowsPlatform,
    pid: u32,
    tid: u32,
    kind: StepKind,
    mut context: ThreadContext,
) -> Result<(), PlatformError> {
    context.set_single_step(true);
    // Remove any pending re-arms for this thread to avoid misrouting the next SS
    let deferred_hw_bp_rearm;
    {
        let proc = platform.get_process_mut(pid)?;
        let _ = proc.take_pending_rearm_for_tid(tid);
        deferred_hw_bp_rearm = proc.take_pending_hw_bp_rearm(tid);
    }
    // If we took a pending HW BP rearm, ensure DR7 enable bit is cleared in the
    // context we're about to write back (CONTEXT_ALL may have a stale value).
    if let Some(dr_index) = deferred_hw_bp_rearm {
        use super::hardware_breakpoints::{x86_disable_enable_bit, X86DebugRegs};
        match &mut context {
            ThreadContext::Wow64RawContext(ctx) => {
                x86_disable_enable_bit(ctx, dr_index);
                ctx.set_dr6(0);
            }
            #[cfg(target_arch = "x86_64")]
            ThreadContext::Win32RawContext(ctx) => {
                x86_disable_enable_bit(ctx, dr_index);
                ctx.set_dr6(0);
            }
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }
    super::thread_context::set_thread_context(platform.get_process(pid)?, pid, tid, context)?;
    {
        let proc = platform.get_process_mut(pid)?;
        let replaced = proc.record_active_single_step(tid, kind, deferred_hw_bp_rearm);
        if replaced {
            debug!(pid, tid, ?kind, "Single-step flag set (replaced existing step record)");
        } else {
            debug!(pid, tid, ?kind, "Single-step flag set");
        }
    }
    Ok(())
}

/// Clear the single-step flag of `tid` (one context round trip).
pub fn clear_single_step_flag(platform: &mut WindowsPlatform, pid: u32, tid: u32) -> Result<(), PlatformError> {
    trace!(pid, tid, "Clearing single-step flag");
    super::thread_context::modify_thread_context(platform.get_process(pid)?, pid, tid, |context| {
        context.set_single_step(false);
        Ok(())
    })?;
    debug!(pid, tid, "Single-step flag cleared");
    Ok(())
}
