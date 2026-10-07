//! Stepping state: the user's active single-steps, the breakpoints the stepper
//! plants, and the freeze/defer protocol that steps a thread over a
//! temporarily-removed software breakpoint without the other threads running
//! through the hole.

use super::breakpoints::{arm_persistent, arm_single_shot, instruction_is_syscall, rearm_if_matches_original};
use super::disasm::decode_one;
use super::disassembler::CapstoneDisassembler;
use super::hw_breakpoints::{x86_disable_enable_bit, X86DebugRegs};
use super::ops::ProcessOps;
use super::DebugBook;
use crate::interfaces::{Architecture, CallFrame, PlatformError};
use crate::protocol::{DebugEvent, StepKind, ThreadContext};
use std::collections::{HashMap, HashSet};
use tracing::{debug, trace, warn};

/// What the user asked a thread to do, recorded while the step is in flight.
#[derive(Debug, Clone)]
pub struct StepState {
    pub kind: StepKind,
    /// If set, a hardware breakpoint DR index that needs re-arming after the
    /// step completes. Only read on x86-family targets (DR-register based
    /// hardware breakpoints).
    pub deferred_hw_bp_rearm: Option<u8>,
}

#[derive(Debug, Default)]
pub struct StepBook {
    /// Active stepping operations by tid.
    active: HashMap<u32, StepState>,
    /// Threads that need re-arming after a single-step: tid -> (address, is_single_shot).
    pending_rearm: HashMap<u32, (u64, bool)>,
    /// Threads currently stepping over a temporarily-removed software breakpoint
    /// (INT3 removed, awaiting the single-step that re-arms it), mapped to the
    /// breakpoint address they are stepping over and whether the step-over is
    /// *exclusive* (other threads frozen + their events deferred). Such a thread
    /// must be allowed to run and must never be frozen by another thread's
    /// step-over. Non-exclusive step-overs are used for instructions that can
    /// block (see [`instruction_is_syscall`]).
    stepping_over: HashMap<u32, (u64, bool)>,
    /// Threads we have frozen (exactly once each) to keep them out of a software
    /// breakpoint while its INT3 is removed. Thawed once no step-over remains
    /// in flight.
    frozen: HashSet<u32>,
    /// Pending hardware-breakpoint re-arm after a single-step: tid -> dr_index.
    pending_hw_rearm: HashMap<u32, u8>,
}

impl StepBook {
    /// Schedule a single-step rearm for (tid -> address).
    pub fn schedule_rearm_after_single_step(&mut self, tid: u32, address: u64, is_single_shot: bool) {
        self.pending_rearm.insert(tid, (address, is_single_shot));
    }

    /// Remove and return a pending rearm entry for a thread, if any.
    pub fn has_pending_rearm_for_tid(&self, tid: u32) -> bool {
        self.pending_rearm.contains_key(&tid)
    }

    pub fn take_pending_rearm_for_tid(&mut self, tid: u32) -> Option<(u64, bool)> {
        self.pending_rearm.remove(&tid)
    }

    /// Record that a thread is in an active single-step operation. Returns true
    /// if an existing record for this thread was replaced.
    pub fn record_active_single_step(&mut self, tid: u32, kind: StepKind, deferred_hw_bp_rearm: Option<u8>) -> bool {
        self.active
            .insert(tid, StepState { kind, deferred_hw_bp_rearm })
            .is_some()
    }

    pub fn has_active_single_step(&self, tid: u32) -> bool {
        self.active.contains_key(&tid)
    }

    /// Take and remove the active single-step state for a thread, if any.
    pub fn take_active_single_step(&mut self, tid: u32) -> Option<StepState> {
        self.active.remove(&tid)
    }

    /// Schedule a HW BP re-arm after a single-step for the given thread.
    pub fn schedule_hw_bp_rearm(&mut self, tid: u32, dr_index: u8) {
        self.pending_hw_rearm.insert(tid, dr_index);
    }

    /// Take and remove a pending HW BP re-arm for a thread.
    pub fn take_pending_hw_bp_rearm(&mut self, tid: u32) -> Option<u8> {
        self.pending_hw_rearm.remove(&tid)
    }

    /// The thread whose *exclusive* step-over is in flight, if any - the only
    /// kind that freezes threads and defers events, and so the only kind that
    /// may gate the thaw. At most one exists at a time (event deferral
    /// serializes them). A non-exclusive step-over must never gate anything:
    /// it can sit in a blocking syscall for an unbounded time (an idle worker
    /// thread parked in `NtWaitForWorkViaWorkerFactory` never returns), which
    /// would leave another stepper's frozen threads suspended forever.
    pub fn exclusive_stepper(&self) -> Option<u32> {
        self.stepping_over
            .iter()
            .find_map(|(&tid, &(_, exclusive))| exclusive.then_some(tid))
    }

    /// Whether some *other* thread is currently mid exclusive software-breakpoint
    /// step-over (INT3 removed) - i.e. an event for `tid` should be deferred
    /// rather than processed now. False for the stepping thread's own
    /// single-step event, and false for non-exclusive step-overs: deferring an
    /// event blocks that thread just like freezing it would, which is exactly
    /// what deadlocks a blocking instruction's step-over.
    pub fn is_stepping_over_other_thread(&self, tid: u32) -> bool {
        self.exclusive_stepper().is_some_and(|stepper| stepper != tid)
    }
}

/// Begin a software-breakpoint step-over for `tid` at `address`: freeze every
/// other thread so none can execute through `address` while its INT3 is
/// temporarily removed (the multi-threaded software-breakpoint race).
///
/// Resuming the debuggee resumes the *entire* process, not just the stepping
/// thread, so without this freeze another thread could run straight through
/// the now-INT3-less address and its hit would be silently lost.
///
/// Only one *exclusive* step-over is ever in flight at a time: the debug loop
/// defers any other thread's event until the step-over completes, so a second
/// thread that also hit the same breakpoint is not processed concurrently. The
/// stepping thread itself is never frozen (it must run to deliver its
/// single-step); a defensive thaw is kept in case an earlier step-over had
/// frozen it.
///
/// A step-over of an instruction that can block indefinitely (a syscall - see
/// [`instruction_is_syscall`]) is *non-exclusive*: nothing is frozen or
/// deferred, the step-over is only registered so the single-step still re-arms
/// the breakpoint. Freezing the threads that would unblock such an instruction
/// deadlocks the whole process. The cost is the original race: another thread
/// may run through the disarmed address and its hit is lost. The decision is
/// made here, not by callers, so no call site can reintroduce the deadlock.
/// Call this *after* the original bytes have been restored.
///
/// `context` labels the trace output (e.g. "coverage", "breakpoint").
pub fn begin_step_over<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    tid: u32,
    address: u64,
    context: &'static str,
) {
    let exclusive = !instruction_is_syscall(&book.bps, ops, pid, address);
    let steps = &mut book.steps;
    steps.stepping_over.insert(tid, (address, exclusive));

    // The stepping thread must run; thaw it if an earlier step-over froze it.
    if steps.frozen.remove(&tid) {
        let _ = ops.thaw_thread(pid, tid);
    }

    if !exclusive {
        trace!(pid, tid, address = %format!("0x{:X}", address), context, "Step-over of a syscall: not freezing other threads");
        return;
    }

    let mut newly_frozen = 0;
    for other in ops.live_threads(pid) {
        if other == tid || steps.stepping_over.contains_key(&other) || steps.frozen.contains(&other) {
            continue;
        }
        match ops.freeze_thread(pid, other) {
            Ok(()) => {
                steps.frozen.insert(other);
                newly_frozen += 1;
            }
            Err(e) => {
                // Typically a thread that has already exited (the thread table
                // keeps entries across exit); such a thread cannot run through
                // the breakpoint anyway, so this is not a correctness concern.
                trace!(tid = other, error = %e, "freeze skipped during breakpoint step-over (thread may have exited)");
            }
        }
    }
    if newly_frozen > 0 {
        trace!(pid, tid, address = %format!("0x{:X}", address), frozen = newly_frozen, context, "Froze other threads for step-over");
    }
}

/// Complete the step-over for `tid` (its single-step has delivered): re-arm
/// the INT3 it was stepping over and, once no exclusive step-over remains in
/// flight, thaw the threads frozen by [`begin_step_over`]. The order is the
/// safety contract - frozen threads may only run again after the INT3 is back
/// in place.
///
/// No-op returning 0 if `tid` was not mid-step-over. Returns the number of
/// threads thawed.
pub fn complete_step_over<O: ProcessOps + ?Sized>(book: &mut DebugBook, ops: &O, pid: u32, tid: u32) -> usize {
    let Some((addr, _exclusive)) = book.steps.stepping_over.remove(&tid) else {
        return 0;
    };
    let _ = rearm_if_matches_original(&book.bps, ops, pid, addr);
    if book.steps.exclusive_stepper().is_none() {
        resume_frozen_threads(&mut book.steps, ops, pid)
    } else {
        0
    }
}

/// Thaw every thread frozen for a step-over. Returns the number thawed.
pub fn resume_frozen_threads<O: ProcessOps + ?Sized>(steps: &mut StepBook, ops: &O, pid: u32) -> usize {
    let mut resumed = 0;
    for other in std::mem::take(&mut steps.frozen) {
        match ops.thaw_thread(pid, other) {
            Ok(()) => resumed += 1,
            Err(e) => trace!(tid = other, error = %e, "thaw skipped after breakpoint step-over (thread may have exited)"),
        }
    }
    resumed
}

/// Drop `tid` from all step-over bookkeeping (used when a thread exits). If it
/// was the last *exclusive* stepper in flight, remaining frozen threads are
/// thawed.
pub fn forget_thread_step_over<O: ProcessOps + ?Sized>(steps: &mut StepBook, ops: &O, pid: u32, tid: u32) {
    steps.frozen.remove(&tid);
    steps.stepping_over.remove(&tid);
    if steps.exclusive_stepper().is_none() {
        resume_frozen_threads(steps, ops, pid);
    }
}

/// Thaw every frozen thread and clear step-over state (safety net on process
/// cleanup).
pub fn resume_all_step_over_suspensions<O: ProcessOps + ?Sized>(steps: &mut StepBook, ops: &O, pid: u32) {
    steps.stepping_over.clear();
    resume_frozen_threads(steps, ops, pid);
}

// ============================================================================
// The step algorithm
// ============================================================================

/// Arm a step of `kind` for `tid`. Returns `Ok(None)`: the step is set up and
/// completes as a `StepComplete` event once the caller resumes the process.
///
/// `call_stack` is the thread's call stack, needed only for [`StepKind::Out`]
/// (the caller computes it before taking the book mutably).
pub fn step<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    disasm: &CapstoneDisassembler,
    pid: u32,
    tid: u32,
    kind: StepKind,
    call_stack: Option<Vec<CallFrame>>,
) -> Result<Option<DebugEvent>, PlatformError> {
    trace!(pid, tid, kind = ?kind, "step called");

    // Per-process architecture, never the host's: a WOW64 target steps its
    // 32-bit register file (trap flag in the WOW64 context) and decodes as x86.
    let arch = book.arch;
    let context = ops.get_context(pid, tid)?;

    match kind {
        StepKind::Into => {
            // TODO: Special cases:
            // - If the current instruction is `PUSHF`, it delegates to `StepOver` because stepping into `PUSHF` can cause confusion with TF on the stack.
            // - If the instruction is `POP SS` or `MOV SS`, it sets a one-shot breakpoint at the instruction after.

            // WOW64 heaven's gate: the far jump into the 64-bit side of the
            // syscall stub. A 32-bit trap flag carried through it traps in
            // wow64cpu/xtajit, where the 32-bit context is meaningless, so run
            // to the 32-bit return address instead (see `x86_far_jump_return`).
            if let Some(resume_at) = x86_far_jump_return(book, ops, disasm, pid, arch, &context)? {
                set_step_breakpoint(book, ops, pid, tid, kind, resume_at)?;
            } else {
                execute_single_step(book, ops, pid, tid, kind, context)?;
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
            let instruction = decode_one(ops, &book.bps, disasm, pid, context.pc(), arch)
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

            if let Some(resume_at) = x86_far_jump_return(book, ops, disasm, pid, arch, &context)? {
                set_step_breakpoint(book, ops, pid, tid, kind, resume_at)?;
            } else if needs_breakpoint {
                set_step_breakpoint(book, ops, pid, tid, kind, next_instruction_addr)?;
            } else {
                // For other instructions, just do a step-into
                execute_single_step(book, ops, pid, tid, kind, context)?;
            }
        }
        StepKind::Out => {
            // Set a persistent breakpoint at the caller's IP, filtered to the
            // current thread, instead of patching the return address. The same
            // technique on every architecture: the stack walk supplies the frame.
            let call_stack = call_stack.ok_or_else(|| PlatformError::Other("step-out needs a call stack".to_string()))?;

            if let (Some(_current_frame), Some(caller_frame)) = (call_stack.first(), call_stack.get(1)) {
                let return_address = caller_frame.instruction_pointer;

                // Install a persistent, thread-filtered breakpoint at the caller's IP
                arm_persistent(&mut book.bps, ops, pid, return_address, Some(tid))?;

                // Track this so the breakpoint handler can emit StepComplete::Out and clean up
                book.bps.insert_step_out(return_address, tid, return_address);
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
fn set_step_breakpoint<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    tid: u32,
    kind: StepKind,
    address: u64,
) -> Result<(), PlatformError> {
    arm_single_shot(&mut book.bps, ops, pid, address)?;
    book.bps.insert_step_over(address, tid, kind);
    debug!(pid, tid, ?kind, "Set one-shot breakpoint for step at 0x{:X}", address);
    Ok(())
}

/// For a 32-bit (WOW64) thread sitting on a far `jmp` - the `wow64cpu!
/// KiFastSystemCall2` / xtajit gate that the `call [ntdll!Wow64Transition]` in
/// every 32-bit syscall stub lands on - the 32-bit address execution returns
/// to: the return address the `call` pushed, at `[esp]`. `None` for any other
/// instruction or architecture.
fn x86_far_jump_return<O: ProcessOps + ?Sized>(
    book: &DebugBook,
    ops: &O,
    disasm: &CapstoneDisassembler,
    pid: u32,
    arch: Architecture,
    context: &ThreadContext,
) -> Result<Option<u64>, PlatformError> {
    if arch != Architecture::X86 {
        return Ok(None);
    }
    let Some(instruction) = decode_one(ops, &book.bps, disasm, pid, context.pc(), arch)
        .map_err(|e| PlatformError::Other(format!("Failed to disassemble instruction: {}", e)))?
    else {
        return Ok(None);
    };
    if instruction.mnemonic != "ljmp" {
        return Ok(None);
    }
    let slot = ops.read(pid, context.sp(), 4)?;
    let return_address = u32::from_le_bytes(slot[..4].try_into().unwrap()) as u64;
    debug!(pid, pc = %format!("0x{:X}", context.pc()), return_address = %format!("0x{:X}", return_address),
        "Far jump (WOW64 gate) - stepping to the 32-bit return address");
    Ok(Some(return_address))
}

/// Sets the single-step flag, handles any deferred hardware breakpoint state,
/// writes the context back, and records the active step.
fn execute_single_step<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    tid: u32,
    kind: StepKind,
    mut context: ThreadContext,
) -> Result<(), PlatformError> {
    context.set_single_step(true);
    // Remove any pending re-arms for this thread to avoid misrouting the next SS
    let _ = book.steps.take_pending_rearm_for_tid(tid);
    let deferred_hw_bp_rearm = book.steps.take_pending_hw_bp_rearm(tid);
    // If we took a pending HW BP rearm, ensure DR7 enable bit is cleared in the
    // context we're about to write back (CONTEXT_ALL may have a stale value).
    if let Some(dr_index) = deferred_hw_bp_rearm {
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
    ops.set_context(pid, tid, context)?;
    let replaced = book.steps.record_active_single_step(tid, kind, deferred_hw_bp_rearm);
    if replaced {
        debug!(pid, tid, ?kind, "Single-step flag set (replaced existing step record)");
    } else {
        debug!(pid, tid, ?kind, "Single-step flag set");
    }
    Ok(())
}

/// Clear the single-step flag of `tid` (one context round trip).
pub fn clear_single_step_flag<O: ProcessOps + ?Sized>(ops: &O, pid: u32, tid: u32) -> Result<(), PlatformError> {
    trace!(pid, tid, "Clearing single-step flag");
    ops.modify_context(pid, tid, &mut |context| {
        context.set_single_step(false);
        Ok(())
    })?;
    debug!(pid, tid, "Single-step flag cleared");
    Ok(())
}
