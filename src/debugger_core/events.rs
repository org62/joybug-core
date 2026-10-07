//! Turning a breakpoint or single-step trap into a `DebugEvent`: the one
//! dispatch ladder every backend runs. Returning `Ok(None)` means the trap
//! was internal (a re-arm step, a coverage hit, a stale hit) and the caller
//! resumes the process silently.
//!
//! The breakpoint ladder, in order: single-shot -> coverage -> internal hook ->
//! persistent (step-out or user) -> stale -> initial/unknown. The single-step
//! ladder: software re-arm -> hardware re-arm -> user step -> DR6 hit ->
//! unexpected. The order is the multi-thread safety story and must not change.

use super::breakpoints::{is_stale_hit, remove_breakpoint, rearm_if_matches_original, restore_persistent_original};
use super::coverage::deactivate_coverage;
use super::ops::{HookDisposition, InitialBpPolicy, ProcessOps};
use super::stepping::{begin_step_over, clear_single_step_flag, complete_step_over};
use super::DebugBook;
use crate::interfaces::PlatformError;
use crate::protocol::{DebugEvent, StepKind};
use tracing::{debug, error, trace, warn};

/// The OS's description of the trap, passed through to the client where the
/// ladder reports a raw `Exception`.
#[derive(Debug, Clone, Copy)]
pub struct TrapInfo {
    /// The exception code as the client sees it (an NTSTATUS value).
    pub code: u32,
    pub first_chance: bool,
}

/// Rewind `tid`'s instruction pointer to `address` (the software breakpoint
/// whose INT3/BRK byte was just restored) and, when `single_step` is set, also
/// set the CPU single-step flag - one context round trip for both. Shared by
/// the single-shot, coverage, and persistent breakpoint paths.
fn reset_ip_after_breakpoint<O: ProcessOps + ?Sized>(
    ops: &O,
    pid: u32,
    tid: u32,
    address: u64,
    single_step: bool,
) -> Result<(), PlatformError> {
    ops.modify_context(pid, tid, &mut |context| {
        context.set_pc(address);
        if single_step {
            context.set_single_step(true);
        }
        Ok(())
    })
}

/// A breakpoint trap at `address` (the breakpoint instruction's own address).
pub fn on_breakpoint<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    tid: u32,
    address: u64,
    trap: TrapInfo,
) -> Result<Option<DebugEvent>, PlatformError> {
    // Gather single-shot removal and possible step-over removal in one borrow
    let (single_shot_original_opt, step_over_hit_opt) = {
        let ss = book.bps.remove_single_shot(address);
        let so = book.bps.remove_step_over(address);
        (ss, so)
    };
    if let Some(original_bytes) = single_shot_original_opt {
        trace!(address = %format!("0x{:X}", address), "Single-shot breakpoint hit. Restoring original bytes.");

        // Restore the original byte and set IP back to the original instruction
        ops.write(pid, address, &original_bytes)?;
        reset_ip_after_breakpoint(ops, pid, tid, address, false)?;

        // If this was a step-over breakpoint, we already removed it above
        if let Some((tid_hit, kind)) = step_over_hit_opt {
            return Ok(Some(DebugEvent::StepComplete { pid, tid: tid_hit, kind, address }));
        } else {
            return Ok(Some(DebugEvent::SingleShotBreakpoint { pid, tid, address }));
        }
    }

    // Code-coverage breakpoint path: count the hit server-side and
    // auto-continue *silently* (never forwarded to the client). Reuses the
    // same restore / reset-IP / step-over-re-arm machinery as the persistent
    // path below. Checked before the persistent path because coverage INT3s
    // are also stored as persistent breakpoints.
    if let Some((count, limit)) = book.coverage.record_hit(address, tid) {
        trace!(address = %format!("0x{:X}", address), count, limit, "Coverage breakpoint hit");

        // Restore the original instruction bytes so the real instruction runs.
        restore_persistent_original(&book.bps, ops, pid, address)?;

        if limit != 0 && count >= limit {
            // Limit reached: leave the original byte in place (INT3 gone) and
            // drop the persistent entry. The instruction runs normally on the
            // auto-continue; no single-step / re-arm needed.
            deactivate_coverage(book, ops, pid, address);
            reset_ip_after_breakpoint(ops, pid, tid, address, false)?;
        } else {
            // Keep counting: single-step over the restored instruction and
            // re-arm the INT3 afterwards, freezing other threads while it is
            // temporarily removed (multi-threaded software-breakpoint race -
            // `begin_step_over` skips the freeze for blocking syscalls).
            book.steps.schedule_rearm_after_single_step(tid, address, false);
            begin_step_over(book, ops, pid, tid, address, "coverage");
            reset_ip_after_breakpoint(ops, pid, tid, address, true)?;
        }

        // Silent: the server auto-continues without exposing this to the client.
        return Ok(None);
    }

    // Internal hook path (a backend's own breakpoint, e.g. the Linux loader
    // notification or the entry-point stop): the same restore / re-arm
    // mechanics as a persistent breakpoint, but the backend decides what, if
    // anything, the client sees and whether the hook stays armed.
    if let Some(hook_id) = book.bps.internal_hook_at(address) {
        trace!(address = %format!("0x{:X}", address), hook_id, "Internal hook hit");
        restore_persistent_original(&book.bps, ops, pid, address)?;
        let (event, disposition) = ops.on_internal_hook(pid, tid, hook_id)?;
        match disposition {
            HookDisposition::Remove => {
                reset_ip_after_breakpoint(ops, pid, tid, address, false)?;
                let _ = remove_breakpoint(&mut book.bps, ops, pid, address);
            }
            HookDisposition::Keep => {
                book.steps.schedule_rearm_after_single_step(tid, address, false);
                begin_step_over(book, ops, pid, tid, address, "internal hook");
                reset_ip_after_breakpoint(ops, pid, tid, address, true)?;
            }
        }
        if matches!(event, Some(DebugEvent::InitialBreakpoint { .. })) {
            book.has_hit_initial_breakpoint = true;
        }
        return Ok(event);
    }

    // Persistent breakpoint path
    if book.bps.is_persistent(address) {
        trace!(address = %format!("0x{:X}", address), "Persistent breakpoint hit. Restoring original bytes and handling re-arm or step-out.");

        let is_thread_match = book.bps.persistent_allowed_for_tid(address, tid);
        let is_step_out_hit = book.bps.has_step_out(address);

        // Restore original instruction bytes
        restore_persistent_original(&book.bps, ops, pid, address)?;

        // Is this a step-out completion?
        if is_thread_match && is_step_out_hit {
            let step_out_info = book.bps.remove_step_out(address);
            if let Some((tid2, original_return_address)) = step_out_info {
                reset_ip_after_breakpoint(ops, pid, tid, address, false)?;
                let _ = remove_breakpoint(&mut book.bps, ops, pid, address);
                return Ok(Some(DebugEvent::StepComplete {
                    pid,
                    tid: tid2,
                    kind: StepKind::Out,
                    address: original_return_address,
                }));
            }
        }

        // Not a step-out: schedule SS to pass and re-arm
        book.steps.schedule_rearm_after_single_step(tid, address, false);
        // Freeze all other threads for the duration of the single-step so no
        // other thread can execute through `address` while its INT3 is
        // temporarily removed (multi-threaded software-breakpoint race). They
        // are resumed once every stepper's breakpoint is re-armed.
        // `begin_step_over` skips the freeze for blocking syscalls.
        begin_step_over(book, ops, pid, tid, address, "breakpoint");
        // Reset IP to the original instruction and set the single-step flag
        // in one context round trip.
        reset_ip_after_breakpoint(ops, pid, tid, address, true)?;

        if is_thread_match {
            return Ok(Some(DebugEvent::Breakpoint { pid, tid, address }));
        } else {
            return Ok(Some(DebugEvent::Exception {
                pid,
                tid,
                code: trap.code,
                address,
                first_chance: trap.first_chance,
                parameters: vec![],
            }));
        }
    }

    // Stale hit on a software breakpoint we already removed. Resuming resumes
    // the whole process, so on a multi-core machine several threads can trap
    // on the same INT3 before the debugger sees the first event; the extra
    // events are delivered after we have restored the original instruction (a
    // coverage breakpoint reaching its hit limit, `StopCodeCoverage`, or a plain
    // `RemoveBreakpoint`). The trap was ours, so rewind the IP to re-execute the
    // restored instruction and continue silently. Without this the hit surfaces
    // as an unknown breakpoint with the IP one byte past the INT3, and resuming
    // from there runs the tail of an instruction - usually an access violation.
    if is_stale_hit(&book.bps, ops, pid, address) {
        debug!(pid, tid, address = %format!("0x{:X}", address), "Stale software breakpoint hit (already removed); rewinding IP and continuing");
        reset_ip_after_breakpoint(ops, pid, tid, address, false)?;
        return Ok(None);
    }

    // Initial or regular breakpoint
    let is_initial_breakpoint = match ops.initial_breakpoint_policy() {
        InitialBpPolicy::FirstUnownedTrap => {
            let not_hit = !book.has_hit_initial_breakpoint;
            if not_hit {
                book.has_hit_initial_breakpoint = true;
            }
            not_hit
        }
        // The backend reports the initial breakpoint through an internal hook.
        InitialBpPolicy::InternalHook => false,
    };
    if is_initial_breakpoint {
        Ok(Some(DebugEvent::InitialBreakpoint { pid, tid, address }))
    } else {
        // Not one of ours: the debuggee executed its own int3/brk. The IP is left
        // where the trap put it (past the INT3 on x64), so a client that just
        // continues resumes mid-instruction unless it knows better.
        warn!(pid, tid, address = %format!("0x{:X}", address), "Breakpoint not owned by the debugger (int3/brk in the target)");
        Ok(Some(DebugEvent::Breakpoint { pid, tid, address }))
    }
}

/// A single-step trap (trap flag, or on x86 a possible debug-register hit)
/// with the thread's instruction pointer at `address`.
pub fn on_single_step<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    tid: u32,
    address: u64,
    trap: TrapInfo,
) -> Result<Option<DebugEvent>, PlatformError> {
    let arch = book.arch;

    // Handle SW breakpoint re-arming first
    // Return None so the server auto-continues without exposing this internal event to the client
    if let Some((rearm_addr, _is_single_shot)) = book.steps.take_pending_rearm_for_tid(tid) {
        trace!(pid = pid, tid = tid, rearm_addr = %format!("0x{:X}", rearm_addr), "SS used for persistent breakpoint re-arm");
        if let Err(e) = clear_single_step_flag(ops, pid, tid) { error!("Failed to clear single-step flag: {}", e); }
        // This thread finished stepping over its breakpoint: re-arm the
        // INT3 and, once no step-over remains, resume the frozen threads.
        let resumed = complete_step_over(book, ops, pid, tid);
        if resumed > 0 {
            trace!(pid, tid, resumed, "Resumed other threads after breakpoint step-over");
        }
        return Ok(None);
    }

    // Handle HW breakpoint re-arming (after stepping past a HW BP)
    // Return None so the server auto-continues without exposing this internal event to the client
    if let Some(rearm_dr_index) = book.steps.take_pending_hw_bp_rearm(tid) {
        trace!(pid, tid, rearm_dr_index, "SS used for hardware breakpoint re-arm");
        // Re-enable the HW BP and clear the trap flag (x64 native or WOW64).
        if arch.is_x86_family() {
            if let Err(e) = ops.modify_debug_regs(pid, tid, true, &mut |regs| {
                regs.enable_bit(rearm_dr_index);
                regs.set_trap_flag(false);
                true
            }) {
                error!("Failed to re-arm hardware breakpoint: {}", e);
            }
        }
        // ARM64: we disabled all HW debug registers before the step. Clear the
        // single-step (SS) flag and re-arm every active breakpoint/watchpoint.
        #[cfg(target_arch = "aarch64")]
        if arch == crate::interfaces::Architecture::Arm64 {
            let _ = rearm_dr_index;
            if let Err(e) = clear_single_step_flag(ops, pid, tid) {
                error!("Failed to clear single-step flag during HW BP re-arm: {}", e);
            }
            let active = book.hw.active();
            if let Err(e) = ops.apply_all_hw_bps(pid, tid, &active) {
                error!("Failed to re-arm ARM64 HW breakpoints: {}", e);
            }
        }
        return Ok(None);
    }

    // Active stepper completion - check BEFORE DR6 so that a user-initiated step
    // from a HW BP isn't misinterpreted as a new HW BP hit (stale DR6 bits).
    if let Some(step_state) = book.steps.take_active_single_step(tid) {
        trace!(pid = pid, tid = tid, kind = ?step_state.kind, address = %format!("0x{:X}", address), "Single-step from active stepper");
        let rearm_addr = address;
        // Clear single-step flag, and if there's a deferred HW BP rearm, combine both
        // into one context operation to avoid a redundant context round trip.
        match step_state.deferred_hw_bp_rearm.filter(|_| arch.is_x86_family()) {
            Some(rearm_dr_index) => {
                trace!(pid, tid, rearm_dr_index, "Re-arming deferred hardware breakpoint after step completion");
                if let Err(e) = ops.modify_debug_regs(pid, tid, true, &mut |regs| {
                    regs.set_trap_flag(false);
                    regs.enable_bit(rearm_dr_index);
                    regs.set_dr6(0);
                    true
                }) {
                    error!("Failed to re-arm deferred hardware breakpoint: {}", e);
                }
            }
            None => {
                if let Err(e) = clear_single_step_flag(ops, pid, tid) { error!("Failed to clear single-step flag: {}", e); }
            }
        }
        let _ = rearm_if_matches_original(&book.bps, ops, pid, rearm_addr);
        // If this step was an explicit user step that took over an
        // in-flight software-breakpoint step-over, the other threads were
        // frozen at the breakpoint hit; re-arm that breakpoint and release
        // them. No-op if this thread was not mid-step-over.
        let resumed = complete_step_over(book, ops, pid, tid);
        if resumed > 0 {
            trace!(pid, tid, resumed, "Resumed other threads after breakpoint step-over (explicit step)");
        }
        return Ok(Some(DebugEvent::StepComplete { pid, tid, kind: step_state.kind, address }));
    }

    // Check for hardware breakpoint hit via DR6 (x64 native or WOW64)
    if arch.is_x86_family() {
        // The read-modify-write only writes back when a hit is found.
        let mut hit: Option<(u8, u64)> = None;
        let hw = &book.hw;
        let read = ops.modify_debug_regs(pid, tid, true, &mut |regs| {
            let Some(dr_index) = regs.check_dr6() else { return false; };
            let Some(bp) = hw.find_by_dr_index(dr_index) else { return false; };
            trace!(pid, tid, dr_index, address = %format!("0x{:X}", bp.address), "Hardware breakpoint hit");
            // Disable the HW BP enable bit so we can step past
            regs.disable_bit(dr_index);
            // Set trap flag to single-step one instruction
            regs.set_trap_flag(true);
            hit = Some((dr_index, regs.pc()));
            true
        });
        if read.is_ok() {
            if let Some((dr_index, pc)) = hit {
                let bp = book.hw.find_by_dr_index(dr_index).expect("found in the closure above");
                let bp_address = bp.address;
                let bp_type = bp.bp_type;

                // Schedule re-arm after the single step completes
                book.steps.schedule_hw_bp_rearm(tid, dr_index);

                // Silent access-trace path: if this watched address is being
                // traced, record the accessing instruction (raw RIP; x86
                // traps *after* the access, so this is the following
                // instruction - attributed back at snapshot time) and
                // auto-continue without forwarding a HardwareBreakpoint event.
                if book.watch.record_access(bp_address, pc, tid) {
                    return Ok(None);
                }

                return Ok(Some(DebugEvent::HardwareBreakpoint { pid, tid, address: bp_address, dr_index, bp_type }));
            }
        }
    }

    // Unexpected SS
    match ops.get_context(pid, tid) {
        Ok(ctx) => trace!(pid = pid, tid = tid, pc = %format!("0x{:X}", ctx.pc()), flags = %format!("0x{:X}", ctx.flags()), "Unexpected single-step event (no active step record)"),
        Err(_) => trace!(pid = pid, tid = tid, "Unexpected single-step event (no active step record) - failed to fetch context for log"),
    }
    Ok(Some(DebugEvent::Exception { pid, tid, code: trap.code, address, first_chance: trap.first_chance, parameters: vec![] }))
}
