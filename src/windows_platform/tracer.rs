//! Trap-flag based instruction tracer for x86_64
//!
//! Provides instruction-level tracing by repeatedly single-stepping
//! with the trap flag and capturing register state at each step.

use crate::interfaces::{PlatformAPI, PlatformError, Architecture};
use crate::protocol::{RegisterSnapshot, TraceEntry, TraceExitCondition, ThreadContext};
use super::WindowsPlatform;
use super::stepper::{set_single_step_flag_native, clear_single_step_flag_native};
use super::debug_events;
use tracing::{trace, debug};
use std::time::Instant;

/// Result of instruction tracing
pub struct TraceResult {
    pub entries: Vec<TraceEntry>,
    pub stop_reason: String,
    pub trace_time_us: u64,
}

/// Trace instructions using trap flag until exit condition is met
pub fn trace_instructions(
    platform: &mut WindowsPlatform,
    pid: u32,
    tid: u32,
    exit_condition: TraceExitCondition,
    max_instructions: usize,
) -> Result<TraceResult, PlatformError> {
    let start_time = Instant::now();
    let mut entries: Vec<TraceEntry> = Vec::new();
    let mut stop_reason = String::from("InstructionLimit");

    debug!(pid, tid, ?exit_condition, max_instructions, "Starting instruction trace");

    // Get architecture for disassembly
    let arch = Architecture::from_native();

    for step_count in 0..max_instructions {
        // Get current thread context
        let thread_context = platform.get_thread_context(pid, tid)?;
        let mut context = match thread_context {
            ThreadContext::Win32RawContext(ctx) => ctx,
        };

        let current_rip = context.Rip;

        // Check exit condition before executing
        match &exit_condition {
            TraceExitCondition::ReachAddress(addr) => {
                if current_rip == *addr {
                    stop_reason = format!("ReachAddress(0x{:X})", addr);
                    debug!(step_count, current_rip, "Reached target address");
                    break;
                }
            }
            TraceExitCondition::InstructionLimit(limit) => {
                if step_count >= *limit {
                    stop_reason = format!("InstructionLimit({})", limit);
                    break;
                }
            }
        }

        // Capture register snapshot (before executing this instruction)
        let snapshot = RegisterSnapshot::from_context(&context);

        // Get instruction size via disassembly
        let insn_size = platform.disassemble_memory(pid, current_rip, 1, arch)
            .map(|insns| insns.first().map(|i| i.size).unwrap_or(1))
            .unwrap_or(1);

        // Record trace entry
        entries.push(TraceEntry {
            address: current_rip,
            size: insn_size,
            registers: snapshot,
        });

        trace!(step = step_count, rip = format!("0x{:X}", current_rip), size = insn_size, "Traced instruction");

        // Set trap flag to single-step
        set_single_step_flag_native(&mut context)?;

        // Set the modified context back
        let updated_context = ThreadContext::Win32RawContext(context);
        super::thread_context::set_thread_context(platform.get_process(pid)?, pid, tid, updated_context)?;

        // Continue execution (will stop on next instruction due to trap flag)
        debug_events::continue_only(pid, tid)?;

        // Wait for the single-step exception
        let debug_event = debug_events::wait_for_debug_event_blocking()?;

        // Handle the debug event
        let event_result = debug_events::handle_debug_event(platform, &debug_event)?;

        // Check if we got an unexpected event (like process exit)
        if let Some(event) = event_result {
            match event {
                crate::protocol::DebugEvent::ProcessExited { exit_code, .. } => {
                    stop_reason = format!("ProcessExited({})", exit_code);
                    break;
                }
                crate::protocol::DebugEvent::Exception { code, address, .. } => {
                    // 0x80000004 is EXCEPTION_SINGLE_STEP - expected
                    if code != 0x80000004 {
                        stop_reason = format!("Exception(0x{:08X}@0x{:X})", code, address);
                        break;
                    }
                }
                _ => {
                    // Continue tracing for other events
                }
            }
        }
    }

    // Clear trap flag after tracing
    if let Ok(thread_context) = platform.get_thread_context(pid, tid) {
        let ThreadContext::Win32RawContext(mut context) = thread_context;
        let _ = clear_single_step_flag_native(&mut context);
        let updated_context = ThreadContext::Win32RawContext(context);
        let _ = super::thread_context::set_thread_context(platform.get_process(pid)?, pid, tid, updated_context);
    }

    let trace_time_us = start_time.elapsed().as_micros() as u64;

    debug!(
        entries = entries.len(),
        trace_time_us,
        stop_reason = %stop_reason,
        "Instruction trace complete"
    );

    Ok(TraceResult {
        entries,
        stop_reason,
        trace_time_us,
    })
}
