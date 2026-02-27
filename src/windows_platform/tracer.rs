//! Trap-flag based instruction tracer for x86_64
//!
//! Provides instruction-level tracing by repeatedly single-stepping
//! with the trap flag and capturing register state at each step.

use crate::interfaces::{PlatformAPI, PlatformError, Architecture};
use crate::memory_operand::analyze_memory_operands;
use crate::protocol::{MemoryAccess, MemoryAccessType, RegisterSnapshot, TraceEntry, TraceExitCondition, ThreadContext};
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

    // Track pending write operations to capture after instruction executes
    let mut pending_write_ops: Vec<(u64, usize)> = Vec::new();

    for step_count in 0..max_instructions {
        // Get current thread context
        let thread_context = platform.get_thread_context(pid, tid)?;
        let mut context = match thread_context {
            ThreadContext::Win32RawContext(ctx) => ctx,
        };

        // Get program counter (Rip on x64, Pc on ARM64)
        #[cfg(target_arch = "x86_64")]
        let current_pc = context.Rip;
        #[cfg(target_arch = "aarch64")]
        let current_pc = context.Pc;

        // Step 1: Capture pending write data from previous instruction
        // (previous instruction has now completed execution)
        if !pending_write_ops.is_empty() && !entries.is_empty() {
            let last_entry = entries.last_mut().unwrap();
            for (write_addr, write_size) in pending_write_ops.drain(..) {
                if let Ok(data) = platform.read_memory(pid, write_addr, write_size) {
                    last_entry.memory_accesses.push(MemoryAccess {
                        access_type: MemoryAccessType::Write,
                        address: write_addr,
                        data,
                    });
                }
            }
        }
        pending_write_ops.clear();

        // Check instruction limit before processing
        if let TraceExitCondition::InstructionLimit(limit) = &exit_condition {
            if step_count >= *limit {
                stop_reason = format!("InstructionLimit({})", limit);
                break;
            }
        }

        // Capture register snapshot (before executing this instruction)
        let snapshot = RegisterSnapshot::from_context(&context);

        // Get instruction bytes and size via disassembly
        let (insn_bytes, insn_size) = platform.disassemble_memory(pid, current_pc, 1, arch)
            .map(|insns| {
                insns.first()
                    .map(|i| (i.bytes.clone(), i.size))
                    .unwrap_or((vec![], 1))
            })
            .unwrap_or((vec![], 1));

        // Step 2: Analyze current instruction for memory operands
        let mut memory_accesses: Vec<MemoryAccess> = Vec::new();

        if !insn_bytes.is_empty() {
            let operands = analyze_memory_operands(&insn_bytes, current_pc, &snapshot, arch);

            for op in operands {
                if op.is_read {
                    // For reads, capture data immediately (before execution)
                    if let Ok(data) = platform.read_memory(pid, op.address, op.size) {
                        let access_type = if op.is_write {
                            MemoryAccessType::ReadWrite
                        } else {
                            MemoryAccessType::Read
                        };
                        memory_accesses.push(MemoryAccess {
                            access_type,
                            address: op.address,
                            data,
                        });
                    }
                }
                if op.is_write && !op.is_read {
                    // For write-only, queue for capture after execution
                    pending_write_ops.push((op.address, op.size));
                } else if op.is_write && op.is_read {
                    // For read-write, we already captured the read data
                    // but also need to capture write data after execution
                    pending_write_ops.push((op.address, op.size));
                }
            }
        }

        // Record trace entry
        entries.push(TraceEntry {
            address: current_pc,
            size: insn_size,
            registers: snapshot,
            memory_accesses,
        });

        trace!(step = step_count, pc = format!("0x{:X}", current_pc), size = insn_size, "Traced instruction");

        // Check if we reached the exit address (after recording the trace entry)
        if let TraceExitCondition::ReachAddress(addr) = &exit_condition {
            if current_pc == *addr {
                stop_reason = format!("ReachAddress(0x{:X})", addr);
                debug!(step_count, current_pc, "Reached target address");
                break;
            }
        }

        // Set trap flag to single-step
        set_single_step_flag_native(&mut context)?;

        // Set the modified context back
        let updated_context = ThreadContext::Win32RawContext(context);
        super::thread_context::set_thread_context(platform.get_process(pid)?, pid, tid, updated_context)?;

        // Continue execution (will stop on next instruction due to trap flag)
        debug_events::continue_only(pid, tid)?;

        // Wait for the single-step exception from our target thread.
        // Other threads may generate debug events (DLL loads, thread creates, etc.)
        // that we must auto-continue before our single-step arrives.
        // ContinueDebugEvent requires the pid/tid FROM the debug event, not arbitrary values.
        let mut trace_break = false;
        loop {
            let debug_event = debug_events::wait_for_debug_event_blocking()?;
            let event_pid = debug_event.dwProcessId;
            let event_tid = debug_event.dwThreadId;
            let event_result = debug_events::handle_debug_event(platform, &debug_event)?;

            // ProcessExited applies regardless of which thread reported it
            if let Some(ref event) = event_result {
                if let crate::protocol::DebugEvent::ProcessExited { exit_code, .. } = event {
                    stop_reason = format!("ProcessExited({})", exit_code);
                    trace_break = true;
                    break;
                }
            }

            if event_tid == tid {
                // Event from our target thread
                if let Some(ref event) = event_result {
                    if let crate::protocol::DebugEvent::Exception { code, address, .. } = event {
                        if *code != 0x80000004 {
                            // Unexpected exception - stop tracing
                            stop_reason = format!("Exception(0x{:08X}@0x{:X})", code, address);
                            trace_break = true;
                        }
                        // 0x80000004 = EXCEPTION_SINGLE_STEP - expected, continue tracing
                    }
                }
                break;
            } else {
                // Event from another thread - auto-continue with correct pid/tid and keep waiting
                debug_events::continue_only(event_pid, event_tid)?;
            }
        }
        if trace_break {
            break;
        }
    }

    // Capture any final pending writes from the last instruction
    if !pending_write_ops.is_empty() && !entries.is_empty() {
        let last_entry = entries.last_mut().unwrap();
        for (write_addr, write_size) in pending_write_ops {
            if let Ok(data) = platform.read_memory(pid, write_addr, write_size) {
                last_entry.memory_accesses.push(MemoryAccess {
                    access_type: MemoryAccessType::Write,
                    address: write_addr,
                    data,
                });
            }
        }
    }

    // Clear trap flag after tracing (while process is still stopped on the pending event).
    // The caller (framework) will ContinueDebugEvent for the last pending event.
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
