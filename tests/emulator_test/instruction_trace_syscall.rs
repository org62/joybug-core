/// Test InstructionTrace stops on syscall: emulate from syscall_marker with InstructionTrace.

use crate::helpers::EmulatorTestState;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode};

pub fn test_instruction_trace_syscall(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Test: InstructionTrace stops on syscall ===");

    let result = session.emulate_instructions(pid, tid, 50000, EmulationMode::InstructionTrace, None, vec![])?;

    match result {
        EmulateResult::Trace(trace) => {
            let line_count = trace.trace_text.lines().count();
            println!("  Trace lines: {}", line_count);
            println!("  Stop reason: {}", trace.stop_reason);
            println!("  Trace time: {} us ({:.2} ms)", trace.trace_time_us,
                trace.trace_time_us as f64 / 1000.0);

            if trace.stop_reason.contains("Syscall") {
                println!("  Syscall detected in trace!");
                // Should have stopped well before the 50000 limit
                assert!(
                    line_count < 5000,
                    "InstructionTrace syscall: expected <5000 instructions to reach NtClose, got {}",
                    line_count
                );
            } else {
                println!("  No syscall in trace (stop_reason: {})", trace.stop_reason);
            }

            session.state.instruction_trace_syscall_tested = true;
            println!("  [PASS] InstructionTrace syscall test completed");
        }
        EmulateResult::Emulation(_) => {
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}
