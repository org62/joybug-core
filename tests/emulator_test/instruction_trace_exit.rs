/// Test InstructionTrace with exit condition: stop at a specific address.

use crate::helpers::EmulatorTestState;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode, TraceExitCondition};

pub fn test_instruction_trace_exit_condition(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    exit_addr: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: InstructionTrace with ReachAddress exit ===");
    println!("  Exit address: 0x{:016X}", exit_addr);

    let result = session.emulate_instructions(
        pid, tid, 50000, EmulationMode::InstructionTrace,
        Some(TraceExitCondition::ReachAddress(exit_addr)), vec![],
    )?;

    match result {
        EmulateResult::Trace(trace) => {
            let line_count = trace.trace_text.lines().count();
            println!("  Trace lines: {}", line_count);
            println!("  Stop reason: {}", trace.stop_reason);
            println!("  Trace time: {} us ({:.2} ms)", trace.trace_time_us,
                trace.trace_time_us as f64 / 1000.0);

            // Should have stopped due to reaching the address, not instruction limit
            assert!(
                trace.stop_reason.contains("ReachedAddress") || trace.stop_reason.contains("Stopped"),
                "InstructionTrace exit: expected ReachedAddress stop, got: {}",
                trace.stop_reason
            );

            // The last trace line should contain the exit address
            if let Some(last_line) = trace.trace_text.lines().last() {
                let expected_pc = format!("pc=0x{:x}", exit_addr);
                assert!(
                    last_line.contains(&expected_pc),
                    "InstructionTrace exit: last line should contain exit PC {}, got: {}",
                    expected_pc,
                    if last_line.len() > 100 { &last_line[..100] } else { last_line }
                );
            }

            // xtea_encrypt with 32 rounds on ARM64/Od is ~1700 instructions;
            // should be well under the 50000 limit
            assert!(
                line_count < 5000,
                "InstructionTrace exit: expected <5000 instructions for xtea_encrypt, got {}",
                line_count
            );

            session.state.instruction_trace_exit_tested = true;
            println!("  [PASS] InstructionTrace exit: stopped at target after {} instructions", line_count);
        }
        EmulateResult::Emulation(_) => {
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}
