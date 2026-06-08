/// Test InstructionTrace mode: verify trace quality and register snapshots.

use crate::helpers::EmulatorTestState;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode};

pub fn test_instruction_trace(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    start_pc: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: InstructionTrace mode ===");

    let limit = 300;
    let result = session.emulate_instructions(pid, tid, limit, EmulationMode::InstructionTrace, None, vec![])?;

    match result {
        EmulateResult::Trace(trace) => {
            let line_count = trace.trace_text.lines().count();
            println!("  Trace lines: {}", line_count);
            println!("  Stop reason: {}", trace.stop_reason);
            println!("  Trace time: {} us ({:.2} ms)", trace.trace_time_us,
                trace.trace_time_us as f64 / 1000.0);

            // Should have traced close to the requested limit
            assert!(
                line_count > 0,
                "InstructionTrace: should have produced trace lines"
            );
            assert!(
                line_count <= limit,
                "InstructionTrace: trace lines ({}) should not exceed limit ({})",
                line_count, limit
            );

            // First line should contain the start address (it's the full register snapshot)
            // On x64, the PC register is called "rip"; on ARM64, it's "pc"
            let first_line = trace.trace_text.lines().next().unwrap();
            let pc_reg_name = if cfg!(target_arch = "x86_64") { "rip" } else { "pc" };
            let expected_pc = format!("{}=0x{:x}", pc_reg_name, start_pc);
            assert!(
                first_line.contains(&expected_pc),
                "InstructionTrace: first line should contain start PC {}, got: {}",
                expected_pc,
                if first_line.len() > 100 { &first_line[..100] } else { first_line }
            );

            // Subsequent lines should have delta-encoded pc register values
            let pc_prefix = format!("{}=", pc_reg_name);
            let mut lines_with_pc = 0;
            for line in trace.trace_text.lines() {
                if line.contains(&pc_prefix) {
                    lines_with_pc += 1;
                }
            }
            assert_eq!(
                lines_with_pc, line_count,
                "InstructionTrace: every line should contain a {}= value", pc_reg_name
            );

            // Show first few lines
            println!("  First 3 trace lines:");
            for (i, line) in trace.trace_text.lines().take(3).enumerate() {
                let display = if line.len() > 120 { format!("{}...", &line[..120]) } else { line.to_string() };
                println!("    [{:2}] {}", i, display);
            }

            session.state.instruction_trace_tested = true;
            println!("  [PASS] InstructionTrace: {} lines traced", line_count);
        }
        EmulateResult::Emulation(_) => {
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}
