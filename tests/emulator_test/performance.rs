/// Test performance: verify InstructionTrace batching is efficient.
/// InstructionTrace uses count=TRACE_BATCH_SIZE per emu_start call, which
/// lets Unicorn build multi-instruction translation blocks within each batch.
/// If someone changed this to count=1, tracing would be 10-100x slower.

use crate::helpers::EmulatorTestState;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode, TraceExitCondition};

pub fn test_performance(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    exit_addr: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: Performance (trace batching) ===");
    println!("  Exit address: 0x{:016X}", exit_addr);

    // Use InstructionTrace with exit condition: this is bounded by the exit
    // address and tests that trace batching (count=TRACE_BATCH_SIZE) is efficient.
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

            // InstructionTrace with batching should complete xtea_encrypt
            // (~1700 instructions on ARM64/Od) in well under 500ms.
            // If count were set to 1 per emu_start call (breaking batching),
            // this would take several seconds.
            assert!(
                trace.trace_time_us < 500_000, // 500ms
                "Performance: trace took {}ms, expected <500ms. \
                 This may indicate count=1 per emu_start call (breaks batching).",
                trace.trace_time_us / 1000
            );

            session.state.performance_tested = true;
            println!("  [PASS] Performance: {}ms for {} trace lines",
                trace.trace_time_us / 1000, line_count);
        }
        EmulateResult::Emulation(_) => {
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}
