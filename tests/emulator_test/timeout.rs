/// Test emulation timeout: run an infinite loop in Basic mode, verify the
/// safety timeout (3s) fires and stops execution. Reads g_counter from
/// emulated memory to verify the loop actually ran many iterations.

use crate::helpers::EmulatorTestState;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode};

pub fn test_timeout(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    counter_addr: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: Timeout (infinite loop) ===");

    // Emulate in Basic mode with max_instructions=0 (no instruction-level limit).
    // The infinite loop will run until the 3s safety timeout fires.
    // Request g_counter from emulated memory to verify iterations ran.
    let result = session.emulate_instructions(
        pid, tid, 0, EmulationMode::Basic, None,
        vec![(counter_addr, 8)],
    )?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)",
                data.emulation_time_us, data.emulation_time_us as f64 / 1000.0);
            println!("  Pages loaded: {}", data.pages_loaded);

            // Must have stopped due to timeout (reported as InstructionLimit)
            assert!(
                data.stop_reason.contains("InstructionLimit"),
                "Expected InstructionLimit stop reason (timeout), got: {}",
                data.stop_reason,
            );

            // Emulation time should be approximately 3 seconds (the SAFETY_TIMEOUT)
            assert!(
                data.emulation_time_us >= 2_500_000,
                "Emulation should run for ~3s, got {}ms",
                data.emulation_time_us / 1000,
            );

            // Read g_counter from emulated memory — should be large
            let counter = data.memory_snapshots.iter()
                .find(|(addr, _)| *addr == counter_addr)
                .map(|(_, data)| u64::from_le_bytes(data[..8].try_into().unwrap()))
                .unwrap_or(0);
            println!("  g_counter (emulated): {} (0x{:X})", counter, counter);

            assert!(
                counter > 1000,
                "g_counter should be large after 3s of emulation, got: {}",
                counter,
            );

            session.state.timeout_tested = true;
            println!("  [PASS] Timeout: {}ms, g_counter = {}",
                data.emulation_time_us / 1000, counter);
        }
        EmulateResult::Trace(_) => {
            return Err(anyhow::anyhow!("Expected Emulation result for Basic mode"));
        }
    }

    Ok(())
}
