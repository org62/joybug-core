/// Test Basic mode: emulate xtea_encrypt, verify code actually executed.

use crate::helpers::EmulatorTestState;
use joybug_core::protocol_io::{DebugSession, EmulateResult, EmulationMode};

pub fn test_basic(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    start_pc: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: Basic mode ===");

    let result = session.emulate_instructions(pid, tid, 500, EmulationMode::Basic, None, vec![])?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us,
                data.emulation_time_us as f64 / 1000.0);
            println!("  Pages loaded: {}", data.pages_loaded);

            // Code must have actually executed: PC should have moved
            assert_ne!(
                data.final_pc, start_pc,
                "Basic mode: PC did not move from start address 0x{:X}",
                start_pc
            );

            // First basic block should be the start address (always recorded)
            assert!(
                !data.basic_blocks.is_empty(),
                "Basic mode: should have at least 1 basic block (the start)"
            );
            assert_eq!(
                data.basic_blocks[0], start_pc,
                "Basic mode: first basic block should be start PC"
            );

            session.state.basic_tested = true;
            println!("  [PASS] Basic mode: PC moved from 0x{:X} to 0x{:X}", start_pc, data.final_pc);
        }
        EmulateResult::Trace(_) => {
            return Err(anyhow::anyhow!("Expected EmulationResult for Basic mode"));
        }
    }

    Ok(())
}
