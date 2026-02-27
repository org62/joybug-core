/// Test BasicBlock mode: verify basic block recording via BLOCK hooks.
/// Note: With count=0 (CRITICAL for JIT), emulation runs until a hook fires
/// (syscall) or the safety timeout. Blocks may span multiple modules.

use crate::helpers::EmulatorTestState;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode};

pub fn test_basic_block(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    start_pc: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: BasicBlock mode ===");

    let result = session.emulate_instructions(pid, tid, 500, EmulationMode::BasicBlock, None)?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Basic blocks: {}", data.basic_blocks.len());
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us,
                data.emulation_time_us as f64 / 1000.0);

            // Should have recorded many basic blocks (count=0 runs at JIT speed)
            assert!(
                data.basic_blocks.len() > 5,
                "BasicBlock mode: expected >5 basic blocks, got {}",
                data.basic_blocks.len()
            );

            // First basic block should be at start address
            assert_eq!(
                data.basic_blocks[0], start_pc,
                "BasicBlock mode: first basic block should be start PC"
            );

            // Show some basic blocks with symbols
            println!("  First 5 basic blocks:");
            for (i, bb) in data.basic_blocks.iter().take(5).enumerate() {
                let sym = session.resolve_address_to_symbol(pid, *bb).ok();
                let sym_str = match sym {
                    Some((Some(m), Some(s), Some(o))) => format!(" ({}!{}+0x{:x})", m, s.name, o),
                    _ => String::new(),
                };
                println!("    [{:2}] 0x{:016X}{}", i, bb, sym_str);
            }

            session.state.basic_block_tested = true;
            println!("  [PASS] BasicBlock mode: {} blocks detected", data.basic_blocks.len());
        }
        EmulateResult::Trace(_) => {
            return Err(anyhow::anyhow!("Expected EmulationResult for BasicBlock mode"));
        }
    }

    Ok(())
}
