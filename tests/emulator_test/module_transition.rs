/// Test ModuleTransition: emulate from entry point, detect CRT → ucrtbase transition.

use crate::helpers::EmulatorTestState;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode};

pub fn test_module_transition(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Test: ModuleTransition mode ===");

    let result = session.emulate_instructions(pid, tid, 50000, EmulationMode::ModuleTransition, None)?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us,
                data.emulation_time_us as f64 / 1000.0);

            // From the entry point, CRT startup should call into ucrtbase/ntdll
            assert!(
                data.stop_reason.contains("ModuleTransition"),
                "ModuleTransition: expected module transition from entry point, got: {}",
                data.stop_reason
            );

            // Resolve the transition target
            if let Ok((module, sym, offset)) = session.resolve_address_to_symbol(pid, data.final_pc) {
                let sym_str = match (module, sym, offset) {
                    (Some(m), Some(s), Some(o)) => format!("{}!{}+0x{:x}", m, s.name, o),
                    _ => format!("0x{:X}", data.final_pc),
                };
                println!("  Transition target: {}", sym_str);
            }

            session.state.module_transition_tested = true;
            println!("  [PASS] ModuleTransition detected");
        }
        EmulateResult::Trace(_) => {
            return Err(anyhow::anyhow!("Expected EmulationResult for ModuleTransition mode"));
        }
    }

    Ok(())
}
