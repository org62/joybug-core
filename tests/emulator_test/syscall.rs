/// Test Syscall mode: emulate from syscall_marker which calls CloseHandle(NULL).
/// This goes through kernel32 → ntdll → NtClose → SVC/SYSCALL.

use crate::helpers::EmulatorTestState;
use joybug2::interfaces::Architecture;
use joybug2::protocol_io::{DebugSession, EmulateResult, EmulationMode};

pub fn test_syscall(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Test: Syscall mode ===");

    // Use a generous limit - CloseHandle → NtClose is a short path
    let result = session.emulate_instructions(pid, tid, 50000, EmulationMode::Syscall, None)?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us,
                data.emulation_time_us as f64 / 1000.0);

            if data.stop_reason.contains("Syscall") {
                println!("  Syscall detected!");
                if let Ok((Some(m), Some(s), Some(o))) = session.resolve_address_to_symbol(pid, data.final_pc) {
                    println!("  Location: {}!{}+0x{:x}", m, s.name, o);
                }
            } else {
                // Log diagnostic info if syscall wasn't found
                println!("  No syscall found (stop_reason: {})", data.stop_reason);
                let arch = Architecture::from_native();
                if let Ok(insns) = session.disassemble_memory(pid, data.final_pc, 3, arch) {
                    println!("  Instructions at stop:");
                    for insn in insns.iter().take(3) {
                        println!("    0x{:016X}: {} {}", insn.address, insn.mnemonic, insn.op_str);
                    }
                }
            }

            session.state.syscall_tested = true;
            println!("  [PASS] Syscall mode completed");
        }
        EmulateResult::Trace(_) => {
            return Err(anyhow::anyhow!("Expected EmulationResult for Syscall mode"));
        }
    }

    Ok(())
}
