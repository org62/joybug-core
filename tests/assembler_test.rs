#![cfg(windows)]

mod common;

use common::{TestServer, find_symbol, get_test_program_path};
use joybug2::interfaces::Architecture;
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

struct AssemblerTestState {
    exit_code: u32,
}

#[test]
fn test_assembler_patch() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe = get_test_program_path("assembler_test");
    println!("Using assembler_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(
        AssemblerTestState { exit_code: 0xFF },
        Some(server_addr.as_str()),
    )
    .expect("Failed to create debug session")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        println!("Initial breakpoint hit, setting BP on breakpoint_here...");

        session.set_breakpoint_by_symbol(
            pid,
            "breakpoint_here",
            None,
            |session, pid, _tid, addr| {
                println!("breakpoint_here hit at 0x{:X}, patching functions...", addr);
                let arch = Architecture::from_native();

                // Test 1: Patch get_value to return 2
                let get_value_sym = find_symbol(session, "get_value", "assembler_test")?;
                println!("  get_value at 0x{:X}", get_value_sym.va);

                let asm_code = if cfg!(target_arch = "x86_64") {
                    "mov eax, 2\nret"
                } else {
                    "mov w0, #2\nret"
                };
                let result = joybug2::assembler::assemble(arch, asm_code, get_value_sym.va)
                    .map_err(|e| anyhow::anyhow!("Assembly failed: {}", e))?;
                println!(
                    "  Assembled {} bytes ({} instructions): {:02X?}",
                    result.bytes.len(),
                    result.stat_count,
                    result.bytes
                );
                session.write_memory(pid, get_value_sym.va, result.bytes)?;
                println!("  Patched get_value to return 2");

                // Test 2: Patch get_global to read g_value_b (x86-64 only, RIP-relative)
                #[cfg(target_arch = "x86_64")]
                {
                    let g_value_b_sym =
                        find_symbol(session, "g_value_b", "assembler_test")?;
                    let get_global_sym =
                        find_symbol(session, "get_global", "assembler_test")?;
                    println!(
                        "  g_value_b at 0x{:X}, get_global at 0x{:X}",
                        g_value_b_sym.va, get_global_sym.va
                    );

                    let asm_code = format!("mov eax, [0x{:x}]\nret", g_value_b_sym.va);
                    let result =
                        joybug2::assembler::assemble(arch, &asm_code, get_global_sym.va)
                            .map_err(|e| anyhow::anyhow!("Assembly failed: {}", e))?;
                    println!(
                        "  Assembled {} bytes ({} instructions): {:02X?}",
                        result.bytes.len(),
                        result.stat_count,
                        result.bytes
                    );
                    session.write_memory(pid, get_global_sym.va, result.bytes)?;
                    println!("  Patched get_global to read g_value_b");
                }

                Ok(BreakpointDecision::Remove)
            },
        )?;

        Ok(())
    })
    .on_process_exited(|session, pid, exit_code| {
        println!("Process {} exited with code {}", pid, exit_code);
        session.state.exit_code = exit_code;
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    assert_eq!(
        final_state.exit_code, 0,
        "Patched program should exit with code 0, got {}",
        final_state.exit_code
    );
    println!("\n=== Assembler Patch Test PASSED ===");
}
