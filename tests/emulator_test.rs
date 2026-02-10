#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::interfaces::Architecture;
use joybug2::protocol_io::{
    BreakpointDecision, DebugSession, EmulateResult, EmulationMode,
};

/// Test state for emulator tests
struct EmulatorTestState {
    mode_basic_tested: bool,
    mode_instruction_trace_tested: bool,
    mode_basic_block_tested: bool,
    mode_module_transition_tested: bool,
    mode_syscall_tested: bool,
    mode_instruction_trace_syscall_tested: bool,
}

impl EmulatorTestState {
    fn new() -> Self {
        Self {
            mode_basic_tested: false,
            mode_instruction_trace_tested: false,
            mode_basic_block_tested: false,
            mode_module_transition_tested: false,
            mode_syscall_tested: false,
            mode_instruction_trace_syscall_tested: false,
        }
    }

    fn all_tested(&self) -> bool {
        self.mode_basic_tested
            && self.mode_instruction_trace_tested
            && self.mode_basic_block_tested
            && self.mode_module_transition_tested
            && self.mode_syscall_tested
            && self.mode_instruction_trace_syscall_tested
    }
}

fn test_mode_basic(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing EmulationMode::Basic ===");

    let result = session.emulate_instructions(pid, tid, 1000, EmulationMode::Basic, None)?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Instructions executed: {}", data.instructions_executed);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us, data.emulation_time_us as f64 / 1000.0);
            println!("  Pages loaded: {}", data.pages_loaded);
            println!("  Basic blocks: {} (should have 1, the start)", data.basic_blocks.len());
            if data.instructions_executed > 0 {
                println!("  Performance: {:.2} us/instruction", data.emulation_time_us as f64 / data.instructions_executed as f64);
            }
            session.state.mode_basic_tested = true;
            println!("  [PASS] Basic mode succeeded");
        }
        EmulateResult::Trace(_) => {
            println!("  [FAIL] Unexpected TenetTrace for Basic mode");
            return Err(anyhow::anyhow!("Expected EmulationResult for Basic mode"));
        }
    }

    Ok(())
}

fn test_mode_instruction_trace(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing EmulationMode::InstructionTrace (Tenet format) ===");

    let result = session.emulate_instructions(pid, tid, 1500, EmulationMode::InstructionTrace, None)?;

    match result {
        EmulateResult::Trace(trace) => {
            let line_count = trace.trace_text.lines().count();
            println!("  Tenet trace: {} lines", line_count);
            println!("  Stop reason: {}", trace.stop_reason);
            println!("  Trace time: {} us ({:.2} ms)", trace.trace_time_us, trace.trace_time_us as f64 / 1000.0);

            // Show first few trace lines
            if !trace.trace_text.is_empty() {
                println!("  First 5 trace lines:");
                for (i, line) in trace.trace_text.lines().take(5).enumerate() {
                    // Truncate long lines
                    let display = if line.len() > 100 {
                        format!("{}...", &line[..100])
                    } else {
                        line.to_string()
                    };
                    println!("    [{:2}] {}", i, display);
                }
            }

            session.state.mode_instruction_trace_tested = true;
            println!("  [PASS] InstructionTrace mode succeeded (Tenet format)");
        }
        EmulateResult::Emulation(_) => {
            println!("  [FAIL] Expected TenetTrace for InstructionTrace mode");
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}

fn test_mode_basic_block(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing EmulationMode::BasicBlock ===");

    let result = session.emulate_instructions(pid, tid, 1000, EmulationMode::BasicBlock, None)?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Instructions executed: {}", data.instructions_executed);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us, data.emulation_time_us as f64 / 1000.0);
            println!("  Basic blocks: {} (uses BLOCK hook)", data.basic_blocks.len());

            if data.instructions_executed > 0 {
                println!("  Performance: {:.2} us/instruction", data.emulation_time_us as f64 / data.instructions_executed as f64);
            }

            // Show first few basic blocks
            if !data.basic_blocks.is_empty() {
                println!("  First 5 basic blocks:");
                for (i, bb) in data.basic_blocks.iter().take(5).enumerate() {
                    let symbol_info = session.resolve_address_to_symbol(pid, *bb).ok();
                    let symbol_str = if let Some((module, sym, offset)) = symbol_info {
                        if let (Some(m), Some(s), Some(o)) = (module, sym, offset) {
                            format!(" ({}!{}+0x{:x})", m, s.name, o)
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    println!("    [{:2}] 0x{:016X}{}", i, bb, symbol_str);
                }
            }

            session.state.mode_basic_block_tested = true;
            println!("  [PASS] BasicBlock mode succeeded");
        }
        EmulateResult::Trace(_) => {
            println!("  [FAIL] Unexpected TenetTrace for BasicBlock mode");
            return Err(anyhow::anyhow!("Expected EmulationResult for BasicBlock mode"));
        }
    }

    Ok(())
}

fn test_mode_module_transition(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing EmulationMode::ModuleTransition ===");

    let result = session.emulate_instructions(pid, tid, 10000, EmulationMode::ModuleTransition, None)?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Instructions executed: {}", data.instructions_executed);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us, data.emulation_time_us as f64 / 1000.0);

            // Check if we found a module transition
            if data.stop_reason.contains("ModuleTransition") {
                println!("  ✓ Module transition detected!");
            } else {
                println!("  ⚠ No module transition found within limit");
            }

            session.state.mode_module_transition_tested = true;
            println!("  [PASS] ModuleTransition mode succeeded");
        }
        EmulateResult::Trace(_) => {
            println!("  [FAIL] Unexpected TenetTrace for ModuleTransition mode");
            return Err(anyhow::anyhow!("Expected EmulationResult for ModuleTransition mode"));
        }
    }

    Ok(())
}

fn test_mode_instruction_trace_syscall_stop(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing InstructionTrace stops on syscall ===");

    // Use a high limit - we expect it to hit a syscall well before this
    let result = session.emulate_instructions(pid, tid, 50000, EmulationMode::InstructionTrace, None)?;

    match result {
        EmulateResult::Trace(trace) => {
            let line_count = trace.trace_text.lines().count();
            println!("  Trace lines: {}", line_count);
            println!("  Stop reason: {}", trace.stop_reason);

            assert!(
                trace.stop_reason.contains("Syscall"),
                "Expected InstructionTrace to stop on syscall, but stop_reason was: {}",
                trace.stop_reason
            );
            println!("  [PASS] InstructionTrace correctly stopped on syscall");

            session.state.mode_instruction_trace_syscall_tested = true;
        }
        EmulateResult::Emulation(_) => {
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}

fn test_mode_syscall(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing EmulationMode::Syscall ===");

    let result = session.emulate_instructions(pid, tid, 50000, EmulationMode::Syscall, None)?;

    match result {
        EmulateResult::Emulation(data) => {
            println!("  Final PC: 0x{:016X}", data.final_pc);
            println!("  Instructions executed: {}", data.instructions_executed);
            println!("  Stop reason: {}", data.stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", data.emulation_time_us, data.emulation_time_us as f64 / 1000.0);

            // Check if we found a syscall
            if data.stop_reason.contains("Syscall") {
                println!("  ✓ Syscall detected at 0x{:016X}", data.final_pc);
                // Try to resolve the syscall address
                if let Ok((module, sym, offset)) = session.resolve_address_to_symbol(pid, data.final_pc) {
                    if let (Some(m), Some(s), Some(o)) = (module, sym, offset) {
                        println!("    Location: {}!{}+0x{:x}", m, s.name, o);
                    }
                }
            } else {
                println!("  ⚠ No syscall found within limit (stop_reason: {})", data.stop_reason);
                // Debug: show what instruction caused the stop
                if let Ok((module, sym, offset)) = session.resolve_address_to_symbol(pid, data.final_pc) {
                    if let (Some(m), Some(s), Some(o)) = (module, sym, offset) {
                        println!("    Exception at: {}!{}+0x{:x}", m, s.name, o);
                    }
                }
                // Disassemble at the exception location
                let arch = Architecture::from_native();
                if let Ok(insns) = session.disassemble_memory(pid, data.final_pc, 5, arch) {
                    println!("    Instructions at exception:");
                    for insn in insns.iter().take(5) {
                        println!("      0x{:016X}: {} {}", insn.address, insn.mnemonic, insn.op_str);
                    }
                }
            }

            session.state.mode_syscall_tested = true;
            println!("  [PASS] Syscall mode succeeded");
        }
        EmulateResult::Trace(_) => {
            println!("  [FAIL] Unexpected TenetTrace for Syscall mode");
            return Err(anyhow::anyhow!("Expected EmulationResult for Syscall mode"));
        }
    }

    Ok(())
}

fn run_emulator_tests(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    address: u64,
) -> anyhow::Result<()> {
    println!("\n=== Running emulator tests at entry point ===");
    println!("  PID: {}, TID: {}, Address: 0x{:016X}", pid, tid, address);

    // Get current location info
    let arch = Architecture::from_native();
    let disasm = session.disassemble_memory(pid, address, 10, arch)?;
    println!("\n  Entry point disassembly:");
    for insn in &disasm {
        println!("    0x{:016X}: {} {}", insn.address, insn.mnemonic, insn.op_str);
    }

    // Test all 5 emulation modes
    test_mode_basic(session, pid, tid)?;
    test_mode_instruction_trace(session, pid, tid)?;
    test_mode_basic_block(session, pid, tid)?;
    test_mode_module_transition(session, pid, tid)?;
    test_mode_syscall(session, pid, tid)?;
    test_mode_instruction_trace_syscall_stop(session, pid, tid)?;

    println!("\n=== All emulator tests completed ===");
    Ok(())
}

#[test]
fn test_emulator_integration() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    println!("=== Emulator Integration Test ===");
    println!("Server address: {}", server_addr);

    let final_state = DebugSession::new(EmulatorTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            println!("\n=== Initial breakpoint hit (ntdll) ===");

            // Find the main executable module (cmd.exe)
            let modules = session.list_modules(pid)?;
            let main_module = modules.iter()
                .find(|m| m.name.to_lowercase().contains("cmd.exe"))
                .ok_or_else(|| anyhow::anyhow!("Could not find cmd.exe module"))?;

            println!("  Found main module: {} at 0x{:016X}", main_module.name, main_module.base);

            // Get module extra info to find entry point
            let extra_info = session.get_module_extra_info(pid, main_module.base)?;
            let entry_point_rva = extra_info.nt_headers.OptionalHeader.AddressOfEntryPoint;
            let entry_point = main_module.base + entry_point_rva as u64;

            println!("  Entry point RVA: 0x{:X}", entry_point_rva);
            println!("  Entry point VA: 0x{:016X}", entry_point);

            // Set a breakpoint at the entry point address (will remove after first hit)
            session.set_breakpoint_at(pid, entry_point, None, |session, pid, tid, address| {
                println!("\n=== Entry point breakpoint hit ===");
                run_emulator_tests(session, pid, tid, address)?;
                Ok(BreakpointDecision::Remove)
            })?;

            println!("  Breakpoint set at entry point, continuing...");
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("\nProcess {} exited with code {}", pid, exit_code);

            // Verify all tests ran
            assert!(
                session.state.mode_basic_tested,
                "Basic mode was not tested"
            );
            assert!(
                session.state.mode_instruction_trace_tested,
                "InstructionTrace mode was not tested"
            );
            assert!(
                session.state.mode_basic_block_tested,
                "BasicBlock mode was not tested"
            );
            assert!(
                session.state.mode_module_transition_tested,
                "ModuleTransition mode was not tested"
            );
            assert!(
                session.state.mode_syscall_tested,
                "Syscall mode was not tested"
            );
            assert!(
                session.state.mode_instruction_trace_syscall_tested,
                "InstructionTrace syscall stop was not tested"
            );

            println!("All emulator modes tested successfully!");
            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("Debug session failed");

    assert!(
        final_state.all_tested(),
        "Not all emulator features were tested"
    );
}
