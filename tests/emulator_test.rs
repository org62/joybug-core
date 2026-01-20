#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::interfaces::Architecture;
use joybug2::protocol::{DebuggerRequest, DebuggerResponse, EmulationMode};
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

/// Test state for emulator tests
struct EmulatorTestState {
    mode_basic_tested: bool,
    mode_instruction_trace_tested: bool,
    mode_basic_block_tested: bool,
    mode_module_transition_tested: bool,
    mode_syscall_tested: bool,
}

impl EmulatorTestState {
    fn new() -> Self {
        Self {
            mode_basic_tested: false,
            mode_instruction_trace_tested: false,
            mode_basic_block_tested: false,
            mode_module_transition_tested: false,
            mode_syscall_tested: false,
        }
    }

    fn all_tested(&self) -> bool {
        self.mode_basic_tested
            && self.mode_instruction_trace_tested
            && self.mode_basic_block_tested
            && self.mode_module_transition_tested
            && self.mode_syscall_tested
    }
}

fn test_mode_basic(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing EmulationMode::Basic ===");

    let req = DebuggerRequest::EmulateInstructions {
        pid,
        tid,
        max_instructions: 1000,
        mode: EmulationMode::Basic,
    };

    match session.send_and_receive(&req)? {
        DebuggerResponse::EmulationResult {
            final_pc,
            instructions_executed,
            stop_reason,
            emulation_time_us,
            pages_loaded,
            basic_blocks,
            instruction_trace,
            ..
        } => {
            println!("  Final PC: 0x{:016X}", final_pc);
            println!("  Instructions executed: {}", instructions_executed);
            println!("  Stop reason: {}", stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", emulation_time_us, emulation_time_us as f64 / 1000.0);
            println!("  Pages loaded: {}", pages_loaded);
            println!("  Basic blocks: {} (should have 1, the start)", basic_blocks.len());
            println!("  Instruction trace: {} (should be 0, no CODE hook)", instruction_trace.len());
            if instructions_executed > 0 {
                println!("  Performance: {:.2} us/instruction", emulation_time_us as f64 / instructions_executed as f64);
            }
            session.state.mode_basic_tested = true;
            println!("  [PASS] Basic mode succeeded");
        }
        DebuggerResponse::Error { message } => {
            println!("  [FAIL] Basic mode error: {}", message);
            return Err(anyhow::anyhow!("Basic mode failed: {}", message));
        }
        other => {
            println!("  [FAIL] Unexpected response: {:?}", other);
            return Err(anyhow::anyhow!("Unexpected response: {:?}", other));
        }
    }

    Ok(())
}

fn test_mode_instruction_trace(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Testing EmulationMode::InstructionTrace ===");

    let req = DebuggerRequest::EmulateInstructions {
        pid,
        tid,
        max_instructions: 1500,
        mode: EmulationMode::InstructionTrace,
    };

    match session.send_and_receive(&req)? {
        DebuggerResponse::EmulationResult {
            final_pc,
            instructions_executed,
            stop_reason,
            emulation_time_us,
            basic_blocks,
            instruction_trace,
            ..
        } => {
            println!("  Final PC: 0x{:016X}", final_pc);
            println!("  Instructions executed: {}", instructions_executed);
            println!("  Stop reason: {}", stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", emulation_time_us, emulation_time_us as f64 / 1000.0);
            println!("  Basic blocks: {}", basic_blocks.len());
            println!("  Instruction trace: {} (should match instructions_executed)", instruction_trace.len());

            // Verify trace matches instruction count
            if instruction_trace.len() == instructions_executed {
                println!("  ✓ Trace count matches instructions executed");
            } else {
                println!("  ⚠ Trace count ({}) differs from instructions ({})",
                    instruction_trace.len(), instructions_executed);
            }

            // Show first few trace entries
            if !instruction_trace.is_empty() {
                println!("  First 5 traced instructions:");
                for (i, (addr, size)) in instruction_trace.iter().take(5).enumerate() {
                    println!("    [{:2}] 0x{:016X} (size: {})", i, addr, size);
                }
            }

            // If exception occurred, show last 50 instructions with disassembly
            if stop_reason.contains("Error") || stop_reason.contains("EXCEPTION") {
                println!("\n  === EXCEPTION DEBUG INFO ===");

                // Disassemble at exception location
                let arch = Architecture::from_native();
                if let Ok(insns) = session.disassemble_memory(pid, final_pc, 5, arch) {
                    println!("  Instructions at exception (0x{:016X}):", final_pc);
                    for insn in insns.iter().take(5) {
                        println!("    0x{:016X}: {} {}", insn.address, insn.mnemonic, insn.op_str);
                    }
                }

                // Show last 50 instructions leading to exception
                let trace_len = instruction_trace.len();
                let start_idx = trace_len.saturating_sub(50);
                println!("\n  Last {} instructions before exception:", trace_len - start_idx);
                for (i, (addr, size)) in instruction_trace.iter().skip(start_idx).enumerate() {
                    let idx = start_idx + i;
                    // Resolve symbol for each instruction
                    let symbol_info = session.resolve_address_to_symbol(pid, *addr).ok();
                    let symbol_str = if let Some((module, sym, offset)) = symbol_info {
                        if let (Some(m), Some(s), Some(o)) = (module, sym, offset) {
                            format!(" ({}!{}+0x{:x})", m, s.name, o)
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    // Disassemble this instruction
                    let disasm_str = session.disassemble_memory(pid, *addr, 1, arch)
                        .ok()
                        .and_then(|insns| insns.first().map(|i| format!("{} {}", i.mnemonic, i.op_str)))
                        .unwrap_or_default();

                    println!("    [{:4}] 0x{:016X} ({}){}: {}", idx, addr, size, symbol_str, disasm_str);
                }
            }

            session.state.mode_instruction_trace_tested = true;
            println!("  [PASS] InstructionTrace mode succeeded");
        }
        DebuggerResponse::Error { message } => {
            println!("  [FAIL] InstructionTrace mode error: {}", message);
            return Err(anyhow::anyhow!("InstructionTrace mode failed: {}", message));
        }
        other => {
            println!("  [FAIL] Unexpected response: {:?}", other);
            return Err(anyhow::anyhow!("Unexpected response: {:?}", other));
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

    let req = DebuggerRequest::EmulateInstructions {
        pid,
        tid,
        max_instructions: 1000,
        mode: EmulationMode::BasicBlock,
    };

    match session.send_and_receive(&req)? {
        DebuggerResponse::EmulationResult {
            final_pc,
            instructions_executed,
            stop_reason,
            emulation_time_us,
            basic_blocks,
            instruction_trace,
            ..
        } => {
            println!("  Final PC: 0x{:016X}", final_pc);
            println!("  Instructions executed: {}", instructions_executed);
            println!("  Stop reason: {}", stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", emulation_time_us, emulation_time_us as f64 / 1000.0);
            println!("  Basic blocks: {} (uses BLOCK hook)", basic_blocks.len());
            println!("  Instruction trace: {} (should be 0, no CODE hook)", instruction_trace.len());

            if instructions_executed > 0 {
                println!("  Performance: {:.2} us/instruction", emulation_time_us as f64 / instructions_executed as f64);
            }

            // Show first few basic blocks
            if !basic_blocks.is_empty() {
                println!("  First 5 basic blocks:");
                for (i, bb) in basic_blocks.iter().take(5).enumerate() {
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
        DebuggerResponse::Error { message } => {
            println!("  [FAIL] BasicBlock mode error: {}", message);
            return Err(anyhow::anyhow!("BasicBlock mode failed: {}", message));
        }
        other => {
            println!("  [FAIL] Unexpected response: {:?}", other);
            return Err(anyhow::anyhow!("Unexpected response: {:?}", other));
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

    let req = DebuggerRequest::EmulateInstructions {
        pid,
        tid,
        max_instructions: 10000,
        mode: EmulationMode::ModuleTransition,
    };

    match session.send_and_receive(&req)? {
        DebuggerResponse::EmulationResult {
            final_pc,
            instructions_executed,
            stop_reason,
            emulation_time_us,
            ..
        } => {
            println!("  Final PC: 0x{:016X}", final_pc);
            println!("  Instructions executed: {}", instructions_executed);
            println!("  Stop reason: {}", stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", emulation_time_us, emulation_time_us as f64 / 1000.0);

            // Check if we found a module transition
            if stop_reason.contains("ModuleTransition") {
                println!("  ✓ Module transition detected!");
            } else {
                println!("  ⚠ No module transition found within limit");
            }

            session.state.mode_module_transition_tested = true;
            println!("  [PASS] ModuleTransition mode succeeded");
        }
        DebuggerResponse::Error { message } => {
            println!("  [FAIL] ModuleTransition mode error: {}", message);
            return Err(anyhow::anyhow!("ModuleTransition mode failed: {}", message));
        }
        other => {
            println!("  [FAIL] Unexpected response: {:?}", other);
            return Err(anyhow::anyhow!("Unexpected response: {:?}", other));
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

    let req = DebuggerRequest::EmulateInstructions {
        pid,
        tid,
        max_instructions: 50000,  // May need many instructions to reach syscall
        mode: EmulationMode::Syscall,
    };

    match session.send_and_receive(&req)? {
        DebuggerResponse::EmulationResult {
            final_pc,
            instructions_executed,
            stop_reason,
            emulation_time_us,
            ..
        } => {
            println!("  Final PC: 0x{:016X}", final_pc);
            println!("  Instructions executed: {}", instructions_executed);
            println!("  Stop reason: {}", stop_reason);
            println!("  Emulation time: {} us ({:.2} ms)", emulation_time_us, emulation_time_us as f64 / 1000.0);

            // Check if we found a syscall
            if stop_reason.contains("Syscall") {
                println!("  ✓ Syscall detected at 0x{:016X}", final_pc);
                // Try to resolve the syscall address
                if let Ok((module, sym, offset)) = session.resolve_address_to_symbol(pid, final_pc) {
                    if let (Some(m), Some(s), Some(o)) = (module, sym, offset) {
                        println!("    Location: {}!{}+0x{:x}", m, s.name, o);
                    }
                }
            } else {
                println!("  ⚠ No syscall found within limit (stop_reason: {})", stop_reason);
                // Debug: show what instruction caused the stop
                if let Ok((module, sym, offset)) = session.resolve_address_to_symbol(pid, final_pc) {
                    if let (Some(m), Some(s), Some(o)) = (module, sym, offset) {
                        println!("    Exception at: {}!{}+0x{:x}", m, s.name, o);
                    }
                }
                // Disassemble at the exception location
                let arch = Architecture::from_native();
                if let Ok(insns) = session.disassemble_memory(pid, final_pc, 5, arch) {
                    println!("    Instructions at exception:");
                    for insn in insns.iter().take(5) {
                        println!("      0x{:016X}: {} {}", insn.address, insn.mnemonic, insn.op_str);
                    }
                }
            }

            session.state.mode_syscall_tested = true;
            println!("  [PASS] Syscall mode succeeded");
        }
        DebuggerResponse::Error { message } => {
            println!("  [FAIL] Syscall mode error: {}", message);
            return Err(anyhow::anyhow!("Syscall mode failed: {}", message));
        }
        other => {
            println!("  [FAIL] Unexpected response: {:?}", other);
            return Err(anyhow::anyhow!("Unexpected response: {:?}", other));
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
