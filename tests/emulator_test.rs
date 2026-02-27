#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::interfaces::Architecture;
use joybug2::protocol_io::{
    BreakpointDecision, DebugSession, EmulateResult, EmulationMode, TraceExitCondition,
};

/// Get the path to the compiled xtea_test.exe
fn get_xtea_test_path() -> String {
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        format!("{}\\target\\debug\\build", manifest_dir)
    });

    let expected_path = format!("{}\\xtea_test.exe", out_dir);
    if std::path::Path::new(&expected_path).exists() {
        return expected_path;
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for profile in &["debug", "release"] {
        let search_dir = format!("{}\\target\\{}\\build", manifest_dir, profile);
        if let Ok(entries) = std::fs::read_dir(&search_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let candidate = entry.path().join("out").join("xtea_test.exe");
                    if candidate.exists() {
                        return candidate.to_string_lossy().to_string();
                    }
                }
            }
        }
    }

    panic!("Could not find xtea_test.exe. Make sure to build the project first.");
}

/// Test state tracking which modes have been verified
struct EmulatorTestState {
    basic_tested: bool,
    instruction_trace_tested: bool,
    basic_block_tested: bool,
    module_transition_tested: bool,
    syscall_tested: bool,
    instruction_trace_syscall_tested: bool,
    performance_tested: bool,
    instruction_trace_exit_tested: bool,
}

impl EmulatorTestState {
    fn new() -> Self {
        Self {
            basic_tested: false,
            instruction_trace_tested: false,
            basic_block_tested: false,
            module_transition_tested: false,
            syscall_tested: false,
            instruction_trace_syscall_tested: false,
            performance_tested: false,
            instruction_trace_exit_tested: false,
        }
    }

    fn all_tested(&self) -> bool {
        self.basic_tested
            && self.instruction_trace_tested
            && self.basic_block_tested
            && self.module_transition_tested
            && self.syscall_tested
            && self.instruction_trace_syscall_tested
            && self.performance_tested
            && self.instruction_trace_exit_tested
    }
}

/// Test Basic mode: emulate xtea_encrypt, verify code actually executed
fn test_basic(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    start_pc: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: Basic mode ===");

    let result = session.emulate_instructions(pid, tid, 500, EmulationMode::Basic, None)?;

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

/// Test BasicBlock mode: verify basic block recording via BLOCK hooks
/// Note: With count=0 (CRITICAL for JIT), emulation runs until a hook fires
/// (syscall) or the safety timeout. Blocks may span multiple modules.
fn test_basic_block(
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

/// Test InstructionTrace mode: verify trace quality and register snapshots
fn test_instruction_trace(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    start_pc: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: InstructionTrace mode ===");

    let limit = 300;
    let result = session.emulate_instructions(pid, tid, limit, EmulationMode::InstructionTrace, None)?;

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
            let first_line = trace.trace_text.lines().next().unwrap();
            let expected_pc = format!("pc=0x{:x}", start_pc);
            assert!(
                first_line.contains(&expected_pc),
                "InstructionTrace: first line should contain start PC {}, got: {}",
                expected_pc,
                if first_line.len() > 100 { &first_line[..100] } else { first_line }
            );

            // Subsequent lines should have delta-encoded pc= values
            let mut lines_with_pc = 0;
            for line in trace.trace_text.lines() {
                if line.contains("pc=") {
                    lines_with_pc += 1;
                }
            }
            assert_eq!(
                lines_with_pc, line_count,
                "InstructionTrace: every line should contain a pc= value"
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

/// Test InstructionTrace with exit condition: stop at a specific address
fn test_instruction_trace_exit_condition(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
    exit_addr: u64,
) -> anyhow::Result<()> {
    println!("\n=== Test: InstructionTrace with ReachAddress exit ===");
    println!("  Exit address: 0x{:016X}", exit_addr);

    let result = session.emulate_instructions(
        pid, tid, 50000, EmulationMode::InstructionTrace,
        Some(TraceExitCondition::ReachAddress(exit_addr)),
    )?;

    match result {
        EmulateResult::Trace(trace) => {
            let line_count = trace.trace_text.lines().count();
            println!("  Trace lines: {}", line_count);
            println!("  Stop reason: {}", trace.stop_reason);
            println!("  Trace time: {} us ({:.2} ms)", trace.trace_time_us,
                trace.trace_time_us as f64 / 1000.0);

            // Should have stopped due to reaching the address, not instruction limit
            assert!(
                trace.stop_reason.contains("ReachedAddress") || trace.stop_reason.contains("Stopped"),
                "InstructionTrace exit: expected ReachedAddress stop, got: {}",
                trace.stop_reason
            );

            // The last trace line should contain the exit address
            if let Some(last_line) = trace.trace_text.lines().last() {
                let expected_pc = format!("pc=0x{:x}", exit_addr);
                assert!(
                    last_line.contains(&expected_pc),
                    "InstructionTrace exit: last line should contain exit PC {}, got: {}",
                    expected_pc,
                    if last_line.len() > 100 { &last_line[..100] } else { last_line }
                );
            }

            // xtea_encrypt with 32 rounds on ARM64/Od is ~1700 instructions;
            // should be well under the 50000 limit
            assert!(
                line_count < 5000,
                "InstructionTrace exit: expected <5000 instructions for xtea_encrypt, got {}",
                line_count
            );

            session.state.instruction_trace_exit_tested = true;
            println!("  [PASS] InstructionTrace exit: stopped at target after {} instructions", line_count);
        }
        EmulateResult::Emulation(_) => {
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}

/// Test ModuleTransition: emulate from entry point, detect CRT → ucrtbase transition
fn test_module_transition(
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

/// Test Syscall mode: emulate from syscall_marker which calls CloseHandle(NULL)
/// This goes through kernel32 → ntdll → NtClose → SVC/SYSCALL
fn test_syscall(
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

/// Test InstructionTrace stops on syscall: emulate from syscall_marker with InstructionTrace
fn test_instruction_trace_syscall(
    session: &mut DebugSession<EmulatorTestState>,
    pid: u32,
    tid: u32,
) -> anyhow::Result<()> {
    println!("\n=== Test: InstructionTrace stops on syscall ===");

    let result = session.emulate_instructions(pid, tid, 50000, EmulationMode::InstructionTrace, None)?;

    match result {
        EmulateResult::Trace(trace) => {
            let line_count = trace.trace_text.lines().count();
            println!("  Trace lines: {}", line_count);
            println!("  Stop reason: {}", trace.stop_reason);
            println!("  Trace time: {} us ({:.2} ms)", trace.trace_time_us,
                trace.trace_time_us as f64 / 1000.0);

            if trace.stop_reason.contains("Syscall") {
                println!("  Syscall detected in trace!");
                // Should have stopped well before the 50000 limit
                assert!(
                    line_count < 5000,
                    "InstructionTrace syscall: expected <5000 instructions to reach NtClose, got {}",
                    line_count
                );
            } else {
                println!("  No syscall in trace (stop_reason: {})", trace.stop_reason);
            }

            session.state.instruction_trace_syscall_tested = true;
            println!("  [PASS] InstructionTrace syscall test completed");
        }
        EmulateResult::Emulation(_) => {
            return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
        }
    }

    Ok(())
}

/// Test performance: verify InstructionTrace batching is efficient.
/// InstructionTrace uses count=TRACE_BATCH_SIZE per emu_start call, which
/// lets Unicorn build multi-instruction translation blocks within each batch.
/// If someone changed this to count=1, tracing would be 10-100x slower.
fn test_performance(
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
        Some(TraceExitCondition::ReachAddress(exit_addr)),
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

#[test]
fn test_emulator_integration() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let xtea_path = get_xtea_test_path();

    println!("=== Emulator Integration Test ===");
    println!("Test program: {}", xtea_path);
    println!("Server: {}", server_addr);

    let final_state = DebugSession::new(EmulatorTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, address| {
            println!("\n=== Initial breakpoint at 0x{:016X} ===", address);

            // Find the main module
            let modules = session.list_modules(pid)?;
            let main_module = modules.iter()
                .find(|m| m.name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find xtea_test module"))?;
            println!("  Module: {} at 0x{:016X} (size: 0x{:X})",
                main_module.name, main_module.base, main_module.size.unwrap_or(0));

            // Find key symbols
            let encrypt_sym = session.find_symbols("xtea_encrypt", 1)?
                .into_iter()
                .find(|s| s.module_name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find xtea_encrypt symbol"))?;
            println!("  xtea_encrypt: 0x{:016X}", encrypt_sym.va);

            let end_marker_sym = session.find_symbols("trace_end_marker", 1)?
                .into_iter()
                .find(|s| s.module_name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find trace_end_marker symbol"))?;
            println!("  trace_end_marker: 0x{:016X}", end_marker_sym.va);

            let syscall_marker_sym = session.find_symbols("syscall_marker", 1)?
                .into_iter()
                .find(|s| s.module_name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find syscall_marker symbol"))?;
            println!("  syscall_marker: 0x{:016X}", syscall_marker_sym.va);

            let entry_info = session.get_module_extra_info(pid, main_module.base)?;
            let entry_rva = entry_info.nt_headers.OptionalHeader.AddressOfEntryPoint;
            let entry_point = main_module.base + entry_rva as u64;
            println!("  Entry point: 0x{:016X}", entry_point);

            let encrypt_addr = encrypt_sym.va;
            let end_marker_addr = end_marker_sym.va;
            let syscall_marker_addr = syscall_marker_sym.va;
            // Breakpoint at syscall_marker: test Syscall and InstructionTrace+Syscall modes
            // syscall_marker calls CloseHandle(NULL) → kernel32 → ntdll!NtClose → SVC/SYSCALL
            session.set_breakpoint_at(pid, syscall_marker_addr, None, move |session, pid, tid, address| {
                println!("\n=== Hit syscall_marker at 0x{:016X} ===", address);

                session.remove_breakpoint(pid, address)?;
                let saved_context = session.get_thread_context(pid, tid)?;

                // --- Test: Syscall mode ---
                test_syscall(session, pid, tid)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                // --- Test: InstructionTrace stops on syscall ---
                test_instruction_trace_syscall(session, pid, tid)?;
                session.set_thread_context(pid, tid, saved_context)?;

                Ok(BreakpointDecision::Remove)
            })?;

            // Breakpoint at xtea_encrypt: test modes on known arithmetic code
            session.set_breakpoint_at(pid, encrypt_addr, None, move |session, pid, tid, address| {
                println!("\n=== Hit xtea_encrypt at 0x{:016X} ===", address);

                // Remove breakpoint so emulator sees original bytes
                session.remove_breakpoint(pid, address)?;

                // Save context for restoration between tests
                let saved_context = session.get_thread_context(pid, tid)?;
                let start_pc = saved_context.get_pc();

                // Disassemble first few instructions for context
                let arch = Architecture::from_native();
                let disasm = session.disassemble_memory(pid, start_pc, 5, arch)?;
                println!("  Disassembly:");
                for insn in &disasm {
                    println!("    0x{:016X}: {} {}", insn.address, insn.mnemonic, insn.op_str);
                }

                // --- Test 1: Basic mode ---
                test_basic(session, pid, tid, start_pc)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                // --- Test 2: BasicBlock mode ---
                test_basic_block(session, pid, tid, start_pc)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                // --- Test 3: InstructionTrace mode ---
                test_instruction_trace(session, pid, tid, start_pc)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                // --- Test 4: InstructionTrace with exit condition ---
                test_instruction_trace_exit_condition(session, pid, tid, end_marker_addr)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                // --- Test 5: Performance (trace batching) ---
                test_performance(session, pid, tid, end_marker_addr)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                Ok(BreakpointDecision::Remove)
            })?;

            // Breakpoint at entry point: test ModuleTransition
            session.set_breakpoint_at(pid, entry_point, None, move |session, pid, tid, address| {
                println!("\n=== Hit entry point at 0x{:016X} ===", address);

                session.remove_breakpoint(pid, address)?;
                let saved_context = session.get_thread_context(pid, tid)?;

                // --- Test: ModuleTransition ---
                test_module_transition(session, pid, tid)?;
                session.set_thread_context(pid, tid, saved_context)?;

                Ok(BreakpointDecision::Remove)
            })?;

            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("\nProcess {} exited with code {}", pid, exit_code);

            assert!(session.state.basic_tested, "Basic mode was not tested");
            assert!(session.state.basic_block_tested, "BasicBlock mode was not tested");
            assert!(session.state.instruction_trace_tested, "InstructionTrace mode was not tested");
            assert!(session.state.instruction_trace_exit_tested, "InstructionTrace exit condition was not tested");
            assert!(session.state.instruction_trace_syscall_tested, "InstructionTrace syscall was not tested");
            assert!(session.state.module_transition_tested, "ModuleTransition mode was not tested");
            assert!(session.state.syscall_tested, "Syscall mode was not tested");
            assert!(session.state.performance_tested, "Performance was not tested");

            println!("\nAll emulator tests passed!");
            Ok(())
        })
        .launch(xtea_path)
        .expect("Debug session failed");

    assert!(final_state.all_tested(), "Not all emulator features were tested");
}
