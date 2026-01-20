#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::interfaces::Architecture;
use joybug2::protocol::{
    DebuggerRequest, DebuggerResponse, EmulationMode, RegisterSnapshot, TraceExitCondition,
};
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

/// Test state for tracer tests
struct TracerTestState {
    trap_flag_trace_done: bool,
    emulator_trace_done: bool,
    comparison_result: Option<ComparisonResult>,
}

/// Result of comparing trap-flag trace with emulator trace
struct ComparisonResult {
    trace_length: usize,
    matches: usize,
    mismatches: Vec<RegisterMismatch>,
}

/// Details about a register mismatch at a specific step
#[allow(dead_code)]
struct RegisterMismatch {
    step: usize,
    address: u64,
    register: String,
    trap_value: u64,
    emu_value: u64,
}

impl TracerTestState {
    fn new() -> Self {
        Self {
            trap_flag_trace_done: false,
            emulator_trace_done: false,
            comparison_result: None,
        }
    }
}

/// Compare two register snapshots
/// Returns None if they match, Some(mismatch) on first difference
/// NOTE: RFLAGS is NOT compared because some instructions leave certain flags
/// undefined (e.g., IMUL leaves SF, ZF, AF, PF undefined), and the emulator
/// may compute different undefined values than the real CPU.
fn compare_snapshots(trap: &RegisterSnapshot, emu: &RegisterSnapshot, step: usize, address: u64) -> Option<RegisterMismatch> {
    macro_rules! check_reg {
        ($name:ident) => {
            if trap.$name != emu.$name {
                return Some(RegisterMismatch {
                    step,
                    address,
                    register: stringify!($name).to_uppercase(),
                    trap_value: trap.$name,
                    emu_value: emu.$name,
                });
            }
        };
    }

    check_reg!(rax);
    check_reg!(rbx);
    check_reg!(rcx);
    check_reg!(rdx);
    check_reg!(rsi);
    check_reg!(rdi);
    check_reg!(rbp);
    check_reg!(rsp);
    check_reg!(r8);
    check_reg!(r9);
    check_reg!(r10);
    check_reg!(r11);
    check_reg!(r12);
    check_reg!(r13);
    check_reg!(r14);
    check_reg!(r15);
    check_reg!(rip);

    // NOTE: RFLAGS intentionally NOT compared - some instructions leave flags undefined
    // and the emulator may compute different values than the real CPU. Both are valid.

    None
}

/// Get the path to the compiled xtea_test.exe
fn get_xtea_test_path() -> String {
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| {
        // Fallback for test environment
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        format!("{}\\target\\debug\\build", manifest_dir)
    });

    // Try to find it in the expected location
    let expected_path = format!("{}\\xtea_test.exe", out_dir);
    if std::path::Path::new(&expected_path).exists() {
        return expected_path;
    }

    // Search in common build directories
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

fn run_tracer_comparison(
    session: &mut DebugSession<TracerTestState>,
    pid: u32,
    tid: u32,
    _address: u64,
) -> anyhow::Result<()> {
    println!("\n=== Running Tracer Comparison Test ===\n");

    // Find xtea_encrypt function
    let modules = session.list_modules(pid)?;
    let main_module = modules
        .iter()
        .find(|m| m.name.to_lowercase().contains("xtea_test"))
        .ok_or_else(|| anyhow::anyhow!("Could not find xtea_test module"))?;

    println!("Found main module: {} at 0x{:016X}", main_module.name, main_module.base);

    // Get symbols to find xtea_encrypt
    let encrypt_symbol = session
        .find_symbols("xtea_encrypt", 1)?
        .into_iter()
        .find(|s| s.module_name.to_lowercase().contains("xtea_test"));

    let encrypt_addr = match encrypt_symbol {
        Some(sym) => {
            println!("Found xtea_encrypt at 0x{:016X}", sym.va);
            sym.va
        }
        None => {
            println!("Could not find xtea_encrypt symbol, using entry point + offset");
            // Fallback: just trace from current position
            let ctx = session.get_thread_context(pid, tid)?;
            ctx.get_pc()
        }
    };

    // Set breakpoint at xtea_encrypt
    session.set_breakpoint_at(pid, encrypt_addr, None, |session, pid, tid, address| {
        println!("\n=== Hit xtea_encrypt at 0x{:016X} ===\n", address);

        // Save initial context for restoration
        let initial_context = session.get_thread_context(pid, tid)?;

        // IMPORTANT: Remove the breakpoint BEFORE tracing so the emulator sees the same
        // bytes as the real CPU. The breakpoint byte (0xCC) would cause different execution.
        println!("Removing breakpoint to ensure consistent memory view...");
        let remove_req = DebuggerRequest::RemoveBreakpoint { pid, addr: address };
        match session.send_and_receive(&remove_req)? {
            DebuggerResponse::Ack => {}
            DebuggerResponse::Error { message } => {
                return Err(anyhow::anyhow!("Failed to remove breakpoint: {}", message));
            }
            _ => {}
        }

        // Step 1: Run trap-flag tracer for N instructions
        let trace_limit = 100; // Trace first 100 instructions for comparison
        println!("Running trap-flag tracer for {} instructions...", trace_limit);

        let trap_trace_req = DebuggerRequest::TraceInstructions {
            pid,
            tid,
            exit_condition: TraceExitCondition::InstructionLimit(trace_limit),
            max_instructions: trace_limit,
        };

        let trap_entries = match session.send_and_receive(&trap_trace_req)? {
            DebuggerResponse::InstructionTrace {
                entries,
                stop_reason,
                trace_time_us,
            } => {
                println!(
                    "  Trap-flag trace: {} entries, {} us, reason: {}",
                    entries.len(),
                    trace_time_us,
                    stop_reason
                );
                session.state.trap_flag_trace_done = true;
                entries
            }
            DebuggerResponse::Error { message } => {
                println!("  Trap-flag trace error: {}", message);
                return Err(anyhow::anyhow!("Trap-flag trace failed: {}", message));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected response: {:?}", other));
            }
        };

        // Step 2: Restore context to same starting point
        println!("\nRestoring context to initial state...");
        session.set_thread_context(pid, tid, initial_context)?;

        // Step 3: Run emulator with InstructionTrace mode
        println!("Running emulator for {} instructions...", trap_entries.len());

        let emu_req = DebuggerRequest::EmulateInstructions {
            pid,
            tid,
            max_instructions: trap_entries.len(),
            mode: EmulationMode::InstructionTrace,
        };

        let emu_registers = match session.send_and_receive(&emu_req)? {
            DebuggerResponse::EmulationResult {
                instructions_executed,
                register_trace,
                emulation_time_us,
                stop_reason,
                ..
            } => {
                println!(
                    "  Emulator trace: {} instructions, {} registers, {} us, reason: {}",
                    instructions_executed,
                    register_trace.len(),
                    emulation_time_us,
                    stop_reason
                );
                session.state.emulator_trace_done = true;
                register_trace
            }
            DebuggerResponse::Error { message } => {
                println!("  Emulator trace error: {}", message);
                return Err(anyhow::anyhow!("Emulator trace failed: {}", message));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected emulator response: {:?}", other));
            }
        };

        // Step 4: Compare traces - fail on first divergence
        println!("\n=== Comparing Traces ===\n");

        let compare_len = trap_entries.len().min(emu_registers.len());
        println!("Trace length: {} (trap) vs {} (emu)", trap_entries.len(), emu_registers.len());
        println!("Comparing {} steps...", compare_len);

        let arch = Architecture::from_native();
        for i in 0..compare_len {
            let trap_snapshot = &trap_entries[i].registers;
            let emu_snapshot = &emu_registers[i];
            let address = trap_entries[i].address;

            if let Some(mismatch) = compare_snapshots(trap_snapshot, emu_snapshot, i, address) {
                // Print context around the mismatch
                println!("\n!!! DIVERGENCE at step {} !!!", i);
                println!(
                    "  Address: 0x{:016X}",
                    mismatch.address
                );
                println!(
                    "  Register {} mismatch: trap=0x{:016X} emu=0x{:016X}",
                    mismatch.register, mismatch.trap_value, mismatch.emu_value
                );

                // Show instruction at divergence point
                if let Ok(insns) = session.disassemble_memory(pid, address, 1, arch) {
                    if let Some(insn) = insns.first() {
                        println!("  Instruction: {} {}", insn.mnemonic, insn.op_str);
                    }
                }

                // Show a few steps leading up to divergence
                println!("\n  Steps leading to divergence:");
                let start = i.saturating_sub(3);
                for j in start..=i {
                    let entry = &trap_entries[j];
                    let disasm = session
                        .disassemble_memory(pid, entry.address, 1, arch)
                        .ok()
                        .and_then(|insns| insns.first().map(|i| format!("{} {}", i.mnemonic, i.op_str)))
                        .unwrap_or_default();
                    let marker = if j == i { " <-- DIVERGED" } else { "" };
                    println!(
                        "    [{:3}] 0x{:016X}: {}{}",
                        j, entry.address, disasm, marker
                    );
                }

                // Store the mismatch
                session.state.comparison_result = Some(ComparisonResult {
                    trace_length: i,
                    matches: i,
                    mismatches: vec![mismatch],
                });

                return Err(anyhow::anyhow!(
                    "Trace diverged at step {}: {} mismatch at 0x{:X}",
                    i, session.state.comparison_result.as_ref().unwrap().mismatches[0].register,
                    address
                ));
            }
        }

        // All steps matched!
        println!("\nAll {} steps matched!", compare_len);

        // Store success result
        session.state.comparison_result = Some(ComparisonResult {
            trace_length: compare_len,
            matches: compare_len,
            mismatches: vec![],
        });

        // Print first few trace entries for verification
        println!("\n=== First 5 Trace Entries ===\n");
        for (i, entry) in trap_entries.iter().take(5).enumerate() {
            let disasm = session
                .disassemble_memory(pid, entry.address, 1, arch)
                .ok()
                .and_then(|insns| insns.first().map(|i| format!("{} {}", i.mnemonic, i.op_str)))
                .unwrap_or_default();
            println!(
                "[{:2}] 0x{:016X}: {} | RAX=0x{:X} RBX=0x{:X} RCX=0x{:X}",
                i, entry.address, disasm, entry.registers.rax, entry.registers.rbx, entry.registers.rcx
            );
        }

        // Return Remove since we already removed it manually
        Ok(BreakpointDecision::Remove)
    })?;

    Ok(())
}

#[test]
fn test_tracer_vs_emulator() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let xtea_path = get_xtea_test_path();
    println!("Using test program: {}", xtea_path);

    let final_state = DebugSession::new(TracerTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, tid, address| {
            println!("\n=== Initial breakpoint hit at 0x{:016X} ===", address);

            // Run the comparison test
            run_tracer_comparison(session, pid, tid, address)?;

            println!("\nContinuing to let process run...");
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("\nProcess {} exited with code {}", pid, exit_code);

            // Print final comparison result if available
            if let Some(ref result) = session.state.comparison_result {
                println!("\n=== Final Comparison Result ===");
                println!("Trace length: {}", result.trace_length);
                println!("Matches: {}", result.matches);
                if result.mismatches.is_empty() {
                    println!("Status: All steps matched!");
                } else {
                    println!("Status: Diverged at step {}", result.matches);
                }
            }

            Ok(())
        })
        .launch(xtea_path)
        .expect("Debug session failed");

    // Final assertions
    println!("\n=== Test Assertions ===");

    assert!(
        final_state.trap_flag_trace_done,
        "Trap-flag trace should have run"
    );
    assert!(
        final_state.emulator_trace_done,
        "Emulator trace should have run"
    );

    if let Some(result) = final_state.comparison_result {
        assert!(result.trace_length > 0, "Should have traced some instructions");
        assert!(
            result.mismatches.is_empty(),
            "Traces should match exactly, but diverged at step {}",
            result.matches
        );
        println!(
            "SUCCESS: Traced {} instructions with perfect match!",
            result.trace_length
        );
    } else {
        panic!("No comparison result - test did not complete");
    }

    println!("\n=== Test Complete ===");
}

/// Simpler test that just runs the trap-flag tracer on cmd.exe
#[test]
fn test_trap_flag_tracer_simple() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    struct SimpleState {
        traced: bool,
        trace_count: usize,
    }

    let final_state = DebugSession::new(
        SimpleState {
            traced: false,
            trace_count: 0,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, tid, address| {
        println!("\n=== Initial breakpoint at 0x{:016X} ===", address);

        // Trace just 10 instructions
        let req = DebuggerRequest::TraceInstructions {
            pid,
            tid,
            exit_condition: TraceExitCondition::InstructionLimit(10),
            max_instructions: 10,
        };

        match session.send_and_receive(&req)? {
            DebuggerResponse::InstructionTrace {
                entries,
                stop_reason,
                trace_time_us,
            } => {
                println!("Traced {} instructions in {} us", entries.len(), trace_time_us);
                println!("Stop reason: {}", stop_reason);

                // Print trace
                let arch = Architecture::from_native();
                for (i, entry) in entries.iter().enumerate() {
                    let disasm = session
                        .disassemble_memory(pid, entry.address, 1, arch)
                        .ok()
                        .and_then(|insns| insns.first().map(|i| format!("{} {}", i.mnemonic, i.op_str)))
                        .unwrap_or_default();
                    println!(
                        "[{:2}] 0x{:016X}: {} | RAX=0x{:X}",
                        i, entry.address, disasm, entry.registers.rax
                    );
                }

                session.state.traced = true;
                session.state.trace_count = entries.len();
            }
            DebuggerResponse::Error { message } => {
                println!("Trace error: {}", message);
                return Err(anyhow::anyhow!("Trace failed: {}", message));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected response: {:?}", other));
            }
        }

        Ok(())
    })
    .on_process_exited(|_session, pid, exit_code| {
        println!("Process {} exited with code {}", pid, exit_code);
        Ok(())
    })
    .launch("cmd.exe /c echo test".to_string())
    .expect("Debug session failed");

    assert!(final_state.traced, "Should have traced instructions");
    assert!(final_state.trace_count > 0, "Should have traced at least 1 instruction");
    println!("Successfully traced {} instructions", final_state.trace_count);
}
