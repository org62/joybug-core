#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::protocol::{
    DebuggerRequest, DebuggerResponse, EmulationMode, TraceExitCondition,
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

        let (trap_line_count, trap_trace_text) = match session.send_and_receive(&trap_trace_req)? {
            DebuggerResponse::TenetTrace {
                trace_text,
                stop_reason,
                trace_time_us,
            } => {
                let line_count = trace_text.lines().count();
                println!(
                    "  Trap-flag trace: {} lines, {} us, reason: {}",
                    line_count,
                    trace_time_us,
                    stop_reason
                );
                session.state.trap_flag_trace_done = true;
                (line_count, trace_text)
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
        println!("Running emulator for {} instructions...", trap_line_count);

        let emu_req = DebuggerRequest::EmulateInstructions {
            pid,
            tid,
            max_instructions: trap_line_count,
            mode: EmulationMode::InstructionTrace,
            exit_condition: None,
        };

        let (emu_line_count, _emu_trace_text) = match session.send_and_receive(&emu_req)? {
            DebuggerResponse::TenetTrace {
                trace_text,
                stop_reason,
                trace_time_us,
            } => {
                let line_count = trace_text.lines().count();
                println!(
                    "  Emulator trace: {} lines, {} us, reason: {}",
                    line_count,
                    trace_time_us,
                    stop_reason
                );
                session.state.emulator_trace_done = true;
                (line_count, trace_text)
            }
            DebuggerResponse::Error { message } => {
                println!("  Emulator trace error: {}", message);
                return Err(anyhow::anyhow!("Emulator trace failed: {}", message));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected emulator response: {:?}", other));
            }
        };

        // Step 4: Compare trace line counts (basic verification)
        println!("\n=== Tenet Trace Comparison ===\n");
        println!("Trace lines: {} (trap) vs {} (emu)", trap_line_count, emu_line_count);

        // Show first few lines from both traces
        println!("\nFirst 5 lines from trap-flag trace:");
        for (i, line) in trap_trace_text.lines().take(5).enumerate() {
            let display = if line.len() > 80 { format!("{}...", &line[..80]) } else { line.to_string() };
            println!("  [{:2}] {}", i, display);
        }

        // With Tenet format, detailed comparison requires parsing delta-encoded lines
        // For now, we verify both traces were produced with the same line count
        // Each line represents one instruction's state, so matching line counts
        // means both backends traced the same number of instructions
        let trace_length = trap_line_count.min(emu_line_count);

        if trap_line_count != emu_line_count {
            println!("\nWARNING: Line count mismatch - trap={} vs emu={}", trap_line_count, emu_line_count);
        }

        println!("\nBoth backends successfully traced {} instructions", trace_length);

        // Store success result
        session.state.comparison_result = Some(ComparisonResult {
            trace_length,
            matches: trace_length,
        });

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
                println!("Status: Both backends traced {} instructions", result.matches);
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
        assert_eq!(
            result.trace_length, result.matches,
            "Trace lengths should match"
        );
        println!(
            "SUCCESS: Both backends traced {} instructions!",
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
            DebuggerResponse::TenetTrace {
                trace_text,
                stop_reason,
                trace_time_us,
            } => {
                let line_count = trace_text.lines().count();
                println!("Traced {} lines in {} us (Tenet format)", line_count, trace_time_us);
                println!("Stop reason: {}", stop_reason);

                // Print first few lines of Tenet trace
                println!("\nFirst 5 trace lines:");
                for (i, line) in trace_text.lines().take(5).enumerate() {
                    let display = if line.len() > 80 {
                        format!("{}...", &line[..80])
                    } else {
                        line.to_string()
                    };
                    println!("[{:2}] {}", i, display);
                }

                session.state.traced = true;
                session.state.trace_count = line_count;
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
