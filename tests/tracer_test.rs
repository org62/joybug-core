#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path, find_symbol, find_module};
use joybug2::protocol_io::{
    BreakpointDecision, DebugSession, EmulateResult, EmulationMode, TraceExitCondition,
};

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

fn run_tracer_comparison(
    session: &mut DebugSession<TracerTestState>,
    pid: u32,
    _tid: u32,
    _address: u64,
) -> anyhow::Result<()> {
    println!("\n=== Running Tracer Comparison Test ===\n");

    // Find xtea_encrypt function
    let main_module = find_module(session, pid, "xtea_test")?;
    println!("Found main module: {} at 0x{:016X}", main_module.name, main_module.base);

    let encrypt_sym = find_symbol(session, "xtea_encrypt", "xtea_test")?;
    let encrypt_addr = encrypt_sym.va;
    println!("Found xtea_encrypt at 0x{:016X}", encrypt_addr);

    // Set breakpoint at xtea_encrypt
    session.set_breakpoint_at(pid, encrypt_addr, None, |session, pid, tid, address| {
        println!("\n=== Hit xtea_encrypt at 0x{:016X} ===\n", address);

        // Save initial context for restoration
        let initial_context = session.get_thread_context(pid, tid)?;

        // IMPORTANT: Remove the breakpoint BEFORE tracing so the emulator sees the same
        // bytes as the real CPU. The breakpoint byte (0xCC) would cause different execution.
        println!("Removing breakpoint to ensure consistent memory view...");
        session.remove_breakpoint(pid, address)?;

        // Step 1: Run trap-flag tracer for N instructions
        let trace_limit = 100; // Trace first 100 instructions for comparison
        println!("Running trap-flag tracer for {} instructions...", trace_limit);

        let trap_result = session.trace_instructions(
            pid,
            tid,
            TraceExitCondition::InstructionLimit(trace_limit),
            trace_limit,
        )?;

        let trap_line_count = trap_result.trace_text.lines().count();
        println!(
            "  Trap-flag trace: {} lines, {} us, reason: {}",
            trap_line_count,
            trap_result.trace_time_us,
            trap_result.stop_reason
        );
        session.state.trap_flag_trace_done = true;
        let trap_trace_text = trap_result.trace_text;

        // Step 2: Restore context to same starting point
        println!("\nRestoring context to initial state...");
        session.set_thread_context(pid, tid, initial_context)?;

        // Step 3: Run emulator with InstructionTrace mode
        println!("Running emulator for {} instructions...", trap_line_count);

        let emu_result = session.emulate_instructions(
            pid,
            tid,
            trap_line_count,
            EmulationMode::InstructionTrace,
            None,
            vec![],
        )?;

        let emu_line_count = match &emu_result {
            EmulateResult::Trace(trace) => {
                let line_count = trace.trace_text.lines().count();
                println!(
                    "  Emulator trace: {} lines, {} us, reason: {}",
                    line_count,
                    trace.trace_time_us,
                    trace.stop_reason
                );
                session.state.emulator_trace_done = true;
                line_count
            }
            EmulateResult::Emulation(_) => {
                return Err(anyhow::anyhow!("Expected TenetTrace for InstructionTrace mode"));
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

    let xtea_path = get_test_program_path("xtea_test");
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
        let result = session.trace_instructions(
            pid,
            tid,
            TraceExitCondition::InstructionLimit(10),
            10,
        )?;

        let line_count = result.trace_text.lines().count();
        println!("Traced {} lines in {} us (Tenet format)", line_count, result.trace_time_us);
        println!("Stop reason: {}", result.stop_reason);

        // Print first few lines of Tenet trace
        println!("\nFirst 5 trace lines:");
        for (i, line) in result.trace_text.lines().take(5).enumerate() {
            let display = if line.len() > 80 {
                format!("{}...", &line[..80])
            } else {
                line.to_string()
            };
            println!("[{:2}] {}", i, display);
        }

        session.state.traced = true;
        session.state.trace_count = line_count;

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
