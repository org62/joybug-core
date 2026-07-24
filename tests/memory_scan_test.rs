#![cfg(windows)]

mod common;

use common::{get_test_program_path, TestServer};
use joybug2::protocol_io::{
    BreakpointDecision, DebugSession, ScanCompareType, ScanValue, ScanValueType,
};

// ---------------------------------------------------------------------------
// Test 1: ExactValue narrowing for all 6 types
// ---------------------------------------------------------------------------

const NUM_TYPES: usize = 6;
const TYPE_NAMES: [&str; NUM_TYPES] = ["U8", "U16", "U32", "U64", "F32", "F64"];

struct ExactValueState {
    pid: u32,
    iteration: u32,
    scan_ids: [Option<u64>; NUM_TYPES],
    match_counts: [Vec<u64>; NUM_TYPES],
    scan_times_us: [Vec<u64>; NUM_TYPES],
    done: bool,
}

impl ExactValueState {
    fn new() -> Self {
        Self {
            pid: 0,
            iteration: 0,
            scan_ids: [None; NUM_TYPES],
            match_counts: Default::default(),
            scan_times_us: Default::default(),
            done: false,
        }
    }
}

/// Compute the expected value for each type at a given iteration.
fn expected_value(type_idx: usize, iteration: u32) -> ScanValue {
    let i = iteration as u64;
    match type_idx {
        0 => ScanValue::U8((42u8).wrapping_add(i as u8)),
        1 => ScanValue::U16((0x1234u16).wrapping_add(i as u16)),
        2 => ScanValue::U32(0x12345678u32.wrapping_add(i as u32)),
        3 => ScanValue::U64(0x123456789ABCu64.wrapping_add(i)),
        4 => ScanValue::F32(3.14f32 + iteration as f32 * 1.5f32),
        5 => ScanValue::F64(2.718281828f64 + iteration as f64 * 0.5f64),
        _ => unreachable!(),
    }
}

fn value_type_for(type_idx: usize) -> ScanValueType {
    match type_idx {
        0 => ScanValueType::U8,
        1 => ScanValueType::U16,
        2 => ScanValueType::U32,
        3 => ScanValueType::U64,
        4 => ScanValueType::F32,
        5 => ScanValueType::F64,
        _ => unreachable!(),
    }
}

fn print_timing_table(name: &str, type_name: &str, counts: &[u64], times: &[u64]) {
    println!("\n=== {} Scan Timing ({}) ===", name, type_name);
    println!("  {:>4}  {:>10}  {:>10}", "Iter", "Matches", "Time(us)");
    let mut total_us = 0u64;
    for (i, (c, t)) in counts.iter().zip(times.iter()).enumerate() {
        println!("  {:>4}  {:>10}  {:>10}", i, c, t);
        total_us += t;
    }
    println!("  Total: {} us", total_us);
}

#[test]
fn memory_scan_exact_value() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("memory_scan_test");
    println!("Using memory_scan_test.exe at: {}", test_exe);

    let final_state =
        DebugSession::new(ExactValueState::new(), Some(server_addr.as_str()))
            .expect("Failed to create debug session")
            .on_initial_breakpoint(|session, pid, _tid, _addr| {
                session.state.pid = pid;
                println!("Initial breakpoint hit for pid={}", pid);

                session.set_breakpoint_by_symbol(
                    pid,
                    "pause_here",
                    None,
                    |session, pid, _tid, _addr| {
                        let iter = session.state.iteration;

                        if session.state.done {
                            return Ok(BreakpointDecision::Remove);
                        }

                        if iter == 0 {
                            // First hit: start scans for all 6 types
                            println!("\n--- Iteration 0: starting scans ---");
                            for idx in 0..NUM_TYPES {
                                let val = expected_value(idx, 0);
                                let vtype = value_type_for(idx);
                                // Use tolerance for floats
                                let tol = if idx >= 4 { Some(0.001) } else { None };
                                let (scan_id, match_count, time_us) =
                                    session.scan_memory_start(
                                        pid,
                                        vtype,
                                        ScanCompareType::ExactValue,
                                        Some(val),
                                        None,
                                        None,
                                        tol,
                                        true,
                                        // Exercise the scoped (fixed thread count) pool path;
                                        // results must be identical to the all-cores path.
                                        Some(2),
                                    )?;
                                println!(
                                    "  {}: scan_id={}, matches={}, time={}us",
                                    TYPE_NAMES[idx], scan_id, match_count, time_us
                                );
                                session.state.scan_ids[idx] = Some(scan_id);
                                session.state.match_counts[idx].push(match_count);
                                session.state.scan_times_us[idx].push(time_us);
                            }
                        } else {
                            // Subsequent hits: refine scans
                            println!("\n--- Iteration {} ---", iter);
                            let mut all_converged = true;
                            for idx in 0..NUM_TYPES {
                                let last_count = *session.state.match_counts[idx]
                                    .last()
                                    .unwrap_or(&u64::MAX);
                                if last_count == 0 {
                                    // Already empty, skip
                                    session.state.match_counts[idx].push(0);
                                    session.state.scan_times_us[idx].push(0);
                                    continue;
                                }
                                let val = expected_value(idx, iter);
                                let scan_id = session.state.scan_ids[idx].unwrap();
                                let (match_count, time_us) = session.scan_memory_next(
                                    scan_id,
                                    ScanCompareType::ExactValue,
                                    Some(val),
                                    None,
                                    None,
                                )?;
                                println!(
                                    "  {}: matches={}, time={}us",
                                    TYPE_NAMES[idx], match_count, time_us
                                );
                                session.state.match_counts[idx].push(match_count);
                                session.state.scan_times_us[idx].push(time_us);
                                if match_count > 5 {
                                    all_converged = false;
                                }
                            }
                            if all_converged || iter >= 15 {
                                println!("\n--- Converged at iteration {} ---", iter);
                                session.state.done = true;
                            }
                        }

                        session.state.iteration += 1;

                        if session.state.done {
                            // Verify results before removing breakpoint
                            println!("\n--- Verifying final results ---");
                            let verify_iter = session.state.iteration - 1;
                            for idx in 0..NUM_TYPES {
                                let scan_id = session.state.scan_ids[idx].unwrap();
                                let (addrs, values, total) =
                                    session.scan_memory_get_results(scan_id, 0, 10)?;
                                let expected = expected_value(idx, verify_iter);
                                println!(
                                    "  {}: total={}, addrs={:?}, expected={:?}",
                                    TYPE_NAMES[idx], total, addrs, expected
                                );
                                assert!(
                                    total >= 1,
                                    "{}: expected at least 1 match in final results, got {}",
                                    TYPE_NAMES[idx],
                                    total
                                );
                                // Verify at least one returned value matches expected
                                let found_match = values.iter().any(|v| {
                                    match (v, &expected) {
                                        (ScanValue::U8(a), ScanValue::U8(b)) => a == b,
                                        (ScanValue::U16(a), ScanValue::U16(b)) => a == b,
                                        (ScanValue::U32(a), ScanValue::U32(b)) => a == b,
                                        (ScanValue::U64(a), ScanValue::U64(b)) => a == b,
                                        (ScanValue::F32(a), ScanValue::F32(b)) => {
                                            (a - b).abs() < 0.01
                                        }
                                        (ScanValue::F64(a), ScanValue::F64(b)) => {
                                            (a - b).abs() < 0.001
                                        }
                                        _ => false,
                                    }
                                });
                                assert!(
                                    found_match,
                                    "{}: no result matched expected value {:?}, got {:?}",
                                    TYPE_NAMES[idx], expected, values
                                );

                                // Clean up
                                session.scan_memory_reset(scan_id)?;
                            }
                            return Ok(BreakpointDecision::Remove);
                        }

                        Ok(BreakpointDecision::Keep)
                    },
                )?;
                Ok(())
            })
            .on_process_exited(|_session, pid, exit_code| {
                println!("Process {} exited with code 0x{:X}", pid, exit_code);
                Ok(())
            })
            .launch(test_exe)
            .expect("Debug session failed");

    // Print timing tables
    for idx in 0..NUM_TYPES {
        print_timing_table(
            "ExactValue",
            TYPE_NAMES[idx],
            &final_state.match_counts[idx],
            &final_state.scan_times_us[idx],
        );
    }

    // Assert convergence
    for idx in 0..NUM_TYPES {
        let counts = &final_state.match_counts[idx];
        assert!(
            !counts.is_empty(),
            "{}: no scan iterations recorded",
            TYPE_NAMES[idx]
        );
        let first = counts[0];
        let last = *counts.last().unwrap();
        assert!(
            last < first || first <= 5,
            "{}: match count did not decrease (first={}, last={})",
            TYPE_NAMES[idx],
            first,
            last
        );
        assert!(
            last >= 1,
            "{}: expected at least 1 final match, got {}",
            TYPE_NAMES[idx],
            last
        );
    }
    assert!(final_state.done, "Test did not complete");
    println!("\n=== memory_scan_exact_value PASSED ===");
}

// ---------------------------------------------------------------------------
// Test 2: UnknownInitialValue -> IncreasedValueBy for u32
// ---------------------------------------------------------------------------

struct UnknownValueState {
    pid: u32,
    iteration: u32,
    scan_id: Option<u64>,
    match_counts: Vec<u64>,
    scan_times_us: Vec<u64>,
    done: bool,
}

impl UnknownValueState {
    fn new() -> Self {
        Self {
            pid: 0,
            iteration: 0,
            scan_id: None,
            match_counts: Vec::new(),
            scan_times_us: Vec::new(),
            done: false,
        }
    }
}

#[test]
fn memory_scan_unknown_initial() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("memory_scan_test");
    println!("Using memory_scan_test.exe at: {}", test_exe);

    let final_state =
        DebugSession::new(UnknownValueState::new(), Some(server_addr.as_str()))
            .expect("Failed to create debug session")
            .on_initial_breakpoint(|session, pid, _tid, _addr| {
                session.state.pid = pid;
                println!("Initial breakpoint hit for pid={}", pid);

                session.set_breakpoint_by_symbol(
                    pid,
                    "pause_here",
                    None,
                    |session, pid, _tid, _addr| {
                        let iter = session.state.iteration;

                        if session.state.done {
                            return Ok(BreakpointDecision::Remove);
                        }

                        if iter == 0 {
                            // Start with UnknownInitialValue — snapshot all u32s
                            println!("\n--- Iteration 0: UnknownInitialValue scan ---");
                            let (scan_id, match_count, time_us) =
                                session.scan_memory_start(
                                    pid,
                                    ScanValueType::U32,
                                    ScanCompareType::UnknownInitialValue,
                                    None,
                                    None,
                                    None,
                                    None,
                                    true,
                                    None,
                                )?;
                            println!(
                                "  scan_id={}, matches={}, time={}us",
                                scan_id, match_count, time_us
                            );
                            session.state.scan_id = Some(scan_id);
                            session.state.match_counts.push(match_count);
                            session.state.scan_times_us.push(time_us);
                        } else {
                            // Filter by IncreasedValueBy(1)
                            println!("\n--- Iteration {}: IncreasedValueBy(1) ---", iter);
                            let scan_id = session.state.scan_id.unwrap();
                            let (match_count, time_us) = session.scan_memory_next(
                                scan_id,
                                ScanCompareType::IncreasedValueBy,
                                Some(ScanValue::U32(1)),
                                None,
                                None,
                            )?;
                            println!(
                                "  matches={}, time={}us",
                                match_count, time_us
                            );
                            session.state.match_counts.push(match_count);
                            session.state.scan_times_us.push(time_us);

                            if match_count <= 20 || iter >= 10 {
                                println!(
                                    "\n--- Converged at iteration {} (matches={}) ---",
                                    iter, match_count
                                );
                                session.state.done = true;
                            }
                        }

                        session.state.iteration += 1;

                        if session.state.done {
                            // Verify results
                            let scan_id = session.state.scan_id.unwrap();
                            let verify_iter = session.state.iteration - 1;
                            let expected_u32 =
                                0x12345678u32.wrapping_add(verify_iter as u32);
                            let (addrs, values, total) =
                                session.scan_memory_get_results(scan_id, 0, 100)?;
                            println!(
                                "\n--- Final results: total={}, expected=0x{:X} ---",
                                total, expected_u32
                            );
                            for (a, v) in addrs.iter().zip(values.iter()) {
                                println!("  0x{:X} = {:?}", a, v);
                            }

                            // At least one address should contain expected g_u32
                            let found = values.iter().any(|v| match v {
                                ScanValue::U32(x) => *x == expected_u32,
                                _ => false,
                            });
                            assert!(
                                found,
                                "Expected to find g_u32=0x{:X} in results, got {:?}",
                                expected_u32, values
                            );

                            session.scan_memory_reset(scan_id)?;
                            return Ok(BreakpointDecision::Remove);
                        }

                        Ok(BreakpointDecision::Keep)
                    },
                )?;
                Ok(())
            })
            .on_process_exited(|_session, pid, exit_code| {
                println!("Process {} exited with code 0x{:X}", pid, exit_code);
                Ok(())
            })
            .launch(test_exe)
            .expect("Debug session failed");

    // Print timing table
    println!("\n=== UnknownInitialValue -> IncreasedValueBy Scan Timing (U32) ===");
    println!("  {:>4}  {:>10}  {:>10}", "Iter", "Matches", "Time(us)");
    let mut total_us = 0u64;
    for (i, (c, t)) in final_state
        .match_counts
        .iter()
        .zip(final_state.scan_times_us.iter())
        .enumerate()
    {
        println!("  {:>4}  {:>10}  {:>10}", i, c, t);
        total_us += t;
    }
    println!("  Total: {} us", total_us);

    // Assertions
    assert!(
        !final_state.match_counts.is_empty(),
        "No scan iterations recorded"
    );
    let initial_count = final_state.match_counts[0];
    println!(
        "\nInitial snapshot count: {} (should be very large)",
        initial_count
    );
    assert!(
        initial_count > 1000,
        "UnknownInitialValue should match very many addresses, got {}",
        initial_count
    );

    if final_state.match_counts.len() > 1 {
        let final_count = *final_state.match_counts.last().unwrap();
        assert!(
            final_count < initial_count,
            "Match count should decrease after filtering (initial={}, final={})",
            initial_count,
            final_count
        );
    }
    assert!(final_state.done, "Test did not complete");
    println!("\n=== memory_scan_unknown_initial PASSED ===");
}
