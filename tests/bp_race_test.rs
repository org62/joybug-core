#![cfg(windows)]

//! Reproduction for the multi-threaded software-breakpoint step-over race.
//!
//! When a thread hits a persistent software breakpoint, the debugger removes the
//! INT3, sets the trap flag, single-steps that one thread past the original
//! instruction, and then re-arms the INT3. On a multi-core machine every OTHER
//! thread of the debuggee keeps running during that step-over window (the whole
//! process is resumed by ContinueDebugEvent, not just the stepping thread). Any
//! other thread that executes the breakpoint address while the INT3 is absent
//! sails straight through and its hit is silently lost.
//!
//! `bp_race_test.exe` makes this deterministic: two worker threads each call
//! `target_func` exactly ITER times, so the debugger must observe exactly
//! 2 * ITER hits on a single persistent breakpoint at `target_func`. If any hit
//! is missed, the race occurred.

mod common;

use common::{find_symbol, get_test_program_path, TestServer};
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

// Must match ITER / NUM_THREADS in tests/test_programs/bp_race_test.c
const ITER: u64 = 10_000;
const NUM_THREADS: u64 = 2;

struct RaceState {
    hits: u64,
    exit_code: Option<u32>,
}

#[test]
// Known ARM64 issue: STATUS_SINGLE_STEP is intermittently not delivered after a
// BRK step-over, so the breakpoint is never re-armed and hits are lost. Run
// explicitly with `--ignored` when working on that.
#[cfg_attr(target_arch = "aarch64", ignore = "known ARM64 dropped single-step issue")]
fn test_software_breakpoint_multithread_race() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("bp_race_test");
    println!("Using bp_race_test.exe at: {}", test_exe);

    let expected_hits = NUM_THREADS * ITER;

    let final_state = DebugSession::new(
        RaceState {
            hits: 0,
            exit_code: None,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        // Resolve target_func in the debuggee and drop a single unfiltered
        // persistent breakpoint on it. Every call from either thread must stop.
        let sym = find_symbol(session, "target_func", "bp_race_test")?;
        println!("target_func at 0x{:X}", sym.va);

        session.set_breakpoint_at(pid, sym.va, None, |session, _pid, _tid, _addr| {
            session.state.hits += 1;
            Ok(BreakpointDecision::Keep)
        })?;
        Ok(())
    })
    .on_process_exited(|session, _pid, exit_code| {
        session.state.exit_code = Some(exit_code);
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    println!(
        "breakpoint hits = {} / expected {} (exit_code = {:?})",
        final_state.hits, expected_hits, final_state.exit_code
    );

    // Sanity: the debuggee itself must have completed all its calls, otherwise
    // the "expected" ground truth is invalid.
    assert_eq!(
        final_state.exit_code,
        Some(0),
        "debuggee did not complete all target_func calls (exit code {:?}); \
         g_calls != expected inside the target",
        final_state.exit_code
    );

    // The core assertion. A missed breakpoint means the step-over window let
    // another thread run through target_func while the INT3 was removed.
    assert_eq!(
        final_state.hits, expected_hits,
        "software breakpoint race: observed {} hits but the target executed \
         target_func exactly {} times. {} hit(s) were missed while the INT3 was \
         temporarily removed for a single-step over on another thread.",
        final_state.hits,
        expected_hits,
        expected_hits.saturating_sub(final_state.hits),
    );
}
