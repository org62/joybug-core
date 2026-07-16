#![cfg(windows)]

//! End-to-end tests for the server-side code-coverage engine.
//!
//! Coverage breakpoints are counted inside the server and the debuggee
//! auto-continues silently (no client `Breakpoint` events), so these tests drive
//! a real target (`cmd.exe`) to completion and read the counts back with
//! `get_coverage` in `on_process_exited` (the process entry survives process
//! exit; it is only dropped on detach). Functions are enumerated from ntdll's
//! RUNTIME_FUNCTION table (PE exception directory) so the test needs no PDBs.

mod common;

use common::{module_file_name_matches, runtime_function_entry_vas, TestServer};
use joybug2::protocol::CoverageHit;
use joybug2::protocol_io::DebugSession;

struct CovState {
    /// (name, base) for ntdll, captured from process-create / dll-load events.
    modules: Vec<(String, u64)>,
    armed: usize,
    final_hits: Vec<CoverageHit>,
}

fn is_ntdll(name: &str) -> bool {
    module_file_name_matches(name, "ntdll.dll")
}

/// Launch `cmd.exe /c echo`, arm coverage on every ntdll function with `limit`,
/// run to exit, and return `(armed_count, final_hits)`.
fn run_coverage(limit: u64) -> (usize, Vec<CoverageHit>) {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let state = CovState { modules: Vec::new(), armed: 0, final_hits: Vec::new() };

    let final_state = DebugSession::new(state, Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_process_created(|session, _pid, _tid, image_name, base| {
            if is_ntdll(image_name) {
                session.state.modules.push((image_name.to_string(), base));
            }
            Ok(())
        })
        .on_dll_loaded(|session, _pid, _tid, dll_name, base| {
            if is_ntdll(dll_name) {
                session.state.modules.push((dll_name.to_string(), base));
            }
            Ok(())
        })
        .on_initial_breakpoint(move |session, pid, _tid, _addr| {
            let modules = session.state.modules.clone();
            let mut addrs: Vec<u64> = Vec::new();
            for (_name, base) in &modules {
                addrs.extend(runtime_function_entry_vas(session, pid, *base));
            }
            addrs.sort_unstable();
            addrs.dedup();
            session.state.armed = addrs.len();
            println!("Arming {} coverage breakpoints (limit={})", addrs.len(), limit);
            session.start_coverage(pid, addrs, limit).expect("start_coverage failed");
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            // The process entry (and its coverage map) is still present here.
            session.state.final_hits = session.get_coverage(pid).unwrap_or_default();
            println!("Process exited with code {}", exit_code);
            Ok(())
        })
        .launch("cmd.exe /c echo coverage".to_string())
        .expect("Debug session failed");

    (final_state.armed, final_state.final_hits)
}

/// Every reported hit carries first-hit metadata: seqs are exactly the
/// consecutive set `1..=hits.len()` (only coverage first-hits advance the
/// counter, and each hit address has exactly one first hit), and at least one
/// thread id is recorded per hit.
fn assert_hit_metadata(hits: &[CoverageHit]) {
    let mut seqs: Vec<u64> = hits.iter().map(|h| h.first_hit_seq).collect();
    seqs.sort_unstable();
    for (i, seq) in seqs.iter().enumerate() {
        assert_eq!(*seq, i as u64 + 1, "first_hit_seq should be consecutive 1..N");
    }
    for h in hits {
        assert!(!h.thread_ids.is_empty(), "hit at 0x{:x} reported no thread ids", h.address);
    }
}

/// `limit = 1` removes each breakpoint on its first hit, so every count is 0 or 1
/// and the target still runs to completion. Validates arming, silent counting,
/// and auto-removal.
#[test]
fn test_code_coverage_removes_after_first_hit() {
    joybug2::init_tracing();

    let (armed, hits) = run_coverage(1);
    let hit_fns = hits.iter().filter(|h| h.hit_count > 0).count();
    let max = hits.iter().map(|h| h.hit_count).max().unwrap_or(0);
    println!("armed={} hit_fns={} max_count={}", armed, hit_fns, max);

    assert!(armed > 100, "expected many armed coverage breakpoints, got {}", armed);
    assert!(hit_fns >= 10, "expected >=10 ntdll functions hit, got {}", hit_fns);
    assert_eq!(max, 1, "limit=1 should remove after first hit; max count was {}", max);
    assert_hit_metadata(&hits);
}

/// `limit = 3` keeps counting up to 3 hits per function. Validates the
/// keep-and-re-arm path (some hot ntdll function is called more than once) and
/// that the per-address cap is honored.
#[test]
fn test_code_coverage_counts_and_caps_repeated_hits() {
    joybug2::init_tracing();

    let (armed, hits) = run_coverage(3);
    let hit_fns = hits.iter().filter(|h| h.hit_count > 0).count();
    let max = hits.iter().map(|h| h.hit_count).max().unwrap_or(0);
    println!("armed={} hit_fns={} max_count={}", armed, hit_fns, max);

    assert!(armed > 100, "expected many armed coverage breakpoints, got {}", armed);
    assert!(hit_fns >= 10, "expected >=10 ntdll functions hit, got {}", hit_fns);
    assert!(max >= 2, "limit=3 should count repeated hits; max count was {}", max);
    assert!(max <= 3, "limit=3 should cap counts at 3; max count was {}", max);
    assert_hit_metadata(&hits);
}
