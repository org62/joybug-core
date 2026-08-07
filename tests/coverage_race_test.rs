#![cfg(windows)]

//! Regression test for stale code-coverage breakpoint hits in a multi-threaded
//! target.
//!
//! `ContinueDebugEvent` resumes the whole debuggee, so several threads can trap on
//! the same coverage INT3 before the debugger processes the first event. The extra
//! events are queued by the kernel and delivered *after* the hit limit has already
//! retired that breakpoint and written the original instruction back. The server
//! must still recognize those hits as its own: rewind the thread's IP to the
//! restored instruction and continue silently.
//!
//! Before that was handled, such a hit surfaced as a client `Breakpoint` event at
//! an address nobody had a breakpoint on, with the IP one byte past the (already
//! removed) INT3 — resuming ran the tail of an instruction and the target died with
//! an access violation. That is what this test pins down: coverage over a target
//! whose eight threads sweep the same 256 function entries must produce no
//! client-visible breakpoint events, no access violation, and a clean exit.

mod common;

use common::{find_module, get_test_program_path, TestServer};
use joybug_core::protocol::{DebugEvent, SymbolLoadState};
use joybug_core::protocol_io::DebugSession;

struct CovRaceState {
    /// Addresses of client-visible `Breakpoint` events (there should be none).
    unexpected_breakpoints: Vec<u64>,
    /// (code, address) of every exception reported (an AV here is the old bug).
    exceptions: Vec<(u32, u64)>,
    armed: usize,
    hit_fns: usize,
    exit_code: Option<u32>,
}

/// Every `fn_*` entry from the target's PDB. `list_symbols` errors while the
/// background symbol load is still in flight, so first poll `get_symbol_status`
/// (the retry protocol that error prescribes) until the module's load settles,
/// and fail fast with the real error if it settles as failed.
fn sweep_function_vas(
    session: &mut DebugSession<CovRaceState>,
    pid: u32,
    module_path: &str,
    base: u64,
) -> Vec<u64> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let state = session
            .get_symbol_status(pid)
            .expect("get_symbol_status failed")
            .into_iter()
            .find(|s| s.module_path == module_path)
            .map(|s| s.state);
        match state {
            Some(SymbolLoadState::Loaded { .. }) => break,
            Some(SymbolLoadState::Failed { error })
            | Some(SymbolLoadState::ExportsOnly { error, .. }) => {
                panic!("symbol load failed for {}: {}", module_path, error)
            }
            other => assert!(
                std::time::Instant::now() < deadline,
                "symbols for {} did not load within 60s (state: {:?})",
                module_path,
                other
            ),
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let symbols = session
        .list_symbols(module_path)
        .expect("list_symbols failed after symbols loaded");
    let mut addrs: Vec<u64> = symbols
        .iter()
        .filter(|s| s.is_function && s.name.starts_with("fn_"))
        .map(|s| base + s.rva as u64)
        .collect();
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

#[test]
// Shares the ARM64 dropped-single-step problem of `bp_race_test`: coverage
// re-arming depends on the step-over single-step being delivered.
#[cfg_attr(target_arch = "aarch64", ignore = "known ARM64 dropped single-step issue")]
fn test_coverage_stale_hit_is_not_reported_as_unknown_breakpoint() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("cov_race_test");
    println!("Using cov_race_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(
        CovRaceState {
            unexpected_breakpoints: Vec::new(),
            exceptions: Vec::new(),
            armed: 0,
            hit_fns: 0,
            exit_code: None,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        let module = find_module(session, pid, "cov_race_test")?;
        let addrs = sweep_function_vas(session, pid, &module.name, module.base);
        assert!(
            addrs.len() >= 200,
            "expected the 256 fn_* entries from the PDB, got {}",
            addrs.len()
        );
        println!("Arming {} coverage breakpoints (limit=1)", addrs.len());
        session.state.armed = addrs.len();
        session.start_coverage(pid, addrs, 1)?;
        Ok(())
    })
    // Any breakpoint event reaching the client is the bug: coverage hits are
    // counted and continued inside the server, and the target sets none itself.
    .on_event(|session, event| {
        if let DebugEvent::Breakpoint { address, tid, .. } = event {
            println!("UNEXPECTED breakpoint at 0x{:X} (tid {})", address, tid);
            session.state.unexpected_breakpoints.push(*address);
        }
        Ok(true) // keep the session running
    })
    .on_exception(|session, _pid, _tid, code, address, first_chance, _params| {
        println!(
            "Exception 0x{:X} at 0x{:X} (first_chance={})",
            code, address, first_chance
        );
        session.state.exceptions.push((code, address));
        Ok(joybug_core::protocol_io::ExceptionAction::PassToApplication)
    })
    .on_process_exited(|session, pid, exit_code| {
        session.state.hit_fns = session
            .get_coverage(pid)
            .unwrap_or_default()
            .iter()
            .filter(|h| h.hit_count > 0)
            .count();
        session.state.exit_code = Some(exit_code);
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    println!(
        "armed={} hit_fns={} exit_code={:?} unexpected_breakpoints={} exceptions={}",
        final_state.armed,
        final_state.hit_fns,
        final_state.exit_code,
        final_state.unexpected_breakpoints.len(),
        final_state.exceptions.len()
    );

    assert!(
        final_state.unexpected_breakpoints.is_empty(),
        "coverage breakpoint hits leaked to the client as unknown breakpoints: {:?}",
        final_state
            .unexpected_breakpoints
            .iter()
            .map(|a| format!("0x{:X}", a))
            .collect::<Vec<_>>()
    );
    assert!(
        !final_state
            .exceptions
            .iter()
            .any(|(code, _)| *code == 0xC000_0005),
        "target access-violated under coverage: {:?}",
        final_state.exceptions
    );
    // Every swept function is called by all eight threads, so limit=1 coverage
    // must report all of them.
    assert_eq!(
        final_state.hit_fns, final_state.armed,
        "every armed function is called by the target; all should be reported hit"
    );
    assert_eq!(
        final_state.exit_code,
        Some(0),
        "target should run to completion cleanly (non-zero = corrupted execution)"
    );
}
