#![cfg(windows)]

//! Pointer-scan restart-survival test.
//!
//! Proves that a pointer-scan results file produced against one run of a target
//! can be re-resolved against a *fresh* run of the same target — the real
//! Cheat-Engine workflow (scan once, reuse the pointer map after the game/app
//! restarts and ASLR relocates everything).
//!
//! This specifically guards against re-basing paths by `module_index` (a position
//! into the live module list, whose order is HashMap-seeded and differs every
//! launch). The results file stores module *names*; re-resolution must map those
//! names to the current process's module bases.

mod common;

use common::{get_test_program_path, TestServer};
use joybug_core::protocol_io::{
    BreakpointDecision, DebugSession, ScanCompareType, ScanValue, ScanValueType,
};

const SENTINEL: u64 = 0x1337C0DE00000000;
const MAX_OFFSET: u64 = 0x40;
const MAX_DEPTH: u32 = 4; // one indirection per linked-list node back to the head

/// Find (sentinel address, pointer_scan_test image base) in the live process.
fn find_target_and_image_base<T>(
    session: &mut DebugSession<T>,
    pid: u32,
) -> anyhow::Result<(u64, u64)> {
    let image_base = session
        .list_modules(pid)?
        .into_iter()
        .find(|m| m.name.to_lowercase().contains("pointer_scan_test"))
        .map(|m| m.base)
        .ok_or_else(|| anyhow::anyhow!("pointer_scan_test image module not found"))?;

    // Locate the sentinel by value (a heap node's `value` field), not by walking
    // the list — exactly how a user would seed a pointer scan.
    let (scan_id, match_count, _us) = session.scan_memory_start(
        pid,
        ScanValueType::U64,
        ScanCompareType::ExactValue,
        Some(ScanValue::U64(SENTINEL)),
        None,
        None,
        None,
        true, // writable_only: the live value lives on the heap
        None,
    )?;
    assert!(match_count >= 1, "value scan should find the sentinel");
    let (addrs, _vals, _total) = session.scan_memory_get_results(scan_id, 0, 100)?;
    let target = *addrs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no sentinel address returned"))?;
    session.scan_memory_reset(scan_id)?;
    Ok((target, image_base))
}

struct Run1 {
    results_path: Option<String>,
    match_count: u64,
    image_base: u64,
    target: u64,
}

struct Run2 {
    results_path: String,
    old_image_base: u64,
    old_target: u64,
    verified: bool,
}

#[test]
fn pointer_scan_survives_process_restart() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("pointer_scan_test");

    // ---- Run 1: scan and persist the results file path. ----
    let run1 = DebugSession::new(
        Run1 { results_path: None, match_count: 0, image_base: 0, target: 0 },
        Some(server_addr.as_str()),
    )
    .expect("Failed to create debug session (run 1)")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        session.set_breakpoint_by_symbol(pid, "breakpoint_here", None, |session, pid, _tid, _addr| {
            let (target, image_base) = find_target_and_image_base(session, pid)?;
            println!("[run1] target=0x{:X} image_base=0x{:X}", target, image_base);

            // Restrict the static base to the test image so paths root there.
            let (results_path, match_count, _us) = session.pointer_scan_start(
                pid, target, MAX_OFFSET, MAX_DEPTH, None, None, Some(vec![image_base]), None, false,
            )?;
            assert!(match_count >= 1, "[run1] pointer scan should find at least one path");
            println!("[run1] {} paths -> {}", match_count, results_path);

            session.state.results_path = Some(results_path);
            session.state.match_count = match_count;
            session.state.image_base = image_base;
            session.state.target = target;
            Ok(BreakpointDecision::Remove)
        })?;
        Ok(())
    })
    .launch(test_exe.clone())
    .expect("debug session run 1 failed");

    let results_path = run1.results_path.clone().expect("run 1 did not produce a results file");
    println!(
        "[between runs] reusing {} ({} paths) across a full restart",
        results_path, run1.match_count
    );

    // ---- Run 2: a brand-new process. Re-resolve the run-1 file against it. ----
    let run2 = DebugSession::new(
        Run2 {
            results_path: results_path.clone(),
            old_image_base: run1.image_base,
            old_target: run1.target,
            verified: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to create debug session (run 2)")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        session.set_breakpoint_by_symbol(pid, "breakpoint_here", None, |session, pid, _tid, _addr| {
            let (new_target, new_image_base) = find_target_and_image_base(session, pid)?;
            let old_image_base = session.state.old_image_base;
            let old_target = session.state.old_target;
            let path = session.state.results_path.clone();
            println!(
                "[run2] target: 0x{:X} -> 0x{:X} | image_base: 0x{:X} -> 0x{:X}",
                old_target, new_target, old_image_base, new_image_base
            );
            // The restart should relocate the heap target; if it also moved the
            // image, re-basing by name is genuinely exercised. (Either way the
            // functional assertions below must hold.)
            assert_ne!(old_target, new_target, "[run2] heap target should move across a restart");

            // 1) Paging the old file against the new process must re-base each
            //    path's static root to the *current* image base (by name), not to
            //    whatever module the stale HashMap index happens to land on.
            let (paths, total) =
                session.pointer_scan_get_results(pid, path.clone(), 0, 100_000, Vec::new())?;
            assert!(total >= 1, "[run2] results file should still contain paths");
            let rebased = paths.iter().filter(|p| p.module_base == new_image_base).count();
            println!("[run2] get_results: {}/{} paths re-based to current image", rebased, paths.len());
            assert!(
                rebased >= 1,
                "[run2] at least one path must re-base to the current image base 0x{:X} (got bases {:?})",
                new_image_base,
                paths.iter().map(|p| p.module_base).collect::<Vec<_>>()
            );

            // 2) The decisive check: rescanning the old file against the new
            //    target must keep at least one path — the chain still resolves
            //    end-to-end after the restart relocated every layer.
            let (new_path, survivors, _us) =
                session.pointer_scan_rescan(pid, path.clone(), new_target)?;
            println!("[run2] rescan survivors: {}", survivors);
            assert!(
                survivors >= 1,
                "[run2] pointer chain should still resolve to the target after restart"
            );

            session.pointer_scan_reset(new_path)?;
            session.pointer_scan_reset(path)?;
            session.state.verified = true;
            Ok(BreakpointDecision::Remove)
        })?;
        Ok(())
    })
    .launch(test_exe)
    .expect("debug session run 2 failed");

    assert!(run2.verified, "run 2 did not complete its verification");
    println!("=== pointer-scan restart survival: OK ===");
}
