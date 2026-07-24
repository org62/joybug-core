#![cfg(windows)]

//! Pointer-scan benchmark against a large pointer-dense process.
//!
//! Heavy and ignored by default. Run explicitly (release recommended):
//!   cargo test --release --test pointer_scan_bench -- --ignored --nocapture
//! Tune via env: JOYBUG_BENCH_GB (default 6), JOYBUG_BENCH_DENSITY (default 15).
//!
//! Per-phase server timings are printed by the scanner itself (the test sets
//! JOYBUG_PTRSCAN_TIMING=1).

mod common;

use std::time::Instant;

use common::{find_symbol, get_test_program_path, TestServer};
use joybug2::protocol_io::DebugSession;

struct BenchState {
    done: bool,
}

#[test]
#[ignore = "heavy: allocates a multi-GB target process"]
fn pointer_scan_benchmark() {
    joybug2::init_tracing();
    // SAFETY: set before any threads read the env in this test process.
    unsafe { std::env::set_var("JOYBUG_PTRSCAN_TIMING", "1") };

    let gb = std::env::var("JOYBUG_BENCH_GB").ok().and_then(|v| v.parse::<f64>().ok()).unwrap_or(6.0);
    let density = std::env::var("JOYBUG_BENCH_DENSITY").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(15);
    let max_offset: u64 = std::env::var("JOYBUG_BENCH_MAX_OFFSET").ok()
        .and_then(|v| {
            let t = v.trim().to_lowercase();
            if let Some(h) = t.strip_prefix("0x") { u64::from_str_radix(h, 16).ok() } else { t.parse().ok() }
        }).unwrap_or(0x400);
    let max_depth: u32 = std::env::var("JOYBUG_BENCH_MAX_DEPTH").ok().and_then(|v| v.parse().ok()).unwrap_or(5);
    println!("config: gb={} density={}% max_offset=0x{:X} max_depth={}", gb, density, max_offset, max_depth);

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let exe = get_test_program_path("pointer_bench_target");
    let cmd = format!("\"{}\" {} {}", exe, gb, density);
    println!("launching: {}", cmd);

    let final_state = DebugSession::new(BenchState { done: false }, Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint(move |session, pid, _tid, _addr| {
            session.set_single_shot_breakpoint(pid, "pointer_bench_target!pause_here", move |session, pid, _tid, _addr| {
                // The exe global `g_target` holds the sentinel address to scan for.
                let sym = find_symbol(session, "pointer_bench_target!g_target", "pointer_bench_target")?;
                let bytes = session.read_memory(pid, sym.va, 8)?;
                let target = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                println!("\n=== pointer-scan benchmark: target=0x{:X} ===", target);

                // 1) Reverse scan (no module restriction): builds the full map and
                //    walks back from the target.
                let t = Instant::now();
                let (path, count, server_us) =
                    session.pointer_scan_start(pid, target, max_offset, max_depth, None, None, None, None, false)?;
                println!("[reverse]  {} paths | server {:.2}s | client_wall {:?}",
                    count, server_us as f64 / 1e6, t.elapsed());
                let _ = session.pointer_scan_reset(path);

                // 2) Forward scan restricted to the main module: same map build, but
                //    the walk is seeded from the exe's static pointers.
                let modules = session.list_modules(pid)?;
                if let Some(base) = modules.iter()
                    .find(|m| m.name.to_lowercase().contains("pointer_bench_target"))
                    .map(|m| m.base)
                {
                    let t = Instant::now();
                    let (path, count, server_us) =
                        session.pointer_scan_start(pid, target, max_offset, max_depth, None, None, Some(vec![base]), None, false)?;
                    println!("[forward]  {} paths | server {:.2}s | client_wall {:?}",
                        count, server_us as f64 / 1e6, t.elapsed());
                    let _ = session.pointer_scan_reset(path);
                }

                session.state.done = true;
                session.terminate_process(pid)?;
                Ok(())
            })?;
            Ok(())
        })
        .launch(cmd)
        .expect("Debug session failed");

    assert!(final_state.done, "benchmark did not run to completion");
    println!("\n=== benchmark complete ===");
}
