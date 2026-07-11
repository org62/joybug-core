#![cfg(windows)]

//! Stress test for PDB line-table parsing on very large assembly modules — the
//! scenario behind "how does the source view handle multi-GB .asm files?".
//!
//! It generates an .asm with N `nop` lines (each its own source line and machine
//! instruction, so the PDB gets N line-table entries), assembles + links it with
//! `ml64`/`link`, launches it, and measures the time and peak process memory of
//! the (lazy) line-table parse plus a full file line-map fetch.
//!
//! Opt-in only — this compiles a large file and can use a lot of disk/RAM, so it
//! never runs in the normal suite:
//!
//! ```text
//! # from the MSVC dev shell (ml64/link must be on PATH):
//! JOYBUG_BIG_SOURCE_TEST=1 cargo test --test big_source_test -- --nocapture
//! # scale it up (default 1,000,000 source lines ≈ 8 MB .asm / 8 MB PDB):
//! JOYBUG_BIG_SOURCE_TEST=1 JOYBUG_BIG_SOURCE_LINES=20000000 cargo test --test big_source_test -- --nocapture
//! ```
//!
//! Rough scaling (each nop line ≈ 8 bytes of source, ≈ 32 bytes of in-RAM line
//! entry): 1 M lines ≈ 8 MB source / ~32 MB table; a "couple GB" .asm is ~250 M+
//! lines ≈ ~8 GB line table. The joybug-tauri Source *view* reads the file text
//! in bounded windows (open_source_file + read_source_window), so the webview
//! stays bounded regardless of file size — this test targets the remaining
//! backend cost, the uncapped joybug2 line-table parse.

mod common;

use common::{TestServer, find_symbol, find_module};
use joybug2::protocol_io::DebugSession;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Peak working set of the current process, in bytes (the in-process debug
/// server parses the line table here, so this captures the parse's footprint).
fn peak_working_set() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) != 0 {
            counters.PeakWorkingSetSize as u64
        } else {
            0
        }
    }
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Generate `lines` nop instructions in one PROC, assemble + link with debug info.
fn build_big_asm(lines: usize, dir: &Path) -> PathBuf {
    let asm = dir.join("bignop.asm");
    let t0 = Instant::now();
    {
        let mut f = BufWriter::new(File::create(&asm).expect("create .asm"));
        writeln!(f, ".code").unwrap();
        writeln!(f, "main PROC").unwrap();
        for _ in 0..lines {
            writeln!(f, "    nop").unwrap();
        }
        writeln!(f, "    xor eax, eax").unwrap();
        writeln!(f, "    ret").unwrap();
        writeln!(f, "main ENDP").unwrap();
        writeln!(f, "END").unwrap();
    }
    let asm_bytes = std::fs::metadata(&asm).map(|m| m.len()).unwrap_or(0);
    println!("generated {} lines, {:.1} MB .asm in {:?}", lines, mib(asm_bytes), t0.elapsed());

    let obj = dir.join("bignop.obj");
    let t1 = Instant::now();
    let status = Command::new("ml64")
        .args(["/nologo", "/Zi", "/c", &format!("/Fo{}", obj.display())])
        .arg(&asm)
        .current_dir(dir)
        .status()
        .expect("run ml64 (needs the MSVC dev shell on PATH)");
    assert!(status.success(), "ml64 failed");
    println!("assembled in {:?}", t1.elapsed());

    let exe = dir.join("bignop.exe");
    let pdb = dir.join("bignop.pdb");
    let t2 = Instant::now();
    let status = Command::new("link")
        .args([
            "/nologo", "/DEBUG", "/SUBSYSTEM:CONSOLE", "/ENTRY:main",
            &format!("/PDB:{}", pdb.display()),
            &format!("/OUT:{}", exe.display()),
        ])
        .arg(&obj)
        .arg("kernel32.lib")
        .current_dir(dir)
        .status()
        .expect("run link");
    assert!(status.success(), "link failed");
    let pdb_bytes = std::fs::metadata(&pdb).map(|m| m.len()).unwrap_or(0);
    println!("linked in {:?}; PDB {:.1} MB", t2.elapsed(), mib(pdb_bytes));
    exe
}

#[test]
fn test_big_source_line_table() {
    if std::env::var("JOYBUG_BIG_SOURCE_TEST").is_err() {
        eprintln!("skipping big-source stress test (set JOYBUG_BIG_SOURCE_TEST=1 to run)");
        return;
    }
    let lines: usize = std::env::var("JOYBUG_BIG_SOURCE_LINES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);

    // Build into a unique temp dir (never committed); clean it up at the end.
    let dir = std::env::temp_dir().join(format!("joybug_big_source_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let exe = build_big_asm(lines, &dir);

    let baseline_mem = peak_working_set();
    println!("baseline peak working set: {:.1} MB", mib(baseline_mem));

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    struct St {
        resolve_ms: u128,
        map_entries: usize,
        map_ms: u128,
        peak_mem: u64,
        tested: bool,
    }

    let final_state = DebugSession::new(
        St { resolve_ms: 0, map_entries: 0, map_ms: 0, peak_mem: 0, tested: false },
        Some(server_addr.as_str()),
    )
    .expect("connect")
    .on_initial_breakpoint(move |session, pid, _tid, _addr| {
        // Wait for the module's symbols (find_symbol blocks on loading).
        let main = find_symbol(session, "bignop!main", "bignop")?;
        let module = find_module(session, pid, "bignop")?;

        // First resolve triggers the lazy full line-table parse.
        let t0 = Instant::now();
        let info = session.resolve_address_to_line(pid, main.va)?;
        session.state.resolve_ms = t0.elapsed().as_millis();
        let info = info.expect("main should resolve to a source line");
        assert!(info.file.path.to_lowercase().ends_with("bignop.asm"));

        // Full line map for the file (one entry per nop line).
        let t1 = Instant::now();
        let (_file, entries) = session.get_source_file_line_map(pid, module.base, &info.file.path, None, None)?;
        session.state.map_ms = t1.elapsed().as_millis();
        session.state.map_entries = entries.len();
        session.state.peak_mem = peak_working_set();

        // Spot-check that a mid-file line resolves too (not just the entry).
        if let Some(mid) = entries.get(entries.len() / 2) {
            let va = module.base + mid.rva as u64;
            let r = session.resolve_address_to_line(pid, va)?;
            assert!(r.is_some(), "mid-file address should resolve to a line");
        }

        session.state.tested = true;
        session.terminate_process(pid)?;
        Ok(())
    })
    .launch(exe.to_string_lossy().to_string())
    .expect("debug session");

    println!("\n===== BIG SOURCE LINE-TABLE RESULTS =====");
    println!("source lines requested : {}", lines);
    println!("line-table entries      : {}", final_state.map_entries);
    println!("first resolve (parse)   : {} ms", final_state.resolve_ms);
    println!("full line-map fetch     : {} ms", final_state.map_ms);
    println!("peak working set        : {:.1} MB (baseline {:.1} MB, delta {:.1} MB)",
        mib(final_state.peak_mem), mib(baseline_mem), mib(final_state.peak_mem.saturating_sub(baseline_mem)));
    println!("=========================================\n");

    // Best-effort cleanup — this can be many GB.
    let _ = std::fs::remove_dir_all(&dir);

    assert!(final_state.tested, "stress test should have run");
    assert!(final_state.map_entries >= lines, "line table should have >= one entry per source line");
}
