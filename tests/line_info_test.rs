#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path, find_symbol, find_module};
use joybug2::interfaces::Architecture;
use joybug2::protocol_io::DebugSession;

/// End-to-end test of the PDB line-table protocol surface:
/// ResolveAddressToLine, GetSourceFileLineMap, ListSourceFiles, and the
/// per-instruction line_info annotation on disassembly.
#[test]
fn test_source_line_info() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe_path = get_test_program_path("xtea_test");

    struct TestState {
        line_info_tested: bool,
    }

    let final_state = DebugSession::new(
        TestState {
            line_info_tested: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        println!("\n========== SOURCE LINE INFO TEST ==========\n");

        // find_symbols waits for symbol loading, so the module's PDB path is
        // known by the time the first line request triggers the lazy parse.
        let main_sym = find_symbol(session, "xtea_test!main", "xtea_test")?;
        println!("xtea_test!main @ {:#x}", main_sym.va);

        let module = find_module(session, pid, "xtea_test")?;

        // =============================================
        // TEST 1: ResolveAddressToLine at main's entry
        // =============================================
        println!("\n----- TEST 1: ResolveAddressToLine -----\n");

        let info = session
            .resolve_address_to_line(pid, main_sym.va)?
            .expect("main's entry should resolve to a source line");

        println!(
            "main resolves to {}:{} (rva {:#x}, checksum {} {})",
            info.file.path, info.line_entry.line_start, info.rva, info.file.checksum_kind, info.file.checksum
        );

        assert!(
            info.file.path.to_lowercase().ends_with("xtea_test.c"),
            "Expected xtea_test.c, got {}",
            info.file.path
        );
        assert!(info.line_entry.line_start > 0, "Line number should be positive");
        assert!(info.line_entry.line_start < 10_000, "Line number implausibly large");
        assert_eq!(info.module_base, module.base, "Module base should match");
        assert_eq!(info.rva, (main_sym.va - module.base) as u32, "RVA should match");
        assert_ne!(info.file.checksum_kind, "none", "MSVC /Zi PDBs record file checksums");
        assert!(!info.file.checksum.is_empty(), "Checksum hex should be non-empty");

        // =============================================
        // TEST 2: GetSourceFileLineMap for that file
        // =============================================
        println!("\n----- TEST 2: GetSourceFileLineMap -----\n");

        let (file, entries) = session.get_source_file_line_map(pid, module.base, &info.file.path, None, None)?;
        let file = file.expect("File record should be found for the resolved path");
        assert_eq!(file.path.to_lowercase(), info.file.path.to_lowercase());
        assert!(!entries.is_empty(), "Line map should have entries");
        println!("{} line entries for {}", entries.len(), file.path);

        // Entries are sorted by line_start and each maps to a valid module RVA.
        let module_size = module.size.unwrap_or(u64::MAX);
        let mut prev_line = 0u32;
        for entry in &entries {
            assert!(entry.line_start >= prev_line, "Entries should be sorted by line_start");
            prev_line = entry.line_start;
            assert!((entry.rva as u64) < module_size, "Entry RVA should be inside the module");
        }

        // main's entry line must appear in the file map with the same RVA.
        assert!(
            entries.iter().any(|e| e.line_start == info.line_entry.line_start && e.rva == info.rva),
            "main's line/RVA should appear in the file line map"
        );

        // =============================================
        // TEST 3: ListSourceFiles contains the .c file
        // =============================================
        println!("\n----- TEST 3: ListSourceFiles -----\n");

        let files = session.list_source_files(pid, module.base)?;
        println!("{} source files referenced by the module", files.len());
        assert!(
            files.iter().any(|f| f.path.to_lowercase().ends_with("xtea_test.c")),
            "Source file list should contain xtea_test.c"
        );

        // =============================================
        // TEST 4: Disassembly carries line_info once the table is cached
        // =============================================
        println!("\n----- TEST 4: Instruction line_info annotation -----\n");

        // The resolve in TEST 1 parsed and cached the line table, so the
        // cached-only annotation path in disassemble_memory must now fire.
        let arch = Architecture::from_native();
        let (instructions, _, _, _) = session.disassemble_function(pid, main_sym.va, 200, arch)?;
        assert!(!instructions.is_empty(), "Should disassemble main");

        let annotated = instructions.iter().filter(|i| i.line_info.is_some()).count();
        println!("{}/{} instructions carry line_info", annotated, instructions.len());
        assert!(annotated > 0, "Disassembly should carry line_info after the table is cached");

        let first = instructions[0]
            .line_info
            .as_ref()
            .expect("main's first instruction should have line_info");
        assert!(first.file_path.to_lowercase().ends_with("xtea_test.c"));
        assert_eq!(first.line, info.line_entry.line_start, "First instruction line should match ResolveAddressToLine");

        session.state.line_info_tested = true;
        println!("\n========== SOURCE LINE INFO TEST PASSED ==========\n");
        Ok(())
    })
    .launch(test_exe_path)
    .expect("Debug session failed");

    assert!(final_state.line_info_tested, "Line info tests should have run");
}

/// Reproduce joybug-tauri's runner-driven source-line stepping: the on_event
/// handler, on each StepComplete, keeps issuing steps (returning Ok(true) so the
/// loop's auto-continue resumes) until the source line changes. This mirrors
/// `session/dispatch.rs::advance_source_line_step` + `runner::on_event`.
#[test]
fn test_source_line_step_via_on_event() {
    use joybug2::protocol_io::{DebugEvent, StepAction, StepKind};

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe_path = get_test_program_path("xtea_test");

    struct St {
        start: Option<(String, u32)>,
        started: bool,
        done: bool,
        steps: u32,
    }

    let final_state = DebugSession::new(
        St { start: None, started: false, done: false, steps: 0 },
        Some(server_addr.as_str()),
    )
    .expect("connect")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        // Persistent breakpoint at main (matches joybug-tauri's toggle_breakpoint),
        // stepped off while still active — the case the e2e exercises.
        let main = find_symbol(session, "xtea_test!main", "xtea_test")?.va;
        session.set_breakpoint_at(pid, main, None, |session, pid, tid, addr| {
            if session.state.started {
                return Ok(joybug2::protocol_io::BreakpointDecision::Keep);
            }
            let start = session
                .resolve_address_to_line(pid, addr)
                .ok()
                .flatten()
                .map(|i| (i.file.path, i.line_entry.line_start));
            println!("start line = {:?}", start);
            assert!(start.is_some(), "main should have a source line");
            session.state.start = start;
            session.state.started = true;
            session.step(pid, tid, StepKind::Over, |_s, _p, _t, _a, _k| Ok(StepAction::Stop))?;
            Ok(joybug2::protocol_io::BreakpointDecision::Keep)
        })?;
        Ok(())
    })
    .on_event(|session, event| {
        if let DebugEvent::StepComplete { pid, tid, address, .. } = event {
            if session.state.started && !session.state.done {
                session.state.steps += 1;
                let cur = session
                    .resolve_address_to_line(*pid, *address)
                    .ok()
                    .flatten()
                    .map(|i| (i.file.path, i.line_entry.line_start));
                let same = cur == session.state.start;
                println!("step {} @ {:#x} -> line {:?} same={}", session.state.steps, address, cur, same);
                if same && session.state.steps < 50_000 {
                    session.step(*pid, *tid, StepKind::Over, |_s, _p, _t, _a, _k| Ok(StepAction::Stop))?;
                    return Ok(true);
                }
                // Line changed (or gave up): finish the test.
                session.state.done = true;
                session.terminate_process(*pid)?;
                return Ok(false);
            }
        }
        Ok(true)
    })
    .launch(test_exe_path)
    .expect("debug session");

    assert!(final_state.started, "should have started stepping");
    assert!(final_state.done, "source-line step should have terminated");
    assert!(final_state.steps >= 1, "should have taken at least one step");
    assert!(final_state.steps < 50_000, "should not have hit the iteration cap");
    println!("source-line step took {} instructions", final_state.steps);
}

/// A module with symbols but no line request yet must not annotate, and an
/// unknown source file must return an empty map rather than an error.
#[test]
fn test_source_line_info_edge_cases() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe_path = get_test_program_path("xtea_test");

    struct TestState {
        edge_cases_tested: bool,
    }

    let final_state = DebugSession::new(
        TestState {
            edge_cases_tested: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        let main_sym = find_symbol(session, "xtea_test!main", "xtea_test")?;
        let module = find_module(session, pid, "xtea_test")?;

        // Unknown file path: empty map, not an error.
        let (file, entries) = session.get_source_file_line_map(pid, module.base, "Z:\\no\\such\\file.c", None, None)?;
        assert!(file.is_none(), "Unknown file should not match");
        assert!(entries.is_empty(), "Unknown file should yield an empty map");

        // An address outside any known line range (e.g. deep in ntdll before
        // its lines are ever requested from a cached table) resolves via the
        // parse-triggering path or returns None; either way it must not error.
        let _ = session.resolve_address_to_line(pid, main_sym.va + 1)?;

        session.state.edge_cases_tested = true;
        Ok(())
    })
    .launch(test_exe_path)
    .expect("Debug session failed");

    assert!(final_state.edge_cases_tested, "Edge case tests should have run");
}
