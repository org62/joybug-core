#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path};
use joybug_core::protocol_io::DebugSession;

struct SearchTestState {
    string_search_done: bool,
    hex_search_done: bool,
    cap_test_done: bool,
    empty_pattern_done: bool,
    no_match_done: bool,
}

impl SearchTestState {
    fn new() -> Self {
        Self {
            string_search_done: false,
            hex_search_done: false,
            cap_test_done: false,
            empty_pattern_done: false,
            no_match_done: false,
        }
    }
}

#[test]
fn memory_search() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe = get_test_program_path("memory_search_test");
    println!("Using memory_search_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(SearchTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            println!("Initial breakpoint hit, setting single-shot BP on breakpoint_here...");
            session.set_single_shot_breakpoint(pid, "breakpoint_here", |session, pid, _tid, addr| {
                println!("breakpoint_here hit at 0x{:X}, running memory search tests...", addr);

                // 1. String search
                {
                    let pattern = b"JOYBUG_SEARCH_MARKER".to_vec();
                    let (addresses, capped) = session.search_memory(pid, pattern, 1000)?;
                    println!("  String search: {} matches, capped={}", addresses.len(), capped);
                    for a in &addresses {
                        println!("    0x{:X}", a);
                    }
                    assert!(addresses.len() >= 3, "Expected >= 3 string matches, got {}", addresses.len());
                    assert!(!capped, "Should not be capped with limit 1000");
                    session.state.string_search_done = true;
                }

                // 2. Hex pattern search
                {
                    let pattern = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
                    let (addresses, capped) = session.search_memory(pid, pattern, 1000)?;
                    println!("  Hex search: {} matches, capped={}", addresses.len(), capped);
                    for a in &addresses {
                        println!("    0x{:X}", a);
                    }
                    assert!(addresses.len() >= 3, "Expected >= 3 hex matches, got {}", addresses.len());
                    assert!(!capped, "Should not be capped with limit 1000");
                    session.state.hex_search_done = true;
                }

                // 3. max_results capping
                {
                    let pattern = b"JOYBUG_SEARCH_MARKER".to_vec();
                    let (addresses, capped) = session.search_memory(pid, pattern, 1)?;
                    println!("  Cap test: {} matches, capped={}", addresses.len(), capped);
                    assert_eq!(addresses.len(), 1, "Expected exactly 1 match with max_results=1");
                    assert!(capped, "Should be capped with max_results=1");
                    session.state.cap_test_done = true;
                }

                // 4. Empty pattern should error
                {
                    let result = session.search_memory(pid, vec![], 100);
                    println!("  Empty pattern test: {:?}", result.is_err());
                    assert!(result.is_err(), "Empty pattern should return an error");
                    session.state.empty_pattern_done = true;
                }

                // 5. No match
                {
                    let pattern = b"THIS_STRING_DEFINITELY_DOES_NOT_EXIST_ANYWHERE_IN_MEMORY_12345".to_vec();
                    let (addresses, capped) = session.search_memory(pid, pattern, 1000)?;
                    println!("  No match test: {} matches, capped={}", addresses.len(), capped);
                    assert_eq!(addresses.len(), 0, "Expected 0 matches for non-existent pattern");
                    assert!(!capped, "Should not be capped when no matches found");
                    session.state.no_match_done = true;
                }

                println!("All memory search sub-tests passed!");
                Ok(())
            })?;
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("Process {} exited with code 0x{:X}", pid, exit_code);
            println!("\n=== Memory Search Test Results ===");
            println!("  string_search_done:  {}", session.state.string_search_done);
            println!("  hex_search_done:     {}", session.state.hex_search_done);
            println!("  cap_test_done:       {}", session.state.cap_test_done);
            println!("  empty_pattern_done:  {}", session.state.empty_pattern_done);
            println!("  no_match_done:       {}", session.state.no_match_done);
            Ok(())
        })
        .launch(test_exe)
        .expect("Debug session failed");

    // Verify all sub-tests ran
    assert!(final_state.string_search_done, "String search test did not run");
    assert!(final_state.hex_search_done, "Hex search test did not run");
    assert!(final_state.cap_test_done, "Cap test did not run");
    assert!(final_state.empty_pattern_done, "Empty pattern test did not run");
    assert!(final_state.no_match_done, "No match test did not run");

    println!("\n=== Memory Search Test PASSED ===");
}
