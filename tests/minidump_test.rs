#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path};
use joybug_core::protocol::MinidumpKind;
use joybug_core::protocol_io::DebugSession;

struct State {
    mini_size: u64,
    full_size: u64,
    bad_path_errored: bool,
}

/// A dump can be hundreds of MB (`Full` covers the whole address space), so
/// check the header and the size without reading the file into memory.
fn assert_mdmp(path: &std::path::Path, reported: u64) {
    use std::io::Read;
    let mut file = std::fs::File::open(path).expect("dump file should exist");
    assert_eq!(file.metadata().unwrap().len(), reported, "reported size should match file size");
    assert!(reported > 0x1000, "dump is implausibly small: {} bytes", reported);
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"MDMP", "missing MDMP signature");
}

#[test]
fn minidump_write() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("memory_search_test");

    let dir = std::env::temp_dir().join(format!("joybug-minidump-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mini = dir.join("mini.dmp");
    let full = dir.join("full.dmp");
    let bad = dir.join("no-such-dir").join("x.dmp");

    let state = State { mini_size: 0, full_size: 0, bad_path_errored: false };
    let final_state = DebugSession::new(state, Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint({
            let (mini, full, bad) = (mini.clone(), full.clone(), bad.clone());
            move |session, pid, _tid, _addr| {
                let size = session.write_minidump(pid, &mini.to_string_lossy(), MinidumpKind::Mini)?;
                println!("mini dump: {} bytes", size);
                session.state.mini_size = size;

                let size = session.write_minidump(pid, &full.to_string_lossy(), MinidumpKind::Full)?;
                println!("full dump: {} bytes", size);
                session.state.full_size = size;

                let err = session.write_minidump(pid, &bad.to_string_lossy(), MinidumpKind::Mini);
                println!("bad path: {:?}", err.as_ref().err());
                session.state.bad_path_errored = err.is_err();
                Ok(())
            }
        })
        .launch(test_exe)
        .expect("Debug session failed");

    assert_mdmp(&mini, final_state.mini_size);
    assert_mdmp(&full, final_state.full_size);
    assert!(final_state.full_size > final_state.mini_size, "full dump should be larger than mini dump");
    assert!(final_state.bad_path_errored, "unwritable path should error");
    assert!(!bad.exists());

    let _ = std::fs::remove_dir_all(&dir);
}
