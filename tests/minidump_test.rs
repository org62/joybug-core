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

/// The dump's exception stream as `(thread id, code, address)`, or `None`
/// when the dump has none. Walks the stream directory by hand: the header
/// holds the stream count at 8 and the directory offset at 12, each entry is
/// `(type, size, offset)`, and stream type 6 is `MINIDUMP_EXCEPTION_STREAM`.
fn exception_stream(path: &std::path::Path) -> Option<(u32, u32, u64)> {
    let dump = std::fs::read(path).expect("dump file should exist");
    let u32_at = |at: usize| u32::from_le_bytes(dump[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(dump[at..at + 8].try_into().unwrap());
    let (count, directory) = (u32_at(8) as usize, u32_at(12) as usize);
    (0..count)
        .map(|i| directory + i * 12)
        .find(|&entry| u32_at(entry) == 6)
        .map(|entry| u32_at(entry + 8) as usize)
        // ThreadId, alignment, then the record: code, flags, nested record, address.
        .map(|stream| (u32_at(stream), u32_at(stream + 8), u64_at(stream + 24)))
}

/// A dump written while stopped on an exception says which thread raised
/// what, where — the stream `.ecxr` and `!analyze` read.
#[test]
fn minidump_at_an_exception_records_it() {
    use joybug_core::protocol::DebugEvent;
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let dir = std::env::temp_dir().join(format!("joybug-minidump-exc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dump = dir.join("exception.dmp");

    let seen = DebugSession::new(None::<(u32, u32, u64)>, Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_event({
            let dump = dump.clone();
            move |session, event| {
                if let DebugEvent::Exception { pid, tid, code, address, .. } = event {
                    if session.state.is_none() {
                        session.write_minidump(*pid, &dump.to_string_lossy(), MinidumpKind::Mini)?;
                        session.state = Some((*tid, *code, *address));
                    }
                }
                Ok(true)
            }
        })
        .launch(get_test_program_path("exception_test"))
        .expect("Debug session failed");

    let (tid, code, address) = seen.expect("the target should raise its exception");
    assert_eq!(code, 0xE000_0001, "exception_test raises 0xE0000001");
    assert_eq!(exception_stream(&dump), Some((tid, code, address)));

    let _ = std::fs::remove_dir_all(&dir);
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
    // The initial breakpoint is the debugger's stop, not a crash.
    assert_eq!(exception_stream(&mini), None, "a breakpoint stop has no exception stream");
    assert!(final_state.full_size > final_state.mini_size, "full dump should be larger than mini dump");
    assert!(final_state.bad_path_errored, "unwritable path should error");
    assert!(!bad.exists());

    let _ = std::fs::remove_dir_all(&dir);
}
