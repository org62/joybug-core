#![cfg(windows)]

mod common;

use common::TestServer;
use joybug_core::peb_normalize::PebNormalizeOptions;
use joybug_core::protocol_io::DebugSession;

// PEB / sub-struct field offsets (x64 native layout). These are intentionally
// hardcoded here, independent of the implementation's own constants, so that a
// wrong offset in production is actually caught instead of agreeing with itself.
const PEB_BEING_DEBUGGED: u64 = 0x02;
const PEB_PROCESS_HEAP: u64 = 0x30;
const HEAP_FLAGS: u64 = 0x70;
const HEAP_FORCE_FLAGS: u64 = 0x74;

// Expected post-normalize values.
const HEAP_GROWABLE: u32 = 0x2;
const DEBUGGER_BEING_DEBUGGED: u8 = 1;

struct State {
    initial_bp_hit: bool,
    peb_address: u64,
    before_being_debugged: Option<u8>,
    after_being_debugged: Option<u8>,
    after_heap_flags: Option<u32>,
    after_heap_force_flags: Option<u32>,
    applied: Vec<String>,
    failures: Vec<(String, String)>,
}

impl State {
    fn new() -> Self {
        Self {
            initial_bp_hit: false,
            peb_address: 0,
            before_being_debugged: None,
            after_being_debugged: None,
            after_heap_flags: None,
            after_heap_force_flags: None,
            applied: Vec::new(),
            failures: Vec::new(),
        }
    }
}

fn read_u8(session: &mut DebugSession<State>, pid: u32, addr: u64) -> u8 {
    session.read_memory(pid, addr, 1).expect("read u8")[0]
}

fn read_u32(session: &mut DebugSession<State>, pid: u32, addr: u64) -> u32 {
    let b = session.read_memory(pid, addr, 4).expect("read u32");
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn read_u64(session: &mut DebugSession<State>, pid: u32, addr: u64) -> u64 {
    let b = session.read_memory(pid, addr, 8).expect("read u64");
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[test]
fn test_normalize_peb_restores_non_debugged_fields() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let final_state = DebugSession::new(State::new(), Some(server_addr.as_str()))
        .expect("connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            session.state.initial_bp_hit = true;

            // Resolve PEB and snapshot pre-normalize values.
            // normalize_peb internally calls get_peb_address; we mirror that via a
            // probing call with no options to fetch the address up-front.
            let probe = session.normalize_peb(pid, PebNormalizeOptions::default())?;
            assert!(probe.peb_address != 0, "PEB address must be non-zero");
            session.state.peb_address = probe.peb_address;

            session.state.before_being_debugged = Some(read_u8(session, pid, probe.peb_address + PEB_BEING_DEBUGGED));

            // Now actually apply every field.
            let report = session.normalize_peb(pid, PebNormalizeOptions::all())?;
            session.state.applied  = report.applied.clone();
            session.state.failures = report.failures.clone();

            // Snapshot post-normalize values.
            session.state.after_being_debugged = Some(read_u8(session, pid, probe.peb_address + PEB_BEING_DEBUGGED));

            let heap = read_u64(session, pid, probe.peb_address + PEB_PROCESS_HEAP);
            session.state.after_heap_flags       = Some(read_u32(session, pid, heap + HEAP_FLAGS));
            session.state.after_heap_force_flags = Some(read_u32(session, pid, heap + HEAP_FORCE_FLAGS));

            Ok(())
        })
        .launch("cmd.exe /c exit 0".to_string())
        .expect("debug session failed");

    assert!(final_state.initial_bp_hit, "initial breakpoint should fire");
    assert!(final_state.peb_address != 0, "PEB address resolved");
    assert_eq!(final_state.before_being_debugged, Some(DEBUGGER_BEING_DEBUGGED),
        "PEB.BeingDebugged must be 1 under the debugger before normalization");

    // Two fields applied, no failures, no WOW64.
    let expected = ["being_debugged", "heap_flags"];
    for name in &expected {
        assert!(final_state.applied.iter().any(|s| s == name),
            "Expected '{}' to be applied; got {:?}", name, final_state.applied);
    }
    assert!(final_state.failures.is_empty(),
        "No failures expected; got {:?}", final_state.failures);

    assert_eq!(final_state.after_being_debugged,   Some(0),             "BeingDebugged should be 0 after normalize");
    assert_eq!(final_state.after_heap_flags,       Some(HEAP_GROWABLE), "HEAP.Flags should be HEAP_GROWABLE");
    assert_eq!(final_state.after_heap_force_flags, Some(0),             "HEAP.ForceFlags should be 0");
}

// End-to-end behavioral tests using the peb_state_probe.c sample, which reads
// the PEB-resident fields itself and encodes what it observes in its exit code:
//   bit0 (0x1) = IsDebuggerPresent / PEB.BeingDebugged
//   bit1 (0x2) = process-heap debug flags
// Exit code 0 means the PEB looked like a normally launched process.
const DETECT_BEING_DEBUGGED: u32 = 0x1;

struct ExitState {
    initial_bp_hit: bool,
    exit_code: Option<u32>,
}

impl ExitState {
    fn new() -> Self {
        Self { initial_bp_hit: false, exit_code: None }
    }
}

#[test]
fn test_sample_reports_clean_after_normalize_peb() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let exe = common::get_test_program_path("peb_state_probe");

    let final_state = DebugSession::new(ExitState::new(), Some(server_addr.as_str()))
        .expect("connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            session.state.initial_bp_hit = true;
            // Normalize the PEB before main() runs.
            let report = session.normalize_peb(pid, PebNormalizeOptions::all())?;
            assert!(report.failures.is_empty(), "normalize_peb failures: {:?}", report.failures);
            Ok(())
        })
        .on_process_exited(|session, _pid, exit_code| {
            session.state.exit_code = Some(exit_code);
            Ok(())
        })
        .launch(exe)
        .expect("debug session failed");

    assert!(final_state.initial_bp_hit, "initial breakpoint should fire");
    println!("with normalize_peb: exit code = {:?}", final_state.exit_code);
    assert_eq!(final_state.exit_code, Some(0),
        "sample should look non-debugged (exit 0) after normalize_peb, got {:?}", final_state.exit_code);
}

#[test]
fn test_sample_sees_debugger_launched_values_without_normalize() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let exe = common::get_test_program_path("peb_state_probe");

    let final_state = DebugSession::new(ExitState::new(), Some(server_addr.as_str()))
        .expect("connect to debug server")
        .on_initial_breakpoint(|session, _pid, _tid, _addr| {
            // No normalization: the sample should observe the debugger-launched values.
            session.state.initial_bp_hit = true;
            Ok(())
        })
        .on_process_exited(|session, _pid, exit_code| {
            session.state.exit_code = Some(exit_code);
            Ok(())
        })
        .launch(exe)
        .expect("debug session failed");

    assert!(final_state.initial_bp_hit, "initial breakpoint should fire");
    println!("without normalize_peb: exit code = {:?}", final_state.exit_code);
    let code = final_state.exit_code.expect("process should have exited with a code");
    assert_ne!(code, 0, "sample should see debugger-launched values when the PEB is not normalized");
    assert_ne!(code & DETECT_BEING_DEBUGGED, 0,
        "BeingDebugged bit (0x1) must be set under the debugger, got 0x{:x}", code);
}

/// Exercise the normal flag first, then clear it and request two more breaks.
/// The separate control connection is the same out-of-band path the UI uses.
/// A finite target makes a missing breakpoint fail at process exit, not hang.
fn check_break_into_with_normalized_peb(wow64: bool) {
    use joybug_core::interfaces::Architecture;
    use joybug_core::protocol::{DebugEvent, DebuggerRequest};
    use joybug_core::protocol_io::expect_ack;
    use std::path::PathBuf;

    struct BreakState {
        control: DebugSession<()>,
        peb: u64,
        native_ntdll: std::ops::Range<u64>,
        main_tid: u32,
        hits: u32,
    }

    let server = TestServer::spawn();
    let address = server.address().to_string();
    let control = DebugSession::new((), Some(&address)).expect("connect control client");
    let state = BreakState {
        control,
        peb: 0,
        native_ntdll: 0..0,
        main_tid: 0,
        hits: 0,
    };
    let session = DebugSession::new(state, Some(&address))
        .expect("connect debug client")
        .on_initial_breakpoint(move |session, pid, tid, _| {
            let expected_arch = if wow64 { Architecture::X86 } else { Architecture::from_native() };
            assert_eq!(session.get_process_architecture(pid)?, expected_arch);
            session.state.main_tid = tid;
            let probe = session.normalize_peb(pid, PebNormalizeOptions::default())?;
            session.state.peb = probe.peb_address;
            assert_eq!(session.read_memory(pid, probe.peb_address + PEB_BEING_DEBUGGED, 1)?, [1]);

            let modules = session.list_modules(pid)?;
            let ntdll = modules.iter()
                .find(|module| module.name.to_ascii_lowercase().ends_with("\\system32\\ntdll.dll"))
                .expect("native ntdll is loaded");
            session.state.native_ntdll = ntdll.base..ntdll.base + ntdll.size.unwrap();
            let response = session.state.control.send_and_receive(&DebuggerRequest::BreakInto { pid })?;
            expect_ack("BreakInto", response)
        })
        .on_event(|session, event| {
            if let DebugEvent::Breakpoint { pid, tid, address } = event {
                assert_ne!(*tid, session.state.main_tid, "break-in runs on its own thread");
                assert!(session.state.native_ntdll.contains(address), "breakpoint must be in native ntdll");
                let expected_flag = if session.state.hits == 0 { 1 } else { 0 };
                assert_eq!(
                    session.read_memory(*pid, session.state.peb + PEB_BEING_DEBUGGED, 1)?,
                    [expected_flag],
                    "break-in must preserve BeingDebugged"
                );
                session.state.hits += 1;
                if session.state.hits == 3 {
                    session.terminate_process(*pid)?;
                } else {
                    if session.state.hits == 1 {
                        let report = session.normalize_peb(*pid, PebNormalizeOptions {
                            being_debugged: true,
                            heap_flags: false,
                        })?;
                        assert!(report.failures.is_empty(), "{:?}", report.failures);
                        assert_eq!(session.read_memory(*pid, session.state.peb + PEB_BEING_DEBUGGED, 1)?, [0]);
                    }
                    let response = session.state.control.send_and_receive(&DebuggerRequest::BreakInto { pid: *pid })?;
                    expect_ack("BreakInto", response)?;
                }
            }
            Ok(true)
        });
    let target = PathBuf::from(std::env::var_os("WINDIR").expect("Windows directory"))
        .join(if wow64 { "SysWOW64" } else { "System32" })
        .join("ping.exe");
    let state = session.launch(format!("\"{}\" -n 10 127.0.0.1", target.display()))
        .expect("debug finite-running ping target");
    assert_eq!(state.hits, 3, "one normal and two normalized break-ins must stop the target");
}

#[test]
fn break_into_preserves_normalized_peb() {
    check_break_into_with_normalized_peb(false);
}

#[test]
fn wow64_break_into_preserves_normalized_peb() {
    check_break_into_with_normalized_peb(true);
}
