#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::anti_anti_debug::PebHideOptions;
use joybug2::protocol_io::DebugSession;

// PEB / sub-struct field offsets (x64 native layout). These are intentionally
// hardcoded here, independent of the implementation's own constants, so that a
// wrong offset in production is actually caught instead of agreeing with itself.
const PEB_BEING_DEBUGGED: u64 = 0x02;
const PEB_PROCESS_PARAMS: u64 = 0x20;
const PEB_PROCESS_HEAP: u64 = 0x30;
const PEB_NT_GLOBAL_FLAG: u64 = 0xBC;
const PEB_OS_BUILD_NUMBER: u64 = 0x120;
const HEAP_FLAGS: u64 = 0x70;
const HEAP_FORCE_FLAGS: u64 = 0x74;
const RUPP_WINDOW_FIELDS_OFFSET: u64 = 0x88;
const RUPP_WINDOW_FIELDS_SIZE: usize = 9 * 4;

// Expected post-hide values.
const SPOOFED_OS_BUILD_NUMBER: u16 = 19045;
const HEAP_GROWABLE: u32 = 0x2;
const DEBUGGER_BEING_DEBUGGED: u8 = 1;

struct State {
    initial_bp_hit: bool,
    peb_address: u64,
    before_being_debugged: Option<u8>,
    after_being_debugged: Option<u8>,
    after_nt_global_flag: Option<u32>,
    after_os_build_number: Option<u16>,
    after_heap_flags: Option<u32>,
    after_heap_force_flags: Option<u32>,
    after_window_fields: Option<Vec<u8>>,
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
            after_nt_global_flag: None,
            after_os_build_number: None,
            after_heap_flags: None,
            after_heap_force_flags: None,
            after_window_fields: None,
            applied: Vec::new(),
            failures: Vec::new(),
        }
    }
}

fn read_u8(session: &mut DebugSession<State>, pid: u32, addr: u64) -> u8 {
    session.read_memory(pid, addr, 1).expect("read u8")[0]
}

fn read_u16(session: &mut DebugSession<State>, pid: u32, addr: u64) -> u16 {
    let b = session.read_memory(pid, addr, 2).expect("read u16");
    u16::from_le_bytes([b[0], b[1]])
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
fn test_hide_peb_zeroes_anti_debug_fields() {
    joybug2::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let final_state = DebugSession::new(State::new(), Some(server_addr.as_str()))
        .expect("connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            session.state.initial_bp_hit = true;

            // Resolve PEB and snapshot pre-hide values.
            // hide_peb internally calls get_peb_address; we mirror that via a probing
            // hide_peb call with no options to fetch the address up-front.
            let probe = session.hide_peb(pid, PebHideOptions::default())?;
            assert!(probe.peb_address != 0, "PEB address must be non-zero");
            session.state.peb_address = probe.peb_address;

            session.state.before_being_debugged = Some(read_u8(session, pid, probe.peb_address + PEB_BEING_DEBUGGED));

            // Now actually apply every technique.
            let report = session.hide_peb(pid, PebHideOptions::all())?;
            session.state.applied  = report.applied.clone();
            session.state.failures = report.failures.clone();

            // Snapshot post-hide values.
            session.state.after_being_debugged   = Some(read_u8 (session, pid, probe.peb_address + PEB_BEING_DEBUGGED));
            session.state.after_nt_global_flag   = Some(read_u32(session, pid, probe.peb_address + PEB_NT_GLOBAL_FLAG));
            session.state.after_os_build_number  = Some(read_u16(session, pid, probe.peb_address + PEB_OS_BUILD_NUMBER));

            let heap = read_u64(session, pid, probe.peb_address + PEB_PROCESS_HEAP);
            session.state.after_heap_flags       = Some(read_u32(session, pid, heap + HEAP_FLAGS));
            session.state.after_heap_force_flags = Some(read_u32(session, pid, heap + HEAP_FORCE_FLAGS));

            let params = read_u64(session, pid, probe.peb_address + PEB_PROCESS_PARAMS);
            let window_fields = session.read_memory(pid, params + RUPP_WINDOW_FIELDS_OFFSET, RUPP_WINDOW_FIELDS_SIZE)
                .expect("read window fields");
            session.state.after_window_fields = Some(window_fields);

            Ok(())
        })
        .launch("cmd.exe /c exit 0".to_string())
        .expect("debug session failed");

    assert!(final_state.initial_bp_hit, "initial breakpoint should fire");
    assert!(final_state.peb_address != 0, "PEB address resolved");
    assert_eq!(final_state.before_being_debugged, Some(DEBUGGER_BEING_DEBUGGED),
        "PEB.BeingDebugged must be 1 under the debugger before hiding");

    // Five techniques applied, no failures, no WOW64.
    let expected = ["being_debugged", "heap_flags", "nt_global_flag", "startup_info", "os_build_number"];
    for name in &expected {
        assert!(final_state.applied.iter().any(|s| s == name),
            "Expected '{}' to be applied; got {:?}", name, final_state.applied);
    }
    assert!(final_state.failures.is_empty(),
        "No failures expected; got {:?}", final_state.failures);

    assert_eq!(final_state.after_being_debugged,  Some(0),     "BeingDebugged should be 0 after hide");
    assert_eq!(final_state.after_nt_global_flag,  Some(0),     "NtGlobalFlag should be 0 after hide");
    assert_eq!(final_state.after_os_build_number, Some(SPOOFED_OS_BUILD_NUMBER), "OSBuildNumber should be spoofed");
    assert_eq!(final_state.after_heap_flags,      Some(HEAP_GROWABLE), "HEAP.Flags should be HEAP_GROWABLE");
    assert_eq!(final_state.after_heap_force_flags, Some(0),    "HEAP.ForceFlags should be 0");

    let fields = final_state.after_window_fields.as_ref().expect("window fields snapshot");
    assert!(fields.iter().all(|&b| b == 0),
        "RTL_USER_PROCESS_PARAMETERS window fields should be all zero, got {:?}", fields);
}

// End-to-end behavioral tests using the anti_debug_test.c sample, which checks
// the PEB-resident anti-debug indicators itself and encodes a detection bitmask
// in its exit code:
//   bit0 (0x1) = IsDebuggerPresent / PEB.BeingDebugged
//   bit1 (0x2) = NtGlobalFlag debug bits
//   bit2 (0x4) = process-heap debug flags
// Exit code 0 means nothing was observable via the PEB.
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
fn test_anti_debug_sample_defeated_by_hide_peb() {
    joybug2::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let exe = common::get_test_program_path("anti_debug_test");

    let final_state = DebugSession::new(ExitState::new(), Some(server_addr.as_str()))
        .expect("connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            session.state.initial_bp_hit = true;
            // Apply the anti-anti-debug feature before main() runs.
            let report = session.hide_peb(pid, PebHideOptions::all())?;
            assert!(report.failures.is_empty(), "hide_peb failures: {:?}", report.failures);
            Ok(())
        })
        .on_process_exited(|session, _pid, exit_code| {
            session.state.exit_code = Some(exit_code);
            Ok(())
        })
        .launch(exe)
        .expect("debug session failed");

    assert!(final_state.initial_bp_hit, "initial breakpoint should fire");
    println!("with hide_peb: exit code = {:?}", final_state.exit_code);
    assert_eq!(final_state.exit_code, Some(0),
        "sample should report no debugger (exit 0) after hide_peb, got {:?}", final_state.exit_code);
}

#[test]
fn test_anti_debug_sample_detects_without_hiding() {
    joybug2::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let exe = common::get_test_program_path("anti_debug_test");

    let final_state = DebugSession::new(ExitState::new(), Some(server_addr.as_str()))
        .expect("connect to debug server")
        .on_initial_breakpoint(|session, _pid, _tid, _addr| {
            // No hiding: the sample should observe the debugger.
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
    println!("without hide_peb: exit code = {:?}", final_state.exit_code);
    let code = final_state.exit_code.expect("process should have exited with a code");
    assert_ne!(code, 0, "sample should detect the debugger when PEB is not hidden");
    assert_ne!(code & DETECT_BEING_DEBUGGED, 0,
        "BeingDebugged bit (0x1) must be set under the debugger, got 0x{:x}", code);
}
