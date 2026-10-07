#![cfg(target_os = "linux")]

//! Hardware watchpoints, register writes, threads, line tables and attach on
//! the Linux backend.

mod common;

use common::{get_test_program_path, TestServer};
use joybug_core::protocol::{DebugEvent, ThreadContext};
use joybug_core::protocol_io::{BreakpointDecision, DebugSession, HardwareBreakpointSize, HardwareBreakpointType};

#[derive(Default)]
struct State {
    names: Vec<String>,
    exit_code: Option<u32>,
    hw_hits: u32,
    thread_created: u32,
    thread_exited: u32,
    worker_hits: u32,
}

fn session(server: &TestServer) -> DebugSession<State> {
    DebugSession::new(State::default(), Some(server.address()))
        .expect("connect")
        .on_event(|session, event| {
            let name = match event {
                DebugEvent::ThreadCreated { .. } => {
                    session.state.thread_created += 1;
                    "ThreadCreated"
                }
                DebugEvent::ThreadExited { .. } => {
                    session.state.thread_exited += 1;
                    "ThreadExited"
                }
                DebugEvent::HardwareBreakpoint { .. } => {
                    session.state.hw_hits += 1;
                    "HardwareBreakpoint"
                }
                DebugEvent::ProcessExited { exit_code, .. } => {
                    session.state.exit_code = Some(*exit_code);
                    "ProcessExited"
                }
                DebugEvent::Exception { .. } => "Exception",
                _ => "Other",
            };
            session.state.names.push(name.to_string());
            Ok(true)
        })
}

#[test]
fn hardware_write_watchpoint_fires_once_and_the_process_finishes() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_hardware_breakpoint_by_symbol(
                pid,
                "hello!g_write_dword",
                HardwareBreakpointType::Write,
                HardwareBreakpointSize::Byte4,
                |session, pid, tid, _address| {
                    // The write already happened: the value is in place.
                    let syms = session.find_symbols("hello!g_write_dword", 1)?;
                    let value = session.read_memory(pid, syms[0].va, 4)?;
                    assert_eq!(u32::from_le_bytes(value[..4].try_into().unwrap()), 42);
                    let _ = tid;
                    Ok(BreakpointDecision::Keep)
                },
            )?;
            Ok(())
        })
        .launch(hello)
        .expect("launch");
    assert_eq!(state.hw_hits, 1, "{:?}", state.names);
    assert!(!state.names.contains(&"Exception".to_string()), "no stray single-step exceptions: {:?}", state.names);
    assert_eq!(state.exit_code, Some(42));
}

#[test]
fn registers_round_trip_and_an_edit_changes_the_outcome() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "hello!compute", None, |session, pid, tid, address| {
                let ctx = session.get_thread_context(pid, tid)?;
                let ThreadContext::Win32RawContext(mut raw) = ctx else { panic!("x64 context") };
                assert_eq!(raw.Rip, address);
                assert_eq!(raw.SegCs, 0x33, "64-bit code segment");
                assert_eq!(raw.MxCsr & 0x1f80, 0x1f80, "default MXCSR mask bits");
                assert_eq!(raw.Rdi, 21, "first SysV argument");
                // compute(x): make it compute(-21) so g_counter goes negative
                // and main returns 1 instead of 42.
                raw.Rdi = (-21i64) as u64;
                session.set_thread_context(pid, tid, ThreadContext::Win32RawContext(raw))?;
                let again = session.get_thread_context(pid, tid)?;
                assert_eq!(again.as_native().map(|c| c.Rdi), Some((-21i64) as u64));
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .launch(hello)
        .expect("launch");
    assert_eq!(state.exit_code, Some(1), "the edited argument changed the exit code");
}

#[test]
fn threads_are_reported_and_a_breakpoint_hits_in_each() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let threads = get_test_program_path("threads");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "threads!worker", None, |session, pid, tid, _address| {
                session.state.worker_hits += 1;
                let args = session.get_arguments(pid, tid, 1)?;
                assert!(args[0] == 1 || args[0] == 2, "worker id: {}", args[0]);
                let threads = session.list_threads(pid)?;
                assert!(threads.iter().any(|t| t.tid == tid), "the hitting thread is listed");
                Ok(BreakpointDecision::Keep)
            })?;
            Ok(())
        })
        .launch(threads)
        .expect("launch");
    assert_eq!(state.worker_hits, 2, "{:?}", state.names);
    assert_eq!(state.thread_created, 2, "{:?}", state.names);
    assert!(state.thread_exited >= 2, "{:?}", state.names);
    assert_eq!(state.exit_code, Some(0));
}

#[test]
fn dwarf_line_information_resolves_source_lines() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            let syms = session.find_symbols("hello!compute", 1)?;
            let info = session.resolve_address_to_line(pid, syms[0].va)?.expect("line info for compute");
            assert!(info.file.path.ends_with("hello.c"), "{}", info.file.path);
            // `compute` is defined at line 24 of hello.c; its prologue maps to
            // the first lines of the function.
            assert!(info.line_entry.line_start >= 24 && info.line_entry.line_start <= 28, "compute's line: {}", info.line_entry.line_start);
            let modules = session.list_modules(pid)?;
            let exe = modules.iter().find(|m| m.name.ends_with("/hello")).unwrap();
            let files = session.list_source_files(pid, exe.base)?;
            assert!(files.iter().any(|f| f.path.ends_with("hello.c")), "{files:?}");
            let (file, lines) = session.get_source_file_line_map(pid, exe.base, &info.file.path, None, None)?;
            assert!(file.is_some());
            assert!(lines.len() > 5, "line entries for hello.c: {}", lines.len());
            Ok(())
        })
        .launch(hello)
        .expect("launch");
    assert_eq!(state.exit_code, Some(42));
}

#[test]
fn attach_to_a_sleeping_process_and_terminate_it() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let sleeper = get_test_program_path("sleeper");
    let mut child = std::process::Command::new(&sleeper)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id();
    // Let it reach its sleep loop (libc mapped, prctl done).
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut session = session(&server);
    let listed = session.list_processes().expect("list_processes");
    let me = listed.iter().find(|p| p.pid == pid).expect("sleeper listed");
    assert_eq!(me.name, "sleeper");

    let state = session
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            let modules = session.list_modules(pid)?;
            assert!(modules.iter().any(|m| m.name.ends_with("/sleeper")), "{modules:?}");
            assert!(modules.iter().any(|m| m.name.contains("libc.so")), "libc discovered from the link map: {modules:?}");
            let syms = session.find_symbols("libc!nanosleep", 1).or_else(|_| session.find_symbols("libc!clock_nanosleep", 1))?;
            assert!(!syms.is_empty(), "libc symbols resolve after attach");
            session.terminate_process(pid)?;
            Ok(())
        })
        .attach(pid)
        .expect("attach");
    assert!(state.names.contains(&"ProcessExited".to_string()), "{:?}", state.names);
    assert_eq!(state.exit_code, Some(128 + 9), "SIGKILL");
    let _ = child.wait();
}
