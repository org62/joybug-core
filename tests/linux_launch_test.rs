#![cfg(target_os = "linux")]

//! The Linux backend end to end through the real server and client: the
//! event sequence of a launch, breakpoints by symbol, stepping, call stacks,
//! faults, memory regions.

mod common;

use common::{get_test_program_path, TestServer};
use joybug_core::protocol::{DebugEvent, StepAction, StepKind};
use joybug_core::protocol_io::BreakpointDecision;
use joybug_core::protocol_io::{DebugSession, ExceptionAction};

#[derive(Default)]
struct Events {
    names: Vec<String>,
    modules: Vec<String>,
    exit_code: Option<u32>,
    initial_breakpoints: usize,
}

fn session(state: Events, server: &TestServer) -> DebugSession<Events> {
    DebugSession::new(state, Some(server.address()))
        .expect("connect")
        .on_event(|session, event| {
            let name = match event {
                DebugEvent::ProcessCreated { .. } => "ProcessCreated",
                DebugEvent::DllLoaded { dll_name, .. } => {
                    session.state.modules.push(dll_name.clone().unwrap_or_default());
                    "DllLoaded"
                }
                DebugEvent::DllUnloaded { .. } => "DllUnloaded",
                DebugEvent::InitialBreakpoint { .. } => {
                    session.state.initial_breakpoints += 1;
                    "InitialBreakpoint"
                }
                DebugEvent::ThreadCreated { .. } => "ThreadCreated",
                DebugEvent::ThreadExited { .. } => "ThreadExited",
                DebugEvent::Breakpoint { .. } => "Breakpoint",
                DebugEvent::StepComplete { .. } => "StepComplete",
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
fn launch_reports_the_expected_event_sequence() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello");
    let state = session(Events::default(), &server).launch(hello).expect("launch");

    assert_eq!(state.names.first().map(String::as_str), Some("ProcessCreated"));
    assert_eq!(state.initial_breakpoints, 1, "exactly one InitialBreakpoint: {:?}", state.names);
    let ib = state.names.iter().position(|n| n == "InitialBreakpoint").unwrap();
    assert!(state.names[..ib].iter().all(|n| matches!(n.as_str(), "ProcessCreated" | "DllLoaded")), "{:?}", state.names);
    assert!(state.modules.iter().any(|m| m.contains("ld-linux")), "ld.so reported: {:?}", state.modules);
    assert!(state.modules.iter().any(|m| m.contains("libc.so")), "libc reported before the entry point: {:?}", state.modules);
    assert!(state.modules.iter().any(|m| m == "[vdso]"), "{:?}", state.modules);
    assert_eq!(state.names.last().map(String::as_str), Some("ProcessExited"));
    assert_eq!(state.exit_code, Some(42));
}

#[test]
fn pie_launch_uses_the_load_bias() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello_pie");
    let state = session(Events::default(), &server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            let symbols = session.find_symbols("hello_pie!main", 1)?;
            assert_eq!(symbols.len(), 1, "main resolves in the PIE");
            let va = symbols[0].va;
            let modules = session.list_modules(pid)?;
            let exe = modules.iter().find(|m| m.name.ends_with("hello_pie")).expect("exe module");
            assert!(va > exe.base && va < exe.base + exe.size.unwrap(), "main inside the module");
            // The bytes at main must decode: a PIE main starts with a push/endbr.
            let insns = session.disassemble_memory(pid, va, 1, joybug_core::interfaces::Architecture::X64)?;
            assert!(!insns.is_empty());
            Ok(())
        })
        .launch(hello)
        .expect("launch");
    assert_eq!(state.exit_code, Some(42));
}

#[test]
fn breakpoint_by_symbol_hits_with_a_call_stack() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello");
    let state = session(Events::default(), &server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "hello!compute", None, |session, pid, tid, address| {
                let ctx = session.get_thread_context(pid, tid)?;
                assert_eq!(ctx.pc(), address, "PC rewound to the breakpoint");
                // The breakpoint byte is restored while stopped.
                let byte = session.read_memory(pid, address, 1)?;
                assert_ne!(byte[0], 0xCC);
                let args = session.get_arguments(pid, tid, 1)?;
                assert_eq!(args[0], 21, "compute(argc + 20) with argc == 1");
                let frames = session.get_call_stack(pid, tid)?;
                let names: Vec<String> = frames.iter().map(|f| f.symbol.as_ref().map(|s| s.format_symbol()).unwrap_or_default()).collect();
                assert!(names[0].starts_with("hello!compute"), "{names:?}");
                assert!(names.iter().any(|n| n.starts_with("hello!hello_marker")), "{names:?}");
                assert!(names.iter().any(|n| n.starts_with("hello!main")), "{names:?}");
                assert!(names.iter().any(|n| n.starts_with("libc!")), "libc frames below main: {names:?}");
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .launch(hello)
        .expect("launch");
    assert!(state.names.contains(&"Breakpoint".to_string()), "{:?}", state.names);
    assert_eq!(state.exit_code, Some(42));
}

#[test]
fn step_into_over_and_out() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello");
    let state = session(Events::default(), &server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "hello!hello_marker", None, |session, pid, tid, _address| {
                let mut remaining = vec![StepKind::Into, StepKind::Over, StepKind::Over, StepKind::Out];
                session.step(pid, tid, remaining.remove(0), move |session, pid, tid, address, kind| {
                    let insns = session.disassemble_memory(pid, address, 1, joybug_core::interfaces::Architecture::X64)?;
                    let sym = insns[0].symbol_info.as_ref().map(|s| s.format_symbol()).unwrap_or_default();
                    println!("{kind:?} -> {address:#x} {sym}");
                    if kind == StepKind::Out {
                        assert!(sym.starts_with("hello!main"), "step-out lands in the caller: {sym}");
                    } else {
                        assert!(sym.starts_with("hello!hello_marker"), "{sym}");
                    }
                    let _ = tid;
                    if remaining.is_empty() {
                        Ok(StepAction::Stop)
                    } else {
                        Ok(StepAction::Continue(remaining.remove(0)))
                    }
                })?;
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .launch(hello)
        .expect("launch");
    assert!(state.names.iter().filter(|n| *n == "StepComplete").count() >= 4, "{:?}", state.names);
    assert_eq!(state.exit_code, Some(42));
}

#[test]
fn a_fault_is_an_exception_and_passing_it_kills_the_process() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let segv = get_test_program_path("segv");
    let state = session(Events::default(), &server)
        .on_exception(|_session, _pid, _tid, code, _address, _first_chance, params| {
            // Twice: first chance, then the second chance before it kills
            // (see linux_signals_test.rs).
            assert_eq!(code, 0xC000_0005);
            assert_eq!(params.get(1).copied(), Some(0), "fault address");
            Ok(ExceptionAction::PassToApplication)
        })
        .launch(segv)
        .expect("launch");
    assert!(state.names.contains(&"Exception".to_string()), "{:?}", state.names);
    assert_eq!(state.exit_code, Some(128 + 11), "killed by SIGSEGV");
}

#[test]
fn memory_regions_and_modules_are_consistent() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let hello = get_test_program_path("hello");
    let state = session(Events::default(), &server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            let regions = session.enumerate_memory_regions(pid)?;
            assert!(regions.windows(2).all(|w| w[0].base_address < w[1].base_address), "sorted");
            assert!(regions.iter().all(|r| r.state == 0x1000), "all committed");
            let modules = session.list_modules(pid)?;
            let exe = modules.iter().find(|m| m.name.ends_with("/hello")).expect("exe module");
            let image_regions: Vec<_> = regions.iter().filter(|r| r.allocation_base == exe.base).collect();
            assert!(!image_regions.is_empty(), "exe mappings carry the module base");
            assert!(image_regions.iter().all(|r| r.region_type == 0x1000000), "MEM_IMAGE");
            assert!(regions.iter().any(|r| r.region_type == 0x20000), "private memory present");
            Ok(())
        })
        .launch(hello)
        .expect("launch");
    assert_eq!(state.exit_code, Some(42));
}
