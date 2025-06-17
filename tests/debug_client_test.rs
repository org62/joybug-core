#![cfg(windows)]

use joybug2::protocol::{DebuggerResponse, DebugEvent, ModuleInfo, ThreadInfo};
use joybug2::protocol_io::DebugClient;
use std::thread;
use tokio;

#[test]
fn test_debug_client_event_collection() {
    joybug2::init_tracing();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });
    let mut client = DebugClient::connect(None).expect("connect");
    struct TestState {
        modules: Vec<ModuleInfo>,
        threads: Vec<ThreadInfo>,
        events: Vec<DebugEvent>,
    }
    let mut state = TestState { modules: Vec::new(), threads: Vec::new(), events: Vec::new() };

    client.launch("cmd.exe /c echo test".to_string(), &mut state, |client, state, resp| {
        match resp {
            DebuggerResponse::Event { event } => {
                state.events.push(event.clone());
                if let DebugEvent::ProcessCreated { pid, .. } = &event {
                    let threads = client.list_threads(*pid).expect("Should get thread list");
                    state.threads.extend(threads);
                    println!("threads: {:?}", state.threads);
                }
                if let DebugEvent::ProcessExited { pid, .. } = &event {
                    let modules = client.list_modules(*pid).expect("Should get module list");
                    state.modules.extend(modules);
                    println!("modules: {:?}", state.modules);

                    let threads = client.list_threads(*pid).expect("Should get thread list");
                    state.threads.extend(threads);
                    println!("threads2: {:?}", state.threads);
                    return false;
                }
            }
            _ => {}
        }
        true
    }).expect("debug loop");

    let process_created = state.events.iter().filter(|e| matches!(e, DebugEvent::ProcessCreated { .. })).count();
    let process_exited = state.events.iter().filter(|e| matches!(e, DebugEvent::ProcessExited { .. })).count();
    let breakpoints = state.events.iter().filter(|e| matches!(e, DebugEvent::Breakpoint { .. })).count();
    let dll_loaded = state.events.iter().filter(|e| matches!(e, DebugEvent::DllLoaded { .. })).count();
    let thread_created = state.events.iter().filter(|e| matches!(e, DebugEvent::ThreadCreated { .. })).count();

    assert_eq!(process_created, 1, "Should be exactly one process created event");
    assert_eq!(process_exited, 1, "Should be exactly one process exited event");
    assert_eq!(breakpoints, 1, "Should be exactly one breakpoint event");
    assert!(dll_loaded >= 1, "Should be at least one DLL loaded event");
    assert!(state.modules.len() >= dll_loaded, "Should be at least as many modules as DLLs loaded");
    assert_eq!(state.threads.len(), 1 + thread_created, "Should have main thread plus any created threads");
} 