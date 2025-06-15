#![cfg(windows)]

use joybug_basics_tests1::protocol::{DebuggerResponse, DebugEvent};
use joybug_basics_tests1::protocol_io::DebugClient;
use std::thread;
use tokio;

#[test]
fn test_debug_client_event_collection() {
    joybug_basics_tests1::init_tracing();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug_basics_tests1::server::run_server()).unwrap();
    });
    let mut client = DebugClient::connect(None).expect("connect");
    let mut events = Vec::new();

    client.launch("cmd.exe /c echo test".to_string(), &mut events, |_client, events, resp| {
        match resp {
            DebuggerResponse::Event { event } => {
                events.push(event.clone());
                if matches!(event, DebugEvent::ProcessExited { .. }) {
                    return false;
                }
            }
            _ => {}
        }
        true
    }).expect("debug loop");

    let process_created = events.iter().filter(|e| matches!(e, DebugEvent::ProcessCreated { .. })).count();
    let process_exited = events.iter().filter(|e| matches!(e, DebugEvent::ProcessExited { .. })).count();
    let breakpoints = events.iter().filter(|e| matches!(e, DebugEvent::Breakpoint { .. })).count();
    let dll_loaded = events.iter().filter(|e| matches!(e, DebugEvent::DllLoaded { .. })).count();

    assert_eq!(process_created, 1, "Should be exactly one process created event");
    assert_eq!(process_exited, 1, "Should be exactly one process exited event");
    assert_eq!(breakpoints, 1, "Should be exactly one breakpoint event");
    assert!(dll_loaded >= 1, "Should be at least one DLL loaded event");
} 