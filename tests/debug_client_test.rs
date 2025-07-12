#![cfg(windows)]

use joybug2::protocol::{DebuggerResponse, DebugEvent, DebuggerRequest};
use joybug2::protocol_io::DebugClient;
use std::thread;
use tokio;

fn print_call_stack(client: &mut DebugClient, event: &DebugEvent) {
    let pid = event.pid();
    let tid = event.tid();
    if pid != 0 && tid != 0 {
        println!("Requesting call stack for PID: {}, TID: {}", pid, tid);
        match client.send_and_receive(&DebuggerRequest::GetCallStack { pid, tid }) {
            Ok(DebuggerResponse::CallStack { frames }) => {
                println!("Call Stack ({} frames):", frames.len());
                for (i, frame) in frames.iter().enumerate() {
                    if let Some(symbol) = &frame.symbol {
                        println!("  #{}: 0x{:016x} - {}", i, frame.instruction_pointer, symbol.format_symbol());
                    } else {
                        println!("  #{}: 0x{:016x}", i, frame.instruction_pointer);
                    }
                }
            }
            Ok(DebuggerResponse::Error { message }) => {
                println!("Call stack error: {}", message);
            }
            Ok(other) => {
                println!("Unexpected response to GetCallStack: {:?}", other);
            }
            Err(e) => {
                println!("Failed to get call stack: {}", e);
            }
        }
    } else {
        println!("Skipping call stack request for event without valid PID/TID");
    }
}

#[test]
fn test_debug_client_event_collection() {
    joybug2::init_tracing();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });
    let mut client = DebugClient::connect(None).expect("connect");
    struct TestState {
        events: Vec<DebugEvent>,
    }
    let mut state = TestState { events: Vec::new() };

    client.launch("cmd.exe /c echo test".to_string(), &mut state, |client, state, resp| {
        match resp {
            DebuggerResponse::Event { event } => {
                println!("=== Debug Event: {} ===", event);
                state.events.push(event.clone());
                
                // Get and print call stack for this event
                print_call_stack(client, &event);
                println!();
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
    let thread_exited = state.events.iter().filter(|e| matches!(e, DebugEvent::ThreadExited { .. })).count();

    assert_eq!(process_created, 1, "Should be exactly one process created event");
    assert_eq!(process_exited, 1, "Should be exactly one process exited event");
    assert_eq!(breakpoints, 1, "Should be exactly one breakpoint event");
    assert!(dll_loaded >= 1, "Should be at least one DLL loaded event");
    assert!(thread_created >= 1, "Should be at least one thread created event");
    assert!(thread_exited >= 1, "Should be at least one thread exited event");

    for event in state.events {
        println!("event: {}", event);
    }
} 