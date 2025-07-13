#![cfg(windows)]

use joybug2::interfaces::CallFrame;
use joybug2::protocol::{DebuggerResponse, DebugEvent, DebuggerRequest};
use joybug2::protocol_io::DebugClient;
use std::thread;
use tokio;

fn get_call_stack(client: &mut DebugClient, event: &DebugEvent) -> Option<Vec<CallFrame>> {
    let pid = event.pid();
    let tid = event.tid();
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
            Some(frames)
        }
        Ok(DebuggerResponse::Error { message }) => {
            panic!("Call stack error: {}", message);
        }
        Ok(other) => {
            panic!("Unexpected response to GetCallStack: {:?}", other);
        }
        Err(e) => {
            panic!("Failed to get call stack: {}", e);
        }
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
        dll_load_call_stacks: Vec<Option<Vec<CallFrame>>>,
    }
    let mut state = TestState { events: Vec::new(), dll_load_call_stacks: Vec::new() };

    client.launch("cmd.exe /c echo test".to_string(), &mut state, |client, state, resp| {
        match resp {
            DebuggerResponse::Event { event } => {
                println!("=== Debug Event: {} ===", event);
                
                // Get and print call stack for this event except for ThreadExited
                if matches!(event, DebugEvent::DllLoaded { .. }) {
                    let call_stack = get_call_stack(client, &event);
                    state.dll_load_call_stacks.push(call_stack);
                }
                state.events.push(event.clone());
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

    let mandatory_symbols_substrings = vec!["MapViewOfSection", "RtlUserThreadStart", "LdrpDoDebuggerBreak", "LdrpDoDebuggerBreak"];

    let found_map_view_of_section = state.dll_load_call_stacks.iter()
        .flatten()
        .flat_map(|call_stack| call_stack.iter())
        .filter_map(|frame| frame.symbol.as_ref())
        .any(|symbol| mandatory_symbols_substrings.iter()
        .any(|substring| symbol.format_symbol().contains(substring)));

    assert!(found_map_view_of_section, "Expected to find 'MapViewOfSection' in a DllLoaded event call stack");

    for event in state.events {
        println!("event: {}", event);
    }
} 