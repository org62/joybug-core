#![cfg(windows)]

use joybug2::interfaces::CallFrame;
use joybug2::protocol::{DebuggerResponse, DebugEvent, DebuggerRequest, StepKind};
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

fn test_symbol_search(client: &mut DebugClient, event: &DebugEvent) {
    // Search symbols by name, *Query*
    if let DebugEvent::ProcessExited { .. } = &event {
        println!("=== Searching for symbols in ntdll.dll ===");
        
        // Test symbol search with actual ntdll functions
        let test_symbols = vec![
            "ntdll!NtCreateFile",
            "NtReadFile", 
            "ntdll!Nt",
            "LdrInitializeThunk"
        ];
        
        for symbol_name in test_symbols {
            match client.send_and_receive(&DebuggerRequest::FindSymbol { 
                symbol_name: symbol_name.to_string(), 
                max_results: 5 
            }) {
                Ok(DebuggerResponse::ResolvedSymbolList { symbols }) => {
                    assert!(symbols.len() > 0, "Expected to find at least one symbol matching '{}'", symbol_name);
                    println!("Found {} symbols matching '{}':", symbols.len(), symbol_name);
                    for (i, symbol) in symbols.iter().enumerate() {
                        println!("  {}: {} (Module: {}, RVA: 0x{:x}, VA: 0x{:x})", 
                            i + 1, symbol.name, symbol.module_name, symbol.rva, symbol.va);
                    }
                    if symbols.is_empty() {
                        panic!("  No symbols found for '{}'", symbol_name);
                    }
                }
                Ok(DebuggerResponse::Error { message }) => {
                    panic!("Symbol search error for '{}': {}", symbol_name, message);
                }
                Ok(other) => {
                    panic!("Unexpected response to FindSymbol for '{}': {:?}", symbol_name, other);
                }
                Err(e) => {
                    panic!("Failed to search symbols for '{}': {}", symbol_name, e);
                }
            }
        }
    }
}

fn test_stepping(client: &mut DebugClient, event: &DebugEvent) {
    // Only test stepping when we have a process created event
    if let DebugEvent::Breakpoint { pid, tid, .. } = event {
        println!("=== Testing Step In functionality ===");
        
        let step_count = 3; // Step 3 times to test basic functionality
        
        for i in 1..=step_count {
            println!("Performing step {} of {}", i, step_count);
            
            match client.send_and_receive(&DebuggerRequest::Step { 
                pid: *pid, 
                tid: *tid, 
                kind: StepKind::Into 
            }) {
                Ok(DebuggerResponse::Event { event }) => {
                    match event {
                        DebugEvent::StepComplete { address, kind, .. } => {
                            println!("  Step {}: Step complete ({:?}) at address 0x{:016x}", i, kind, address);
                        }
                        _ => {
                            // Note: In a bigger test this is not necessary true, but good for now.
                            println!("Step {}: Unexpected event: {:?}", i, event);
                        }
                    }
                }
                Ok(DebuggerResponse::Error { message }) => {
                    panic!("Step {}: Error - {}", i, message);
                }
                Ok(other) => {
                    panic!("Step {}: Unexpected response: {:?}", i, other);
                }
                Err(e) => {
                    panic!("Step {}: Communication error: {}", i, e);
                }
            }
        }
        
        println!("Step testing completed successfully");
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
        single_shot_breakpoint_hit: bool,
        single_shot_breakpoint_addr: u64,
    }
    let mut state = TestState { events: Vec::new(), dll_load_call_stacks: Vec::new(), single_shot_breakpoint_hit: false, single_shot_breakpoint_addr: 0 };

    client.launch("cmd.exe /c echo test".to_string(), &mut state, |client, state, resp| {
        match resp {
            DebuggerResponse::Event { event } => {
                println!("=== Debug Event: {} ===", event);
                
                // Get and print call stack for this event except for ThreadExited
                if matches!(event, DebugEvent::DllLoaded { .. }) {
                    let call_stack = get_call_stack(client, &event);
                    state.dll_load_call_stacks.push(call_stack);
                }

                if let DebugEvent::Breakpoint { pid, tid, address } = &event {
                    // If single_shot_breakpoint_addr is 0, this is the initial process breakpoint.
                    if state.single_shot_breakpoint_addr == 0 {
                        println!("=== Hit initial breakpoint, setting up Single-Shot Breakpoint ===");
                        
                        // Find a symbol to break on, e.g., WriteConsoleW
                        let symbol_name = "kernelbase!WriteConsoleW".to_string();
                        let symbols = match client.send_and_receive(&DebuggerRequest::FindSymbol {
                            symbol_name: symbol_name.clone(),
                            max_results: 1
                        }) {
                            Ok(DebuggerResponse::ResolvedSymbolList { symbols }) => symbols,
                            _ => panic!("Failed to find symbol for single-shot breakpoint test."),
                        };
                        
                        if symbols.is_empty() {
                            panic!("Could not find symbol '{}' for testing single-shot breakpoint.", symbol_name);
                        }
                        
                        state.single_shot_breakpoint_addr = symbols[0].va;
                        println!("Setting single-shot breakpoint at {} (0x{:x})", symbol_name, state.single_shot_breakpoint_addr);
                        
                        // Set the single-shot breakpoint
                        match client.send_and_receive(&DebuggerRequest::SetSingleShotBreakpoint { pid: *pid, addr: state.single_shot_breakpoint_addr }) {
                            Ok(DebuggerResponse::Ack) => (),
                            _ => panic!("Failed to set single-shot breakpoint."),
                        }
                    } else if *address == state.single_shot_breakpoint_addr {
                        println!("*** Hit single-shot breakpoint at 0x{:x} ***", address);
                        state.single_shot_breakpoint_hit = true;

                        // Get the first 3 arguments for WriteConsoleW
                        match client.send_and_receive(&DebuggerRequest::GetFunctionArguments { pid: *pid, tid: *tid, count: 3 }) {
                            Ok(DebuggerResponse::FunctionArguments { arguments }) => {
                                if arguments.len() >= 3 {
                                    let buffer_addr = arguments[1]; // lpBuffer
                                    let chars_to_write = arguments[2] as u32; // nNumberOfCharsToWrite

                                    if buffer_addr != 0 && chars_to_write > 0 {
                                        println!("WriteConsoleW args: buffer=0x{:x}, len={}", buffer_addr, chars_to_write);
                                        match client.send_and_receive(&DebuggerRequest::ReadWideString { pid: *pid, address: buffer_addr, max_len: Some(chars_to_write as usize) }) {
                                            Ok(DebuggerResponse::WideStringData { data }) => {
                                                println!("Read from console buffer: '{}'", data);
                                                assert_eq!(data, "test", "The console output should be 'test'");
                                            }
                                            _ => panic!("Failed to read wide string from process memory"),
                                        }
                                    }
                                }
                            }
                            _ => panic!("Failed to get function arguments for WriteConsoleW"),
                        }
                    }
                }

                state.events.push(event.clone());
                println!();

                test_symbol_search(client, &event);
                test_stepping(client, &event);
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
    assert_eq!(breakpoints, 2, "Should be exactly two breakpoint events");
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

    assert!(state.single_shot_breakpoint_hit, "Did not hit the single-shot breakpoint");

    for event in state.events {
        println!("event: {}", event);
    }
} 