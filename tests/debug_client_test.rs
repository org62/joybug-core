#![cfg(windows)]

use joybug2::interfaces::CallFrame;
use joybug2::protocol::{StepKind, StepAction};
use joybug2::protocol_io::DebugSession;
use std::thread;
use tokio;
use joybug2::interfaces::InstructionFormatter;
use joybug2::interfaces::Architecture;

/// Clean, simple test state for tracking events
struct TestState {
    dll_load_call_stacks: Vec<Option<Vec<CallFrame>>>,
    single_shot_breakpoint_hit: bool,
    steps_completed: usize,
    initial_breakpoint_hit: bool,
    process_created: bool,
    dll_loads_count: usize,
    thread_exits_count: usize,
    ntclose_bp_hits: usize,
}

impl TestState {
    fn new() -> Self {
        Self {
            dll_load_call_stacks: Vec::new(),
            single_shot_breakpoint_hit: false,
            steps_completed: 0,
            initial_breakpoint_hit: false,
            process_created: false,
            dll_loads_count: 0,
            thread_exits_count: 0,
            ntclose_bp_hits: 0,
        }
    }
}

fn print_disassembly(session: &mut DebugSession<TestState>, pid: u32, tid: u32, address: u64) -> anyhow::Result<()> {
    let arch = Architecture::from_native();
    let disassembly = session.disassemble_memory(pid, address, 10, arch)?;
    println!("{}", disassembly.format_disassembly());
    let call_stack = session.get_call_stack(pid, tid)?;
    println!("Call stack:");
    for frame in call_stack {
        if let Some(symbol) = &frame.symbol {
            println!("  {}", symbol.format_symbol());
        } else {
            panic!("  Symbol: <unknown>");
        }
    }
    Ok(())
}

/// Test symbol search functionality
fn test_symbol_search(session: &mut DebugSession<TestState>) {
    println!("=== Testing Symbol Search ===");
    
    let test_symbols = vec![
        "ntdll!NtCreateFile",
        "NtReadFile", 
        "ntdll!Nt",
        "LdrInitializeThunk"
    ];
    
    for symbol_name in test_symbols {
        match session.find_symbols(symbol_name, 5) {
            Ok(symbols) => {
                println!("Found {} symbols matching '{}':", symbols.len(), symbol_name);
                for (i, symbol) in symbols.iter().enumerate() {
                    println!("  {}: {} (Module: {}, RVA: 0x{:x}, VA: 0x{:x})", 
                        i + 1, symbol.name, symbol.module_name, symbol.rva, symbol.va);
                }
                if symbols.is_empty() {
                    panic!("  No symbols found for '{}'", symbol_name);
                }
            }
            Err(e) => {
                panic!("Symbol search error for '{}': {}", symbol_name, e);
            }
        }
    }
}

#[test]
fn test_debug_client_event_collection() {
    joybug2::init_tracing();
    
    // Start the debug server
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });
    
    // Launch process with clean stateful callback-based interface
    let final_state = DebugSession::new(TestState::new(), None)
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, address| {
            println!("=== Hit Initial Breakpoint at 0x{:x} ===", address);
            session.state.initial_breakpoint_hit = true;
            
            // Set a persistent breakpoint on NtClose and track hits (all threads)
            session.set_breakpoint_by_symbol(pid, "ntdll!NtClose", None, |session, _pid, _tid, _addr| {
                session.state.ntclose_bp_hits += 1;
                if session.state.ntclose_bp_hits >= 3 {
                    Ok(joybug2::protocol_io::BreakpointDecision::Remove)
                } else {
                    Ok(joybug2::protocol_io::BreakpointDecision::Keep)
                }
            })?;

            // Set the breakpoint first, let the process run, and *then* test stepping
            // from within the breakpoint handler. This is a more robust sequence.
            session.set_single_shot_breakpoint(pid, "cmd!CmdPutChars", |session, pid, tid, bp_addr| {
                println!("=== Hit Single-Shot Breakpoint at 0x{:x} ===", bp_addr);
                session.state.single_shot_breakpoint_hit = true;
                
                // Validate console output can be read at the breakpoint
                let args = session.get_arguments(pid, tid, 2)?;
                assert_eq!(args.len(), 2, "Should have 2 arguments");
                let buffer_addr = args[0];
                let chars_to_write = args[1] as usize;
                let output = session.read_wide_string(pid, buffer_addr, Some(chars_to_write))?;
                assert_eq!(output, "test", "Console output should be 'test'");
                println!("Console output validation successful");

                // Now that we are at a stable point, test the stepping functionality
                println!("=== Testing Stepping Functionality ===");
                session.step(pid, tid, StepKind::Into, |session, _pid, _tid, step_addr, kind| {
                    println!("Step completed ({:?}) at 0x{:016x}", kind, step_addr);
                    session.state.steps_completed += 1;
                    if session.state.steps_completed < 3 {
                        println!("Continuing to next step");
                        Ok(StepAction::Continue(StepKind::Into))
                    } else {
                        println!("Stopping");
                        Ok(StepAction::Stop)
                    }
                })?;
                println!("Continue after single-shot breakpoint");
                Ok(())
            })?;
            
            println!("Single-shot breakpoint configured successfully, continuing process...");
            Ok(())
        })
        .on_dll_loaded(|session, pid, tid, dll_name, base_address| {
            println!("=== DLL Loaded: {} at 0x{:x} ===", dll_name, base_address);
            
            // Track DLL loads and get call stack
            session.state.dll_loads_count += 1;
            if let Ok(call_stack) = session.get_call_stack(pid, tid) {
                println!("Call Stack ({} frames):", call_stack.len());
                for (i, frame) in call_stack.iter().enumerate() {
                    if let Some(symbol) = &frame.symbol {
                        println!("  #{}: 0x{:016x} - {}", i, frame.instruction_pointer, symbol.format_symbol());
                    } else {
                        println!("  #{}: 0x{:016x}", i, frame.instruction_pointer);
                    }
                }
                session.state.dll_load_call_stacks.push(Some(call_stack));
            } else {
                panic!("Failed to get call stack for DLL load event");
            }
            
            println!("Call stack captured for DLL load event");
            
            // Test symbol search when ntdll is loaded (happens early)
            if dll_name.to_lowercase().contains("ntdll") {
                test_symbol_search(session);
                println!("Symbol search tests completed");
            }
            Ok(())
        })
        .on_process_created(|session, _pid, _tid, image_name, base_address| {
            println!("=== Process Created: {} at 0x{:x} ===", image_name, base_address);
            session.state.process_created = true;
            Ok(())
        })
        .on_thread_created(|session, pid, tid, address| {
            println!("=== Thread created at 0x{:016x} ===", address);
            print_disassembly(session, pid, tid, address)?;
            Ok(())
        })
        .on_thread_exited(|session, pid, _tid, exit_code| {
            println!(
                "=== Thread Exited: pid={}, exit_code=0x{:x} ===",
                pid, exit_code
            );
            session.state.thread_exits_count += 1;
            Ok(())
        })
        .on_process_exited(|_session, pid, exit_code| {
            println!(
                "=== Process Exited: pid={}, exit_code=0x{:x} ===",
                pid, exit_code
            );
            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("Debug session failed");
    
    // Validate all test requirements were met
    validate_test_results(&final_state);
}

fn validate_test_results(state: &TestState) {
    println!("\n=== Test Validation ===");
    
    // Validate tracked events
    assert!(state.process_created, "Should have received process created event");
    assert!(state.initial_breakpoint_hit, "Should have hit initial breakpoint");
    assert!(state.single_shot_breakpoint_hit, "Single-shot breakpoint should have been hit");
    assert!(state.dll_loads_count >= 1, "Should be at least one DLL loaded event");
    
    // Validate stepping functionality
    assert_eq!(state.steps_completed, 3, "Should have completed exactly 3 steps");
    assert_eq!(state.ntclose_bp_hits, 3, "NtClose should be hit exactly 3 times, got {}", state.ntclose_bp_hits);
    
    // Validate call stack functionality
    let mandatory_symbols = vec!["MapViewOfSection", "RtlUserThreadStart", "LdrpDoDebuggerBreak"];
    let found_required_symbols = state.dll_load_call_stacks.iter()
        .flatten()
        .flat_map(|call_stack| call_stack.iter())
        .filter_map(|frame| frame.symbol.as_ref())
        .any(|symbol| mandatory_symbols.iter()
            .any(|required| symbol.format_symbol().contains(required)));
    
    assert!(found_required_symbols, "Expected to find required symbols in DLL load call stacks");
    
    println!("✅ All test validations passed!");
    println!("Process created: {}", state.process_created);
    println!("Initial breakpoint hit: {}", state.initial_breakpoint_hit);
    println!("Single-shot breakpoint hit: {}", state.single_shot_breakpoint_hit);
    println!("DLL loads: {}", state.dll_loads_count);
    println!("DLL load call stacks captured: {}", state.dll_load_call_stacks.len());
    println!("Steps completed: {}", state.steps_completed);
    println!("Thread exits observed: {}", state.thread_exits_count);
} 