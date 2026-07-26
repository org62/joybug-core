#![cfg(windows)]

mod common;

use common::{TestServer, print_disassembly_and_callstack};
use joybug_core::interfaces::Architecture;
use std::collections::VecDeque;
use joybug_core::protocol::{StepKind, StepAction};
use joybug_core::protocol_io::DebugSession;

/// Clean, simple test state for tracking events
struct TestState {
    step_sequence: Vec<StepKind>,
    expected_out_prefixes: VecDeque<&'static str>,
}

impl TestState {
    fn new() -> Self {
        Self {
            step_sequence: vec![StepKind::Into, StepKind::Into, StepKind::Into, StepKind::Over, StepKind::Over, StepKind::Out, StepKind::Out],
            expected_out_prefixes: VecDeque::from([
                "ntdll!_LdrpInitialize",
                "ntdll!LdrpInitializeInternal",
            ]),
        }
    }
}

fn assert_disasm_symbol_prefix(session: &mut DebugSession<TestState>, pid: u32, address: u64, expected_prefix: &str) {
    let arch = Architecture::from_native();
    let insns = session
        .disassemble_memory(pid, address, 1, arch)
        .expect("Failed to disassemble at step-complete address");
    let first = insns.first().expect("No instruction returned at step-complete address");
    let symbol_text = if let Some(ref sym) = first.symbol_info {
        sym.format_symbol()
    } else {
        format!("0x{:016x}", first.address)
    };
    assert!(
        symbol_text.starts_with(expected_prefix),
        "Expected disasm symbol starting with '{}', got: {}",
        expected_prefix,
        symbol_text
    );
}

#[test]
fn test_stepper_test() {
    joybug_core::init_tracing();
    
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    
    // Launch process with clean stateful callback-based interface
    let _final_state = DebugSession::new(TestState::new(), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, tid, address| {
            println!("Initial breakpoint hit at 0x{:016x}", address);
            print_disassembly_and_callstack(session, pid, tid, address)?;
            // Init the stepper
            let first_step = session.state.step_sequence.remove(0);
            session.step(pid, tid, first_step, |session, pid, tid, address, kind| {
                println!("Step completed ({:?}) at 0x{:016x}, pid: {}, tid: {}, steps left: {}", kind, address, pid, tid, session.state.step_sequence.len());
                let _ = print_disassembly_and_callstack(session, pid, tid, address);
                if kind == StepKind::Out {
                    if let Some(prefix) = session.state.expected_out_prefixes.pop_front() {
                        assert_disasm_symbol_prefix(session, pid, address, prefix);
                    }
                }
                if session.state.step_sequence.is_empty() {
                    println!("No more steps to take, stopping");
                    Ok(StepAction::Stop)
                } else {
                    let next_step = session.state.step_sequence.remove(0);
                    println!("Taking next step: {:?}", next_step);
                    Ok(StepAction::Continue(next_step))
                }
            })?;
            println!("Finished initial breakpoint");
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("Process {} exited with code {}", pid, exit_code);
            assert!(session.state.expected_out_prefixes.is_empty(), "Expected out prefixes not popped: {:?}", session.state.expected_out_prefixes);
            assert!(session.state.step_sequence.is_empty(), "Step sequence not empty: {:?}", session.state.step_sequence);
            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("Debug session failed");
    // make sure all expected_out_prefixes are popped
}
