#![cfg(windows)]

use joybug2::interfaces::{Architecture};
use joybug2::protocol::{StepKind, StepAction};
use joybug2::protocol_io::DebugSession;
use std::thread;
use tokio;
use joybug2::interfaces::InstructionFormatter;

/// Clean, simple test state for tracking events
struct TestState {
    step_sequence: Vec<StepKind>,
}

impl TestState {
    fn new() -> Self {
        Self {
            step_sequence: vec![StepKind::Into, StepKind::Into, StepKind::Into, StepKind::Over, StepKind::Over],
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

#[test]
fn test_stepper_test() {
    joybug2::init_tracing();
    
    // Start the debug server
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });
    
    // Launch process with clean stateful callback-based interface
    let _final_state = DebugSession::new(TestState::new(), None)
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, tid, address| {
            println!("Initial breakpoint hit at 0x{:016x}", address);
            print_disassembly(session, pid, tid, address)?;
            // Init the stepper
            let first_step = session.state.step_sequence.remove(0);
            session.step(pid, tid, first_step, |session, pid, tid, address, kind| {
                println!("Step completed ({:?}) at 0x{:016x}, pid: {}, tid: {}, steps left: {}", kind, address, pid, tid, session.state.step_sequence.len());
                let _ = print_disassembly(session, pid, tid, address);
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
        .launch("cmd.exe /c echo test".to_string())
        .expect("Debug session failed");
}
