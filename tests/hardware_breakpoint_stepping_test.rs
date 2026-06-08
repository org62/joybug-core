#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path};
use joybug2::protocol::{StepAction, StepKind};
use joybug2::protocol_io::{
    BreakpointDecision, DebugSession, HardwareBreakpointSize,
    HardwareBreakpointType,
};

struct TestState {
    hw_bp_hit_count: u32,
    hw_bp_address: u64,
    step_completed: bool,
    step_address: u64,
}

impl TestState {
    fn new() -> Self {
        Self {
            hw_bp_hit_count: 0,
            hw_bp_address: 0,
            step_completed: false,
            step_address: 0,
        }
    }
}

/// Test that stepping over a hardware execution breakpoint actually advances
/// past the instruction, rather than getting stuck at the same address.
///
/// Bug scenario: When a HW BP fires, the debug event handler disables the DR7
/// enable bit and schedules a pending re-arm via single-step. If the user then
/// steps (Into/Over), the pending re-arm consumes the step's single-step
/// exception, causing the step to be silently swallowed. Execution continues
/// freely until the HW BP fires again at the same address.
#[test]
#[cfg(not(target_arch = "aarch64"))]
fn hardware_breakpoint_step_over() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe = get_test_program_path("hardware_bp_test");
    println!("Using hardware_bp_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(TestState::new(), Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            // Set a software breakpoint on breakpoint_here to set up the HW BP
            session.set_breakpoint_by_symbol(
                pid,
                "breakpoint_here",
                None,
                |session: &mut DebugSession<TestState>, pid, _tid, _addr| {
                    println!("SW BP hit: breakpoint_here — setting HW execute BP on execute_target");

                    // Set HW execute breakpoint on execute_target
                    session.set_hardware_breakpoint_by_symbol(
                        pid,
                        "execute_target",
                        HardwareBreakpointType::Execute,
                        HardwareBreakpointSize::Byte1,
                        |session: &mut DebugSession<TestState>, pid, tid, addr| {
                            session.state.hw_bp_hit_count += 1;
                            session.state.hw_bp_address = addr;
                            let hit = session.state.hw_bp_hit_count;
                            if hit <= 3 {
                                println!("HW BP hit #{} at 0x{:X}", hit, addr);
                            }

                            if hit == 1 {
                                // First hit: step over the instruction
                                println!("Stepping over from HW BP at 0x{:X}...", addr);
                                session.step(pid, tid, StepKind::Over, |session, _pid, _tid, step_addr, kind| {
                                    println!("Step completed ({:?}) at 0x{:X}", kind, step_addr);
                                    session.state.step_completed = true;
                                    session.state.step_address = step_addr;
                                    Ok(StepAction::Stop)
                                })?;
                            } else if hit >= 3 {
                                // If we get here, the step was swallowed and we're looping.
                                // Remove the HW BP to let the process exit so we can assert.
                                println!("HW BP hit {} times — bug confirmed, removing BP to unblock", hit);
                                return Ok(BreakpointDecision::Remove);
                            }

                            Ok(BreakpointDecision::Keep)
                        },
                    )?;

                    Ok(BreakpointDecision::Remove)
                },
            )?;
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("Process {} exited with code 0x{:X}", pid, exit_code);
            println!("HW BP hits: {}", session.state.hw_bp_hit_count);
            println!("Step completed: {}", session.state.step_completed);
            if session.state.step_completed {
                println!("Step address: 0x{:X}", session.state.step_address);
                println!("HW BP address: 0x{:X}", session.state.hw_bp_address);
            }
            Ok(())
        })
        .launch(test_exe)
        .expect("Debug session failed");

    // The step callback MUST have fired
    assert!(
        final_state.step_completed,
        "Step over from hardware breakpoint never completed — \
         the step was likely swallowed by the HW BP re-arm handler"
    );

    // The step must have advanced past the HW BP address
    assert_ne!(
        final_state.step_address, final_state.hw_bp_address,
        "Step over landed back at the same HW BP address 0x{:X} — \
         the instruction was not advanced",
        final_state.hw_bp_address
    );

    // The HW BP should have been hit exactly once (not re-triggered after swallowed step)
    assert_eq!(
        final_state.hw_bp_hit_count, 1,
        "HW BP was hit {} times, expected 1 — \
         the step was swallowed and execution looped back to the HW BP",
        final_state.hw_bp_hit_count
    );

    println!("\n=== Hardware Breakpoint Step-Over Test PASSED ===");
}
