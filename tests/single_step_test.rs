#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path};
use joybug2::protocol_io::{DebugSession, ExceptionAction};

// EXCEPTION_SINGLE_STEP / STATUS_SINGLE_STEP.
const SINGLE_STEP_CODE: u32 = 0x80000004;

fn test_exe_path() -> String {
    get_test_program_path("single_step_test")
}

/// A single-step exception raised by the debuggee itself must be treatable like
/// any other exception. With HandledByDebugger (DBG_CONTINUE) the exception is
/// swallowed, the program's SEH handler never runs, and it exits with code 1.
#[test]
fn test_single_step_handled_by_debugger() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = test_exe_path();

    struct TestState {
        exit_code: Option<u32>,
    }

    let final_state = DebugSession::new(
        TestState { exit_code: None },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .set_exception_action(
        SINGLE_STEP_CODE,
        ExceptionAction::HandledByDebugger,
        ExceptionAction::Stop,
    )
    .on_process_exited(|session, _pid, exit_code| {
        session.state.exit_code = Some(exit_code);
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    assert_eq!(
        final_state.exit_code,
        Some(1),
        "Expected exit code 1 (single-step exception swallowed by debugger), got {:?}",
        final_state.exit_code
    );
}

/// The reported case: "Go (Pass Exception)" on a program-raised single-step
/// exception. With PassToApplication (DBG_EXCEPTION_NOT_HANDLED) the exception
/// is delivered to the program, its SEH handler runs, and it exits with code 0.
#[test]
fn test_single_step_passed_to_application() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = test_exe_path();

    struct TestState {
        exit_code: Option<u32>,
    }

    let final_state = DebugSession::new(
        TestState { exit_code: None },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .set_exception_action(
        SINGLE_STEP_CODE,
        ExceptionAction::PassToApplication,
        ExceptionAction::Stop,
    )
    .on_process_exited(|session, _pid, exit_code| {
        session.state.exit_code = Some(exit_code);
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    assert_eq!(
        final_state.exit_code,
        Some(0),
        "Expected exit code 0 (single-step exception passed to application), got {:?}",
        final_state.exit_code
    );
}
