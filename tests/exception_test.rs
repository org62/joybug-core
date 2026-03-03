#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path};
use joybug2::protocol_io::{DebugSession, ExceptionAction};

fn test_exe_path() -> String {
    get_test_program_path("exception_test")
}

/// Confirms the existing bug: with default behavior (DBG_CONTINUE),
/// the exception is swallowed, the SEH handler never runs,
/// and the process exits with code 1.
#[test]
fn test_exception_not_passed_to_application() {
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
    // Default exception config: Stop on all exceptions.
    // Override to HandledByDebugger (DBG_CONTINUE) for the custom exception,
    // which replicates the old hard-coded behavior.
    .set_exception_action(
        0xE0000001,
        ExceptionAction::HandledByDebugger,
        ExceptionAction::Stop,
    )
    .on_process_exited(|session, _pid, exit_code| {
        session.state.exit_code = Some(exit_code);
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    // With DBG_CONTINUE, the exception is swallowed and __except block is skipped.
    // g_caught stays 0, so the process exits with code 1.
    assert_eq!(
        final_state.exit_code,
        Some(1),
        "Expected exit code 1 (exception swallowed by debugger), got {:?}",
        final_state.exit_code
    );
}

/// Confirms the fix: when pass_exception is used (DBG_EXCEPTION_NOT_HANDLED),
/// the SEH handler runs, the catch block executes,
/// and the process exits with code 0.
#[test]
fn test_exception_passed_to_application() {
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
    // Configure exception 0xE0000001 to PassToApplication on first-chance
    .set_exception_action(
        0xE0000001,
        ExceptionAction::PassToApplication,
        ExceptionAction::Stop,
    )
    .on_process_exited(|session, _pid, exit_code| {
        session.state.exit_code = Some(exit_code);
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    // With DBG_EXCEPTION_NOT_HANDLED, the exception is passed to the application.
    // The SEH handler runs, g_caught = 1, and the process exits with code 0.
    assert_eq!(
        final_state.exit_code,
        Some(0),
        "Expected exit code 0 (exception passed to application), got {:?}",
        final_state.exit_code
    );
}
