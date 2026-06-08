#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::protocol_io::DebugSession;

struct TestState {
    parent_pid: Option<u32>,
    child_pid: Option<u32>,
    initial_breakpoints: Vec<u32>, // PIDs that hit initial breakpoint
    exited_pids: Vec<u32>,
}

impl TestState {
    fn new() -> Self {
        Self {
            parent_pid: None,
            child_pid: None,
            initial_breakpoints: Vec::new(),
            exited_pids: Vec::new(),
        }
    }
}

#[test]
fn test_parent_child_debugging() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe = common::get_test_program_path("parent_child_test");
    println!("Test exe: {}", test_exe);

    let final_state = DebugSession::new(TestState::new(), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_process_created(|session, pid, _tid, name, _base| {
            println!("ProcessCreated: pid={} name={}", pid, name);
            if session.state.parent_pid.is_none() {
                session.state.parent_pid = Some(pid);
                println!("  -> parent pid set to {}", pid);
            } else if session.state.child_pid.is_none() {
                session.state.child_pid = Some(pid);
                println!("  -> child pid set to {}", pid);
            }
            Ok(())
        })
        .on_initial_breakpoint(|session, pid, _tid, address| {
            println!("InitialBreakpoint: pid={} address=0x{:x}", pid, address);
            session.state.initial_breakpoints.push(pid);
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("ProcessExited: pid={} exit_code={}", pid, exit_code);
            session.state.exited_pids.push(pid);
            Ok(())
        })
        .launch_with_children(test_exe)
        .expect("Debug session failed");

    // Verify parent and child were both created
    let parent_pid = final_state.parent_pid.expect("Parent PID should be set");
    let child_pid = final_state.child_pid.expect("Child PID should be set");
    assert_ne!(parent_pid, child_pid, "Parent and child should have different PIDs");

    // Both should have hit initial breakpoints
    assert!(
        final_state.initial_breakpoints.contains(&parent_pid),
        "Parent should have hit initial breakpoint"
    );
    assert!(
        final_state.initial_breakpoints.contains(&child_pid),
        "Child should have hit initial breakpoint"
    );

    // Both should have exited — child first, then parent
    assert!(
        final_state.exited_pids.contains(&child_pid),
        "Child should have exited"
    );
    assert!(
        final_state.exited_pids.contains(&parent_pid),
        "Parent should have exited"
    );

    // Child should exit before parent
    let child_exit_idx = final_state.exited_pids.iter().position(|&p| p == child_pid).unwrap();
    let parent_exit_idx = final_state.exited_pids.iter().position(|&p| p == parent_pid).unwrap();
    assert!(
        child_exit_idx < parent_exit_idx,
        "Child should exit before parent (child_idx={}, parent_idx={})",
        child_exit_idx,
        parent_exit_idx
    );

    println!("=== Multi-process test passed! ===");
    println!("  Parent PID: {}", parent_pid);
    println!("  Child PID: {}", child_pid);
    println!("  Initial breakpoints: {:?}", final_state.initial_breakpoints);
    println!("  Exit order: {:?}", final_state.exited_pids);
}
