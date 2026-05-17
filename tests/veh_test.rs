#![cfg(windows)]

mod common;

use common::get_test_program_path;
use joybug2::local_server::LocalServer;
use joybug2::protocol_io::DebugSession;
use joybug2::veh_platform::VEHPlatform;

fn veh_server() -> LocalServer {
    LocalServer::spawn_with(VEHPlatform::new())
}

#[test]
fn test_veh_launch_initial_breakpoint() {
    joybug2::init_tracing();

    let server = veh_server();
    let addr = server.address().to_string();
    let exe = get_test_program_path("veh_test");

    struct State {
        got_initial_bp: bool,
        pid: u32,
    }

    let state = DebugSession::new(
        State { got_initial_bp: false, pid: 0 },
        Some(addr.as_str()),
    )
    .expect("connect")
    .on_initial_breakpoint(|sess, pid, _tid, address| {
        println!("Initial breakpoint at 0x{:X} for pid {}", address, pid);
        sess.state.got_initial_bp = true;
        sess.state.pid = pid;
        Ok(())
    })
    .on_process_exited(|_sess, pid, exit_code| {
        println!("Process {} exited with code {}", pid, exit_code);
        Ok(())
    })
    .launch(exe)
    .expect("debug session");

    assert!(state.got_initial_bp, "Should have received initial breakpoint");
}

#[test]
fn test_veh_launch_run_to_exit() {
    joybug2::init_tracing();

    let server = veh_server();
    let addr = server.address().to_string();
    let exe = get_test_program_path("veh_test");

    struct State {
        exit_code: Option<u32>,
    }

    let state = DebugSession::new(
        State { exit_code: None },
        Some(addr.as_str()),
    )
    .expect("connect")
    .on_initial_breakpoint(|_sess, pid, _tid, address| {
        println!("Initial breakpoint at 0x{:X} for pid {}", address, pid);
        Ok(())
    })
    .on_process_exited(|sess, pid, exit_code| {
        println!("Process {} exited with code {}", pid, exit_code);
        sess.state.exit_code = Some(exit_code);
        Ok(())
    })
    .launch(exe)
    .expect("debug session");

    assert_eq!(state.exit_code, Some(0), "Process should exit cleanly");
}
