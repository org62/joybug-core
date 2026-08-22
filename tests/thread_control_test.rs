#![cfg(windows)]

mod common;

use common::TestServer;
use joybug_core::protocol_io::DebugSession;

struct TestState {
    suspended_seen: bool,
    resumed_seen: bool,
    /// Thread we issued TerminateThread for.
    killed_tid: Option<u32>,
    killed_exit_code: Option<u32>,
    process_exited: bool,
}

/// SuspendThread / ResumeThread nest and are reflected in `list_threads`'
/// live `suspend_count` (the debugger's own freeze at the event is not
/// counted); TerminateThread surfaces as a ThreadExited with our exit code.
#[test]
fn test_thread_suspend_resume_terminate() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let state = TestState { suspended_seen: false, resumed_seen: false, killed_tid: None, killed_exit_code: None, process_exited: false };

    let final_state = DebugSession::new(state, Some(server_addr.as_str()))
        .expect("connect")
        .on_initial_breakpoint(|session, pid, tid, _address| {
            let count_of = |session: &mut DebugSession<TestState>, tid: u32| -> u32 {
                session
                    .list_threads(pid)
                    .unwrap()
                    .into_iter()
                    .find(|t| t.tid == tid)
                    .map(|t| t.suspend_count)
                    .expect("event thread listed")
            };
            assert_eq!(count_of(session, tid), 0, "fresh thread is not suspended (debug freeze is not counted)");

            session.suspend_thread(pid, tid).unwrap();
            session.suspend_thread(pid, tid).unwrap();
            assert_eq!(count_of(session, tid), 2, "suspend count nests");
            session.state.suspended_seen = true;

            session.resume_thread(pid, tid).unwrap();
            assert_eq!(count_of(session, tid), 1);
            session.resume_thread(pid, tid).unwrap();
            assert_eq!(count_of(session, tid), 0, "fully resumed");
            session.state.resumed_seen = true;

            session.terminate_thread(pid, tid, 7).unwrap();
            session.state.killed_tid = Some(tid);
            Ok(())
        })
        .on_thread_exited(|session, pid, tid, exit_code| {
            if session.state.killed_tid == Some(tid) {
                session.state.killed_exit_code = Some(exit_code);
                // Killing the initial thread at the loader breakpoint leaves the
                // loader's worker thread parked forever, so end the process
                // ourselves once the kill has been observed.
                session.terminate_process(pid).unwrap();
            }
            Ok(())
        })
        .on_process_exited(|session, _pid, _exit_code| {
            session.state.process_exited = true;
            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("debug loop");

    assert!(final_state.suspended_seen);
    assert!(final_state.resumed_seen);
    assert_eq!(final_state.killed_exit_code, Some(7), "killed thread exited with our code");
    assert!(final_state.process_exited);
}
