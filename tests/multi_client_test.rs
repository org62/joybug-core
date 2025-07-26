#![cfg(windows)]

use joybug2::protocol::DebugEvent;
use joybug2::protocol_io::DebugSession;
use std::thread;
use tokio;

#[test]
fn test_multi_client_sessions() {
    joybug2::init_tracing();
    // Spawn the server in a background thread.
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });

    let client1_thread = thread::spawn(|| {
        struct TestState {
            events: Vec<DebugEvent>,
        }
        DebugSession::new(
            TestState {
                events: Vec::new(),
            },
            None,
        )
        .expect("connect client 1")
        .on_event(|sess, event| {
            sess.state.events.push(event.clone());
            Ok(())
        })
        .launch("cmd.exe /c echo client1".to_string())
        .expect("debug loop for client 1")
    });

    let client2_thread = thread::spawn(|| {
        struct TestState {
            events: Vec<DebugEvent>,
        }
        DebugSession::new(
            TestState {
                events: Vec::new(),
            },
            None,
        )
        .expect("connect client 2")
        .on_event(|sess, event| {
            sess.state.events.push(event.clone());
            Ok(())
        })
        .launch("cmd.exe /c echo client2".to_string())
        .expect("debug loop for client 2")
    });

    let state1 = client1_thread.join().unwrap();
    let state2 = client2_thread.join().unwrap();

    let process_created1 = state1
        .events
        .iter()
        .filter(|e| matches!(e, DebugEvent::ProcessCreated { .. }))
        .count();
    let process_exited1 = state1
        .events
        .iter()
        .filter(|e| matches!(e, DebugEvent::ProcessExited { .. }))
        .count();
    assert_eq!(
        process_created1, 1,
        "Client 1: Should be exactly one process created event"
    );
    assert_eq!(
        process_exited1, 1,
        "Client 1: Should be exactly one process exited event"
    );

    let process_created2 = state2
        .events
        .iter()
        .filter(|e| matches!(e, DebugEvent::ProcessCreated { .. }))
        .count();
    let process_exited2 = state2
        .events
        .iter()
        .filter(|e| matches!(e, DebugEvent::ProcessExited { .. }))
        .count();
    assert_eq!(
        process_created2, 1,
        "Client 2: Should be exactly one process created event"
    );
    assert_eq!(
        process_exited2, 1,
        "Client 2: Should be exactly one process exited event"
    );
} 