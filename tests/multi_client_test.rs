#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::protocol::DebugEvent;
use joybug2::protocol_io::DebugSession;
use std::thread;

#[test]
fn test_multi_client_sessions() {
    joybug2::init_tracing();
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let client1_addr = server_addr.clone();
    let client1_thread = thread::spawn(move || {
        struct TestState {
            events: Vec<DebugEvent>,
        }
        DebugSession::new(
            TestState {
                events: Vec::new(),
            },
            Some(client1_addr.as_str()),
        )
        .expect("connect client 1")
        .on_event(|sess, event| {
            sess.state.events.push(event.clone());
            Ok(true)
        })
        .launch("cmd.exe /c echo client1".to_string())
        .expect("debug loop for client 1")
    });

    let client2_addr = server_addr.clone();
    let client2_thread = thread::spawn(move || {
        struct TestState {
            events: Vec<DebugEvent>,
        }
        DebugSession::new(
            TestState {
                events: Vec::new(),
            },
            Some(client2_addr.as_str()),
        )
        .expect("connect client 2")
        .on_event(|sess, event| {
            sess.state.events.push(event.clone());
            Ok(true)
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