#![cfg(target_os = "linux")]

//! Signal policy on the Linux backend: which signals stop the debugger
//! (`SetReportedSignals`), what a continue does with one (deliver or drop),
//! and the second-chance stop before a signal nobody handles kills the target.

mod common;

use common::{get_test_program_path, TestServer};
use joybug_core::posix_signals::signal_exception_code;
use joybug_core::protocol::DebugEvent;
use joybug_core::protocol_io::{DebugSession, ExceptionAction};

const SIGUSR1: u32 = 10;
const SIGUSR2: u32 = 12;

#[derive(Default)]
struct State {
    /// `(code, first_chance, parameters)` of every exception, in order.
    exceptions: Vec<(u32, bool, Vec<u64>)>,
    exit_code: Option<u32>,
}

fn session(server: &TestServer, action: ExceptionAction) -> DebugSession<State> {
    DebugSession::new(State::default(), Some(server.address()))
        .expect("connect")
        .on_event(|session, event| {
            if let DebugEvent::ProcessExited { exit_code, .. } = event {
                session.state.exit_code = Some(*exit_code);
            }
            Ok(true)
        })
        .on_exception(move |session, _pid, _tid, code, _address, first_chance, parameters| {
            session.state.exceptions.push((code, first_chance, parameters.to_vec()));
            Ok(action)
        })
}

#[test]
fn an_unreported_signal_reaches_the_program_unseen() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let state = session(&server, ExceptionAction::HandledByDebugger).launch(get_test_program_path("signals")).expect("launch");
    assert!(state.exceptions.is_empty(), "{:?}", state.exceptions);
    assert_eq!(state.exit_code, Some(10), "the handler ran");
}

#[test]
fn a_reported_signal_stops_and_is_dropped_when_handled() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let mut session = session(&server, ExceptionAction::HandledByDebugger);
    session.set_reported_signals(&[SIGUSR1]).expect("set policy");
    let state = session.launch(get_test_program_path("signals")).expect("launch");

    assert_eq!(state.exceptions.len(), 1, "{:?}", state.exceptions);
    let (code, first_chance, parameters) = &state.exceptions[0];
    assert_eq!(*code, signal_exception_code(SIGUSR1));
    assert!(*first_chance);
    assert_eq!(parameters.first().copied(), Some(SIGUSR1 as u64), "the signal number rides along: {parameters:?}");
    assert_ne!(parameters.get(2).copied(), Some(0), "raise() names the sender: {parameters:?}");
    assert_eq!(state.exit_code, Some(11), "the signal never arrived");
}

#[test]
fn a_reported_signal_is_delivered_when_passed() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let mut session = session(&server, ExceptionAction::PassToApplication);
    session.set_reported_signals(&[SIGUSR1]).expect("set policy");
    let state = session.launch(get_test_program_path("signals")).expect("launch");

    // The program handles SIGUSR1: nothing is "unhandled", so no second chance.
    assert_eq!(state.exceptions.len(), 1, "{:?}", state.exceptions);
    assert_eq!(state.exit_code, Some(10), "the handler ran");
}

#[test]
fn passing_an_unhandled_signal_gives_a_second_chance_first() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let mut session = session(&server, ExceptionAction::PassToApplication);
    session.set_reported_signals(&[SIGUSR2]).expect("set policy");
    let state = session.launch(format!("{} unhandled", get_test_program_path("signals"))).expect("launch");

    let chances: Vec<(u32, bool)> = state.exceptions.iter().map(|(code, first, _)| (*code, *first)).collect();
    let code = signal_exception_code(SIGUSR2);
    assert_eq!(chances, vec![(code, true), (code, false)], "first chance, then second chance");
    assert_eq!(state.exit_code, Some(128 + SIGUSR2), "killed by the signal once the second chance was passed too");
}

#[test]
fn a_fault_gets_a_second_chance_with_the_same_record() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let state = session(&server, ExceptionAction::PassToApplication).launch(get_test_program_path("segv")).expect("launch");

    assert_eq!(state.exceptions.len(), 2, "{:?}", state.exceptions);
    assert_eq!((state.exceptions[0].0, state.exceptions[0].1), (0xC000_0005, true));
    assert_eq!((state.exceptions[1].0, state.exceptions[1].1), (0xC000_0005, false));
    assert_eq!(state.exceptions[0].2, vec![1, 0], "a write to address 0");
    assert_eq!(state.exceptions[1].2, state.exceptions[0].2, "the second chance repeats the record");
    assert_eq!(state.exit_code, Some(128 + 11));
}

#[test]
fn clearing_the_policy_stops_reporting() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let mut session = session(&server, ExceptionAction::HandledByDebugger);
    session.set_reported_signals(&[SIGUSR1]).expect("set policy");
    session.set_reported_signals(&[]).expect("clear policy");
    let state = session.launch(get_test_program_path("signals")).expect("launch");
    assert!(state.exceptions.is_empty(), "{:?}", state.exceptions);
    assert_eq!(state.exit_code, Some(10));
}
