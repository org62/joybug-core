#![cfg(target_os = "linux")]

//! Child processes on the Linux backend: a `fork` child and a `vfork` +
//! `exec` child (`posix_spawn`), debugged with `debug_children` and left
//! alone without it.

mod common;

use common::{get_test_program_path, TestServer};
use joybug_core::protocol::DebugEvent;
use joybug_core::protocol_io::{BreakpointDecision, DebugSession};

#[derive(Default)]
struct State {
    /// `(pid, image name)` in creation order; the first is the launched process.
    created: Vec<(u32, String)>,
    initial_breakpoints: Vec<u32>,
    /// `(pid, exit code)` in exit order.
    exited: Vec<(u32, u32)>,
    /// Pids a user breakpoint was hit in.
    breakpoint_pids: Vec<u32>,
    exceptions: usize,
}

impl State {
    fn exit_code_of(&self, pid: u32) -> Option<u32> {
        self.exited.iter().find(|(p, _)| *p == pid).map(|(_, code)| *code)
    }
}

fn session(server: &TestServer) -> DebugSession<State> {
    DebugSession::new(State::default(), Some(server.address())).expect("connect").on_event(|session, event| {
        match event {
            DebugEvent::ProcessCreated { pid, image_file_name, .. } => {
                session.state.created.push((*pid, image_file_name.clone().unwrap_or_default()));
            }
            DebugEvent::ProcessExited { pid, exit_code, .. } => session.state.exited.push((*pid, *exit_code)),
            DebugEvent::Exception { .. } => session.state.exceptions += 1,
            _ => {}
        }
        Ok(true)
    })
}

#[test]
fn a_fork_child_is_debugged_as_its_own_process() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let forker = get_test_program_path("forker");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.state.initial_breakpoints.push(pid);
            let root = session.state.created[0].0;
            if pid != root {
                // The child is the same image: its symbols resolve, and a
                // breakpoint set in it is the child's alone.
                let modules = session.list_modules(pid)?;
                assert!(modules.iter().any(|m| m.name.ends_with("/forker")), "{modules:?}");
                assert!(modules.iter().any(|m| m.name.contains("libc.so")), "the child's libraries are listed: {modules:?}");
                session.set_breakpoint_by_symbol(pid, "forker!child_work", None, |session, pid, tid, _address| {
                    session.state.breakpoint_pids.push(pid);
                    let args = session.get_arguments(pid, tid, 1)?;
                    assert_eq!(args[0], 3, "child_work(3)");
                    Ok(BreakpointDecision::Remove)
                })?;
            }
            Ok(())
        })
        .launch_with_children(forker)
        .expect("launch");

    assert_eq!(state.created.len(), 2, "parent and child: {:?}", state.created);
    let (parent, child) = (state.created[0].0, state.created[1].0);
    assert_ne!(parent, child);
    assert!(state.created[1].1.ends_with("/forker"), "{:?}", state.created);
    assert_eq!(state.initial_breakpoints, vec![parent, child], "one initial breakpoint each, parent first");
    assert_eq!(state.breakpoint_pids, vec![child], "the breakpoint was hit in the child");
    assert_eq!(state.exit_code_of(child), Some(7));
    assert_eq!(state.exit_code_of(parent), Some(41), "the parent saw its child exit 7");
    assert_eq!(state.exited.first().map(|e| e.0), Some(child), "the child exits first: {:?}", state.exited);
    assert_eq!(state.exceptions, 0);
}

#[test]
fn a_fork_child_runs_free_without_debug_children() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let forker = get_test_program_path("forker");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            // Only the child ever calls this. Its copy of the address space
            // has the breakpoint byte; left there, the child would die of a
            // SIGTRAP and the parent would exit 40.
            session.set_breakpoint_by_symbol(pid, "forker!child_work", None, |session, pid, _tid, _address| {
                session.state.breakpoint_pids.push(pid);
                Ok(BreakpointDecision::Keep)
            })?;
            Ok(())
        })
        .launch(forker)
        .expect("launch");

    assert_eq!(state.created.len(), 1, "{:?}", state.created);
    assert!(state.breakpoint_pids.is_empty(), "the child is not ours: {:?}", state.breakpoint_pids);
    assert_eq!(state.exited, vec![(state.created[0].0, 41)], "the child ran child_work unharmed");
}

#[test]
fn a_spawned_child_is_debugged_from_its_exec() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let forker = get_test_program_path("forker");
    let hello = get_test_program_path("hello");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.state.initial_breakpoints.push(pid);
            let root = session.state.created[0].0;
            if pid == root {
                // posix_spawn's child runs this in the parent's own memory
                // (vfork). It must not trip over the parent's breakpoint.
                session.set_breakpoint_by_symbol(pid, "libc!execve", None, |session, pid, _tid, _address| {
                    session.state.breakpoint_pids.push(pid);
                    Ok(BreakpointDecision::Keep)
                })?;
            } else {
                session.set_breakpoint_by_symbol(pid, "hello!compute", None, |session, pid, tid, _address| {
                    session.state.breakpoint_pids.push(pid);
                    let args = session.get_arguments(pid, tid, 1)?;
                    assert_eq!(args[0], 21);
                    Ok(BreakpointDecision::Remove)
                })?;
            }
            Ok(())
        })
        .launch_with_children(format!("{forker} spawn {hello}"))
        .expect("launch");

    assert_eq!(state.created.len(), 2, "{:?}", state.created);
    let (parent, child) = (state.created[0].0, state.created[1].0);
    assert!(state.created[1].1.ends_with("/hello"), "the child is announced as the program it exec'd: {:?}", state.created);
    assert_eq!(state.initial_breakpoints, vec![parent, child]);
    assert_eq!(state.breakpoint_pids, vec![child], "only hello!compute in the child was hit");
    assert_eq!(state.exit_code_of(child), Some(42));
    assert_eq!(state.exit_code_of(parent), Some(51), "the parent saw its child exit 42");
    assert_eq!(state.exceptions, 0);
}

#[test]
fn a_spawned_child_survives_the_parents_breakpoints() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let forker = get_test_program_path("forker");
    let hello = get_test_program_path("hello");
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "libc!execve", None, |session, pid, _tid, _address| {
                session.state.breakpoint_pids.push(pid);
                Ok(BreakpointDecision::Keep)
            })?;
            Ok(())
        })
        .launch(format!("{forker} spawn {hello}"))
        .expect("launch");

    assert_eq!(state.created.len(), 1, "{:?}", state.created);
    assert!(state.breakpoint_pids.is_empty(), "{:?}", state.breakpoint_pids);
    assert_eq!(state.exited, vec![(state.created[0].0, 51)], "the undebugged child exec'd and exited 42");
}
