#![cfg(windows)]

mod common;

use common::TestServer;
use joybug_core::protocol::DebugEvent;
use joybug_core::protocol_io::DebugSession;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// Poll until the process object is destroyed, or fail. `OpenProcess` is the
/// detector, not a process snapshot: an exited-but-still-referenced process is
/// absent from a Toolhelp snapshot yet remains openable for as long as any handle
/// to it (or to one of its threads) is held.
fn assert_released(pid: u32, context: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return; // object gone
        }
        unsafe { CloseHandle(h) };
        assert!(
            std::time::Instant::now() < deadline,
            "pid {} still exists as a process object after {} — the exited target \
             is a zombie (missing final ContinueDebugEvent, or a debugger handle \
             on it was never released)",
            pid,
            context
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// The two halves of the process-exit contract.
///
/// 1. While the client is parked on `ProcessExited`, the target is still fully
///    inspectable — Windows holds the process object (address space included)
///    open until the debugger acknowledges that last event. This is what makes a
///    debugger break on process exit useful rather than cosmetic.
///
/// 2. Once the session unwinds, that acknowledgement must actually be sent and
///    the server's handles dropped. Otherwise the dead target lingers as a
///    zombie process for the lifetime of the connection.
#[test]
fn exited_process_is_inspectable_then_released() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    struct St {
        pid: u32,
        base: u64,
        inspected: bool,
    }

    let st = DebugSession::new(St { pid: 0, base: 0, inspected: false }, Some(addr.as_str()))
        .expect("connect")
        .on_event(|session, event| {
            match event {
                DebugEvent::ProcessCreated { base_of_image, .. } => {
                    session.state.base = *base_of_image;
                }
                DebugEvent::ProcessExited { pid, tid, .. } => {
                    session.state.pid = *pid;

                    // (1) The corpse is still readable: registers off the exiting
                    // thread and the image's mapped bytes.
                    session
                        .get_thread_context(*pid, *tid)
                        .expect("thread context must resolve while parked on ProcessExited");
                    let base = session.state.base;
                    let hdr = session
                        .read_memory(*pid, base, 2)
                        .expect("image memory must be readable while parked on ProcessExited");
                    assert_eq!(&hdr, b"MZ", "expected the PE header at the image base");
                    assert!(
                        !session.list_modules(*pid).expect("list_modules").is_empty(),
                        "module list must survive until the exit event is acknowledged"
                    );
                    session.state.inspected = true;
                }
                _ => {}
            }
            Ok(true)
        })
        .launch("cmd /c \"exit /b 7\"".to_string())
        .expect("launch");

    assert!(st.inspected, "never saw a ProcessExited event");
    let pid = st.pid;

    // (2) The debug loop has unwound, which sends the final ContinueDebugEvent and
    // drops the server's handles on the target. The process object must then be
    // destroyed — note that the server is still running here: a zombie that only
    // goes away when the server exits is exactly the bug this guards.
    assert_released(pid, "the session ended");
}

/// The release must not depend on how the session ends. A handler that stops the
/// loop at `ProcessExited` — what the UI does when the user picks "stop" instead
/// of "go" at a break on process exit — takes a different path out of the event
/// dispatch, and used to skip the acknowledgement entirely.
#[test]
fn exited_process_is_released_when_the_handler_stops_the_session() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    let pid = DebugSession::new(0u32, Some(addr.as_str()))
        .expect("connect")
        .on_event(|session, event| {
            if let DebugEvent::ProcessExited { pid, .. } = event {
                session.state = *pid;
                return Ok(false); // stop the session instead of continuing
            }
            Ok(true)
        })
        .launch("cmd /c \"exit /b 7\"".to_string())
        .expect("launch");

    assert_ne!(pid, 0, "never saw a ProcessExited event");
    assert_released(pid, "the handler stopped the session at the exit event");
}
