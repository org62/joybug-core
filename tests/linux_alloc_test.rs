#![cfg(target_os = "linux")]
//! `allocate_memory` by mmap injection: the target gains a readable, writable
//! (and optionally executable) mapping and its thread's registers are intact.
mod common;
use common::{get_test_program_path, TestServer};
use joybug_core::protocol::{DebugEvent, ThreadContext};
use joybug_core::protocol_io::DebugSession;

#[test]
fn allocate_memory_maps_pages_in_the_target() {
    let server = TestServer::start().expect("server");
    let hello = get_test_program_path("hello");
    let state = DebugSession::new(None::<u32>, Some(server.address()))
        .expect("connect")
        .on_event(|session, event| {
            if let DebugEvent::InitialBreakpoint { pid, tid, .. } = event {
                let ThreadContext::Win32RawContext(before) = session.get_thread_context(*pid, *tid)? else { panic!() };
                let rw = session.allocate_memory(*pid, 8192, false)?;
                assert_eq!(rw & 0xfff, 0, "page aligned: {rw:#x}");
                session.write_memory(*pid, rw + 100, vec![1, 2, 3, 4])?;
                assert_eq!(session.read_memory(*pid, rw + 100, 4)?, vec![1, 2, 3, 4]);
                let rx = session.allocate_memory(*pid, 4096, true)?;
                let region = session.query_memory_region(*pid, rx)?;
                assert_eq!(region.protect, 0x40, "PAGE_EXECUTE_READWRITE: {:#x}", region.protect);
                let ThreadContext::Win32RawContext(after) = session.get_thread_context(*pid, *tid)? else { panic!() };
                assert_eq!((before.Rip, before.Rax, before.Rsp, before.Rdi), (after.Rip, after.Rax, after.Rsp, after.Rdi));
                return Ok(true);
            }
            if let DebugEvent::ProcessExited { exit_code, .. } = event {
                session.state = Some(*exit_code);
            }
            Ok(true)
        })
        .launch(hello)
        .expect("launch");
    assert_eq!(state, Some(42), "the target still ran to its normal exit");
}
