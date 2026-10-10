#![cfg(target_os = "linux")]
//! `protect_memory` by mprotect injection: the pages change protection, the
//! rest of the mapping keeps its own, and the thread's registers are intact.
mod common;
use common::{get_test_program_path, TestServer};
use joybug_core::protocol::{DebugEvent, ThreadContext};
use joybug_core::protocol_io::DebugSession;

const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_GUARD: u32 = 0x100;

#[test]
fn protect_memory_changes_pages_in_the_target() {
    let server = TestServer::start().expect("server");
    let hello = get_test_program_path("hello");
    let state = DebugSession::new(None::<u32>, Some(server.address()))
        .expect("connect")
        .on_event(|session, event| {
            if let DebugEvent::InitialBreakpoint { pid, tid, .. } = event {
                let ThreadContext::Win32RawContext(before) = session.get_thread_context(*pid, *tid)? else { panic!() };
                let rw = session.allocate_memory(*pid, 8192, false)?;

                // An unaligned address inside the first page: that page only.
                let old = session.protect_memory(*pid, rw + 0x10, 0x20, PAGE_EXECUTE_READ)?;
                assert_eq!(old, PAGE_READWRITE, "the old protection is reported: {old:#x}");
                let first = session.query_memory_region(*pid, rw)?;
                assert_eq!((first.protect, first.region_size), (PAGE_EXECUTE_READ, 4096));
                assert_eq!(session.query_memory_region(*pid, rw + 4096)?.protect, PAGE_READWRITE, "the second page is untouched");

                assert_eq!(session.protect_memory(*pid, rw, 8192, PAGE_READONLY)?, PAGE_EXECUTE_READ);
                assert_eq!(session.query_memory_region(*pid, rw + 4096)?.protect, PAGE_READONLY);

                assert!(session.protect_memory(*pid, rw, 4096, PAGE_READWRITE | PAGE_GUARD).is_err(), "no guard pages on Linux");
                assert!(session.protect_memory(*pid, 0x1000, 4096, PAGE_READONLY).is_err(), "an unmapped range is ENOMEM");

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
