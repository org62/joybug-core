#![cfg(target_os = "linux")]
//! A debuggee that replaces its image (`sh -c prog`): the old modules are
//! unloaded, the new program's modules are reported, its entry point is a
//! plain breakpoint (the one InitialBreakpoint was the shell's), and
//! breakpoints by symbol in the new image work.
mod common;
use common::{get_test_program_path, TestServer};
use joybug_core::protocol::DebugEvent;
use joybug_core::protocol_io::DebugSession;

#[derive(Default)]
struct Events {
    names: Vec<String>,
    unloaded: usize,
    loaded_after_unload: Vec<String>,
    breakpoint_after_unload: Option<u64>,
    exit_code: Option<u32>,
}

#[test]
fn exec_replaces_the_image_and_debugging_continues() {
    let server = TestServer::start().expect("server");
    let hello = get_test_program_path("hello");
    // `exec` so the shell replaces itself (dash forks for a plain command).
    let command = format!("/bin/sh -c \"exec {hello}\"");
    let state = DebugSession::new(Events::default(), Some(server.address()))
        .expect("connect")
        .on_event(|session, event| {
            let st = &mut session.state;
            let name = match event {
                DebugEvent::ProcessCreated { .. } => "ProcessCreated",
                DebugEvent::InitialBreakpoint { .. } => "InitialBreakpoint",
                DebugEvent::DllUnloaded { .. } => {
                    st.unloaded += 1;
                    "DllUnloaded"
                }
                DebugEvent::DllLoaded { dll_name, .. } => {
                    if st.unloaded > 0 {
                        st.loaded_after_unload.push(dll_name.clone().unwrap_or_default());
                    }
                    "DllLoaded"
                }
                DebugEvent::Breakpoint { address, .. } => {
                    if st.unloaded > 0 && st.breakpoint_after_unload.is_none() {
                        st.breakpoint_after_unload = Some(*address);
                    }
                    "Breakpoint"
                }
                DebugEvent::ProcessExited { exit_code, .. } => {
                    st.exit_code = Some(*exit_code);
                    "ProcessExited"
                }
                _ => "Other",
            };
            st.names.push(name.to_string());
            Ok(true)
        })
        .launch(command)
        .expect("launch");

    assert_eq!(state.names.iter().filter(|n| *n == "InitialBreakpoint").count(), 1, "{:?}", state.names);
    assert!(state.unloaded >= 2, "the shell's modules were unloaded: {:?}", state.names);
    assert!(
        state.loaded_after_unload.iter().any(|n| n.ends_with("/hello")),
        "the new image is a module: {:?}",
        state.loaded_after_unload
    );
    assert!(state.loaded_after_unload.iter().any(|n| n.contains("libc")), "libc reported after exec: {:?}", state.loaded_after_unload);
    assert!(state.breakpoint_after_unload.is_some(), "the new entry point is a breakpoint: {:?}", state.names);
    assert_eq!(state.exit_code, Some(42), "hello's exit code, not the shell's");
}
