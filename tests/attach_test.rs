#![cfg(windows)]

use joybug2::protocol::{DebugEvent, ModuleInfo};
use joybug2::protocol_io::DebugSession;
use std::thread;
use tokio;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::Foundation::CloseHandle;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::time::Duration;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[test]
fn test_attach_and_list_modules() {
    joybug2::init_tracing();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });

    // Create a suspended process
    let cmd = to_wide("cmd /c \"echo Tick 1 & echo Tick 2 & ping localhost -n 2 >nul\"");
    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let success = unsafe {
        CreateProcessW(
            ptr::null(),
            cmd.as_ptr() as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
            false.into(),
            0,
            ptr::null_mut(),
            ptr::null(),
            &mut startup_info,
            &mut process_info,
        )
    };
    assert_ne!(success, 0, "CreateProcessW failed");

    struct TestState {
        modules: Vec<ModuleInfo>,
        events: Vec<DebugEvent>,
        pid: u32,
    }

    let mut session = DebugSession::new(
        TestState {
            modules: Vec::new(),
            events: Vec::new(),
            pid: 0,
        },
        None,
    )
    .expect("connect");

    let processes = session.list_processes().expect("list_processes");
    let target_process = processes
        .iter()
        .find(|p| p.pid == process_info.dwProcessId);

    assert!(target_process.is_some(), "Could not find target process");
    assert_eq!(target_process.unwrap().name, "cmd.exe");

    // wait for 500 milliseconds before attaching
    thread::sleep(Duration::from_millis(500));

    let final_state = DebugSession::new(
        TestState {
            modules: Vec::new(),
            events: Vec::new(),
            pid: 0,
        },
        None,
    )
    .expect("connect")
    .on_process_created(|sess, pid, _tid, _name, _base| {
        sess.state.pid = pid;
        Ok(())
    })
    .on_dll_loaded(|_sess, _pid, _tid, _name, _base| Ok(()))
    .on_event(|sess, event| {
        sess.state.events.push(event.clone());
        Ok(true)
    })
    .attach(process_info.dwProcessId)
    .expect("debug loop");

    let mut final_session = DebugSession::new(final_state, None).expect("reconnect");
    let modules = final_session
        .list_modules(final_session.state.pid)
        .expect("Should get module list");
    final_session.state.modules.extend(modules);
    println!("modules: {:?}", final_session.state.modules);

    unsafe {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }

    let process_created = final_session
        .state
        .events
        .iter()
        .filter(|e| matches!(e, DebugEvent::ProcessCreated { .. }))
        .count();
    let process_exited = final_session
        .state
        .events
        .iter()
        .filter(|e| matches!(e, DebugEvent::ProcessExited { .. }))
        .count();
    assert_eq!(
        process_created,
        1,
        "Should be exactly one process created event"
    );
    assert_eq!(
        process_exited,
        1,
        "Should be exactly one process exited event"
    );
    assert!(final_session
        .state
        .modules
        .iter()
        .any(|m| m.name.ends_with("cmd.exe")));
} 