#![cfg(windows)]

use joybug_basics_tests1::protocol::{DebuggerResponse, DebugEvent, ModuleInfo};
use joybug_basics_tests1::protocol_io::DebugClient;
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
    joybug_basics_tests1::init_tracing();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug_basics_tests1::server::run_server()).unwrap();
    });

    // Create a suspended process
    let cmd = to_wide("cmd /c \"(for /l %i in (1,1,2) do @echo Tick %i & timeout /t 1 >nul)\"");
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

    let mut client = DebugClient::connect(None).expect("connect");

    let processes = client.list_processes().expect("list_processes");
    let target_process = processes
        .iter()
        .find(|p| p.pid == process_info.dwProcessId);

    assert!(target_process.is_some(), "Could not find target process");
    assert_eq!(target_process.unwrap().name, "cmd.exe");

    struct TestState {
        modules: Vec<ModuleInfo>,
        events: Vec<DebugEvent>,
    }
    let mut state = TestState { modules: Vec::new(), events: Vec::new() };

    // wait for 500 milliseconds before attaching
    thread::sleep(Duration::from_millis(500));

    client.attach(process_info.dwProcessId, &mut state, |client, state, resp| {
        match resp {
            DebuggerResponse::Event { event } => {
                state.events.push(event.clone());
                if let DebugEvent::ProcessExited { pid, .. } = &event {
                    let modules = client.list_modules(*pid).expect("Should get module list");
                    state.modules.extend(modules);
                    println!("modules: {:?}", state.modules);
                    return false;
                }
            }
            _ => {}
        }
        true
    }).expect("debug loop");

    unsafe {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }
    
    let process_created = state.events.iter().filter(|e| matches!(e, DebugEvent::ProcessCreated { .. })).count();
    let process_exited = state.events.iter().filter(|e| matches!(e, DebugEvent::ProcessExited { .. })).count();
    assert_eq!(process_created, 1, "Should be exactly one process created event");
    assert_eq!(process_exited, 1, "Should be exactly one process exited event");
    assert!(state.modules.iter().any(|m| m.name.ends_with("cmd.exe")));
} 