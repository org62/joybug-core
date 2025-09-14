use super::WindowsPlatform;
use super::utils;
use super::debug_events;
use crate::interfaces::{PlatformError, Architecture};
use crate::protocol::{ProcessInfo};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use tracing::{trace, error};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, FALSE, DBG_CONTINUE, INVALID_HANDLE_VALUE
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, WaitForDebugEvent,
    CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT,
    DebugActiveProcess,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, IsWow64Process2,
    DEBUG_PROCESS, INFINITE, PROCESS_INFORMATION, STARTUPINFOW, OpenProcess, TerminateProcess, PROCESS_TERMINATE,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_UNKNOWN
};

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Determine the architecture of a process by checking if it's running under WoW64
fn determine_process_architecture(process_handle: windows_sys::Win32::Foundation::HANDLE) -> Result<Architecture, PlatformError> {
    let mut process_machine: u16 = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine: u16 = IMAGE_FILE_MACHINE_UNKNOWN;

    let result = unsafe { IsWow64Process2(process_handle, &mut process_machine, &mut native_machine) };

    if result == FALSE {
        let error = unsafe { GetLastError() };
        error!("IsWow64Process2 failed with error code: {}, falling back to GetNativeSystemInfo", error);
        return Err(PlatformError::OsError(format!("IsWow64Process2 failed: {} ({})", error, utils::error_message(error))));
    }

    match native_machine {
        IMAGE_FILE_MACHINE_AMD64 => {
            if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
                // Not a WOW64 process, so it's a native 64-bit process
                Ok(Architecture::X64)
            } else {
                // This is a 32-bit process on a 64-bit system. For our purposes, we'll treat it as X64
                // as the debugging APIs will behave as if it's a 64-bit process.
                Ok(Architecture::X64)
            }
        }
        IMAGE_FILE_MACHINE_ARM64 => {
             if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
                // Not a WOW64 process, so it's a native 64-bit process
                Ok(Architecture::Arm64)
            } else {
                // This is a 32-bit process on a 64-bit system.
                Ok(Architecture::Arm64)
            }
        }
        _ => {
            error!("Unknown native machine type: {}, defaulting to X64", native_machine);
            Err(PlatformError::OsError(format!("Unknown native machine type: {}", native_machine)))
        }
    }
}

pub(super) fn launch(platform: &mut WindowsPlatform, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
    println!("[windows_platform] launch thread id: {:?}", std::thread::current().id());
    trace!(command, "WindowsPlatform::launch called");
    let cmd_line_wide = to_wide(command);
    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let success = unsafe {
        CreateProcessW(
            ptr::null(),
            cmd_line_wide.as_ptr() as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
            FALSE,
            DEBUG_PROCESS,
            ptr::null_mut(),
            ptr::null(),
            &mut startup_info,
            &mut process_info,
        )
    };
    if success == FALSE {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "CreateProcessW failed");
        return Err(PlatformError::OsError(format!("CreateProcessW failed: {} ({})", error, error_str)));
    }
    
    let pid = process_info.dwProcessId;
    let process_handle = process_info.hProcess;
    
    // Determine the architecture of the process
    let architecture = determine_process_architecture(process_handle)?;
    
    // Add the new process to the platform
    platform.add_process(pid, process_handle, architecture)?;
    
    // Immediately run the debug loop for the new process
    let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
    let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
    if wait_res == FALSE {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "WaitForDebugEvent failed after launch");
        return Err(PlatformError::OsError(format!("WaitForDebugEvent failed after launch: {} ({})", error, error_str)));
    }
    if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
        let fallback_name = command.split_whitespace().next().unwrap_or("");
        debug_events::handle_create_process_event(platform, &debug_event, Some(fallback_name)).map(Some)
    } else {
        error!("Unexpected debug event after launch");
        return Err(PlatformError::OsError("Unexpected debug event after launch".to_string()));
    }
}

pub(super) fn attach(platform: &mut WindowsPlatform, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
    trace!(pid, "WindowsPlatform::attach called");

    if unsafe { DebugActiveProcess(pid) } == 0 {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "DebugActiveProcess failed");
        return Err(PlatformError::OsError(format!("DebugActiveProcess failed: {} ({})", error, error_str)));
    }

    // After attaching, we must wait for the initial CREATE_PROCESS_DEBUG_EVENT
    let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
    let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
    if wait_res == FALSE {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "WaitForDebugEvent after attach failed");
        return Err(PlatformError::OsError(format!("WaitForDebugEvent after attach failed: {} ({})", error, error_str)));
    }

    if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
        // Extract the process handle from the debug event to add to our platform
        let process_handle = unsafe { debug_event.u.CreateProcessInfo.hProcess };
        
        // Determine the architecture of the process
        let architecture = determine_process_architecture(process_handle)?;
        
        platform.add_process(pid, process_handle, architecture)?;
        
        debug_events::handle_create_process_event(platform, &debug_event, None).map(Some)
    } else {
        error!(event_code = debug_event.dwDebugEventCode, "Unexpected debug event after attach");
        // We should probably continue the event we received...
        unsafe { ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE); }
        Err(PlatformError::Other("Unexpected debug event after attach".to_string()))
    }
}

pub(super) fn list_processes() -> Result<Vec<ProcessInfo>, PlatformError> {
    trace!("WindowsPlatform::list_processes called");
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            error!(error, error_str, "CreateToolhelp32Snapshot failed");
            return Err(PlatformError::OsError(format!("CreateToolhelp32Snapshot failed: {} ({})", error, error_str)));
        }

        let mut pe32: PROCESSENTRY32W = std::mem::zeroed();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut pe32) == 0 {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            CloseHandle(snapshot);
            error!(error, error_str, "Process32FirstW failed");
            return Err(PlatformError::OsError(format!("Process32FirstW failed: {} ({})", error, error_str)));
        }
        
        let mut processes = Vec::new();

        loop {
            let name = String::from_utf16_lossy(&pe32.szExeFile);
            let name = name.trim_end_matches('\0').to_string();

            processes.push(ProcessInfo {
                pid: pe32.th32ProcessID,
                name,
            });

            if Process32NextW(snapshot, &mut pe32) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        Ok(processes)
    }
}

pub fn terminate_process_unlocked(pid: u32) -> Result<(), PlatformError> {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            let e = GetLastError();
            let err = utils::error_message(e);
            error!(pid, code = e, err, "OpenProcess(PROCESS_TERMINATE) failed");
            return Err(PlatformError::OsError(format!("OpenProcess(PROCESS_TERMINATE) failed: {} ({})", e, err)));
        }
        let rc = TerminateProcess(h, 1);
        CloseHandle(h);
        if rc == 0 {
            let e = GetLastError();
            let err = utils::error_message(e);
            error!(pid, code = e, err, "TerminateProcess failed");
            return Err(PlatformError::OsError(format!("TerminateProcess failed: {} ({})", e, err)));
        }
        trace!(pid, "TerminateProcess succeeded (unlocked)");
        Ok(())
    }
}