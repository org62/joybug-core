use super::WindowsPlatform;
use super::utils;
use super::debug_events;
use crate::interfaces::{PlatformError, Architecture};
use crate::protocol::{ProcessInfo};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use tracing::{trace, error, debug};
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
    CreateProcessW,
    DEBUG_PROCESS, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::System::SystemInformation::{
    GetNativeSystemInfo, SYSTEM_INFO,
};

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Determine the architecture of a process by checking if it's running under WoW64
fn determine_process_architecture(process_handle: windows_sys::Win32::Foundation::HANDLE) -> Architecture {
    use windows_sys::Win32::System::Threading::IsWow64Process;
    
    let mut is_wow64 = FALSE;
    let result = unsafe { IsWow64Process(process_handle, &mut is_wow64) };
    
    if result == FALSE {
        debug!("Failed to determine if process is WoW64, defaulting to X64");
        return Architecture::X64;
    }
    
    // Get the system architecture
    let mut system_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetNativeSystemInfo(&mut system_info) };
    
    let processor_architecture = unsafe { system_info.Anonymous.Anonymous.wProcessorArchitecture };
    
    match processor_architecture {
        9 => { // PROCESSOR_ARCHITECTURE_AMD64
            if is_wow64 != FALSE {
                // 32-bit process on 64-bit system - we'll consider this as X64 for debugging purposes
                Architecture::X64
            } else {
                // 64-bit process on 64-bit system
                Architecture::X64
            }
        }
        12 => { // PROCESSOR_ARCHITECTURE_ARM64
            if is_wow64 != FALSE {
                // 32-bit process on ARM64 system
                Architecture::Arm64
            } else {
                // 64-bit process on ARM64 system
                Architecture::Arm64
            }
        }
        _ => {
            debug!("Unknown processor architecture: {}, defaulting to X64", processor_architecture);
            Architecture::X64
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
    let architecture = determine_process_architecture(process_handle);
    
    // Add the new process to the platform
    platform.add_process(pid, process_handle, architecture);
    
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
        let architecture = determine_process_architecture(process_handle);
        
        platform.add_process(pid, process_handle, architecture);
        
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