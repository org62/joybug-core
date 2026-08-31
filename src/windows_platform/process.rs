use super::WindowsPlatform;
use super::utils;
use super::debug_events;
use crate::env_block::EnvironmentBlock;
use crate::interfaces::{PlatformError, Architecture};
use crate::protocol::{ProcessInfo};
use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use tracing::{trace, error, warn};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, FALSE, DBG_CONTINUE, INVALID_HANDLE_VALUE
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, WaitForDebugEvent, SymLoadModule64,
    CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT,
    DebugActiveProcess, DebugActiveProcessStop,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, IsWow64Process2, OpenThread,
    CREATE_NEW_CONSOLE,
    DEBUG_PROCESS, DEBUG_ONLY_THIS_PROCESS, INFINITE, PROCESS_INFORMATION, STARTUPINFOW, OpenProcess, TerminateProcess,
    PROCESS_TERMINATE, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_DUP_HANDLE,
    THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_UNKNOWN
};
use windows_sys::Win32::System::Diagnostics::Debug::DebugBreakProcess;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Determine the architecture of a process by checking if it's running under WoW64
pub(super) fn determine_process_architecture(process_handle: windows_sys::Win32::Foundation::HANDLE) -> Result<Architecture, PlatformError> {
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

pub(super) fn launch(platform: &mut WindowsPlatform, command: &str, debug_children: bool, working_directory: Option<&str>, environment: Option<&[(String, String)]>) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
    println!("[windows_platform] launch thread id: {:?}", std::thread::current().id());
    trace!(command, working_directory, ?environment, "WindowsPlatform::launch called");
    let cmd_line_wide = to_wide(command);
    // Wide buffer must outlive the CreateProcessW call; null pointer => inherit debugger CWD.
    let working_dir_wide = working_directory.map(to_wide);
    let working_dir_ptr = working_dir_wide
        .as_ref()
        .map_or(ptr::null(), |w| w.as_ptr());
    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // Must outlive the CreateProcessW call; carries its own creation flag.
    let env_block = EnvironmentBlock::new(environment);
    // CREATE_NEW_CONSOLE gives a console debuggee its own visible console window
    // instead of inheriting the debugger's (which, for the sandbox server, is
    // redirected to a log file and thus invisible). Harmless for GUI-subsystem
    // targets — they simply don't display the unused console.
    let debug_flags = (if debug_children { DEBUG_PROCESS } else { DEBUG_ONLY_THIS_PROCESS })
        | CREATE_NEW_CONSOLE
        | env_block.create_flags();
    let success = unsafe {
        CreateProcessW(
            ptr::null(),
            cmd_line_wide.as_ptr() as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
            FALSE,
            debug_flags,
            env_block.as_ptr(),
            working_dir_ptr,
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

    // We never use the initial thread handle from CreateProcessW — the debug loop
    // gets its own (duplicated) one from CREATE_PROCESS_DEBUG_EVENT. Closing it now
    // matters: a live thread handle keeps the *process* object alive, so holding it
    // would leave every launched target behind as a zombie for the server's
    // lifetime, no matter how cleanly the debug session shuts down.
    unsafe { CloseHandle(process_info.hThread) };

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

pub(super) fn detach(platform: &mut WindowsPlatform, pid: u32) -> Result<(), PlatformError> {
    trace!(pid, "WindowsPlatform::detach called");

    // Undo debugger-injected side effects first: restore original bytes for
    // software breakpoints (so the target does not execute leftover int3/brk
    // instructions once we're gone) and lift any step-over thread suspensions
    // (DebugActiveProcessStop does not undo explicit SuspendThread calls).
    let proc = platform.get_process_mut(pid)?;
    proc.restore_all_software_breakpoints();
    proc.resume_all_step_over_suspensions();

    // DebugActiveProcessStop cleanly ends the debug relationship: it flushes any
    // pending debug event, resumes the target, and lets it keep running without
    // a debugger attached.
    if unsafe { DebugActiveProcessStop(pid) } == 0 {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "DebugActiveProcessStop failed");
        return Err(PlatformError::OsError(format!(
            "DebugActiveProcessStop failed: {} ({})",
            error, error_str
        )));
    }

    platform.remove_process(pid);
    Ok(())
}

/// Open a process non-invasively: obtain a handle via `OpenProcess` (no
/// `DebugActiveProcess`), register it, and populate its module/thread lists and
/// symbols from Toolhelp snapshots. This makes every read-only capability that
/// normally needs an attached process — disassembly, symbol resolution, PE info,
/// dereference, thread context, and call stacks — work without debugging the
/// target. The process keeps running the whole time; it is never suspended.
pub(super) fn open_non_invasive(platform: &mut WindowsPlatform, pid: u32) -> Result<(), PlatformError> {
    trace!(pid, "WindowsPlatform::open_non_invasive called");

    // Idempotent: if this pid is already tracked (attached or previously opened),
    // there is nothing to do.
    if platform.process_handle(pid).is_ok() {
        return Ok(());
    }

    let handle = unsafe {
        OpenProcess(
            // PROCESS_DUP_HANDLE: the Handles window names handles by duplicating
            // them into the server, and closes them the same way.
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE,
            0,
            pid,
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "OpenProcess failed in open_non_invasive");
        return Err(PlatformError::OsError(format!("OpenProcess failed: {} ({})", error, error_str)));
    }

    let architecture = determine_process_architecture(handle).unwrap_or(Architecture::X64);

    // add_process runs SymInitialize on the handle (needed for symbols/StackWalk).
    platform.add_process(pid, handle, architecture)?;

    // Populate modules (Toolhelp), register each with DbgHelp for stack walking,
    // and kick off background symbol loading. Best-effort per module.
    for module in utils::get_modules(pid).unwrap_or_default() {
        if let Ok(cname) = CString::new(module.name.as_str()) {
            let _lock = super::dbghelp::DBGHELP_LOCK.lock().unwrap();
            let ok = unsafe {
                SymLoadModule64(handle, ptr::null_mut(), cname.as_ptr() as *const u8, ptr::null(),
                    module.base, module.size.unwrap_or(0) as u32)
            };
            if ok == 0 {
                warn!(pid, module = %module.name, "SymLoadModule64 failed in open_non_invasive: 0x{:x}", unsafe { GetLastError() });
            }
        }
        if let Some(ref symbol_manager) = platform.symbol_manager {
            symbol_manager.start_loading_symbols(&module);
        }
        if let Ok(process) = platform.get_process_mut(pid) {
            process.module_manager_mut().add_module(module);
        }
    }

    // Populate threads (Toolhelp) with per-thread handles for context/stack walks.
    for thread in utils::list_threads_toolhelp(pid).unwrap_or_default() {
        let thandle = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, thread.tid) };
        if thandle.is_null() {
            warn!(pid, tid = thread.tid, "OpenThread failed in open_non_invasive");
            continue;
        }
        if let Ok(process) = platform.get_process_mut(pid) {
            process.thread_manager_mut().add_thread(thread.tid, thread.start_address, thandle);
        }
    }

    trace!(pid, "Process opened non-invasively");
    Ok(())
}

/// Release a non-invasively opened process: drop the tracked handle, symbols, and
/// thread handles. The target is unaffected (it was never attached).
pub(super) fn close_non_invasive(platform: &mut WindowsPlatform, pid: u32) -> Result<(), PlatformError> {
    trace!(pid, "WindowsPlatform::close_non_invasive called");
    platform.remove_process(pid);
    Ok(())
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

pub fn debug_break_process_unlocked(pid: u32) -> Result<(), PlatformError> {
    unsafe {
        let h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if h.is_null() {
            let e = GetLastError();
            let err = utils::error_message(e);
            error!(pid, code = e, err, "OpenProcess(PROCESS_ALL_ACCESS) failed");
            return Err(PlatformError::OsError(format!("OpenProcess(PROCESS_ALL_ACCESS) failed: {} ({})", e, err)));
        }
        let rc = DebugBreakProcess(h);
        CloseHandle(h);
        if rc == 0 {
            let e = GetLastError();
            let err = utils::error_message(e);
            error!(pid, code = e, err, "DebugBreakProcess failed");
            return Err(PlatformError::OsError(format!("DebugBreakProcess failed: {} ({})", e, err)));
        }
        trace!(pid, "DebugBreakProcess succeeded (unlocked)");
        Ok(())
    }
}