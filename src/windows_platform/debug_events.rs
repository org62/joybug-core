use super::{utils, WindowsPlatform};
use crate::interfaces::PlatformError;
use crate::protocol::{ModuleInfo};
use tracing::{error, trace};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, DBG_CONTINUE, DUPLICATE_SAME_ACCESS, HANDLE, DuplicateHandle};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, INFINITE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, WaitForDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    CREATE_PROCESS_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
};

pub(super) fn handle_create_process_event(
    platform: &mut WindowsPlatform,
    debug_event: &DEBUG_EVENT,
    image_path_fallback: Option<&str>,
) -> Result<crate::protocol::DebugEvent, PlatformError> {
    let info = unsafe { debug_event.u.CreateProcessInfo };
    let pid = debug_event.dwProcessId;

    let image_file_name =
        utils::get_path_from_handle(info.hFile).unwrap_or_else(|| image_path_fallback.unwrap_or("<unknown>").to_string());
    unsafe {
        CloseHandle(info.hFile);
    }
    let size_of_image =
        utils::get_module_size_from_address(info.hProcess, info.lpBaseOfImage as usize)
            .map(|sz| sz as u64);

    // Get the process for this PID and clear its managers
    let process = platform.get_process_mut(pid)?;
    process.module_manager.clear();
    process.thread_manager.clear();
    
    let main_module = ModuleInfo {
        name: image_file_name.clone(),
        base: info.lpBaseOfImage as u64,
        size: size_of_image,
    };
    
    process.module_manager.add_module(main_module.clone());

    // Start loading symbols for the main executable in the background
    if let Some(ref symbol_manager) = platform.symbol_manager {
        symbol_manager.start_loading_symbols(&main_module);
    }

    let mut thread_handle = 0 as HANDLE;
    let current_process = unsafe { GetCurrentProcess() };
    if unsafe {
        DuplicateHandle(
            current_process,
            info.hThread,
            current_process,
            &mut thread_handle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(
            error,
            error_str,
            "DuplicateHandle for thread failed in CREATE_PROCESS_DEBUG_EVENT"
        );
        return Err(PlatformError::OsError(format!(
            "DuplicateHandle for thread failed in CREATE_PROCESS_DEBUG_EVENT: {} ({})",
            error, error_str
        )));
    } else {
        let start_address = info.lpStartAddress.map_or(0, |addr| addr as usize as u64);
        let process = platform.get_process_mut(pid)?;
        process.thread_manager.add_thread(
            debug_event.dwThreadId,
            start_address,
            thread_handle,
        );
    }

    trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, base_of_image = %format!("0x{:X}", info.lpBaseOfImage as u64), image_file_name = ?image_file_name, size_of_image = %format!("{:X?}", size_of_image), "ProcessCreated event");
    Ok(crate::protocol::DebugEvent::ProcessCreated {
        pid: debug_event.dwProcessId,
        tid: debug_event.dwThreadId,
        image_file_name: Some(image_file_name),
        base_of_image: info.lpBaseOfImage as u64,
        size_of_image: size_of_image,
    })
}

pub(super) fn continue_exec(
    platform: &mut WindowsPlatform,
    pid: u32,
    tid: u32,
) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
    trace!(pid, tid, "WindowsPlatform::continue_exec called");
    let cont_res = unsafe { ContinueDebugEvent(pid, tid, DBG_CONTINUE) };
    if cont_res == FALSE {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "ContinueDebugEvent failed");
        return Err(PlatformError::OsError(format!(
            "ContinueDebugEvent failed: {} ({})",
            error, error_str
        )));
    }
    let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
    let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
    if wait_res == FALSE {
        let error = unsafe { GetLastError() };
        let error_str = utils::error_message(error);
        error!(error, error_str, "WaitForDebugEvent failed");
        return Err(PlatformError::OsError(format!(
            "WaitForDebugEvent failed: {} ({})",
            error, error_str
        )));
    }
    let event = match debug_event.dwDebugEventCode {
        EXCEPTION_DEBUG_EVENT => {
            let ex_info = unsafe { debug_event.u.Exception };
            let ex_record = ex_info.ExceptionRecord;
            if ex_record.ExceptionCode == windows_sys::Win32::Foundation::EXCEPTION_BREAKPOINT {
                trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, address = %format!("0x{:X}", ex_record.ExceptionAddress as u64), "Breakpoint event");
                Some(crate::protocol::DebugEvent::Breakpoint {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    address: ex_record.ExceptionAddress as u64,
                })
            } else {
                let mut params = Vec::new();
                let num_params = ex_record.NumberParameters as usize;
                for i in 0..num_params {
                    params.push(ex_record.ExceptionInformation[i] as u64);
                }
                trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, code = %format!("0x{:X}", ex_record.ExceptionCode as u32), address = %format!("0x{:X}", ex_record.ExceptionAddress as u64), first_chance = ex_info.dwFirstChance == 1, parameters = ?params, "Exception event");
                Some(crate::protocol::DebugEvent::Exception {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    code: ex_record.ExceptionCode as u32,
                    address: ex_record.ExceptionAddress as u64,
                    first_chance: ex_info.dwFirstChance == 1,
                    parameters: params,
                })
            }
        }
        CREATE_PROCESS_DEBUG_EVENT => {
            match handle_create_process_event(platform, &debug_event, None) {
                Ok(event) => Some(event),
                Err(e) => {
                    error!("Failed to handle create process event: {}", e);
                    // Decide what to do on an error. Maybe return an error event or just unknown.
                    // For now, let's stick to the existing pattern of returning an `Option`.
                    Some(crate::protocol::DebugEvent::Unknown)
                }
            }
        }
        EXIT_PROCESS_DEBUG_EVENT => {
            let info = unsafe { debug_event.u.ExitProcess };
            trace!(pid = debug_event.dwProcessId, exit_code = %format!("0x{:X}", info.dwExitCode), "ProcessExited event");
            
            // Note: We don't remove the process from tracking here to allow post-mortem analysis
            // The process will be removed when the client explicitly detaches or the connection closes
            
            Some(crate::protocol::DebugEvent::ProcessExited {
                pid: debug_event.dwProcessId,
                exit_code: info.dwExitCode,
            })
        }
        CREATE_THREAD_DEBUG_EVENT => {
            let info = unsafe { debug_event.u.CreateThread };

            let mut thread_handle = 0 as HANDLE;
            let current_process = unsafe { GetCurrentProcess() };
            if unsafe {
                DuplicateHandle(
                    current_process,
                    info.hThread,
                    current_process,
                    &mut thread_handle,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                let error = unsafe { GetLastError() };
                let error_str = utils::error_message(error);
                error!(
                    error,
                    error_str,
                    "DuplicateHandle for thread failed in CREATE_THREAD_DEBUG_EVENT"
                );
            } else {
                let start_address = info.lpStartAddress.map_or(0, |addr| addr as usize as u64);
                let process = platform.get_process_mut(debug_event.dwProcessId)?;
                process.thread_manager.add_thread(
                    debug_event.dwThreadId,
                    start_address,
                    thread_handle,
                );
            }

            trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, start_address = %format!("0x{:X}", info.lpStartAddress.map_or(0, |addr| addr as usize as u64)), "ThreadCreated event");
            Some(crate::protocol::DebugEvent::ThreadCreated {
                pid: debug_event.dwProcessId,
                tid: debug_event.dwThreadId,
                start_address: info.lpStartAddress.map_or(0, |addr| addr as usize as u64),
            })
        }
        EXIT_THREAD_DEBUG_EVENT => {
            let info = unsafe { debug_event.u.ExitThread };
            trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, exit_code = %format!("0x{:X}", info.dwExitCode), "ThreadExited event");
            if let Ok(process) = platform.get_process_mut(debug_event.dwProcessId) {
                process.thread_manager.remove_thread(debug_event.dwThreadId);
            }
            Some(crate::protocol::DebugEvent::ThreadExited {
                pid: debug_event.dwProcessId,
                tid: debug_event.dwThreadId,
                exit_code: info.dwExitCode,
            })
        }
        LOAD_DLL_DEBUG_EVENT => {
            let info = unsafe { debug_event.u.LoadDll };
            let dll_name =
                utils::get_path_from_handle(info.hFile).unwrap_or_else(|| "<unknown>".to_string());
            unsafe {
                CloseHandle(info.hFile);
            }
            let process = platform.get_process(debug_event.dwProcessId)?;
            let h_process = process.process_handle.0;
            let size_of_dll =
                utils::get_module_size_from_address(h_process, info.lpBaseOfDll as usize)
                    .map(|sz| sz as u64);
            if size_of_dll.is_none() {
                error!("Failed to get size of DLL");
                return Err(PlatformError::OsError("Failed to get size of DLL".to_string()));
            }

            let module_info = ModuleInfo {
                name: dll_name.clone(),
                base: info.lpBaseOfDll as u64,
                size: size_of_dll,
            };
            
            let process = platform.get_process_mut(debug_event.dwProcessId)?;
            process.module_manager.add_module(module_info.clone());

            // Start loading symbols for the newly loaded module in the background
            if let Some(ref symbol_manager) = platform.symbol_manager {
                symbol_manager.start_loading_symbols(&module_info);
            }

            trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, base_of_dll = %format!("0x{:X}", info.lpBaseOfDll as u64), dll_name = ?dll_name, size_of_dll = %format!("{:X?}", size_of_dll), "DllLoaded event");
            Some(crate::protocol::DebugEvent::DllLoaded {
                pid: debug_event.dwProcessId,
                tid: debug_event.dwThreadId,
                dll_name: Some(dll_name),
                base_of_dll: info.lpBaseOfDll as u64,
                size_of_dll,
            })
        }
        UNLOAD_DLL_DEBUG_EVENT => {
            let info = unsafe { debug_event.u.UnloadDll };
            trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, base_of_dll = %format!("0x{:X}", info.lpBaseOfDll as u64), "DllUnloaded event");
            if let Ok(process) = platform.get_process_mut(debug_event.dwProcessId) {
                process.module_manager.remove_module(info.lpBaseOfDll as u64);
            }
            Some(crate::protocol::DebugEvent::DllUnloaded {
                pid: debug_event.dwProcessId,
                tid: debug_event.dwThreadId,
                base_of_dll: info.lpBaseOfDll as u64,
            })
        }
        OUTPUT_DEBUG_STRING_EVENT => {
            trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, "OutputDebugString event");
            Some(crate::protocol::DebugEvent::Output {
                pid: debug_event.dwProcessId,
                tid: debug_event.dwThreadId,
                output: "<TODO: extract debug string>".to_string(),
            })
        }
        RIP_EVENT => {
            let info = unsafe { debug_event.u.RipInfo };
            trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, error = %format!("0x{:X}", info.dwError), event_type = %format!("0x{:X}", info.dwType), "RipEvent");
            Some(crate::protocol::DebugEvent::RipEvent {
                pid: debug_event.dwProcessId,
                tid: debug_event.dwThreadId,
                error: info.dwError,
                event_type: info.dwType,
            })
        }
        _ => {
            error!("Unknown debug event");
            Some(crate::protocol::DebugEvent::Unknown)
        }
    };
    Ok(event)
} 