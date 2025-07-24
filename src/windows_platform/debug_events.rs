use super::{utils, WindowsPlatform, stepper};
use crate::interfaces::PlatformError;
use crate::protocol::ModuleInfo;
use tracing::{error, trace, warn};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, DBG_CONTINUE, DUPLICATE_SAME_ACCESS, HANDLE, DuplicateHandle, STATUS_SINGLE_STEP};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, INFINITE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, WaitForDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    CREATE_PROCESS_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, SymLoadModule64, SymUnloadModule64
};
use std::ffi::CString;
use std::ptr;

pub(super) fn handle_create_process_event(
    platform: &mut WindowsPlatform,
    debug_event: &DEBUG_EVENT,
    image_path_fallback: Option<&str>,
) -> Result<crate::protocol::DebugEvent, PlatformError> {
    let info = unsafe { debug_event.u.CreateProcessInfo };
    let pid = debug_event.dwProcessId;

    let image_file_name =
        utils::get_path_from_handle(info.hFile).unwrap_or_else(|| image_path_fallback.unwrap_or("<unknown>").to_string());

    // Get the process for this PID to use its handle and clear its managers
    let process = platform.get_process_mut(pid)?;
    let h_process = process.process_handle.0;

    // Refresh the module list now that the process is created
    let size_of_image =
        utils::get_module_size_from_address(h_process, info.lpBaseOfImage as usize)
            .map(|sz| sz as u64);
            
    // Load the module into the symbol handler
    let c_name = CString::new(image_file_name.as_str()).unwrap();
    if unsafe { SymLoadModule64(h_process, info.hFile, c_name.as_ptr() as *const u8, ptr::null(), info.lpBaseOfImage as u64, size_of_image.unwrap_or(0) as u32) } == 0 {
        let error = unsafe { GetLastError() };
        warn!(pid, "SymLoadModule64 failed in create_process for {}: 0x{:x}", image_file_name, error);
    }
    
    // Now that we're done with hFile, close it.
    unsafe {
        CloseHandle(info.hFile);
    }

    // Clear its managers
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
                let address = ex_record.ExceptionAddress as u64;
                trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, address = %format!("0x{:X}", address), "Breakpoint event");

                let process = platform.get_process_mut(debug_event.dwProcessId)?;

                // Check if this is a single-shot breakpoint
                if let Some(original_bytes) = process.single_shot_breakpoints.remove(&address) {
                    trace!(address = %format!("0x{:X}", address), "Single-shot breakpoint hit. Restoring original bytes.");

                    // Restore the original byte
                    super::memory::write_memory_internal(process.process_handle.0, address, &original_bytes)?;

                    // Set IP back to the original instruction's address
                    let mut context = match super::thread_context::get_thread_context(platform, debug_event.dwProcessId, debug_event.dwThreadId)? {
                        crate::protocol::ThreadContext::Win32RawContext(ctx) => ctx,
                    };
                    
                    #[cfg(target_arch = "x86_64")]
                    {
                        context.Rip = address;
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        context.Pc = address;
                    }

                    super::thread_context::set_thread_context(platform, debug_event.dwProcessId, debug_event.dwThreadId, crate::protocol::ThreadContext::Win32RawContext(context.clone()))?;
                }

                Some(crate::protocol::DebugEvent::Breakpoint {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    address: ex_record.ExceptionAddress as u64,
                })
            } else if ex_record.ExceptionCode == STATUS_SINGLE_STEP {
                trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, address = %format!("0x{:X}", ex_record.ExceptionAddress as u64), "Single-step event");
                
                // Check if this is from an active stepper
                let step_key = (debug_event.dwProcessId, debug_event.dwThreadId);
                if let Some(step_state) = platform.active_steppers.remove(&step_key) {
                    // This is from an active stepping operation
                    trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, kind = ?step_state.kind, "Single-step from active stepper");
                    
                    if let Err(e) = stepper::clear_single_step_flag_native2(platform, debug_event.dwProcessId, debug_event.dwThreadId) {
                        error!("Failed to clear single-step flag: {}", e);
                    }
                    
                    // Return a proper StepComplete event
                    Some(crate::protocol::DebugEvent::StepComplete {
                        pid: debug_event.dwProcessId,
                        tid: debug_event.dwThreadId,
                        kind: step_state.kind,
                        address: ex_record.ExceptionAddress as u64,
                    })
                } else {
                    // This is an unexpected single-step (not from our stepper)
                    trace!(pid = debug_event.dwProcessId, tid = debug_event.dwThreadId, "Unexpected single-step event");
                    
                    // Return as normal exception
                    Some(crate::protocol::DebugEvent::Exception {
                        pid: debug_event.dwProcessId,
                        tid: debug_event.dwThreadId,
                        code: ex_record.ExceptionCode as u32,
                        address: ex_record.ExceptionAddress as u64,
                        first_chance: ex_info.dwFirstChance == 1,
                        parameters: vec![],
                    })
                }
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

            let process = platform.get_process(debug_event.dwProcessId)?;
            let h_process = process.process_handle.0;
            let size_of_dll =
                utils::get_module_size_from_address(h_process, info.lpBaseOfDll as usize)
                    .map(|sz| sz as u64);
            if size_of_dll.is_none() {
                error!("Failed to get size of DLL");
                return Err(PlatformError::OsError("Failed to get size of DLL".to_string()));
            }

            // Load module into symbol handler
            let c_name = CString::new(dll_name.as_str()).unwrap();
            if unsafe { SymLoadModule64(h_process, info.hFile, c_name.as_ptr() as *const u8, ptr::null(), info.lpBaseOfDll as u64, size_of_dll.unwrap_or(0) as u32) } == 0 {
                 let error = unsafe { GetLastError() };
                 warn!(pid = debug_event.dwProcessId, "SymLoadModule64 failed on DLL load for {}: 0x{:x}", dll_name, error);
            }

            // now close handle
            unsafe {
                CloseHandle(info.hFile);
            }

            let module_info = ModuleInfo {
                name: dll_name.clone(),
                base: info.lpBaseOfDll as u64,
                size: size_of_dll,
            };
            
            let process = platform.get_process_mut(debug_event.dwProcessId)?;
            process.module_manager.add_module(module_info.clone());

            // Refresh the module list for the symbol handler
            // This is no longer needed as SymLoadModule64 handles incremental updates
            // if unsafe { SymRefreshModuleList(h_process) } == FALSE {
            //     let error = unsafe { GetLastError() };
            //     warn!(pid = debug_event.dwProcessId, "SymRefreshModuleList failed on DLL load: 0x{:x}", error);
            // }

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
                // Unload from our manager
                process.module_manager.remove_module(info.lpBaseOfDll as u64);
                // Unload from symbol handler
                if unsafe { SymUnloadModule64(process.process_handle.0, info.lpBaseOfDll as u64) } == FALSE {
                    let error = unsafe { GetLastError() };
                    warn!(pid = debug_event.dwProcessId, "SymUnloadModule64 failed: 0x{:x}", error);
                }
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
