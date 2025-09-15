use super::{utils, WindowsPlatform, stepper};
use crate::interfaces::PlatformError;
use crate::protocol::ModuleInfo;
use tracing::{error, trace, warn};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, DBG_CONTINUE, DUPLICATE_SAME_ACCESS, HANDLE, DuplicateHandle, STATUS_SINGLE_STEP, MAX_PATH};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, INFINITE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, WaitForDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    CREATE_PROCESS_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, SymLoadModule64, SymUnloadModule64
};
use std::ffi::CString;
use std::ptr;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

// Non-locking helpers to minimize lock holding in server
pub fn continue_only(pid: u32, tid: u32) -> Result<(), PlatformError> {
    trace!(pid, tid, "ContinueDebugEvent only");
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
    Ok(())
}

pub fn wait_for_debug_event_blocking() -> Result<DEBUG_EVENT, PlatformError> {
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
    Ok(debug_event)
}

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
    let h_process = process.handle();

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
    process.module_manager_mut().clear();
    process.thread_manager_mut().clear();
    
    let main_module = ModuleInfo {
        name: image_file_name.clone(),
        base: info.lpBaseOfImage as u64,
        size: size_of_image,
    };
    
    process.module_manager_mut().add_module(main_module.clone());

    // Start loading symbols for the main executable in the background
    if let Some(ref symbol_manager) = platform.symbol_manager {
        symbol_manager.start_loading_symbols(&main_module);
    }

    // --- SPECIAL-CASE NTDLL SYMBOLS HACK ------------------------------------------------------
    // Why:
    // - Early debug events often occur before the system DLL load notifications are delivered.
    // - On Windows, the very first instructions executed in a new process are typically inside
    //   ntdll.dll, but the loader DLL (including ntdll) may not be visible yet via LOAD_DLL events.
    // - Our disassembler attempts to symbolize instructions using the currently known module list.
    //   If ntdll is not listed yet, symbol lookup for RIP will fail and the disassembly is shown
    //   without symbols.
    // Hack:
    // - Opportunistically pre-register ntdll.dll in the target's module list at process-create
    //   time using the server process' own ntdll base and size. This allows symbolization to work
    //   immediately for addresses that fall inside ntdll, even before LOAD_DLL for ntdll arrives.
    // Caveats:
    // - ASLR may cause the target process' ntdll base to differ from the server's; if they differ,
    //   our temporary module range may not match the target addresses, and symbolization will still
    //   fail until the real LOAD_DLL arrives. In practice, system DLLs often share the same base
    //   within a boot session, so this frequently helps in the common case.
    // - We intentionally do NOT call SymLoadModule64 for this synthetic entry to avoid confusing
    //   dbghelp's internal state with a possibly incorrect base. We only add it to our own
    //   ModuleManager and kick off PDB loading via the SymbolManager.
    // - Once the real LOAD_DLL for ntdll arrives, its proper base/size will be registered and this
    //   synthetic entry will be harmlessly redundant (overlapping). Future clean-up could reconcile
    //   or replace it, but for now we keep the logic minimal and non-invasive.
    if let Some(ntdll_module) = try_build_ntdll_moduleinfo_from_self() {
        // Add to the target process' module list so address-to-module checks can succeed early.
        let ntdll_module_cloned = ntdll_module.clone();
        let process = platform.get_process_mut(pid)?;
        process.module_manager_mut().add_module(ntdll_module_cloned);

        // Start background symbol load for ntdll so RVA -> name mapping is available quickly.
        if let Some(ref symbol_manager) = platform.symbol_manager {
            symbol_manager.start_loading_symbols(&ntdll_module);
        }
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
        process.thread_manager_mut().add_thread(
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

/// Builds a `ModuleInfo` for ntdll.dll using the current (server) process' mapping.
///
/// Notes:
/// - This is part of the temporary workaround to enable early symbolization of ntdll code
///   before the target process' DLL load events are observed.
/// - We fetch the base address via GetModuleHandleW(L"ntdll.dll"), and the size by reading
///   the PE headers using our existing `utils::get_module_size_from_address` helper.
/// - The module path is resolved with GetModuleFileNameW for transparency and to ensure the
///   symbol loader can find the correct PDB by PE's embedded CodeView record.
fn try_build_ntdll_moduleinfo_from_self() -> Option<crate::protocol::ModuleInfo> {
    let ntdll_w: Vec<u16> = {
        let mut v: Vec<u16> = "ntdll.dll".encode_utf16().collect();
        v.push(0);
        v
    };

    // SAFETY: Calling into Win32 to query module handle of a well-known module in this process.
    let h_mod = unsafe { GetModuleHandleW(ntdll_w.as_ptr()) } as *mut core::ffi::c_void;
    if h_mod.is_null() {
        return None;
    }
    let base = h_mod as usize as u64;

    // Resolve module path from the HMODULE.
    let module_path = get_module_path_from_handle(h_mod)?;

    // Determine size by reading PE headers in this process' address space.
    let size = unsafe { GetCurrentProcess() };
    // `get_module_size_from_address` expects a HANDLE and base address.
    let size_opt = super::utils::get_module_size_from_address(size, base as usize)
        .map(|s| s as u64);

    Some(crate::protocol::ModuleInfo {
        name: module_path,
        base,
        size: size_opt,
    })
}

/// Retrieves a module's full path via GetModuleFileNameW given an HMODULE.
fn get_module_path_from_handle(h_module: *mut core::ffi::c_void) -> Option<String> {
    // Single-shot attempt with a MAX_PATH-sized buffer. If it doesn't fit, fail fast.
    // This keeps the code simple and avoids repeated syscalls.
    let mut buf: Vec<u16> = vec![0; MAX_PATH as usize];
    let len = unsafe { GetModuleFileNameW(h_module, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= MAX_PATH as usize {
        panic!("GetModuleFileNameW failed to get module path");
    }
    buf.truncate(len);
    String::from_utf16(&buf).ok()
}

// Handle EXCEPTION_DEBUG_EVENT in a dedicated function to keep continue_exec simpler.
pub(super) fn handle_exception_event(
    platform: &mut WindowsPlatform,
    debug_event: &DEBUG_EVENT,
) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
    let pid = debug_event.dwProcessId;
    let tid = debug_event.dwThreadId;
    let ex_info = unsafe { debug_event.u.Exception };
    let ex_record = ex_info.ExceptionRecord;
    let process = platform.get_process_mut(pid)?;

    if ex_record.ExceptionCode == windows_sys::Win32::Foundation::EXCEPTION_BREAKPOINT {
        let address = ex_record.ExceptionAddress as u64;
        trace!(pid = pid, tid = tid, address = %format!("0x{:X}", address), "Breakpoint event");

        // Gather single-shot removal and possible step-over removal in one borrow
        let (single_shot_original_opt, step_over_hit_opt) = {
            let ss = process.remove_single_shot_breakpoint(address);
            let so = process.remove_step_over_breakpoint(address);
            (ss, so)
        };
        if let Some(original_bytes) = single_shot_original_opt {
            trace!(address = %format!("0x{:X}", address), "Single-shot breakpoint hit. Restoring original bytes.");

            // Restore the original byte
            process.restore_original_bytes(address, &original_bytes)?;

            // Set IP back to the original instruction's address
            let mut context = match super::thread_context::get_thread_context(process, pid, tid)? {
                crate::protocol::ThreadContext::Win32RawContext(ctx) => ctx,
            };
            #[cfg(target_arch = "x86_64")]
            { context.Rip = address; }
            #[cfg(target_arch = "aarch64")]
            { context.Pc = address; }
            super::thread_context::set_thread_context(process, pid, tid, crate::protocol::ThreadContext::Win32RawContext(context.clone()))?;

            // If this was a step-over breakpoint, we already removed it above
            if let Some((tid_hit, kind)) = step_over_hit_opt {
                return Ok(Some(crate::protocol::DebugEvent::StepComplete {
                    pid,
                    tid: tid_hit,
                    kind,
                    address,
                }));
            } else {
                return Ok(Some(crate::protocol::DebugEvent::SingleShotBreakpoint { pid, tid, address }));
            }
        }

        // Persistent breakpoint path
        if process.is_persistent_breakpoint(address)
        {
            trace!(address = %format!("0x{:X}", address), "Persistent breakpoint hit. Restoring original bytes and handling re-arm or step-out.");

            // Collect data needed with minimal borrows
            let (is_thread_match, original_bytes_opt, is_step_out_hit) = {
                (
                    process.persistent_allowed_for_tid(address, tid),
                    process.persistent_original_bytes(address),
                    process.has_step_out_breakpoint(address),
                )
            };

            // Restore original instruction bytes
            if let Some(original_bytes) = original_bytes_opt {
                process.restore_original_bytes(address, &original_bytes)?;
            }

            // Reset IP to original instruction
            let mut context = match super::thread_context::get_thread_context(process, pid, tid)? {
                crate::protocol::ThreadContext::Win32RawContext(ctx) => ctx,
            };
            #[cfg(target_arch = "x86_64")]
            { context.Rip = address; }
            #[cfg(target_arch = "aarch64")]
            { context.Pc = address; }
            super::thread_context::set_thread_context(process, pid, tid, crate::protocol::ThreadContext::Win32RawContext(context.clone()))?;

            // Is this a step-out completion?
            if is_thread_match && is_step_out_hit {
                let step_out_info = {
                    process.remove_step_out_breakpoint(address)
                };
                if let Some((tid2, original_return_address)) = step_out_info {
                    let _ = process.remove_breakpoint(address);
                    return Ok(Some(crate::protocol::DebugEvent::StepComplete {
                        pid,
                        tid: tid2,
                        kind: crate::protocol::StepKind::Out,
                        address: original_return_address,
                    }));
                }
            }

            // Not a step-out: schedule SS to pass and re-arm
            process.schedule_rearm_after_single_step(tid, address, false);
            let mut ctx2 = match super::thread_context::get_thread_context(process, pid, tid)? {
                crate::protocol::ThreadContext::Win32RawContext(ctx) => ctx,
            };
            super::stepper::set_single_step_flag_native(&mut ctx2)?;
            super::thread_context::set_thread_context(process, pid, tid, crate::protocol::ThreadContext::Win32RawContext(ctx2))?;

            if is_thread_match {
                return Ok(Some(crate::protocol::DebugEvent::Breakpoint { pid, tid, address }));
            } else {
                return Ok(Some(crate::protocol::DebugEvent::Exception {
                    pid, tid,
                    code: ex_record.ExceptionCode as u32,
                    address: ex_record.ExceptionAddress as u64,
                    first_chance: ex_info.dwFirstChance == 1,
                    parameters: vec![],
                }));
            }
        }

        // Initial or regular breakpoint
        let is_initial_breakpoint = {
            let not_hit = !process.has_initial_breakpoint_been_hit();
            if not_hit { process.mark_initial_breakpoint_hit(); }
            not_hit
        };
        if is_initial_breakpoint {
            return Ok(Some(crate::protocol::DebugEvent::InitialBreakpoint { pid, tid, address: ex_record.ExceptionAddress as u64 }));
        } else {
            return Ok(Some(crate::protocol::DebugEvent::Breakpoint { pid, tid, address: ex_record.ExceptionAddress as u64 }));
        }
    }

    if ex_record.ExceptionCode == STATUS_SINGLE_STEP {
        trace!(
            pid = pid,
            tid = tid,
            address = %format!("0x{:X}", ex_record.ExceptionAddress as u64),
            first_chance = ex_info.dwFirstChance == 1,
            "Single-step event"
        );

        // Handle re-arming first
        if let Some((rearm_addr, _is_single_shot)) = process.take_pending_rearm_for_tid(tid) {
            trace!(pid = pid, tid = tid, rearm_addr = %format!("0x{:X}", rearm_addr), "SS used for persistent breakpoint re-arm");
            if let Err(e) = stepper::clear_single_step_flag_native2(platform, pid, tid) { error!("Failed to clear single-step flag: {}", e); }
            {
                let process = platform.get_process(pid)?;
                let _ = process.rearm_persistent_breakpoint_if_matches_original(rearm_addr);
            }
            return Ok(Some(crate::protocol::DebugEvent::Exception { pid, tid, code: ex_record.ExceptionCode as u32, address: ex_record.ExceptionAddress as u64, first_chance: ex_info.dwFirstChance == 1, parameters: vec![] }));
        }

        // Active stepper completion
        if let Some(step_state) = process.take_active_single_step(tid) {
            trace!(pid = pid, tid = tid, kind = ?step_state.kind, address = %format!("0x{:X}", ex_record.ExceptionAddress as u64), "Single-step from active stepper");
            if let Err(e) = stepper::clear_single_step_flag_native2(platform, pid, tid) { error!("Failed to clear single-step flag: {}", e); }
            let rearm_addr = ex_record.ExceptionAddress as u64;
            {
                let process = platform.get_process(pid)?;
                let _ = process.rearm_persistent_breakpoint_if_matches_original(rearm_addr);
            }
            return Ok(Some(crate::protocol::DebugEvent::StepComplete { pid, tid, kind: step_state.kind, address: ex_record.ExceptionAddress as u64 }));
        }

        // Unexpected SS
        let ctx_for_log = match super::thread_context::get_thread_context(process, pid, tid) {
            Ok(crate::protocol::ThreadContext::Win32RawContext(c)) => Some(c),
            _ => None,
        };
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(ref ctx) = ctx_for_log {
                trace!(pid = pid, tid = tid, rip = %format!("0x{:X}", ctx.Rip), eflags = %format!("0x{:X}", ctx.EFlags), "Unexpected single-step event (no active step record)");
            } else {
                trace!(pid = pid, tid = tid, "Unexpected single-step event (no active step record) - failed to fetch context for log");
            }
        }
        return Ok(Some(crate::protocol::DebugEvent::Exception { pid, tid, code: ex_record.ExceptionCode as u32, address: ex_record.ExceptionAddress as u64, first_chance: ex_info.dwFirstChance == 1, parameters: vec![] }));
    }

    // Generic exceptions
    let mut params = Vec::new();
    let num_params = ex_record.NumberParameters as usize;
    for i in 0..num_params { params.push(ex_record.ExceptionInformation[i] as u64); }
    trace!(pid = pid, tid = tid, code = %format!("0x{:X}", ex_record.ExceptionCode as u32), address = %format!("0x{:X}", ex_record.ExceptionAddress as u64), first_chance = ex_info.dwFirstChance == 1, parameters = ?params, "Exception event");
    Ok(Some(crate::protocol::DebugEvent::Exception { pid, tid, code: ex_record.ExceptionCode as u32, address: ex_record.ExceptionAddress as u64, first_chance: ex_info.dwFirstChance == 1, parameters: params }))
}

pub fn handle_debug_event(
    platform: &mut WindowsPlatform,
    debug_event: &DEBUG_EVENT,
) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
    let event = match debug_event.dwDebugEventCode {
        EXCEPTION_DEBUG_EVENT => match handle_exception_event(platform, &debug_event) {
            Ok(ev) => ev,
            Err(e) => {
                error!("Failed to handle exception event: {}", e);
                Some(crate::protocol::DebugEvent::Unknown)
            }
        },
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
            
            // Cleanup any pending step breakpoint state for this process
            let pid = debug_event.dwProcessId;
            platform.cleanup_step_state_for_process(pid);
            
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
                process.thread_manager_mut().add_thread(
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
            // Cleanup any pending step breakpoint state for this thread
            let pid = debug_event.dwProcessId;
            let tid = debug_event.dwThreadId;
            platform.cleanup_step_state_for_thread(pid, tid);
            if let Ok(process) = platform.get_process_mut(debug_event.dwProcessId) {
                process.thread_manager_mut().remove_thread(debug_event.dwThreadId);
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
            let h_process = process.handle();
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
            process.module_manager_mut().add_module(module_info.clone());

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
                process.module_manager_mut().remove_module(info.lpBaseOfDll as u64);
                // Unload from symbol handler
                if unsafe { SymUnloadModule64(process.handle(), info.lpBaseOfDll as u64) } == FALSE {
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
            let info = unsafe { debug_event.u.DebugString };
            let pid = debug_event.dwProcessId;

            // fUnicode indicates whether the string is UTF-16. nDebugStringLength is in characters.
            let output = if info.fUnicode != 0 {
                // Read UTF-16 string with known length
                match super::memory::read_wide_string(
                    platform,
                    pid,
                    info.lpDebugStringData as u64,
                    Some(info.nDebugStringLength as usize),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(pid, tid = debug_event.dwThreadId, error = %e, "Failed to read wide debug string");
                        "<invalid wide debug string>".to_string()
                    }
                }
            } else {
                // ANSI string
                let len = info.nDebugStringLength as usize;
                match super::memory::read_memory(
                    platform,
                    pid,
                    info.lpDebugStringData as u64,
                    len,
                ) {
                    Ok(bytes) => {
                        let mut s = String::from_utf8_lossy(&bytes).into_owned();
                        if let Some(pos) = s.find('\0') { s.truncate(pos); }
                        s.trim().to_string()
                    }
                    Err(e) => {
                        warn!(pid, tid = debug_event.dwThreadId, error = %e, "Failed to read ansi debug string");
                        "<invalid debug string>".to_string()
                    }
                }
            };

            Some(crate::protocol::DebugEvent::Output {
                pid,
                tid: debug_event.dwThreadId,
                output,
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
