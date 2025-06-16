mod utils;
mod module_manager;

use crate::interfaces::{PlatformAPI, PlatformError};
use crate::protocol::{ModuleInfo, ProcessInfo};
use module_manager::ModuleManager;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
    EXCEPTION_DEBUG_EVENT,
    CREATE_PROCESS_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT,
    CREATE_THREAD_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
    UNLOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT,
    RIP_EVENT,
    CONTEXT_FULL_AMD64,
    CONTEXT,
    DEBUG_EVENT,
    ContinueDebugEvent,
    FormatMessageW,
    WaitForDebugEvent,
    GetThreadContext,
    SetThreadContext,
    ReadProcessMemory,
    WriteProcessMemory,
    DebugActiveProcess,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    DEBUG_PROCESS, 
    INFINITE, 
    THREAD_SET_CONTEXT, 
    THREAD_QUERY_INFORMATION, 
    THREAD_ALL_ACCESS,
    STARTUPINFOW, 
    PROCESS_INFORMATION, 
    CreateProcessW, 
    OpenThread, 
};
use windows_sys::Win32::Foundation::{
    FALSE,
    DBG_CONTINUE,
    INVALID_HANDLE_VALUE,
    GetLastError,
    CloseHandle,
    HANDLE,
};
use windows_sys::core::PWSTR;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use tracing::{trace, error};

// Safe wrapper for HANDLE
struct ProcessHandleSafe(HANDLE);
unsafe impl Send for ProcessHandleSafe {}
unsafe impl Sync for ProcessHandleSafe {}

// Aligned wrapper for CONTEXT structure
#[repr(align(16))]
struct AlignedContext {
    context: CONTEXT,
}

pub struct WindowsPlatform {
    pid: Option<u32>,
    process_handle: Option<ProcessHandleSafe>,
    module_manager: ModuleManager,
}

impl WindowsPlatform {
    pub fn new() -> Self {
        Self { pid: None, process_handle: None, module_manager: ModuleManager::new() }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    fn error_message(error_code: u32) -> String {
        use std::ptr::null_mut;
        let mut buf = [0u16; 512];
        let len = unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                error_code,
                0,
                buf.as_mut_ptr() as PWSTR,
                buf.len() as u32,
                null_mut(),
            )
        };
        if len == 0 {
            format!("Unknown error code {}", error_code)
        } else {
            let msg = String::from_utf16_lossy(&buf[..len as usize]);
            msg.trim().to_string()
        }
    }
}

impl PlatformAPI for WindowsPlatform {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        trace!(pid, "WindowsPlatform::attach called");

        if unsafe { DebugActiveProcess(pid) } == 0 {
            let error = unsafe { GetLastError() };
            let error_str = Self::error_message(error);
            error!(error, error_str, "DebugActiveProcess failed");
            return Err(PlatformError::OsError(format!("DebugActiveProcess failed: {} ({})", error, error_str)));
        }

        self.pid = Some(pid);
        
        // After attaching, we must wait for the initial CREATE_PROCESS_DEBUG_EVENT
        let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
        if wait_res == FALSE {
            let error = unsafe { GetLastError() };
            let error_str = Self::error_message(error);
            error!(error, error_str, "WaitForDebugEvent after attach failed");
            return Err(PlatformError::OsError(format!("WaitForDebugEvent after attach failed: {} ({})", error, error_str)));
        }

        if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
            let info = unsafe { debug_event.u.CreateProcessInfo };
            self.process_handle = Some(ProcessHandleSafe(info.hProcess));
            let image_file_name = utils::get_path_from_handle(info.hFile).unwrap_or_else(|| "<unknown>".to_string());
            let size_of_image = utils::get_module_size_from_address(info.hProcess, info.lpBaseOfImage as usize).map(|sz| sz as u64);
            
            self.module_manager.clear();
            self.module_manager.add_module(ModuleInfo {
                name: image_file_name.clone(),
                base: info.lpBaseOfImage as u64,
                size: size_of_image,
            });

            Ok(Some(crate::protocol::DebugEvent::ProcessCreated {
                pid: debug_event.dwProcessId,
                tid: debug_event.dwThreadId,
                image_file_name: Some(image_file_name),
                base_of_image: info.lpBaseOfImage as u64,
                size_of_image,
            }))
        } else {
            error!(event_code = debug_event.dwDebugEventCode, "Unexpected debug event after attach");
            // We should probably continue the event we received...
            unsafe { ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE); }
            Err(PlatformError::Other("Unexpected debug event after attach".to_string()))
        }
    }

    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        trace!(pid, tid, "WindowsPlatform::continue_exec called");
        let cont_res = unsafe {
            ContinueDebugEvent(pid, tid, DBG_CONTINUE)
        };
        if cont_res == FALSE {
            let error = unsafe { GetLastError() };
            let error_str = Self::error_message(error);
            error!(error, error_str, "ContinueDebugEvent failed");
            return Err(PlatformError::OsError(format!("ContinueDebugEvent failed: {} ({})", error, error_str)));
        }
        let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
        if wait_res == FALSE {
            let error = unsafe { GetLastError() };
            let error_str = Self::error_message(error);
            error!(error, error_str, "WaitForDebugEvent failed");
            return Err(PlatformError::OsError(format!("WaitForDebugEvent failed: {} ({})", error, error_str)));
        }
        let event = match debug_event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let ex_info = unsafe { debug_event.u.Exception };
                let ex_record = ex_info.ExceptionRecord;
                if ex_record.ExceptionCode == windows_sys::Win32::Foundation::EXCEPTION_BREAKPOINT {
                    trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), address = %format!("0x{:X}", ex_record.ExceptionAddress as u64), "Breakpoint event");
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
                    trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), code = %format!("0x{:X}", ex_record.ExceptionCode as u32), address = %format!("0x{:X}", ex_record.ExceptionAddress as u64), first_chance = ex_info.dwFirstChance == 1, parameters = ?params, "Exception event");
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
                let info = unsafe { debug_event.u.CreateProcessInfo };
                let image_file_name = utils::get_path_from_handle(info.hFile).unwrap_or_else(|| "<unknown>".to_string());
                let size_of_image = utils::get_module_size_from_address(info.hProcess, info.lpBaseOfImage as usize).map(|sz| sz as u64);

                self.module_manager.add_module(ModuleInfo {
                    name: image_file_name.clone(),
                    base: info.lpBaseOfImage as u64,
                    size: size_of_image,
                });

                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), base_of_image = %format!("0x{:X}", info.lpBaseOfImage as u64), image_file_name = ?image_file_name, size_of_image = ?size_of_image, "ProcessCreated event");
                Some(crate::protocol::DebugEvent::ProcessCreated {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    image_file_name: Some(image_file_name),
                    base_of_image: info.lpBaseOfImage as u64,
                    size_of_image,
                })
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.ExitProcess };
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), exit_code = %format!("0x{:X}", info.dwExitCode), "ProcessExited event");
                Some(crate::protocol::DebugEvent::ProcessExited {
                    pid: debug_event.dwProcessId,
                    exit_code: info.dwExitCode,
                })
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.CreateThread };
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), start_address = %format!("0x{:X}", info.lpStartAddress.map_or(0, |addr| addr as usize as u64)), "ThreadCreated event");
                Some(crate::protocol::DebugEvent::ThreadCreated {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    start_address: info.lpStartAddress.map_or(0, |addr| addr as usize as u64),
                })
            }
            EXIT_THREAD_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.ExitThread };
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), exit_code = %format!("0x{:X}", info.dwExitCode), "ThreadExited event");
                Some(crate::protocol::DebugEvent::ThreadExited {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    exit_code: info.dwExitCode,
                })
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.LoadDll };
                let dll_name = utils::get_path_from_handle(info.hFile).unwrap_or_else(|| "<unknown>".to_string());
                let h_process = self.process_handle.as_ref().ok_or_else(|| PlatformError::OsError("No process handle for LOAD_DLL_DEBUG_EVENT".to_string()))?.0;
                let size_of_dll = utils::get_module_size_from_address(h_process, info.lpBaseOfDll as usize).map(|sz| sz as u64);
                if size_of_dll.is_none() {
                    error!("Failed to get size of DLL");
                    return Err(PlatformError::OsError("Failed to get size of DLL".to_string()));
                }

                self.module_manager.add_module(ModuleInfo {
                    name: dll_name.clone(),
                    base: info.lpBaseOfDll as u64,
                    size: size_of_dll,
                });

                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), base_of_dll = %format!("0x{:X}", info.lpBaseOfDll as u64), dll_name = ?dll_name, size_of_dll = ?size_of_dll, "DllLoaded event");
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
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), base_of_dll = %format!("0x{:X}", info.lpBaseOfDll as u64), "DllUnloaded event");
                self.module_manager.remove_module(info.lpBaseOfDll as u64);
                Some(crate::protocol::DebugEvent::DllUnloaded {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    base_of_dll: info.lpBaseOfDll as u64,
                })
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), "OutputDebugString event");
                Some(crate::protocol::DebugEvent::Output {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    output: "<TODO: extract debug string>".to_string(),
                })
            }
            RIP_EVENT => {
                let info = unsafe { debug_event.u.RipInfo };
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), error = %format!("0x{:X}", info.dwError), event_type = %format!("0x{:X}", info.dwType), "RipEvent");
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
            },
        };
        Ok(event)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<(), PlatformError> {
        trace!(addr, "WindowsPlatform::set_breakpoint called");
        Err(PlatformError::NotImplemented)
    }

    fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        self.module_manager.clear();
        println!("[windows_platform] launch thread id: {:?}", std::thread::current().id());
        trace!(command, "WindowsPlatform::launch called");
        let cmd_line_wide = Self::to_wide(command);
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
            let error_str = Self::error_message(error);
            error!(error, error_str, "CreateProcessW failed");
            return Err(PlatformError::OsError(format!("CreateProcessW failed: {} ({})", error, error_str)));
        }
        self.process_handle = Some(ProcessHandleSafe(process_info.hProcess));
        self.pid = Some(process_info.dwProcessId);
        // Immediately run the debug loop for the new process
        let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
        if wait_res == FALSE {
            let error = unsafe { GetLastError() };
            let error_str = Self::error_message(error);
            error!(error, error_str, "WaitForDebugEvent failed after launch");
            return Err(PlatformError::OsError(format!("WaitForDebugEvent failed after launch: {} ({})", error, error_str)));
        }
        if debug_event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
            error!("Unexpected debug event after launch");
            return Err(PlatformError::OsError("Unexpected debug event after launch".to_string()));
        }

        let info = unsafe { debug_event.u.CreateProcessInfo };
        let image_file_name = utils::get_path_from_handle(info.hFile).unwrap_or_else(|| command.split_whitespace().next().unwrap_or("<unknown>").to_string());
        let size_of_image = utils::get_module_size_from_address(info.hProcess, info.lpBaseOfImage as usize).map(|sz| sz as u64);
        if size_of_image.is_none() {
            error!("Failed to get size of image");
            return Err(PlatformError::OsError("Failed to get size of image".to_string()));
        }
        self.module_manager.add_module(ModuleInfo {
            name: image_file_name.clone(),
            base: info.lpBaseOfImage as u64,
            size: size_of_image,
        });

        Ok(Some(crate::protocol::DebugEvent::ProcessCreated { pid: process_info.dwProcessId, tid: process_info.dwThreadId, image_file_name: Some(image_file_name), base_of_image: info.lpBaseOfImage as u64, size_of_image }))
    }

    fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError> {
        trace!(pid = %format!("0x{:X}", pid), address = %format!("0x{:X}", address), size, "WindowsPlatform::read_memory called");
        unsafe {
            let handle = if let Some(handle) = self.process_handle.as_ref() {
                if self.pid == Some(pid) && handle.0 != std::ptr::null_mut() && handle.0 != INVALID_HANDLE_VALUE {
                    handle.0
                } else {
                    error!("No valid process handle for memory read");
                    return Err(PlatformError::OsError("No valid process handle for memory read".to_string()));
                }
            } else {
                error!("No process handle for memory read");
                return Err(PlatformError::OsError("No process handle for memory read".to_string()));
            };
            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0;
            let ok = ReadProcessMemory(
                handle,
                address as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                &mut bytes_read,
            );
            if ok == 0 {
                let error = GetLastError();
                let error_str = Self::error_message(error);
                error!(error, error_str, "ReadProcessMemory failed");
                return Err(PlatformError::OsError(format!("ReadProcessMemory failed: {} ({})", error, error_str)));
            }
            buffer.truncate(bytes_read);
            trace!(bytes_read, "ReadProcessMemory succeeded");
            Ok(buffer)
        }
    }

    fn write_memory(&mut self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        trace!(pid = %format!("0x{:X}", pid), address = %format!("0x{:X}", address), data_len = data.len(), "WindowsPlatform::write_memory called");
        unsafe {
            let handle = if let Some(handle) = self.process_handle.as_ref() {
                if self.pid == Some(pid) && handle.0 != std::ptr::null_mut() && handle.0 != INVALID_HANDLE_VALUE {
                    handle.0
                } else {
                    error!("No valid process handle for memory write");
                    return Err(PlatformError::OsError("No valid process handle for memory write".to_string()));
                }
            } else {
                trace!("No process handle for memory write");
                return Err(PlatformError::OsError("No process handle for memory write".to_string()));
            };
            let mut bytes_written = 0;
            let ok = WriteProcessMemory(
                handle,
                address as *mut std::ffi::c_void,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                &mut bytes_written,
            );
            if ok == 0 || bytes_written != data.len() {
                let error = GetLastError();
                let error_str = Self::error_message(error);
                error!(ok, bytes_written, error, error_str, "WriteProcessMemory failed");
                return Err(PlatformError::OsError(format!("WriteProcessMemory failed: {} ({})", error, error_str)));
            }
            trace!(bytes_written, "WriteProcessMemory succeeded");
            Ok(())
        }
    }

    fn get_thread_context(&mut self, _pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError> {
        trace!(tid, "WindowsPlatform::get_thread_context called");
        #[cfg(windows)]
        {
            let thread_handle = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, tid as u32) };
            if thread_handle == std::ptr::null_mut() {
                let error = unsafe { GetLastError() };
                let error_str = Self::error_message(error);
                error!(error, error_str, "OpenThread failed");
                return Err(PlatformError::OsError(format!("OpenThread failed: {} ({})", error, error_str)));
            }
            let mut aligned_context = AlignedContext {
                context: unsafe { std::mem::zeroed() },
            };
            aligned_context.context.ContextFlags = CONTEXT_FULL_AMD64;
            let ok = unsafe { GetThreadContext(thread_handle, &mut aligned_context.context) };
            unsafe { CloseHandle(thread_handle) };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                let error_str = Self::error_message(error);
                error!(error, error_str, "GetThreadContext failed");
                return Err(PlatformError::OsError(format!("GetThreadContext failed: {} ({})", error, error_str)));
            }
            trace!("GetThreadContext succeeded");
            Ok(crate::protocol::ThreadContext::Win32RawContext(aligned_context.context))
        }
        #[cfg(not(windows))]
        {
            Err(PlatformError::NotImplemented)
        }
    }

    fn set_thread_context(&mut self, _pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError> {
        trace!(tid, "WindowsPlatform::set_thread_context called");
        #[cfg(windows)]
        unsafe {
            let thread_handle = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid as u32);
            if thread_handle == std::ptr::null_mut() {
                let error = GetLastError();
                let error_str = Self::error_message(error);
                error!(error, error_str, "OpenThread failed");
                return Err(PlatformError::OsError(format!("OpenThread failed: {} ({})", error, error_str)));
            }
            match context {
                crate::protocol::ThreadContext::Win32RawContext(ctx) => {
                    // Use aligned memory for CONTEXT
                    let mut aligned_context = AlignedContext {
                        context: std::mem::zeroed(),
                    };
                    std::ptr::copy_nonoverlapping(
                        &ctx as *const _ as *const u8,
                        &mut aligned_context.context as *mut _ as *mut u8,
                        std::mem::size_of::<CONTEXT>(),
                    );
                    let ok = SetThreadContext(thread_handle, &aligned_context.context);
                    CloseHandle(thread_handle);
                    if ok == 0 {
                        let error = GetLastError();
                        let error_str = Self::error_message(error);
                        error!(error, error_str, "SetThreadContext failed");
                        return Err(PlatformError::OsError(format!("SetThreadContext failed: {} ({})", error, error_str)));
                    }
                    trace!("SetThreadContext succeeded");
                    Ok(())
                }
            }
        }
        #[cfg(not(windows))]
        {
            Err(PlatformError::NotImplemented)
        }
    }

    fn list_modules(&self, _pid: u32) -> Result<Vec<ModuleInfo>, PlatformError> {
        Ok(self.module_manager.list_modules())
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        trace!("WindowsPlatform::list_processes called");
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                let error = GetLastError();
                let error_str = Self::error_message(error);
                error!(error, error_str, "CreateToolhelp32Snapshot failed");
                return Err(PlatformError::OsError(format!("CreateToolhelp32Snapshot failed: {} ({})", error, error_str)));
            }

            let mut pe32: PROCESSENTRY32W = std::mem::zeroed();
            pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut pe32) == 0 {
                let error = GetLastError();
                let error_str = Self::error_message(error);
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
} 