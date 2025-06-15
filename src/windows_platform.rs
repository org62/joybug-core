#![allow(dead_code)]
use crate::interfaces::{PlatformAPI, PlatformError};
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
};
use windows_sys::core::PWSTR;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use tracing::{trace, error};

// Safe wrapper for PROCESS_INFORMATION
pub struct ProcessInfoSafe(pub PROCESS_INFORMATION);
unsafe impl Send for ProcessInfoSafe {}
unsafe impl Sync for ProcessInfoSafe {}

// Aligned wrapper for CONTEXT structure
#[repr(align(16))]
struct AlignedContext {
    context: CONTEXT,
}

pub struct WindowsPlatform {
    pid: Option<u32>,
    process_info: Option<ProcessInfoSafe>,
}

impl WindowsPlatform {
    pub fn new() -> Self {
        Self { pid: None, process_info: None }
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
    fn attach(&mut self, pid: u32) -> Result<(), PlatformError> {
        trace!(pid, "WindowsPlatform::attach called");
        self.pid = Some(pid);
        Ok(())
    }

    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        println!("[windows_platform] continue_exec thread id: {:?}", std::thread::current().id());
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
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), base_of_image = %format!("0x{:X}", info.lpBaseOfImage as u64), "ProcessCreated event");
                Some(crate::protocol::DebugEvent::ProcessCreated {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    image_file_name: None, // Not trivial to get here
                    base_of_image: info.lpBaseOfImage as u64,
                    size_of_image: None, // Not trivial to get here
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
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), base_of_dll = %format!("0x{:X}", info.lpBaseOfDll as u64), "DllLoaded event");
                Some(crate::protocol::DebugEvent::DllLoaded {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    dll_name: None, // Not trivial to get here
                    base_of_dll: info.lpBaseOfDll as u64,
                    size_of_dll: None, // Not trivial to get here
                })
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.UnloadDll };
                trace!(pid = %format!("0x{:X}", debug_event.dwProcessId), tid = %format!("0x{:X}", debug_event.dwThreadId), base_of_dll = %format!("0x{:X}", info.lpBaseOfDll as u64), "DllUnloaded event");
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
        self.process_info = Some(ProcessInfoSafe(process_info));
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
        Ok(Some(crate::protocol::DebugEvent::ProcessCreated { pid: process_info.dwProcessId, tid: process_info.dwThreadId, image_file_name: None, base_of_image: 0, size_of_image: None }))
    }

    fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError> {
        trace!(pid = %format!("0x{:X}", pid), address = %format!("0x{:X}", address), size, "WindowsPlatform::read_memory called");
        unsafe {
            let handle = if let Some(ref info) = self.process_info {
                if info.0.dwProcessId == pid && info.0.hProcess != std::ptr::null_mut() && info.0.hProcess != INVALID_HANDLE_VALUE {
                    info.0.hProcess
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
            let handle = if let Some(ref info) = self.process_info {
                if info.0.dwProcessId == pid && info.0.hProcess != std::ptr::null_mut() && info.0.hProcess != INVALID_HANDLE_VALUE {
                    info.0.hProcess
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
} 