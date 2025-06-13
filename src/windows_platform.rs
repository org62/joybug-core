#![allow(dead_code)]
use crate::interfaces::{PlatformAPI, PlatformError};
use async_trait::async_trait;
use windows_sys::Win32::System::Diagnostics::Debug::{WaitForDebugEvent, ContinueDebugEvent, DEBUG_EVENT};
use windows_sys::Win32::System::Threading::{CreateProcessW, STARTUPINFOW, PROCESS_INFORMATION, DEBUG_PROCESS, INFINITE};
use windows_sys::Win32::Foundation::{FALSE, GetLastError, DBG_CONTINUE};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

// Safe wrapper for PROCESS_INFORMATION
pub struct ProcessInfoSafe(pub PROCESS_INFORMATION);
unsafe impl Send for ProcessInfoSafe {}
unsafe impl Sync for ProcessInfoSafe {}

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
}

#[async_trait]
impl PlatformAPI for WindowsPlatform {
    async fn attach(&mut self, pid: u32) -> Result<(), PlatformError> {
        self.pid = Some(pid);
        Ok(())
    }

    async fn continue_exec(&mut self) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
        use windows_sys::Win32::System::Diagnostics::Debug::*;
        let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
        if wait_res == FALSE {
            return Err(PlatformError::OsError("WaitForDebugEvent failed".to_string()));
        }
        let event = match debug_event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let ex_info = unsafe { debug_event.u.Exception };
                let ex_record = ex_info.ExceptionRecord;
                if ex_record.ExceptionCode == windows_sys::Win32::Foundation::EXCEPTION_BREAKPOINT {
                    Some(crate::protocol::DebugEvent::Breakpoint {
                        pid: debug_event.dwProcessId,
                        tid: debug_event.dwThreadId,
                        address: ex_record.ExceptionAddress as u64,
                    })
                } else {
                    Some(crate::protocol::DebugEvent::Exception {
                        pid: debug_event.dwProcessId,
                        tid: debug_event.dwThreadId,
                        code: ex_record.ExceptionCode as u32,
                        address: ex_record.ExceptionAddress as u64,
                        first_chance: ex_info.dwFirstChance == 1,
                    })
                }
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.CreateProcessInfo };
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
                Some(crate::protocol::DebugEvent::ProcessExited {
                    pid: debug_event.dwProcessId,
                    exit_code: info.dwExitCode,
                })
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.CreateThread };
                Some(crate::protocol::DebugEvent::ThreadCreated {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    start_address: info.lpStartAddress.map_or(0, |addr| addr as usize as u64),
                })
            }
            EXIT_THREAD_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.ExitThread };
                Some(crate::protocol::DebugEvent::ThreadExited {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    exit_code: info.dwExitCode,
                })
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { debug_event.u.LoadDll };
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
                Some(crate::protocol::DebugEvent::DllUnloaded {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    base_of_dll: info.lpBaseOfDll as u64,
                })
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                // Not trivial to extract the string, so just a placeholder
                Some(crate::protocol::DebugEvent::Output {
                    output: "<debug string>".to_string(),
                })
            }
            RIP_EVENT => {
                let info = unsafe { debug_event.u.RipInfo };
                Some(crate::protocol::DebugEvent::RipEvent {
                    pid: debug_event.dwProcessId,
                    tid: debug_event.dwThreadId,
                    error: info.dwError,
                    event_type: info.dwType,
                })
            }
            _ => Some(crate::protocol::DebugEvent::Unknown),
        };
        let cont_res = unsafe {
            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
        };
        if cont_res == FALSE {
            return Err(PlatformError::OsError("ContinueDebugEvent failed".to_string()));
        }
        Ok(event)
    }

    async fn set_breakpoint(&mut self, _addr: u64) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    async fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> {
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
            return Err(PlatformError::OsError(format!("CreateProcessW failed: {}", error)));
        }
        self.process_info = Some(ProcessInfoSafe(process_info));
        self.pid = Some(process_info.dwProcessId);
        // Immediately run the debug loop for the new process
        let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        let wait_res = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
        if wait_res == FALSE {
            return Err(PlatformError::OsError("WaitForDebugEvent failed after launch".to_string()));
        }
        let cont_res = unsafe {
            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
        };
        if cont_res == FALSE {
            return Err(PlatformError::OsError("ContinueDebugEvent failed after launch".to_string()));
        }
        // Return a typed event for process started
        Ok(Some(crate::protocol::DebugEvent::ProcessStarted { pid: process_info.dwProcessId }))
    }
} 