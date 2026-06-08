use super::error::InlineHookError;

/// Trait for thread management during hook installation/removal.
///
/// Implementations can freeze/thaw threads or do nothing (debugger mode).
pub trait ThreadFreezer {
    /// Suspend all relevant threads before patching code.
    fn freeze(&mut self) -> Result<(), InlineHookError>;
    /// Adjust any thread whose RIP falls within `old_ip_range` (start, end exclusive)
    /// to the corresponding offset in the trampoline at `new_ip_base`.
    fn adjust_rips(
        &mut self,
        old_ip_range: (usize, usize),
        new_ip_base: usize,
    ) -> Result<(), InlineHookError>;
    /// Resume all suspended threads.
    fn thaw(&mut self) -> Result<(), InlineHookError>;
}

/// No-op freezer for debugger mode where threads are already suspended.
pub struct NoopThreadFreezer;

impl ThreadFreezer for NoopThreadFreezer {
    fn freeze(&mut self) -> Result<(), InlineHookError> {
        Ok(())
    }
    fn adjust_rips(
        &mut self,
        _old_ip_range: (usize, usize),
        _new_ip_base: usize,
    ) -> Result<(), InlineHookError> {
        Ok(())
    }
    fn thaw(&mut self) -> Result<(), InlineHookError> {
        Ok(())
    }
}

// --- Windows implementation ---

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
        THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    const THREAD_ACCESS: u32 =
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION;

    pub struct WindowsThreadFreezer {
        suspended: Vec<HANDLE>,
    }

    impl WindowsThreadFreezer {
        pub fn new() -> Self {
            Self {
                suspended: Vec::new(),
            }
        }

        fn get_last_error() -> u32 {
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        }
    }

    impl Drop for WindowsThreadFreezer {
        fn drop(&mut self) {
            // Safety net: resume any still-suspended threads.
            for &handle in &self.suspended {
                unsafe {
                    ResumeThread(handle);
                    CloseHandle(handle);
                }
            }
        }
    }

    impl ThreadFreezer for WindowsThreadFreezer {
        fn freeze(&mut self) -> Result<(), InlineHookError> {
            let pid = unsafe { GetCurrentProcessId() };
            let tid = unsafe { GetCurrentThreadId() };

            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == -1isize as HANDLE {
                return Err(InlineHookError::ThreadError(format!(
                    "CreateToolhelp32Snapshot failed: {}",
                    Self::get_last_error()
                )));
            }

            let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            let mut ok = unsafe { Thread32First(snapshot, &mut entry) };
            while ok != 0 {
                if entry.th32OwnerProcessID == pid && entry.th32ThreadID != tid {
                    let handle = unsafe { OpenThread(THREAD_ACCESS, 0, entry.th32ThreadID) };
                    if !handle.is_null() {
                        unsafe {
                            SuspendThread(handle);
                        }
                        self.suspended.push(handle);
                    }
                }
                ok = unsafe { Thread32Next(snapshot, &mut entry) };
            }

            unsafe {
                CloseHandle(snapshot);
            }
            Ok(())
        }

        fn adjust_rips(
            &mut self,
            old_ip_range: (usize, usize),
            new_ip_base: usize,
        ) -> Result<(), InlineHookError> {
            for &handle in &self.suspended {
                unsafe {
                    let mut ctx: CONTEXT = std::mem::zeroed();
                    ctx.ContextFlags = 0x00100001; // CONTEXT_CONTROL
                    if GetThreadContext(handle, &mut ctx) == 0 {
                        continue;
                    }
                    let rip = ctx.Rip as usize;
                    if rip >= old_ip_range.0 && rip < old_ip_range.1 {
                        let offset = rip - old_ip_range.0;
                        ctx.Rip = (new_ip_base + offset) as u64;
                        SetThreadContext(handle, &ctx);
                    }
                }
            }
            Ok(())
        }

        fn thaw(&mut self) -> Result<(), InlineHookError> {
            for handle in self.suspended.drain(..) {
                unsafe {
                    ResumeThread(handle);
                    CloseHandle(handle);
                }
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
pub use windows_impl::WindowsThreadFreezer;
