//! DLL injection into a target process via CreateRemoteThread + LoadLibraryA.

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

use crate::interfaces::PlatformError;

type HANDLE = *mut core::ffi::c_void;

/// Inject a DLL into the target process by path.
///
/// Uses the classic CreateRemoteThread + LoadLibraryA technique.
/// Does NOT check the LoadLibraryA return value because on x64 the HMODULE
/// (64-bit pointer) is truncated to a 32-bit DWORD exit code, making the
/// check unreliable. Instead, the caller should detect success by waiting
/// for the initial breakpoint event from the injected DLL.
pub fn inject_dll(process_handle: HANDLE, dll_path: &str) -> Result<(), PlatformError> {
    let dll_path_cstr = format!("{}\0", dll_path);
    let path_bytes = dll_path_cstr.as_bytes();
    let path_len = path_bytes.len();

    unsafe {
        let remote_mem = VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            return Err(PlatformError::OsError(format!(
                "VirtualAllocEx failed: {}",
                GetLastError()
            )));
        }

        let mut bytes_written = 0usize;
        let write_ok = WriteProcessMemory(
            process_handle,
            remote_mem,
            path_bytes.as_ptr() as *const _,
            path_len,
            &mut bytes_written,
        );
        if write_ok == 0 {
            let err = GetLastError();
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(PlatformError::OsError(format!(
                "WriteProcessMemory (DLL path) failed: {}",
                err
            )));
        }

        // kernel32 is at the same address in every process on a given boot,
        // so we can pass our own LoadLibraryA address to CreateRemoteThread.
        let kernel32: HANDLE = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if kernel32.is_null() {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(PlatformError::OsError(
                "GetModuleHandleA(kernel32) failed".into(),
            ));
        }
        let load_library_addr = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr());
        let load_library_addr = match load_library_addr {
            Some(addr) => addr,
            None => {
                VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                return Err(PlatformError::OsError(
                    "GetProcAddress(LoadLibraryA) failed".into(),
                ));
            }
        };

        let thread_proc: LPTHREAD_START_ROUTINE =
            Some(std::mem::transmute(load_library_addr as usize));
        let mut thread_id = 0u32;
        let thread: HANDLE = CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            thread_proc,
            remote_mem,
            0,
            &mut thread_id,
        );
        if thread.is_null() {
            let err = GetLastError();
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(PlatformError::OsError(format!(
                "CreateRemoteThread failed: {}",
                err
            )));
        }

        WaitForSingleObject(thread, INFINITE);

        // Don't check the thread exit code: on x64, LoadLibraryA returns a
        // 64-bit HMODULE but GetExitCodeThread truncates to 32-bit DWORD, so
        // a valid HMODULE with zero in the low 32 bits would look like failure.
        // The caller detects success via the initial breakpoint event.

        CloseHandle(thread);
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

        Ok(())
    }
}
