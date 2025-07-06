use super::{utils, WindowsPlatform};
use crate::interfaces::PlatformError;
use tracing::{error, trace};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};

pub(super) fn read_memory(
    platform: &mut WindowsPlatform,
    pid: u32,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), size, "WindowsPlatform::read_memory called");
    unsafe {
        let process = platform.get_process(pid)?;
        let handle = process.process_handle.0;
        
        if handle == std::ptr::null_mut() || handle == INVALID_HANDLE_VALUE {
            error!("No valid process handle for memory read");
            return Err(PlatformError::OsError(
                "No valid process handle for memory read".to_string(),
            ));
        }
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
            let error_str = utils::error_message(error);
            error!(error, error_str, "ReadProcessMemory failed");
            return Err(PlatformError::OsError(format!(
                "ReadProcessMemory failed: {} ({})",
                error, error_str
            )));
        }
        buffer.truncate(bytes_read);
        trace!(bytes_read, "ReadProcessMemory succeeded");
        Ok(buffer)
    }
}

pub(super) fn write_memory(
    platform: &mut WindowsPlatform,
    pid: u32,
    address: u64,
    data: &[u8],
) -> Result<(), PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), data_len = data.len(), "WindowsPlatform::write_memory called");
    unsafe {
        let process = platform.get_process(pid)?;
        let handle = process.process_handle.0;
        
        if handle == std::ptr::null_mut() || handle == INVALID_HANDLE_VALUE {
            error!("No valid process handle for memory write");
            return Err(PlatformError::OsError(
                "No valid process handle for memory write".to_string(),
            ));
        }
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
            let error_str = utils::error_message(error);
            error!(ok, bytes_written, error, error_str, "WriteProcessMemory failed");
            return Err(PlatformError::OsError(format!(
                "WriteProcessMemory failed: {} ({})",
                error, error_str
            )));
        }
        trace!(bytes_written, "WriteProcessMemory succeeded");
        Ok(())
    }
} 