use super::{utils, WindowsPlatform};
use crate::interfaces::{PlatformAPI, PlatformError};
use tracing::{error, trace, warn};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

pub(super) fn read_memory_internal(
    handle: HANDLE,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, PlatformError> {
    trace!(address = %format!("0x{:X}", address), size, "read_memory_internal called");
    unsafe {
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

pub(super) fn read_memory(
    platform: &mut WindowsPlatform,
    pid: u32,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), size, "WindowsPlatform::read_memory called");
    let process = platform.get_process(pid)?;
    let handle = process.process_handle.0;
    read_memory_internal(handle, address, size)
}

pub(super) fn read_memory_unlocked(
    pid: u32,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), size, "read_memory_unlocked called");
    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ, 0, pid);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            error!(error, error_str, "OpenProcess(PROCESS_VM_READ) failed");
            return Err(PlatformError::OsError(format!(
                "OpenProcess(PROCESS_VM_READ) failed: {} ({})",
                error, error_str
            )));
        }
        let res = read_memory_internal(handle, address, size);
        // Intentionally do not CloseHandle here: for PROCESS_VM_READ OpenProcess returns a handle we own; we should close it.
        windows_sys::Win32::Foundation::CloseHandle(handle);
        res
    }
}

pub(super) fn write_memory_internal(
    handle: HANDLE,
    address: u64,
    data: &[u8],
) -> Result<(), PlatformError> {
    trace!(address = %format!("0x{:X}", address), data_len = data.len(), "write_memory_internal called");
    unsafe {
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

pub(super) fn write_memory(
    platform: &mut WindowsPlatform,
    pid: u32,
    address: u64,
    data: &[u8],
) -> Result<(), PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), data_len = data.len(), "WindowsPlatform::write_memory called");
    let process = platform.get_process(pid)?;
    let handle = process.process_handle.0;
    write_memory_internal(handle, address, data)
}

pub(super) fn read_wide_string(
    platform: &mut WindowsPlatform,
    pid: u32,
    address: u64,
    max_len: Option<usize>, // Number of characters
) -> Result<String, PlatformError> {
    let mut buffer = Vec::new();

    if let Some(len) = max_len {
        // Length is known, read exactly that many bytes.
        let bytes_to_read = len * 2;
        buffer = platform.read_memory(pid, address, bytes_to_read)?;
    } else {
        // Length is unknown, read in chunks until null terminator.
        const CHUNK_SIZE: usize = 64; // read 64 bytes at a time
        let mut total_read_bytes = 0;
        const MAX_TOTAL_READ: usize = 4096 * 2; // safety break at 8KB

        loop {
            let chunk = platform.read_memory(pid, address + total_read_bytes as u64, CHUNK_SIZE)?;
            if chunk.is_empty() {
                break; // End of memory
            }

            // Check for null terminator (two consecutive null bytes for UTF-16)
            if let Some(null_pos_bytes) = chunk.windows(2).position(|w| w == [0, 0]) {
                buffer.extend_from_slice(&chunk[..null_pos_bytes]);
                break;
            } else {
                buffer.extend_from_slice(&chunk);
            }

            total_read_bytes += chunk.len();
            if total_read_bytes >= MAX_TOTAL_READ {
                warn!("read_wide_string reached max read limit of {} bytes without finding a null terminator.", MAX_TOTAL_READ);
                break;
            }
        }
    }

    // Decode UTF-16LE
    let wide_chars: Vec<u16> = buffer.chunks_exact(2)
        .map(|a| u16::from_le_bytes([a[0], a[1]]))
        .collect();
    
    let result = String::from_utf16_lossy(&wide_chars);
    Ok(result.trim().to_string())
} 