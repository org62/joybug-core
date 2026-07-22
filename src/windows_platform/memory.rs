use super::{utils, WindowsPlatform};
use crate::interfaces::{PlatformAPI, PlatformError};
use tracing::{error, trace, warn, debug};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION};

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

            // If we got partial data, return it with a warning instead of failing
            if bytes_read > 0 {
                debug!(
                    address = %format!("0x{:X}", address),
                    requested_size = size,
                    bytes_read,
                    error,
                    error_str,
                    "ReadProcessMemory partial read"
                );
                buffer.truncate(bytes_read);
                return Ok(buffer);
            }

            // If error 299 (ERROR_PARTIAL_COPY) with bytes_read == 0,
            // query region and retry with clamped size
            const ERROR_PARTIAL_COPY: u32 = 299;
            if error == ERROR_PARTIAL_COPY {
                warn!(address = %format!("0x{:X}", address), "ERROR_PARTIAL_COPY fallback triggered");
                let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let query_result = VirtualQueryEx(
                    handle,
                    address as *const std::ffi::c_void,
                    &mut mem_info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if query_result != 0 {
                    const MEM_COMMIT: u32 = 0x1000;
                    let region_base = mem_info.BaseAddress as u64;
                    let region_end = region_base + (mem_info.RegionSize as u64);
                    warn!(
                        region_base = %format!("0x{:X}", region_base),
                        region_end = %format!("0x{:X}", region_end),
                        region_size = %format!("0x{:X}", mem_info.RegionSize),
                        state = %format!("0x{:X}", mem_info.State),
                        "VirtualQueryEx succeeded"
                    );
                    if mem_info.State == MEM_COMMIT {
                        if address < region_end {
                            let available = (region_end - address) as usize;
                            warn!(available, size, "Checking available vs requested size");
                            if available > 0 && available < size {
                                // Retry with clamped size
                                let mut retry_buffer = vec![0u8; available];
                                let mut retry_bytes_read = 0;
                                let retry_ok = ReadProcessMemory(
                                    handle,
                                    address as *const std::ffi::c_void,
                                    retry_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                                    available,
                                    &mut retry_bytes_read,
                                );
                                warn!(retry_ok, retry_bytes_read, "Retry read result");
                                if retry_ok != 0 || retry_bytes_read > 0 {
                                    retry_buffer.truncate(retry_bytes_read);
                                    warn!(
                                        address = %format!("0x{:X}", address),
                                        requested_size = size,
                                        available_in_region = available,
                                        bytes_read = retry_bytes_read,
                                        "ReadProcessMemory partial read (region-clamped retry)"
                                    );
                                    return Ok(retry_buffer);
                                }
                            }
                        }
                    }
                } else {
                    let query_error = GetLastError();
                    warn!(query_error, "VirtualQueryEx failed");
                }
            }

            error!(
                address = %format!("0x{:X}", address),
                size,
                error,
                error_str,
                "ReadProcessMemory failed"
            );
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
    platform: &WindowsPlatform,
    pid: u32,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), size, "WindowsPlatform::read_memory called");
    let process = platform.get_process(pid)?;
    let handle = process.handle();
    read_memory_internal(handle, address, size)
}

pub(super) fn read_memory_unlocked(
    pid: u32,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), size, "read_memory_unlocked called");
    unsafe {
        // Include PROCESS_QUERY_INFORMATION for VirtualQueryEx fallback on partial reads
        let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            error!(error, error_str, "OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) failed");
            return Err(PlatformError::OsError(format!(
                "OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) failed: {} ({})",
                error, error_str
            )));
        }
        let res = read_memory_internal(handle, address, size);
        windows_sys::Win32::Foundation::CloseHandle(handle);
        res
    }
}

/// Minimal `PROCESS_VM_READ` handle for a run of `try_read_pointer` calls.
/// `None` (silently — the reads are speculative) if the process can't be opened.
pub(super) fn open_vm_read_handle(pid: u32) -> Option<super::HandleSafe> {
    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ, 0, pid);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(super::HandleSafe(handle))
        }
    }
}

/// Best-effort 8-byte pointer read: a plain `ReadProcessMemory` with NO
/// partial-read `VirtualQueryEx` fallback and NO error logging. `None` on any
/// failure. For SPECULATIVE reads where a miss is expected and ignored — chiefly
/// resolving indirect jump/call targets during disassembly. When code is
/// misdecoded (e.g. data disassembled as `call [garbage]`), the target often
/// lands in unmapped memory; the full path would then run a wasted VirtualQueryEx
/// and log an ERROR per instruction, spamming the log and adding tens of ms.
/// Takes an open handle (see `open_vm_read_handle`) so a decode batch with
/// hundreds of indirect targets pays one OpenProcess, not one per instruction.
pub(super) fn try_read_pointer(handle: HANDLE, address: u64) -> Option<u64> {
    unsafe {
        let mut buf = [0u8; 8];
        let mut bytes_read: usize = 0;
        let ok = ReadProcessMemory(
            handle,
            address as *const std::ffi::c_void,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            8,
            &mut bytes_read,
        );
        (ok != 0 && bytes_read == 8).then(|| u64::from_le_bytes(buf))
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
    platform: &WindowsPlatform,
    pid: u32,
    address: u64,
    data: &[u8],
) -> Result<(), PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), data_len = data.len(), "WindowsPlatform::write_memory called");
    match platform.get_process(pid) {
        Ok(process) => write_memory_internal(process.handle(), address, data),
        Err(_) => write_memory_unlocked(pid, address, data),
    }
}

/// Write memory using an on-demand `OpenProcess` handle (no debug attach required).
/// Mirrors `read_memory_unlocked`.
pub(super) fn write_memory_unlocked(
    pid: u32,
    address: u64,
    data: &[u8],
) -> Result<(), PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), data_len = data.len(), "write_memory_unlocked called");
    unsafe {
        let handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            error!(error, error_str, "OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ) failed");
            return Err(PlatformError::OsError(format!(
                "OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ) failed: {} ({})",
                error, error_str
            )));
        }
        let res = write_memory_internal(handle, address, data);
        if res.is_ok() {
            // Best-effort: keep code caches coherent after patching executable memory.
            FlushInstructionCache(handle, address as *const std::ffi::c_void, data.len());
        }
        windows_sys::Win32::Foundation::CloseHandle(handle);
        res
    }
}

pub(super) fn read_wide_string(
    platform: &WindowsPlatform,
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

pub(super) fn query_memory_region_unlocked(
    pid: u32,
    address: u64,
) -> Result<crate::protocol::MemoryRegionInfo, PlatformError> {
    trace!(pid, address = %format!("0x{:X}", address), "query_memory_region_unlocked");
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            error!(error, error_str, "OpenProcess(PROCESS_QUERY_INFORMATION) failed");
            return Err(PlatformError::OsError(format!(
                "OpenProcess failed: {} ({})", error, error_str
            )));
        }

        let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let result = VirtualQueryEx(
            handle,
            address as *const std::ffi::c_void,
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        windows_sys::Win32::Foundation::CloseHandle(handle);

        if result == 0 {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            error!(address = %format!("0x{:X}", address), error, error_str, "VirtualQueryEx failed");
            return Err(PlatformError::OsError(format!(
                "VirtualQueryEx failed: {} ({})", error, error_str
            )));
        }

        trace!(
            base_address = %format!("0x{:X}", mem_info.BaseAddress as u64),
            region_size = %format!("0x{:X}", mem_info.RegionSize),
            state = %format!("0x{:X}", mem_info.State),
            "query_memory_region_unlocked succeeded"
        );

        Ok(crate::protocol::MemoryRegionInfo {
            base_address: mem_info.BaseAddress as u64,
            allocation_base: mem_info.AllocationBase as u64,
            allocation_protect: mem_info.AllocationProtect,
            region_size: mem_info.RegionSize as u64,
            state: mem_info.State,
            protect: mem_info.Protect,
            region_type: mem_info.Type,
        })
    }
}

pub(super) fn enumerate_memory_regions_unlocked(
    pid: u32,
) -> Result<Vec<crate::protocol::MemoryRegionInfo>, PlatformError> {
    trace!(pid, "enumerate_memory_regions_unlocked");
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = GetLastError();
            let error_str = utils::error_message(error);
            error!(error, error_str, "OpenProcess(PROCESS_QUERY_INFORMATION) failed");
            return Err(PlatformError::OsError(format!(
                "OpenProcess failed: {} ({})", error, error_str
            )));
        }

        let mut regions = Vec::new();
        let mut address: u64 = 0;

        loop {
            let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQueryEx(
                handle,
                address as *const std::ffi::c_void,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                // End of address space or error - stop enumeration
                break;
            }

            regions.push(crate::protocol::MemoryRegionInfo {
                base_address: mem_info.BaseAddress as u64,
                allocation_base: mem_info.AllocationBase as u64,
                allocation_protect: mem_info.AllocationProtect,
                region_size: mem_info.RegionSize as u64,
                state: mem_info.State,
                protect: mem_info.Protect,
                region_type: mem_info.Type,
            });

            // Move to next region
            let next_address = (mem_info.BaseAddress as u64).wrapping_add(mem_info.RegionSize as u64);
            if next_address <= address {
                // Overflow or no progress - stop
                break;
            }
            address = next_address;
        }

        windows_sys::Win32::Foundation::CloseHandle(handle);
        trace!(region_count = regions.len(), "enumerate_memory_regions complete");
        Ok(regions)
    }
} 