use super::{utils, WindowsPlatform};
use crate::interfaces::{PlatformAPI, PlatformError};
use tracing::{error, trace, warn, debug};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION};

/// x86/x64/ARM64 all use 4 KiB pages; the probe splits reads on this boundary.
const PAGE_SIZE: u64 = 0x1000;

/// `ReadProcessMemory` failed but part of the range may still be accessible.
const ERROR_PARTIAL_COPY: u32 = 299;

/// State/protection of the region containing `address`, for error messages.
fn describe_address(handle: HANDLE, address: u64) -> String {
    match unsafe { query_region(handle, address) } {
        Some(info) => format!(
            "{} {}",
            crate::formatting::memory::state_to_str(info.State),
            crate::formatting::memory::protect_to_str(info.Protect)
        ),
        None => "unmapped".to_string(),
    }
}

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

            // ERROR_PARTIAL_COPY only says the range isn't readable as one
            // block — most of it usually is. Walk it region by region (and page
            // by page within a region) to salvage the accessible prefix. This
            // covers a read running off the end of a committed region, a hole in
            // the middle of one, and guard pages, which RPM refuses outright.
            if error == ERROR_PARTIAL_COPY {
                let probed = read_memory_probed(handle, address, size);
                if probed.len() > bytes_read {
                    debug!(
                        address = %format!("0x{:X}", address),
                        requested_size = size,
                        bytes_read = probed.len(),
                        "ReadProcessMemory partial read (region/page probe)"
                    );
                    return Ok(probed);
                }
            }

            // RPM managed a partial copy on its own — return that rather than fail.
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

            // Nothing was readable. Say WHY in the message itself — "299" alone
            // sends every such report on a hunt for the region's real state.
            let why = describe_address(handle, address);
            error!(
                address = %format!("0x{:X}", address),
                size,
                error,
                error_str,
                why,
                "ReadProcessMemory failed"
            );
            return Err(PlatformError::OsError(format!(
                "ReadProcessMemory failed at 0x{:X}: {} — {} ({})",
                address, why, error, error_str
            )));
        }
        buffer.truncate(bytes_read);
        trace!(bytes_read, "ReadProcessMemory succeeded");
        Ok(buffer)
    }
}

/// `VirtualQueryEx` wrapper: the region containing `address`, or `None`.
unsafe fn query_region(handle: HANDLE, address: u64) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let queried = unsafe {
        VirtualQueryEx(
            handle,
            address as *const std::ffi::c_void,
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    (queried != 0).then_some(info)
}

/// One `ReadProcessMemory` call. Returns however many bytes it actually copied
/// (possibly none); never logs — the callers below expect misses.
unsafe fn raw_read(handle: HANDLE, address: u64, size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const std::ffi::c_void,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            size,
            &mut bytes_read,
        )
    };
    buffer.truncate(if ok != 0 { bytes_read } else { bytes_read.min(size) });
    buffer
}

/// Read up to `size` bytes, falling back to one call per page when the whole
/// range fails. A single unreadable page inside an otherwise fine range would
/// otherwise cost the entire read; the prefix before it is still worth having.
unsafe fn read_pagewise(handle: HANDLE, address: u64, size: usize) -> Vec<u8> {
    let bulk = unsafe { raw_read(handle, address, size) };
    if bulk.len() == size {
        return bulk;
    }

    let mut out: Vec<u8> = Vec::with_capacity(size);
    while out.len() < size {
        let cursor = address + out.len() as u64;
        let to_page_end = (PAGE_SIZE - (cursor & (PAGE_SIZE - 1))) as usize;
        let want = to_page_end.min(size - out.len());
        let page = unsafe { raw_read(handle, cursor, want) };
        let got = page.len();
        out.extend_from_slice(&page);
        if got < want {
            break;
        }
    }
    // The bulk call can still win when RPM reported a longer partial copy.
    if bulk.len() > out.len() { bulk } else { out }
}

/// Read a `PAGE_GUARD` range. `ReadProcessMemory` can't: the copy trips the
/// guard and fails with ERROR_PARTIAL_COPY without ever yielding bytes. Clear
/// the guard bit for the duration of the read and re-arm it immediately, which
/// is what keeps a stack guard page doing its job (growing the stack on the next
/// touch). The unguarded window is a single RPM call wide; it needs
/// `PROCESS_VM_OPERATION` on the handle, and yields nothing when absent.
unsafe fn read_guarded(handle: HANDLE, address: u64, size: usize, protect: u32) -> Vec<u8> {
    let mut previous: u32 = 0;
    let unguarded = protect & !PAGE_GUARD;
    let ok = unsafe {
        VirtualProtectEx(
            handle,
            address as *const std::ffi::c_void,
            size,
            unguarded,
            &mut previous,
        )
    };
    if ok == 0 {
        let error = unsafe { GetLastError() };
        debug!(
            address = %format!("0x{:X}", address),
            error,
            "VirtualProtectEx could not lift PAGE_GUARD for read"
        );
        return Vec::new();
    }

    let data = unsafe { read_pagewise(handle, address, size) };

    let mut restored: u32 = 0;
    let restore_ok = unsafe {
        VirtualProtectEx(
            handle,
            address as *const std::ffi::c_void,
            size,
            previous,
            &mut restored,
        )
    };
    if restore_ok == 0 {
        // The target keeps running with a disarmed guard page — loud on purpose.
        let error = unsafe { GetLastError() };
        error!(
            address = %format!("0x{:X}", address),
            size,
            protect = %format!("0x{:X}", previous),
            error,
            "Failed to re-arm PAGE_GUARD after read"
        );
    }
    data
}

/// Salvage what is readable of `[address, address + size)` after a failed bulk
/// `ReadProcessMemory`, walking one committed region at a time. Stops at the
/// first byte that can't be read — the result is always a prefix of the request,
/// so callers can treat a short result as "accessible memory ends here".
fn read_memory_probed(handle: HANDLE, address: u64, size: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    while out.len() < size {
        let cursor = address + out.len() as u64;
        let Some(info) = (unsafe { query_region(handle, cursor) }) else { break };
        let region_end = (info.BaseAddress as u64).saturating_add(info.RegionSize as u64);
        if info.State != MEM_COMMIT || region_end <= cursor {
            break;
        }
        // PAGE_NOACCESS is genuinely unreadable; unlike PAGE_GUARD there is no
        // transient protection change that would make it readable.
        if info.Protect & PAGE_NOACCESS != 0 {
            break;
        }

        let want = ((region_end - cursor) as usize).min(size - out.len());
        let chunk = unsafe {
            if info.Protect & PAGE_GUARD != 0 {
                read_guarded(handle, cursor, want, info.Protect)
            } else {
                read_pagewise(handle, cursor, want)
            }
        };
        let got = chunk.len();
        out.extend_from_slice(&chunk);
        if got < want {
            break;
        }
    }
    out
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
        // PROCESS_QUERY_INFORMATION for the VirtualQueryEx probe on partial reads,
        // PROCESS_VM_OPERATION so that probe can also lift PAGE_GUARD. The latter
        // is a nice-to-have: retry without it rather than lose reads entirely.
        let mut handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
            0,
            pid,
        );
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        }
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
        let write = |written: &mut usize| WriteProcessMemory(
            handle,
            address as *mut std::ffi::c_void,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            written,
        );
        let mut ok = write(&mut bytes_written);
        if ok == 0 || bytes_written != data.len() {
            // WriteProcessMemory relaxes protection itself for an executable page
            // (so code breakpoints land), but not for a plain read-only data page
            // — writing an IAT slot to hook an import fails with ERROR_NOACCESS.
            // Flip the page to RW, retry, and restore the original protection.
            let mut old_protect = 0u32;
            if VirtualProtectEx(handle, address as *const _, data.len(), PAGE_READWRITE, &mut old_protect) != 0 {
                ok = write(&mut bytes_written);
                let mut ignored = 0u32;
                VirtualProtectEx(handle, address as *const _, data.len(), old_protect, &mut ignored);
            }
        }
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
        // Best-effort: keep code caches coherent after patching executable
        // memory (a stub or inline patch written through the debug handle is
        // executed next, and ARM64 caches are not coherent with stores).
        FlushInstructionCache(handle, address as *const std::ffi::c_void, data.len());
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
        windows_sys::Win32::Foundation::CloseHandle(handle);
        res
    }
}

pub(super) fn allocate_memory(
    platform: &WindowsPlatform,
    pid: u32,
    size: usize,
    executable: bool,
) -> Result<u64, PlatformError> {
    trace!(pid, size, executable, "WindowsPlatform::allocate_memory called");
    match platform.get_process(pid) {
        Ok(process) => allocate_memory_internal(process.handle(), size, executable),
        Err(_) => unsafe {
            let handle = OpenProcess(PROCESS_VM_OPERATION, 0, pid);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                let error = GetLastError();
                return Err(PlatformError::OsError(format!(
                    "OpenProcess(PROCESS_VM_OPERATION) failed: {} ({})",
                    error,
                    utils::error_message(error)
                )));
            }
            let res = allocate_memory_internal(handle, size, executable);
            windows_sys::Win32::Foundation::CloseHandle(handle);
            res
        },
    }
}

fn allocate_memory_internal(handle: HANDLE, size: usize, executable: bool) -> Result<u64, PlatformError> {
    let protect = if executable { PAGE_EXECUTE_READWRITE } else { PAGE_READWRITE };
    let base = unsafe { VirtualAllocEx(handle, std::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, protect) };
    if base.is_null() {
        let error = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "VirtualAllocEx({size} bytes) failed: {} ({})",
            error,
            utils::error_message(error)
        )));
    }
    Ok(base as u64)
}

pub(super) fn read_wide_string(
    platform: &WindowsPlatform,
    pid: u32,
    address: u64,
    max_len: Option<usize>, // Number of characters
) -> Result<String, PlatformError> {
    let mut buffer = Vec::new();

    if let Some(len) = max_len {
        // Length is known: read exactly that many characters; a NUL inside the
        // window still terminates the string (decode_wide_until_nul).
        let bytes_to_read = len * 2;
        buffer = platform.read_memory(pid, address, bytes_to_read)?;
    } else {
        // Length is unknown, read in chunks until the null terminator. The chunk
        // size is even, so every chunk starts on a character boundary and the
        // u16-aligned scan below never sees a torn character.
        const CHUNK_SIZE: usize = 64; // read 64 bytes at a time
        let mut total_read_bytes = 0;
        const MAX_TOTAL_READ: usize = 4096 * 2; // safety break at 8KB

        loop {
            let chunk = platform.read_memory(pid, address + total_read_bytes as u64, CHUNK_SIZE)?;
            if chunk.is_empty() {
                break; // End of memory
            }

            // Only the new chunk needs scanning (it starts on a character
            // boundary); the decode below cuts at the terminator.
            let terminated = wide_nul_position(&chunk).is_some();
            buffer.extend_from_slice(&chunk);
            if terminated {
                break;
            }

            total_read_bytes += chunk.len();
            if total_read_bytes >= MAX_TOTAL_READ {
                warn!("read_wide_string reached max read limit of {} bytes without finding a null terminator.", MAX_TOTAL_READ);
                break;
            }
        }
    }

    // Trim surrounding whitespace at the public boundary (long-standing
    // behavior; some callers pass a length-counted buffer that includes a
    // trailing CRLF). The B1 fix is the terminator handling in
    // `decode_wide_until_nul`, which is orthogonal to trimming.
    Ok(decode_wide_until_nul(&buffer).trim().to_string())
}

/// Byte offset of the first NUL *character* (a `[0, 0]` pair on a u16 boundary)
/// in a UTF-16LE buffer. A byte-pair search (`windows(2)`) is wrong here: it also
/// matches the high byte of the last ASCII character followed by the low byte
/// of the terminator, which sits on an odd offset and cuts that character off.
fn wide_nul_position(bytes: &[u8]) -> Option<usize> {
    bytes.chunks_exact(2).position(|c| c == [0, 0]).map(|i| i * 2)
}

/// Decode a UTF-16LE buffer up to (not including) its first NUL character. A
/// trailing odd byte is ignored; whitespace is data and is preserved.
pub(crate) fn decode_wide_until_nul(bytes: &[u8]) -> String {
    let end = wide_nul_position(bytes).unwrap_or(bytes.len());
    let wide_chars: Vec<u16> = bytes[..end]
        .chunks_exact(2)
        .map(|a| u16::from_le_bytes([a[0], a[1]]))
        .collect();
    String::from_utf16_lossy(&wide_chars)
}

#[cfg(test)]
mod wide_string_tests {
    use super::decode_wide_until_nul;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn keeps_the_last_character_before_the_terminator() {
        // "UnholyDragon\0": the retro's B1 — the old byte-pair scan matched the
        // `00 00` straddling 'n' and the NUL and returned "UnholyDrago".
        let mut bytes = utf16("UnholyDragon");
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(decode_wide_until_nul(&bytes), "UnholyDragon");
    }

    #[test]
    fn stops_at_the_first_nul_and_ignores_what_follows() {
        let mut bytes = utf16("a.ex");
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend(utf16("junk"));
        assert_eq!(decode_wide_until_nul(&bytes), "a.ex");
    }

    #[test]
    fn no_terminator_decodes_everything_and_drops_a_torn_byte() {
        let mut bytes = utf16("abc");
        bytes.push(0x41); // half of a character
        assert_eq!(decode_wide_until_nul(&bytes), "abc");
    }

    #[test]
    fn whitespace_is_preserved() {
        let mut bytes = utf16("  padded  ");
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(decode_wide_until_nul(&bytes), "  padded  ");
    }

    #[test]
    fn a_nul_low_byte_inside_a_character_is_not_a_terminator() {
        // U+0100 is `00 01` on the wire: its low byte is zero, and the character
        // before it ends in `00` too — a byte-pair scan would stop here.
        let mut bytes = utf16("aĀb");
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(decode_wide_until_nul(&bytes), "aĀb");
    }
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