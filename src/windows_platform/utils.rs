use tracing::{error, warn, trace};
use windows_sys::Win32::Foundation::{
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleA;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

/// Gets the file path from a Windows file handle.
/// 
/// This function uses the Windows API GetFinalPathNameByHandleA to retrieve
/// the full path of a file given its handle. It handles buffer resizing
/// automatically if the initial buffer is too small.
/// 
/// # Arguments
/// * `file_handle` - A valid Windows file handle
/// 
/// # Returns
/// * `Some(String)` - The file path if successful
/// * `None` - If the handle is invalid or the operation fails
pub fn get_path_from_handle(file_handle: HANDLE) -> Option<String> {
    if std::ptr::eq(file_handle, INVALID_HANDLE_VALUE) || file_handle.is_null() {
        warn!("Invalid file handle provided to get_path_from_handle");
        return None;
    }

    let mut path_buffer: Vec<u8> = vec![0u8; MAX_PATH as usize];
    let mut path_len: u32;

    // FILE_NAME_NORMALIZED 0x0
    // VOLUME_NAME_DOS 0x0
    let flags = 0x0; 

    loop {
        path_len = unsafe {
            GetFinalPathNameByHandleA(
                file_handle,
                path_buffer.as_mut_ptr(),
                path_buffer.len() as u32,
                flags,
            )
        };

        if path_len == 0 {
            let error_code = unsafe { GetLastError() };
            error!(error_code = %error_code, "GetFinalPathNameByHandleA failed");
            return None;
        }

        if path_len > path_buffer.len() as u32 {
            trace!(current_size = %path_buffer.len(), needed_size = %path_len, "Buffer too small, resizing");
            path_buffer.resize(path_len as usize, 0u8);
        } else {
            break;
        }
    }
    
    let actual_len = path_buffer.iter().position(|&c| c == 0).unwrap_or(path_len as usize);
    
    if actual_len == 0 {
         warn!("get_path_from_handle: Resulting path length is zero");
        return None;
    }

    match String::from_utf8(path_buffer[..actual_len].to_vec()) {
        Ok(mut path_str) => {
            if path_str.starts_with("\\\\?\\") {
                path_str = path_str[4..].to_string();
            }
            Some(path_str)
        }
        Err(_) => {
            warn!(bytes = ?&path_buffer[..actual_len], "get_path_from_handle: Failed to convert path from UTF-8 (actually ANSI)");
            None
        }
    }
}

/// Gets the size of a module (DLL/EXE) loaded at the specified base address by reading PE headers.
/// 
/// This function reads the PE (Portable Executable) header from the target process
/// to determine the size of the module loaded at the given base address.
/// 
/// # Arguments
/// * `process_handle` - A valid handle to the target process
/// * `module_base` - The base address where the module is loaded
/// 
/// # Returns
/// * `Some(usize)` - The module size in bytes if successful
/// * `None` - If the operation fails
pub fn get_module_size_from_address(process_handle: HANDLE, module_base: usize) -> Option<usize> {
    if process_handle.is_null() || std::ptr::eq(process_handle, INVALID_HANDLE_VALUE) {
        warn!("Invalid process handle provided to get_module_size_from_address");
        return None;
    }

    // Read DOS header to get PE header offset
    let mut dos_header = vec![0u8; 64]; // sizeof(IMAGE_DOS_HEADER)
    let mut bytes_read = 0;

    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            module_base as *const _,
            dos_header.as_mut_ptr() as *mut _,
            dos_header.len(),
            &mut bytes_read,
        )
    };

    if success == 0 || bytes_read != dos_header.len() {
        let error_code = unsafe { GetLastError() };
        error!(
            error_code = %error_code,
            module_base = format_args!("0x{:X}", module_base),
            "Failed to read DOS header"
        );
        return None;
    }

    // Check DOS signature "MZ"
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        warn!(
            module_base = format_args!("0x{:X}", module_base),
            "Invalid DOS signature"
        );
        return None;
    }

    // Get PE header offset (at offset 0x3C in DOS header)
    let pe_offset = u32::from_le_bytes([
        dos_header[0x3C],
        dos_header[0x3D], 
        dos_header[0x3E],
        dos_header[0x3F],
    ]) as usize;

    // Read PE signature and optional header
    let mut pe_header = vec![0u8; 256]; // Enough for PE signature + file header + optional header start
    let pe_address = module_base + pe_offset;

    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            pe_address as *const _,
            pe_header.as_mut_ptr() as *mut _,
            pe_header.len(),
            &mut bytes_read,
        )
    };

    if success == 0 || bytes_read < 24 { // Need at least PE sig + file header
        let error_code = unsafe { GetLastError() };
        error!(
            error_code = %error_code,
            module_base = format_args!("0x{:X}", module_base),
            pe_address = format_args!("0x{:X}", pe_address),
            "Failed to read PE header"
        );
        return None;
    }

    // Check PE signature "PE\0\0"
    if pe_header[0] != b'P' || pe_header[1] != b'E' || pe_header[2] != 0 || pe_header[3] != 0 {
        warn!(
            module_base = format_args!("0x{:X}", module_base),
            "Invalid PE signature"
        );
        return None;
    }

    // Skip PE signature (4 bytes) + file header (20 bytes) to get to optional header
    // SizeOfImage is at offset 56 in the optional header (for both PE32 and PE32+)
    let optional_header_start = 4 + 20; // PE sig + file header size
    let size_of_image_offset = optional_header_start + 56;

    if bytes_read < size_of_image_offset + 4 {
        error!(
            module_base = format_args!("0x{:X}", module_base),
            "PE header too small to contain SizeOfImage"
        );
        return None;
    }

    let size_of_image = u32::from_le_bytes([
        pe_header[size_of_image_offset],
        pe_header[size_of_image_offset + 1],
        pe_header[size_of_image_offset + 2],
        pe_header[size_of_image_offset + 3],
    ]) as usize;

    trace!(
        module_base = format_args!("0x{:X}", module_base),
        size_of_image = format_args!("0x{:X}", size_of_image),
        "Successfully retrieved module size from PE header"
    );

    Some(size_of_image)
} 