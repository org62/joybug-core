use crate::protocol::ModuleInfo;
use tracing::{error, trace, warn};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleA;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageW, ReadProcessMemory, IMAGE_NT_HEADERS64, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};
use windows_sys::core::PWSTR;

pub fn error_message(error_code: u32) -> String {
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
    let mut dos_header: IMAGE_DOS_HEADER = unsafe { std::mem::zeroed() };
    let mut bytes_read = 0;

    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            module_base as *const _,
            &mut dos_header as *mut _ as *mut _,
            std::mem::size_of::<IMAGE_DOS_HEADER>(),
            &mut bytes_read,
        )
    };

    if success == 0 || bytes_read != std::mem::size_of::<IMAGE_DOS_HEADER>() {
        let error_code = unsafe { GetLastError() };
        error!(
            error_code = %error_code,
            module_base = format_args!("0x{:X}", module_base),
            "Failed to read DOS header"
        );
        return None;
    }

    // Check DOS signature "MZ"
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        warn!(
            module_base = format_args!("0x{:X}", module_base),
            "Invalid DOS signature"
        );
        return None;
    }

    // Get PE header offset
    let nt_header_address = module_base + dos_header.e_lfanew as usize;
    let mut nt_headers: IMAGE_NT_HEADERS64 = unsafe { std::mem::zeroed() };

    // Read PE header
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            nt_header_address as *const _,
            &mut nt_headers as *mut _ as *mut _,
            std::mem::size_of::<IMAGE_NT_HEADERS64>(),
            &mut bytes_read,
        )
    };

    if success == 0 || bytes_read < std::mem::size_of::<IMAGE_NT_HEADERS64>() {
        let error_code = unsafe { GetLastError() };
        error!(
            error_code = %error_code,
            module_base = format_args!("0x{:X}", module_base),
            nt_header_address = format_args!("0x{:X}", nt_header_address),
            "Failed to read PE header"
        );
        return None;
    }

    // Check PE signature "PE\0\0"
    if nt_headers.Signature != IMAGE_NT_SIGNATURE {
        warn!(
            module_base = format_args!("0x{:X}", module_base),
            "Invalid PE signature"
        );
        return None;
    }

    let size_of_image = nt_headers.OptionalHeader.SizeOfImage as usize;

    trace!(
        module_base = format_args!("0x{:X}", module_base),
        size_of_image = format_args!("0x{:X}", size_of_image),
        "Successfully retrieved module size from PE header"
    );

    Some(size_of_image)
}

pub fn _get_modules(pid: u32) -> Result<Vec<ModuleInfo>, String> {
    let mut modules = Vec::new();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };

    if snapshot == INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateToolhelp32Snapshot failed: {}",
            unsafe { GetLastError() }
        ));
    }

    let mut me32: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snapshot, &mut me32) } == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(snapshot) };
        // It can fail with ERROR_NO_MORE_FILES if there are no modules, which is not an error.
        if err == ERROR_NO_MORE_FILES {
            return Ok(modules);
        }
        return Err(format!("Module32FirstW failed: {}", err));
    }

    loop {
        let name = {
            let len = me32
                .szModule
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(me32.szModule.len());
            String::from_utf16_lossy(&me32.szModule[..len])
        };

        let path = {
            let len = me32
                .szExePath
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(me32.szExePath.len());
            String::from_utf16_lossy(&me32.szExePath[..len])
        };

        modules.push(ModuleInfo {
            name: if !path.is_empty() { path } else { name },
            base: me32.modBaseAddr as u64,
            size: Some(me32.modBaseSize as u64),
        });

        if unsafe { Module32NextW(snapshot, &mut me32) } == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_NO_MORE_FILES {
                break; // No more modules
            }
            unsafe { CloseHandle(snapshot) };
            return Err(format!("Module32NextW failed: {}", err));
        }
    }

    unsafe { CloseHandle(snapshot) };
    Ok(modules)
}