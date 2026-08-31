use crate::protocol::{ModuleInfo, ThreadInfo};
use crate::interfaces::PlatformError;
use tracing::{error, trace, warn};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleA, QueryDosDeviceW,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageW, ReadProcessMemory, IMAGE_NT_HEADERS64, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Thread32First, Thread32Next,
    MODULEENTRY32W, THREADENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;
use windows_sys::core::PWSTR;

// `ntdll!NtQueryInformationThread`. Declared once here because a second,
// signature-divergent declaration elsewhere in the crate is only caught at
// link time (`clashing_extern_declarations`); all callers share this one.
#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtQueryInformationThread(
        thread_handle: HANDLE,
        thread_information_class: u32,
        thread_information: *mut std::ffi::c_void,
        thread_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

// `ntdll!NtQueryInformationProcess` / `ntdll!NtQueryObject`. Shared for the
// same reason as `NtQueryInformationThread` above: a signature-divergent
// second declaration is only caught at link time.
#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut std::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    pub fn NtQueryObject(
        handle: HANDLE,
        object_information_class: u32,
        object_information: *mut std::ffi::c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

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

/// Gets the full image path of a process from its handle via
/// `QueryFullProcessImageNameW`. Unlike [`get_path_from_handle`] (which relies on
/// the `CREATE_PROCESS_DEBUG_EVENT`'s file handle — sometimes NULL/limited, e.g.
/// inside Windows Sandbox), this queries the kernel's own record of the image
/// path, so it resolves a full `C:\...\name.exe` even when the file handle route
/// fails. The handle needs `PROCESS_QUERY_LIMITED_INFORMATION` (the debug event's
/// process handle has it).
///
/// # Returns
/// * `Some(path)` - The full image path on success
/// * `None` - If the handle is invalid or the query fails
pub fn get_process_image_path(process_handle: HANDLE) -> Option<String> {
    if process_handle.is_null() {
        return None;
    }
    let mut buf: Vec<u16> = vec![0u16; MAX_PATH as usize];
    let mut size = buf.len() as u32;
    // PROCESS_NAME_WIN32 (0): return a normal Win32 path, not an NT device path.
    let ok = unsafe { QueryFullProcessImageNameW(process_handle, 0, buf.as_mut_ptr(), &mut size) };
    if ok == 0 {
        // ERROR_INSUFFICIENT_BUFFER leaves `size` unchanged on some versions;
        // one grow-and-retry covers unusually long paths.
        let err = unsafe { GetLastError() };
        if err == 122 /* ERROR_INSUFFICIENT_BUFFER */ {
            buf.resize(32768, 0u16);
            size = buf.len() as u32;
            if unsafe { QueryFullProcessImageNameW(process_handle, 0, buf.as_mut_ptr(), &mut size) } == 0 {
                return None;
            }
        } else {
            warn!(error_code = %err, "QueryFullProcessImageNameW failed");
            return None;
        }
    }
    if size == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..size as usize]))
}

/// Resolves the on-disk path of the image mapped at `base` in the target process
/// via `GetMappedFileNameW`, then normalizes the `\Device\HarddiskVolumeN\...`
/// result to a drive-letter path (e.g. `C:\...`).
///
/// This is the reliable fallback for naming a loaded DLL when the
/// `LOAD_DLL_DEBUG_EVENT`'s file handle is NULL — which happens for most DLLs
/// inside Windows Sandbox. Unlike a handle- or module-list-based lookup, it reads
/// the memory manager's section name directly, so it works even mid-load. A
/// drive-letter path (not the raw device path) is what lets dbghelp open the file
/// to load symbols.
///
/// # Returns
/// * `Some(path)` - The resolved image path
/// * `None` - If the address isn't a mapped image or resolution fails
pub fn get_mapped_file_path(process_handle: HANDLE, base: usize) -> Option<String> {
    if process_handle.is_null() || base == 0 {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let len = unsafe {
        GetMappedFileNameW(
            process_handle,
            base as *const core::ffi::c_void,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len == 0 {
        return None;
    }
    let device_path = String::from_utf16_lossy(&buf[..len as usize]);
    // 1. Windows Sandbox serves its OS files from a VSMB share that no drive
    //    letter maps to, but they ARE reachable at `C:\...`. This is a pure
    //    string mapping self-verified with an existence check, so it goes first:
    //    in-sandbox (this path's main case, hit for most DLLs at process start)
    //    it avoids route 2's doomed CreateFile + per-drive probing entirely.
    if let Some(p) = sandbox_vsmb_os_path_to_c(&device_path) {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    // 2. A clean drive-letter path when one exists (plain disk volumes).
    if let Some(p) = drive_path_from_device_path(&device_path) {
        return Some(p);
    }
    // 3. Last resort: the `\\?\GLOBALROOT` form — ugly, but openable by
    //    CreateFile/dbghelp (a raw `\Device\...` path is not), so symbols and PE
    //    reads still work. The basename shown in the UI is unaffected.
    Some(format!(r"\\?\GLOBALROOT{device_path}"))
}

/// Map a Windows Sandbox OS-share device path to its `C:\...` equivalent:
/// `\Device\vmsmb\VSMB-{guid}\os\<rest>` → `C:\<rest>`. Returns None for any other
/// device path (the caller verifies the result exists before trusting it).
fn sandbox_vsmb_os_path_to_c(device_path: &str) -> Option<String> {
    let rest = device_path.strip_prefix(r"\Device\vmsmb\")?; // VSMB-{guid}\os\<rest>
    let (_vsmb_id, after) = rest.split_once('\\')?; // os\<rest>
    let (share, tail) = after.split_once('\\')?; // share = "os", tail = <rest>
    if share.eq_ignore_ascii_case("os") {
        return Some(format!(r"C:\{tail}"));
    }
    None
}

/// True for a `X:\...` drive-letter path (as opposed to a raw `\Device\...` NT path).
fn is_drive_letter_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Convert an NT device path (`\Device\HarddiskVolume3\...`, `\Device\vmsmb\...`)
/// to a drive-letter path (`C:\...`), returning None if none maps.
///
/// Route 1: open the path through the NT `\\?\GLOBALROOT` namespace and ask
/// `GetFinalPathNameByHandle` for its DOS volume name — works for plain disk
/// volumes. (For a VSMB-backed sandbox system file there is no DOS mapping, so
/// this yields the device path again, which we reject.) Route 2: match a DOS
/// drive whose `QueryDosDevice` target prefixes the path.
fn drive_path_from_device_path(device_path: &str) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Route 1: GLOBALROOT + GetFinalPathNameByHandle. Accept only a real drive path.
    let nt = format!(r"\\?\GLOBALROOT{device_path}");
    let wide: Vec<u16> = OsStr::new(&nt).encode_wide().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0, // query only — no read access needed for the final-path lookup
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if !handle.is_null() && !std::ptr::eq(handle, INVALID_HANDLE_VALUE) {
        let dos = get_path_from_handle(handle);
        unsafe { CloseHandle(handle) };
        if let Some(p) = dos {
            if is_drive_letter_path(&p) {
                return Some(p);
            }
        }
    }

    // Route 2: match a DOS drive whose device target prefixes the path. The
    // drive → device table (26 QueryDosDeviceW calls) is built once per process:
    // this runs per DLL-load debug event, and drive mappings effectively never
    // change mid-session (a drive mounted later still resolves via route 1).
    for (drive, target) in dos_device_table() {
        if let Some(rest) = device_path.strip_prefix(target.as_str()) {
            if rest.starts_with('\\') {
                return Some(format!("{drive}{rest}"));
            }
        }
    }
    None
}

/// The `("C:", "\Device\HarddiskVolume3")`-style table of present DOS drives,
/// queried once per process.
fn dos_device_table() -> &'static Vec<(String, String)> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::OnceLock;

    static TABLE: OnceLock<Vec<(String, String)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Vec::new();
        let mut target_buf = [0u16; 512];
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let wide: Vec<u16> =
                OsStr::new(&drive).encode_wide().chain(std::iter::once(0)).collect();
            let n = unsafe {
                QueryDosDeviceW(wide.as_ptr(), target_buf.as_mut_ptr(), target_buf.len() as u32)
            };
            if n == 0 {
                continue;
            }
            // QueryDosDeviceW may return several NUL-separated targets; use the first.
            let end = target_buf.iter().position(|&c| c == 0).unwrap_or(target_buf.len());
            let target = String::from_utf16_lossy(&target_buf[..end]);
            if !target.is_empty() {
                table.push((drive, target));
            }
        }
        table
    })
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
    // Note: GetCurrentProcess() returns a pseudo-handle (INVALID_HANDLE_VALUE/(-1)) which is
    // valid for APIs like ReadProcessMemory when referring to the current process. We therefore
    // only treat a null handle as invalid here.
    if process_handle.is_null() {
        warn!("Invalid (null) process handle provided to get_module_size_from_address");
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

/// Enumerate a process's loaded modules via a Toolhelp snapshot, with no debug
/// attach required. Used as the non-invasive fallback for `list_modules`.
pub fn get_modules(pid: u32) -> Result<Vec<ModuleInfo>, String> {
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

/// Enumerate a process's threads via a Toolhelp snapshot, with no debug attach
/// required. Used as the non-invasive fallback for `list_threads`. `THREADENTRY32`
/// carries no start address, so `start_address` is reported as 0.
pub fn list_threads_toolhelp(pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
    let mut threads = Vec::new();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(PlatformError::OsError(format!(
            "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: {}",
            unsafe { GetLastError() }
        )));
    }

    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    if unsafe { Thread32First(snapshot, &mut entry) } == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(snapshot) };
        if err == ERROR_NO_MORE_FILES {
            return Ok(threads);
        }
        return Err(PlatformError::OsError(format!("Thread32First failed: {}", err)));
    }

    loop {
        if entry.th32OwnerProcessID == pid {
            threads.push(ThreadInfo {
                tid: entry.th32ThreadID,
                ..Default::default()
            });
        }
        if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
            break;
        }
    }

    unsafe { CloseHandle(snapshot) };
    Ok(threads)
}