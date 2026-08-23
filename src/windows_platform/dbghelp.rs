use std::sync::Mutex;

/// Global lock for all DbgHelp.dll function calls as the library is single-threaded.
/// "All DbgHelp functions are single threaded. Therefore, calls from more than one thread 
/// to this function will likely result in unexpected behavior or memory corruption."
/// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize
pub static DBGHELP_LOCK: Mutex<()> = Mutex::new(());

use crate::interfaces::PlatformError;
use crate::protocol::MinidumpKind;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo, MiniDumpWithHandleData,
    MiniDumpWithIndirectlyReferencedMemory, MiniDumpWithThreadInfo, MiniDumpWithUnloadedModules,
    MiniDumpWriteDump, MINIDUMP_TYPE,
};

/// `MINIDUMP_TYPE` bit set for a dump flavour. `Full` is what WinDbg's
/// `.dump /ma` writes; `Mini` keeps stacks, modules, thread info and the
/// memory referenced from stack/register values.
fn dump_type(kind: MinidumpKind) -> MINIDUMP_TYPE {
    match kind {
        MinidumpKind::Full => {
            MiniDumpWithFullMemory
                | MiniDumpWithHandleData
                | MiniDumpWithUnloadedModules
                | MiniDumpWithFullMemoryInfo
                | MiniDumpWithThreadInfo
        }
        MinidumpKind::Mini => {
            MiniDumpWithUnloadedModules
                | MiniDumpWithIndirectlyReferencedMemory
                | MiniDumpWithThreadInfo
        }
    }
}

/// Write a minidump of `pid` (opened as `process`) to `path`, overwriting any
/// existing file. Returns the size of the written file in bytes. On failure
/// the partially-written file is removed.
pub(super) fn write_minidump(
    process: HANDLE,
    pid: u32,
    path: &str,
    kind: MinidumpKind,
) -> Result<u64, PlatformError> {
    let file = std::fs::File::create(path)
        .map_err(|e| PlatformError::OsError(format!("Failed to create '{}': {}", path, e)))?;

    let write_err = {
        let _lock = DBGHELP_LOCK.lock().unwrap();
        let ok = unsafe {
            MiniDumpWriteDump(
                process,
                pid,
                file.as_raw_handle() as HANDLE,
                dump_type(kind),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        // MiniDumpWriteDump reports HRESULTs through GetLastError.
        (ok == 0).then(|| unsafe { GetLastError() })
    };
    drop(file);

    if let Some(code) = write_err {
        let _ = std::fs::remove_file(path);
        // HRESULT_FROM_WIN32(ERROR_PARTIAL_COPY): dbghelp couldn't read the
        // target's loader data. The usual cause is a process still at its
        // create event, before ntdll has populated the PEB.
        let hint = if code == 0x8007012b {
            " (ERROR_PARTIAL_COPY: target memory not readable yet — continue past process creation and retry)"
        } else {
            ""
        };
        return Err(PlatformError::OsError(format!("MiniDumpWriteDump failed: 0x{:08x}{}", code, hint)));
    }

    std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| PlatformError::OsError(format!("Failed to stat '{}': {}", path, e)))
}
