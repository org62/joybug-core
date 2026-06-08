//! PEB hiding: overwrite the well-known PEB fields that anti-debug code probes.
//!
//! Offsets target the 64-bit native PEB layout for Windows 10/11.
//! Reference: `windbg> dt nt!_PEB` and `dt nt!_RTL_USER_PROCESS_PARAMETERS`.

use crate::interfaces::{PlatformAPI, PlatformError};
use super::{PebHideOptions, PebHideReport};

// PEB field offsets (64-bit).
const PEB_BEING_DEBUGGED:    u64 = 0x02;   // UCHAR
const PEB_PROCESS_PARAMS:    u64 = 0x20;   // PRTL_USER_PROCESS_PARAMETERS
const PEB_PROCESS_HEAP:      u64 = 0x30;   // PVOID
const PEB_NT_GLOBAL_FLAG:    u64 = 0xBC;   // ULONG
const PEB_OS_BUILD_NUMBER:   u64 = 0x120;  // USHORT

// Heap header offsets (HEAP struct, x64 Win10+).
const HEAP_FLAGS:            u64 = 0x70;   // ULONG
const HEAP_FORCE_FLAGS:      u64 = 0x74;   // ULONG

/// Normal (non-debug-heap) value for HEAP.Flags: HEAP_GROWABLE only.
const HEAP_GROWABLE: u32 = 0x2;
/// Value written to PEB fields whose "no debugger" state is simply zero
/// (NtGlobalFlag, HEAP.ForceFlags, BeingDebugged uses the single-byte form).
const CLEARED_U32: u32 = 0;
/// Size of a 64-bit pointer field in the target's address space.
const PTR_SIZE: usize = core::mem::size_of::<u64>();

// RTL_USER_PROCESS_PARAMETERS offsets (x64). We zero a contiguous block
// covering: StartingX, StartingY, CountX, CountY, CountCharsX, CountCharsY,
// FillAttribute, WindowFlags, ShowWindowFlags (9 ULONGs).
// StartingX sits at 0x88 on the 64-bit layout (right after the Environment
// pointer at 0x80) — NOT 0x40, which falls inside CurrentDirectory/DllPath.
const RUPP_WINDOW_FIELDS_OFFSET: u64 = 0x88;
const RUPP_WINDOW_FIELDS_SIZE:   usize = 9 * 4;

/// Build number we spoof PEB.OSBuildNumber to when the option is enabled.
/// Win10 22H2 (19045) is a common, unremarkable value.
const SPOOFED_OS_BUILD_NUMBER: u16 = 19045;

/// Overwrite PEB fields in `pid` according to `opts`.
///
/// Always returns a [`PebHideReport`]; per-technique failures are recorded in
/// `report.failures` rather than aborting the call. Only fatal infrastructure
/// errors (e.g. cannot resolve PEB address) return `Err`.
///
/// On WOW64 targets the call returns immediately with
/// `report.wow64_skipped = true` and nothing written — the 64-bit offsets in
/// this module do not match the 32-bit PEB layout.
pub fn hide_peb<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    opts: &PebHideOptions,
) -> Result<PebHideReport, PlatformError> {
    let mut report = PebHideReport::default();

    if platform.is_wow64(pid).unwrap_or(false) {
        report.wow64_skipped = true;
        return Ok(report);
    }

    let peb = platform.get_peb_address(pid)?;
    report.peb_address = peb;

    if opts.being_debugged {
        attempt(&mut report, "being_debugged", || {
            platform.write_memory(pid, peb + PEB_BEING_DEBUGGED, &[0u8])
        });
    }

    if opts.nt_global_flag {
        attempt(&mut report, "nt_global_flag", || {
            platform.write_memory(pid, peb + PEB_NT_GLOBAL_FLAG, &CLEARED_U32.to_le_bytes())
        });
    }

    if opts.os_build_number {
        attempt(&mut report, "os_build_number", || {
            platform.write_memory(
                pid,
                peb + PEB_OS_BUILD_NUMBER,
                &SPOOFED_OS_BUILD_NUMBER.to_le_bytes(),
            )
        });
    }

    if opts.heap_flags {
        attempt(&mut report, "heap_flags", || {
            let heap_ptr_bytes = platform.read_memory(pid, peb + PEB_PROCESS_HEAP, PTR_SIZE)?;
            let heap = u64_from_le(&heap_ptr_bytes)?;
            // Normal (non-debug) values: Flags = HEAP_GROWABLE, ForceFlags = 0.
            platform.write_memory(pid, heap + HEAP_FLAGS,       &HEAP_GROWABLE.to_le_bytes())?;
            platform.write_memory(pid, heap + HEAP_FORCE_FLAGS, &CLEARED_U32.to_le_bytes())?;
            Ok(())
        });
    }

    if opts.startup_info {
        attempt(&mut report, "startup_info", || {
            let params_ptr_bytes = platform.read_memory(pid, peb + PEB_PROCESS_PARAMS, PTR_SIZE)?;
            let params = u64_from_le(&params_ptr_bytes)?;
            let zeros = [0u8; RUPP_WINDOW_FIELDS_SIZE];
            platform.write_memory(pid, params + RUPP_WINDOW_FIELDS_OFFSET, &zeros)
        });
    }

    Ok(report)
}

fn attempt<F>(report: &mut PebHideReport, name: &'static str, f: F)
where
    F: FnOnce() -> Result<(), PlatformError>,
{
    match f() {
        Ok(()) => report.applied.push(name.to_string()),
        Err(e) => report.failures.push((name.to_string(), e.to_string())),
    }
}

fn u64_from_le(bytes: &[u8]) -> Result<u64, PlatformError> {
    let arr: [u8; PTR_SIZE] = bytes
        .try_into()
        .map_err(|_| PlatformError::Other(format!("expected {} bytes, got {}", PTR_SIZE, bytes.len())))?;
    Ok(u64::from_le_bytes(arr))
}
