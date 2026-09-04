//! PEB hiding: overwrite the well-known PEB fields that anti-debug code probes.
//!
//! A WOW64 process has two PEBs — the 32-bit one its own code reads through
//! `fs:[0x30]` and the 64-bit one the loader keeps — with different field
//! offsets and pointer widths. Both are patched, each with its own layout, so a
//! check leaks nothing whichever half runs it.
//!
//! Reference: `windbg> dt nt!_PEB` / `dt ntdll!_PEB` (32-bit view) and
//! `dt nt!_RTL_USER_PROCESS_PARAMETERS`.

use crate::interfaces::{PlatformAPI, PlatformError};
use super::{PebHideOptions, PebHideReport};

/// Field offsets and pointer width of one PEB layout (64- or 32-bit).
struct PebLayout {
    ptr_size: usize,
    being_debugged: u64,
    process_params: u64,
    process_heap: u64,
    nt_global_flag: u64,
    os_build_number: u64,
    heap_flags: u64,
    heap_force_flags: u64,
    /// RTL_USER_PROCESS_PARAMETERS StartingX; a contiguous block of 9 ULONGs
    /// (window placement fields) is zeroed from here.
    rupp_window_fields: u64,
}

/// 64-bit PEB / HEAP / RTL_USER_PROCESS_PARAMETERS (Win10/11).
const LAYOUT64: PebLayout = PebLayout {
    ptr_size: 8,
    being_debugged: 0x02,
    process_params: 0x20,
    process_heap: 0x30,
    nt_global_flag: 0xBC,
    os_build_number: 0x120,
    heap_flags: 0x70,
    heap_force_flags: 0x74,
    rupp_window_fields: 0x88,
};

/// 32-bit (WOW64) PEB / HEAP / RTL_USER_PROCESS_PARAMETERS.
const LAYOUT32: PebLayout = PebLayout {
    ptr_size: 4,
    being_debugged: 0x02,
    process_params: 0x10,
    process_heap: 0x18,
    nt_global_flag: 0x68,
    os_build_number: 0xAC,
    heap_flags: 0x40,
    heap_force_flags: 0x44,
    rupp_window_fields: 0x4C,
};

/// Normal (non-debug-heap) value for HEAP.Flags: HEAP_GROWABLE only.
const HEAP_GROWABLE: u32 = 0x2;
/// Fields whose "no debugger" state is simply zero (NtGlobalFlag, ForceFlags).
const CLEARED_U32: u32 = 0;
/// 9 ULONGs: StartingX/Y, CountX/Y, CountCharsX/Y, FillAttribute, WindowFlags,
/// ShowWindowFlags — same count in both layouts.
const RUPP_WINDOW_FIELDS_SIZE: usize = 9 * 4;
/// Build number we spoof PEB.OSBuildNumber to. Win10 22H2 (19045).
const SPOOFED_OS_BUILD_NUMBER: u16 = 19045;

/// Overwrite PEB fields in `pid` according to `opts`.
///
/// Always returns a [`PebHideReport`]; per-technique failures are recorded in
/// `report.failures` rather than aborting. Only a failure to resolve the PEB
/// address returns `Err`. For a WOW64 target both PEBs are patched.
pub fn hide_peb<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    opts: &PebHideOptions,
) -> Result<PebHideReport, PlatformError> {
    let mut report = PebHideReport::default();

    let is_wow64 = platform.is_wow64(pid).unwrap_or(false);

    // `get_peb_address` returns the target's own PEB — the 32-bit one for WOW64.
    let peb = platform.get_peb_address(pid)?;
    report.peb_address = peb;
    let layout = if is_wow64 { &LAYOUT32 } else { &LAYOUT64 };
    hide_peb_at(platform, pid, peb, layout, opts, &mut report, if is_wow64 { "32" } else { "" });

    // A WOW64 process also has a 64-bit PEB, read by 64-bit ntdll and any 64-bit
    // detection thunk; patch it with the 64-bit layout too.
    if is_wow64 {
        match platform.get_native_peb_address(pid) {
            Ok(peb64) if peb64 != 0 => hide_peb_at(platform, pid, peb64, &LAYOUT64, opts, &mut report, "64"),
            Ok(_) => {}
            Err(e) => report.failures.push(("peb64_resolve".to_string(), e.to_string())),
        }
    }

    Ok(report)
}

/// Apply `opts` to one PEB at `peb` using `layout`. `suffix` distinguishes the
/// 32-/64-bit passes in the report's technique names for a WOW64 target.
fn hide_peb_at<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    peb: u64,
    layout: &PebLayout,
    opts: &PebHideOptions,
    report: &mut PebHideReport,
    suffix: &str,
) {
    let name = |base: &str| if suffix.is_empty() { base.to_string() } else { format!("{}{}", base, suffix) };

    if opts.being_debugged {
        attempt(report, name("being_debugged"), || {
            platform.write_memory(pid, peb + layout.being_debugged, &[0u8])
        });
    }

    if opts.nt_global_flag {
        attempt(report, name("nt_global_flag"), || {
            platform.write_memory(pid, peb + layout.nt_global_flag, &CLEARED_U32.to_le_bytes())
        });
    }

    if opts.os_build_number {
        attempt(report, name("os_build_number"), || {
            platform.write_memory(pid, peb + layout.os_build_number, &SPOOFED_OS_BUILD_NUMBER.to_le_bytes())
        });
    }

    if opts.heap_flags {
        attempt(report, name("heap_flags"), || {
            let heap_ptr_bytes = platform.read_memory(pid, peb + layout.process_heap, layout.ptr_size)?;
            let heap = ptr_from_le(&heap_ptr_bytes, layout.ptr_size)?;
            platform.write_memory(pid, heap + layout.heap_flags,       &HEAP_GROWABLE.to_le_bytes())?;
            platform.write_memory(pid, heap + layout.heap_force_flags, &CLEARED_U32.to_le_bytes())?;
            Ok(())
        });
    }

    if opts.startup_info {
        attempt(report, name("startup_info"), || {
            let params_ptr_bytes = platform.read_memory(pid, peb + layout.process_params, layout.ptr_size)?;
            let params = ptr_from_le(&params_ptr_bytes, layout.ptr_size)?;
            let zeros = [0u8; RUPP_WINDOW_FIELDS_SIZE];
            platform.write_memory(pid, params + layout.rupp_window_fields, &zeros)
        });
    }
}

fn attempt<F>(report: &mut PebHideReport, name: String, f: F)
where
    F: FnOnce() -> Result<(), PlatformError>,
{
    match f() {
        Ok(()) => report.applied.push(name),
        Err(e) => report.failures.push((name, e.to_string())),
    }
}

/// Read a 4- or 8-byte little-endian pointer, zero-extended.
fn ptr_from_le(bytes: &[u8], ptr_size: usize) -> Result<u64, PlatformError> {
    if bytes.len() < ptr_size {
        return Err(PlatformError::Other(format!("expected {} bytes, got {}", ptr_size, bytes.len())));
    }
    Ok(if ptr_size == 4 {
        u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64
    } else {
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    })
}
