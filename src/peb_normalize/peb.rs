//! PEB normalization: rewrite the PEB fields Windows leaves in their
//! "debugger attached" state so the target runs as it would with no debugger.
//!
//! This is not debugger hiding or evasion. The loader flips these fields as a
//! side effect of launching a process under a debugger; the most consequential
//! is the process heap, which switches into debug mode (tail/free checks and
//! parameter validation) and validates every allocation exhaustively — slowing
//! an allocation-heavy target by orders of magnitude. Restoring the fields
//! removes that penalty and clears the `BeingDebugged` flag `IsDebuggerPresent`
//! reports, so code that changes behavior under a debugger (crash reporters, or
//! exception handlers that would fire an `int3` on detection) runs its normal
//! path and the issue reproduces as it would without a debugger attached.
//!
//! A WOW64 process has two PEBs — the 32-bit one its own code reads through
//! `fs:[0x30]` and the 64-bit one the loader keeps — with different field
//! offsets and pointer widths. Both are patched, each with its own layout.
//!
//! Reference: `windbg> dt nt!_PEB` / `dt ntdll!_PEB` (32-bit view).

use crate::interfaces::{PlatformAPI, PlatformError};
use super::{PebNormalizeOptions, PebNormalizeReport};

/// Field offsets and pointer width of one PEB layout (64- or 32-bit).
struct PebLayout {
    ptr_size: usize,
    being_debugged: u64,
    process_heap: u64,
    heap_flags: u64,
    heap_force_flags: u64,
}

/// 64-bit PEB / HEAP (Win10/11).
const LAYOUT64: PebLayout = PebLayout {
    ptr_size: 8,
    being_debugged: 0x02,
    process_heap: 0x30,
    heap_flags: 0x70,
    heap_force_flags: 0x74,
};

/// 32-bit (WOW64) PEB / HEAP.
const LAYOUT32: PebLayout = PebLayout {
    ptr_size: 4,
    being_debugged: 0x02,
    process_heap: 0x18,
    heap_flags: 0x40,
    heap_force_flags: 0x44,
};

/// Normal (non-debug-heap) value for HEAP.Flags: HEAP_GROWABLE only.
const HEAP_GROWABLE: u32 = 0x2;
/// The non-debugged value for HEAP.ForceFlags: zero.
const CLEARED_U32: u32 = 0;

/// Restore PEB fields in `pid` to their non-debugged state per `opts`.
///
/// Always returns a [`PebNormalizeReport`]; per-field failures are recorded in
/// `report.failures` rather than aborting. Only a failure to resolve the PEB
/// address returns `Err`. For a WOW64 target both PEBs are patched.
pub fn normalize_peb<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    opts: &PebNormalizeOptions,
) -> Result<PebNormalizeReport, PlatformError> {
    let mut report = PebNormalizeReport::default();

    let is_wow64 = platform.is_wow64(pid).unwrap_or(false);

    // `get_peb_address` returns the target's own PEB — the 32-bit one for WOW64.
    let peb = platform.get_peb_address(pid)?;
    report.peb_address = peb;
    let layout = if is_wow64 { &LAYOUT32 } else { &LAYOUT64 };
    normalize_peb_at(platform, pid, peb, layout, opts, &mut report, if is_wow64 { "32" } else { "" });

    // A WOW64 process also has a 64-bit PEB, read by 64-bit ntdll and any 64-bit
    // detection thunk; patch it with the 64-bit layout too.
    if is_wow64 {
        match platform.get_native_peb_address(pid) {
            Ok(peb64) if peb64 != 0 => normalize_peb_at(platform, pid, peb64, &LAYOUT64, opts, &mut report, "64"),
            Ok(_) => {}
            Err(e) => report.failures.push(("peb64_resolve".to_string(), e.to_string())),
        }
    }

    Ok(report)
}

/// Apply `opts` to one PEB at `peb` using `layout`. `suffix` distinguishes the
/// 32-/64-bit passes in the report's field names for a WOW64 target.
fn normalize_peb_at<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    peb: u64,
    layout: &PebLayout,
    opts: &PebNormalizeOptions,
    report: &mut PebNormalizeReport,
    suffix: &str,
) {
    let name = |base: &str| if suffix.is_empty() { base.to_string() } else { format!("{}{}", base, suffix) };

    if opts.being_debugged {
        attempt(report, name("being_debugged"), || {
            platform.write_memory(pid, peb + layout.being_debugged, &[0u8])
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
}

fn attempt<F>(report: &mut PebNormalizeReport, name: String, f: F)
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
