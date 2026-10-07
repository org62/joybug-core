use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::{HardwareBreakpointType, HardwareBreakpointSize};
use crate::debugger_core::hw_breakpoints::{
    x86_check_dr6, x86_clear_hw_bp, x86_disable_enable_bit, x86_enable_enable_bit, x86_set_hw_bp,
    InternalHardwareBreakpoint, X86DebugRegs,
};
use tracing::trace;
use windows_sys::Win32::Foundation::HANDLE as ThreadHandle;
use windows_sys::Win32::System::Diagnostics::Debug::{
    Wow64GetThreadContext, Wow64SetThreadContext, WOW64_CONTEXT, WOW64_CONTEXT_CONTROL,
    WOW64_CONTEXT_DEBUG_REGISTERS,
};

/// The debug-register (and optionally control) block of one thread of an
/// x86-family debuggee, read and written with the right API for its kind:
/// `GetThreadContext` for a native x64 thread, `Wow64GetThreadContext` for a
/// WOW64 thread on either host.
pub(super) enum X86DebugCtx {
    #[cfg(target_arch = "x86_64")]
    Native(AlignedContext),
    Wow64(WOW64_CONTEXT),
}

impl X86DebugCtx {
    /// `with_control` adds the control block (EFlags/EIP) for trap-flag work.
    pub(super) fn read(thread_handle: ThreadHandle, arch: Architecture, with_control: bool) -> Result<Self, PlatformError> {
        match arch {
            Architecture::X86 => {
                let mut ctx: WOW64_CONTEXT = unsafe { std::mem::zeroed() };
                ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS | if with_control { WOW64_CONTEXT_CONTROL } else { 0 };
                if unsafe { Wow64GetThreadContext(thread_handle, &mut ctx) } == 0 {
                    let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                    return Err(PlatformError::OsError(format!(
                        "Wow64GetThreadContext(DR) failed: {}",
                        super::utils::error_message(err)
                    )));
                }
                Ok(X86DebugCtx::Wow64(ctx))
            }
            #[cfg(target_arch = "x86_64")]
            Architecture::X64 => {
                let mut aligned = AlignedContext { context: unsafe { std::mem::zeroed() } };
                aligned.context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64
                    | if with_control { windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64 } else { 0 };
                if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
                    let err = unsafe { GetLastError() };
                    return Err(PlatformError::OsError(format!(
                        "GetThreadContext(DR) failed: {}",
                        utils::error_message(err)
                    )));
                }
                Ok(X86DebugCtx::Native(aligned))
            }
            _ => Err(PlatformError::NotImplemented),
        }
    }

    pub(super) fn write(&self, thread_handle: ThreadHandle) -> Result<(), PlatformError> {
        match self {
            X86DebugCtx::Wow64(ctx) => {
                if unsafe { Wow64SetThreadContext(thread_handle, ctx) } == 0 {
                    let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                    return Err(PlatformError::OsError(format!(
                        "Wow64SetThreadContext(DR) failed: {}",
                        super::utils::error_message(err)
                    )));
                }
                Ok(())
            }
            #[cfg(target_arch = "x86_64")]
            X86DebugCtx::Native(aligned) => {
                if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
                    let err = unsafe { GetLastError() };
                    return Err(PlatformError::OsError(format!(
                        "SetThreadContext(DR) failed: {}",
                        utils::error_message(err)
                    )));
                }
                Ok(())
            }
        }
    }

    pub(super) fn regs(&mut self) -> &mut dyn X86DebugRegs {
        match self {
            X86DebugCtx::Wow64(ctx) => ctx,
            #[cfg(target_arch = "x86_64")]
            X86DebugCtx::Native(aligned) => &mut aligned.context,
        }
    }

    pub(super) fn set_bp(&mut self, dr_index: u8, address: u64, bp_type: HardwareBreakpointType, size: HardwareBreakpointSize) {
        x86_set_hw_bp(self.regs(), dr_index, address, bp_type, size);
    }
    pub(super) fn clear_bp(&mut self, dr_index: u8) { x86_clear_hw_bp(self.regs(), dr_index); }
    pub(super) fn check_dr6(&mut self) -> Option<u8> { x86_check_dr6(self.regs()) }
    pub(super) fn enable_bit(&mut self, dr_index: u8) { x86_enable_enable_bit(self.regs(), dr_index); }
    pub(super) fn disable_bit(&mut self, dr_index: u8) { x86_disable_enable_bit(self.regs(), dr_index); }
    pub(super) fn set_dr6(&mut self, value: u64) { self.regs().set_dr6(value); }
    pub(super) fn pc(&mut self) -> u64 { self.regs().pc() }
    pub(super) fn set_trap_flag(&mut self, on: bool) { self.regs().set_trap_flag(on); }
}

// ---- Thread-level operations dispatched on the debuggee's architecture ----

/// Program one breakpoint on one thread.
pub(super) fn apply_single_hw_bp_to_thread_for(
    arch: Architecture,
    thread_handle: ThreadHandle,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) -> Result<(), PlatformError> {
    match arch {
        Architecture::X86 => {
            let mut ctx = X86DebugCtx::read(thread_handle, arch, false)?;
            ctx.set_bp(dr_index, address, bp_type, size);
            trace!("apply_single_hw_bp (wow64): dr{}=0x{:X}", dr_index, address);
            ctx.write(thread_handle)
        }
        _ => apply_single_hw_bp_to_thread(thread_handle, dr_index, address, bp_type, size),
    }
}

/// Clear one breakpoint from one thread.
pub(super) fn clear_hw_bp_from_thread_for(
    arch: Architecture,
    thread_handle: ThreadHandle,
    dr_index: u8,
    bp_type: HardwareBreakpointType,
) -> Result<(), PlatformError> {
    match arch {
        Architecture::X86 => {
            let mut ctx = X86DebugCtx::read(thread_handle, arch, false)?;
            ctx.clear_bp(dr_index);
            ctx.write(thread_handle)
        }
        _ => clear_hw_bp_from_thread(thread_handle, dr_index, bp_type),
    }
}

/// Program every active breakpoint on one thread (new thread, re-arm).
pub(super) fn apply_all_hw_bps_to_thread_for(
    arch: Architecture,
    thread_handle: ThreadHandle,
    bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    match arch {
        Architecture::X86 => {
            if bps.is_empty() {
                return Ok(());
            }
            let mut ctx = X86DebugCtx::read(thread_handle, arch, false)?;
            for bp in bps {
                ctx.set_bp(bp.dr_index, bp.address, bp.bp_type, bp.size);
            }
            ctx.write(thread_handle)
        }
        _ => apply_all_hw_bps_to_thread(thread_handle, bps),
    }
}

/// Re-assert the debug registers only (never the control block), so a pending
/// trap flag is left alone.
pub(super) fn apply_hw_bps_dr_only_for(
    arch: Architecture,
    thread_handle: ThreadHandle,
    bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    match arch {
        // The WOW64 read above is already DR-only.
        Architecture::X86 => apply_all_hw_bps_to_thread_for(arch, thread_handle, bps),
        #[cfg(target_arch = "x86_64")]
        Architecture::X64 => apply_hw_bps_dr_only(thread_handle, bps),
        #[cfg(target_arch = "aarch64")]
        Architecture::Arm64 => apply_hw_bps_dr_only(thread_handle, bps),
        #[allow(unreachable_patterns)]
        _ => Err(PlatformError::NotImplemented),
    }
}

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, GetThreadContext, SetThreadContext,
    CONTEXT_DEBUG_REGISTERS_AMD64,
};
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};

#[cfg(target_arch = "x86_64")]
use super::{AlignedContext, utils};

/// Set a hardware breakpoint in a CONTEXT structure (shared DR7 math).
#[cfg(target_arch = "x86_64")]
pub(super) fn set_hw_bp_in_context(
    ctx: &mut CONTEXT,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) {
    x86_set_hw_bp(ctx, dr_index, address, bp_type, size);
}

/// Clear a hardware breakpoint from a CONTEXT structure (shared DR7 math).
#[cfg(target_arch = "x86_64")]
pub(super) fn clear_hw_bp_in_context(ctx: &mut CONTEXT, dr_index: u8) {
    x86_clear_hw_bp(ctx, dr_index);
}

#[cfg(target_arch = "x86_64")]
pub(super) fn apply_single_hw_bp_to_thread(
    thread_handle: HANDLE,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) -> Result<(), PlatformError> {
    let mut aligned = AlignedContext {
        context: unsafe { std::mem::zeroed() },
    };
    aligned.context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    set_hw_bp_in_context(&mut aligned.context, dr_index, address, bp_type, size);
    trace!("apply_single_hw_bp: dr{}=0x{:X} DR7=0x{:X}", dr_index, address, aligned.context.Dr7);

    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    Ok(())
}

/// Clear a hardware breakpoint from a thread by getting/setting its context.
/// `_bp_type` is unused on x86 (single shared DR bank) but kept for a uniform
/// cross-arch signature; on ARM64 it selects the breakpoint vs watchpoint bank.
#[cfg(target_arch = "x86_64")]
pub(super) fn clear_hw_bp_from_thread(
    thread_handle: HANDLE,
    dr_index: u8,
    _bp_type: HardwareBreakpointType,
) -> Result<(), PlatformError> {
    let mut aligned = AlignedContext {
        context: unsafe { std::mem::zeroed() },
    };
    aligned.context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    clear_hw_bp_in_context(&mut aligned.context, dr_index);

    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    Ok(())
}

/// Apply all active hardware breakpoints to a single thread.
#[cfg(target_arch = "x86_64")]
pub(super) fn apply_all_hw_bps_to_thread(
    thread_handle: HANDLE,
    bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    if bps.is_empty() {
        return Ok(());
    }

    let mut aligned = AlignedContext {
        context: unsafe { std::mem::zeroed() },
    };
    aligned.context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    for bp in bps {
        set_hw_bp_in_context(&mut aligned.context, bp.dr_index, bp.address, bp.bp_type, bp.size);
    }

    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    trace!("Applied {} hardware breakpoints to thread", bps.len());
    Ok(())
}

/// Apply all active hardware breakpoints using DEBUG_REGISTERS context only.
/// This avoids clobbering EFlags (trap flag) or other register groups.
#[cfg(target_arch = "x86_64")]
pub(super) fn apply_hw_bps_dr_only(
    thread_handle: HANDLE,
    bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    if bps.is_empty() {
        return Ok(());
    }

    let mut aligned = AlignedContext {
        context: unsafe { std::mem::zeroed() },
    };
    aligned.context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    for bp in bps {
        set_hw_bp_in_context(&mut aligned.context, bp.dr_index, bp.address, bp.bp_type, bp.size);
    }

    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(DR) failed: {}",
            utils::error_message(err)
        )));
    }

    Ok(())
}

// ============================================================================
// ARM64 (AArch64) hardware breakpoints and watchpoints
//
// ARM64 has two SEPARATE banks of debug registers, exposed in the Windows
// ARM64 CONTEXT structure:
//   - Bvr[8]/Bcr[8] — breakpoint value/control registers (instruction/execute)
//   - Wvr[2]/Wcr[2] — watchpoint value/control registers (data read/write)
//
// We map HardwareBreakpointType::Execute onto the breakpoint bank and
// Write/ReadWrite onto the watchpoint bank. `dr_index` is the slot WITHIN the
// relevant bank (0..8 for breakpoints, 0..2 for watchpoints). Because the two
// banks are independent, a breakpoint slot N and a watchpoint slot N can both
// be in use simultaneously; ARM64 hit detection is done by address match, not
// by slot index, so this overlap is harmless.
// ============================================================================
#[cfg(target_arch = "aarch64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, GetThreadContext, SetThreadContext, CONTEXT_DEBUG_REGISTERS_ARM64,
};
#[cfg(target_arch = "aarch64")]
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
#[cfg(target_arch = "aarch64")]
use super::{AlignedContext, utils};

#[cfg(target_arch = "aarch64")]
use crate::debugger_core::hw_breakpoints::{arm64_clear_all_hw_bps, arm64_clear_hw_bp, arm64_set_hw_bp};

/// Program one hardware breakpoint/watchpoint into an ARM64 CONTEXT (shared math).
#[cfg(target_arch = "aarch64")]
pub(super) fn set_hw_bp_in_context(
    ctx: &mut CONTEXT,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) {
    arm64_set_hw_bp(ctx, dr_index, address, bp_type, size);
}

/// Clear one hardware breakpoint/watchpoint from an ARM64 CONTEXT (shared math).
#[cfg(target_arch = "aarch64")]
pub(super) fn clear_hw_bp_in_context(ctx: &mut CONTEXT, dr_index: u8, bp_type: HardwareBreakpointType) {
    arm64_clear_hw_bp(ctx, dr_index, bp_type);
}

/// Zero every ARM64 hardware breakpoint/watchpoint register (shared math).
#[cfg(target_arch = "aarch64")]
pub(super) fn clear_all_hw_bp_in_context(ctx: &mut CONTEXT) {
    arm64_clear_all_hw_bps(ctx);
}

/// Fetch an ARM64 thread CONTEXT with only the debug-register group.
#[cfg(target_arch = "aarch64")]
fn get_debug_context(thread_handle: HANDLE) -> Result<AlignedContext, PlatformError> {
    let mut aligned = AlignedContext {
        context: unsafe { std::mem::zeroed() },
    };
    aligned.context.ContextFlags = CONTEXT_DEBUG_REGISTERS_ARM64;
    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(DEBUG_ARM64) failed: {}",
            utils::error_message(err)
        )));
    }
    Ok(aligned)
}

#[cfg(target_arch = "aarch64")]
fn set_debug_context(thread_handle: HANDLE, aligned: &AlignedContext) -> Result<(), PlatformError> {
    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(DEBUG_ARM64) failed: {}",
            utils::error_message(err)
        )));
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub(super) fn apply_single_hw_bp_to_thread(
    thread_handle: HANDLE,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) -> Result<(), PlatformError> {
    let mut aligned = get_debug_context(thread_handle)?;
    set_hw_bp_in_context(&mut aligned.context, dr_index, address, bp_type, size);
    trace!(
        "apply_single_hw_bp(arm64): slot={} addr=0x{:X} type={:?}",
        dr_index, address, bp_type
    );
    set_debug_context(thread_handle, &aligned)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn clear_hw_bp_from_thread(
    thread_handle: HANDLE,
    dr_index: u8,
    bp_type: HardwareBreakpointType,
) -> Result<(), PlatformError> {
    let mut aligned = get_debug_context(thread_handle)?;
    clear_hw_bp_in_context(&mut aligned.context, dr_index, bp_type);
    set_debug_context(thread_handle, &aligned)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn apply_all_hw_bps_to_thread(
    thread_handle: HANDLE,
    bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    if bps.is_empty() {
        return Ok(());
    }
    let mut aligned = get_debug_context(thread_handle)?;
    // Start from a clean slate so no stale bits linger in unused slots.
    clear_all_hw_bp_in_context(&mut aligned.context);
    for bp in bps {
        set_hw_bp_in_context(&mut aligned.context, bp.dr_index, bp.address, bp.bp_type, bp.size);
    }
    set_debug_context(thread_handle, &aligned)?;
    trace!("Applied {} ARM64 hardware breakpoints to thread", bps.len());
    Ok(())
}

/// Re-arm all active hardware breakpoints/watchpoints on a thread (used after
/// single-stepping past a hit). Equivalent to apply_all but kept separate to
/// mirror the x86 API surface.
#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
pub(super) fn apply_hw_bps_dr_only(
    thread_handle: HANDLE,
    bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    apply_all_hw_bps_to_thread(thread_handle, bps)
}
