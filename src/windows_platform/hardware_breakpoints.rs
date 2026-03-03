use crate::interfaces::PlatformError;
use crate::protocol::{HardwareBreakpointType, HardwareBreakpointSize};
use crate::windows_platform::debugged_process::InternalHardwareBreakpoint;
use tracing::trace;

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, GetThreadContext, SetThreadContext,
    CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_ALL_AMD64,
};
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};

#[cfg(target_arch = "x86_64")]
use super::{AlignedContext, utils};

/// Encode the DR7 condition bits for a hardware breakpoint type.
/// Returns the 2-bit condition value:
///   00 = execute, 01 = write, 11 = read/write
#[cfg(target_arch = "x86_64")]
fn bp_type_to_condition(bp_type: HardwareBreakpointType) -> u64 {
    match bp_type {
        HardwareBreakpointType::Execute => 0b00,
        HardwareBreakpointType::Write => 0b01,
        HardwareBreakpointType::ReadWrite => 0b11,
    }
}

/// Encode the DR7 length bits for a hardware breakpoint size.
/// Returns the 2-bit length value:
///   00 = 1 byte, 01 = 2 bytes, 11 = 4 bytes, 10 = 8 bytes
#[cfg(target_arch = "x86_64")]
fn bp_size_to_length(size: HardwareBreakpointSize) -> u64 {
    match size {
        HardwareBreakpointSize::Byte1 => 0b00,
        HardwareBreakpointSize::Byte2 => 0b01,
        HardwareBreakpointSize::Byte4 => 0b11,
        HardwareBreakpointSize::Byte8 => 0b10,
    }
}

/// Set a hardware breakpoint in a CONTEXT structure.
/// Sets the appropriate DR0-3 address register and configures DR7 enable/condition/length bits.
#[cfg(target_arch = "x86_64")]
pub(super) fn set_hw_bp_in_context(
    ctx: &mut CONTEXT,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) {
    // Set the address in DR0-DR3
    match dr_index {
        0 => ctx.Dr0 = address,
        1 => ctx.Dr1 = address,
        2 => ctx.Dr2 = address,
        3 => ctx.Dr3 = address,
        _ => return,
    }

    let condition = bp_type_to_condition(bp_type);
    // Execute breakpoints must use 1-byte size
    let length = if bp_type == HardwareBreakpointType::Execute {
        0b00
    } else {
        bp_size_to_length(size)
    };

    // DR7 bit layout per debug register:
    //   Local enable: bit (dr_index * 2)
    //   Condition (RW): bits (16 + dr_index * 4) to (17 + dr_index * 4)
    //   Length (LEN):   bits (18 + dr_index * 4) to (19 + dr_index * 4)
    let idx = dr_index as u64;

    // Set local enable bit
    ctx.Dr7 |= 1 << (idx * 2);

    // Clear and set condition bits
    let cond_shift = 16 + idx * 4;
    ctx.Dr7 &= !(0b11 << cond_shift);
    ctx.Dr7 |= condition << cond_shift;

    // Clear and set length bits
    let len_shift = 18 + idx * 4;
    ctx.Dr7 &= !(0b11 << len_shift);
    ctx.Dr7 |= length << len_shift;
}

/// Clear a hardware breakpoint from a CONTEXT structure.
/// Zeros the DR address register and clears DR7 enable/condition/length bits.
#[cfg(target_arch = "x86_64")]
pub(super) fn clear_hw_bp_in_context(ctx: &mut CONTEXT, dr_index: u8) {
    // Zero the address register
    match dr_index {
        0 => ctx.Dr0 = 0,
        1 => ctx.Dr1 = 0,
        2 => ctx.Dr2 = 0,
        3 => ctx.Dr3 = 0,
        _ => return,
    }

    let idx = dr_index as u64;

    // Clear local enable bit
    ctx.Dr7 &= !(1 << (idx * 2));

    // Clear condition bits
    let cond_shift = 16 + idx * 4;
    ctx.Dr7 &= !(0b11 << cond_shift);

    // Clear length bits
    let len_shift = 18 + idx * 4;
    ctx.Dr7 &= !(0b11 << len_shift);
}

/// Check DR6 status register for which hardware breakpoint triggered.
/// Returns the DR index (0-3) if a breakpoint was hit, and clears DR6.
#[cfg(target_arch = "x86_64")]
pub(super) fn check_dr6_for_hw_bp(ctx: &mut CONTEXT) -> Option<u8> {
    let dr6 = ctx.Dr6;
    // Bits 0-3 of DR6 indicate which breakpoint triggered
    for i in 0..4u8 {
        if dr6 & (1 << i) != 0 {
            // Clear DR6 (write 0 to the hit bits; DR6 bits 0-3 are cleared by writing 0)
            ctx.Dr6 = 0;
            return Some(i);
        }
    }
    None
}

/// Disable the local enable bit for a hardware breakpoint in DR7.
#[cfg(target_arch = "x86_64")]
pub(super) fn disable_hw_bp_enable(ctx: &mut CONTEXT, dr_index: u8) {
    let idx = dr_index as u64;
    ctx.Dr7 &= !(1 << (idx * 2));
}

/// Enable the local enable bit for a hardware breakpoint in DR7.
#[cfg(target_arch = "x86_64")]
pub(super) fn enable_hw_bp_enable(ctx: &mut CONTEXT, dr_index: u8) {
    let idx = dr_index as u64;
    ctx.Dr7 |= 1 << (idx * 2);
}

/// Apply a single hardware breakpoint to a thread by getting/setting its context.
/// Uses CONTEXT_ALL to ensure DR register changes persist across ContinueDebugEvent.
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
    aligned.context.ContextFlags = CONTEXT_ALL_AMD64;

    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(ALL) failed: {}",
            utils::error_message(err)
        )));
    }

    set_hw_bp_in_context(&mut aligned.context, dr_index, address, bp_type, size);
    trace!("apply_single_hw_bp: dr{}=0x{:X} DR7=0x{:X}", dr_index, address, aligned.context.Dr7);

    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(ALL) failed: {}",
            utils::error_message(err)
        )));
    }

    Ok(())
}

/// Clear a hardware breakpoint from a thread by getting/setting its context.
#[cfg(target_arch = "x86_64")]
pub(super) fn clear_hw_bp_from_thread(
    thread_handle: HANDLE,
    dr_index: u8,
) -> Result<(), PlatformError> {
    let mut aligned = AlignedContext {
        context: unsafe { std::mem::zeroed() },
    };
    aligned.context.ContextFlags = CONTEXT_ALL_AMD64;

    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(ALL) failed: {}",
            utils::error_message(err)
        )));
    }

    clear_hw_bp_in_context(&mut aligned.context, dr_index);

    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(ALL) failed: {}",
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
    aligned.context.ContextFlags = CONTEXT_ALL_AMD64;

    if unsafe { GetThreadContext(thread_handle, &mut aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "GetThreadContext(ALL) failed: {}",
            utils::error_message(err)
        )));
    }

    for bp in bps {
        set_hw_bp_in_context(&mut aligned.context, bp.dr_index, bp.address, bp.bp_type, bp.size);
    }

    if unsafe { SetThreadContext(thread_handle, &aligned.context) } == 0 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!(
            "SetThreadContext(ALL) failed: {}",
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

#[cfg(target_arch = "aarch64")]
pub(super) fn apply_hw_bps_dr_only(
    _thread_handle: windows_sys::Win32::Foundation::HANDLE,
    _bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    if _bps.is_empty() {
        return Ok(());
    }
    Err(PlatformError::NotImplemented)
}

// ARM64 stubs
#[cfg(target_arch = "aarch64")]
pub(super) fn apply_single_hw_bp_to_thread(
    _thread_handle: windows_sys::Win32::Foundation::HANDLE,
    _dr_index: u8,
    _address: u64,
    _bp_type: HardwareBreakpointType,
    _size: HardwareBreakpointSize,
) -> Result<(), PlatformError> {
    Err(PlatformError::NotImplemented)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn clear_hw_bp_from_thread(
    _thread_handle: windows_sys::Win32::Foundation::HANDLE,
    _dr_index: u8,
) -> Result<(), PlatformError> {
    Err(PlatformError::NotImplemented)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn apply_all_hw_bps_to_thread(
    _thread_handle: windows_sys::Win32::Foundation::HANDLE,
    _bps: &[InternalHardwareBreakpoint],
) -> Result<(), PlatformError> {
    if _bps.is_empty() {
        return Ok(());
    }
    Err(PlatformError::NotImplemented)
}
