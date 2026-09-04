use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::{HardwareBreakpointType, HardwareBreakpointSize};
use crate::windows_platform::debugged_process::InternalHardwareBreakpoint;
use tracing::trace;
use windows_sys::Win32::Foundation::HANDLE as ThreadHandle;
use windows_sys::Win32::System::Diagnostics::Debug::{
    Wow64GetThreadContext, Wow64SetThreadContext, WOW64_CONTEXT, WOW64_CONTEXT_CONTROL,
    WOW64_CONTEXT_DEBUG_REGISTERS,
};

// ============================================================================
// x86 family: the DR0-DR7 model shared by a native x64 thread (`CONTEXT`, x64
// host only) and a WOW64 thread (`WOW64_CONTEXT`, either host). The encoding
// helpers are generic over this trait; the per-host `CONTEXT` wrappers below
// and the WOW64 path both delegate to them.
// ============================================================================

pub(super) trait X86DebugRegs {
    fn set_dr(&mut self, index: u8, value: u64);
    fn dr6(&self) -> u64;
    fn set_dr6(&mut self, value: u64);
    fn dr7(&self) -> u64;
    fn set_dr7(&mut self, value: u64);
    /// Instruction pointer (RIP / EIP).
    fn pc(&self) -> u64;
    fn set_trap_flag(&mut self, on: bool);
}

impl X86DebugRegs for WOW64_CONTEXT {
    fn set_dr(&mut self, index: u8, value: u64) {
        let v = value as u32;
        match index { 0 => self.Dr0 = v, 1 => self.Dr1 = v, 2 => self.Dr2 = v, 3 => self.Dr3 = v, _ => {} }
    }
    fn dr6(&self) -> u64 { self.Dr6 as u64 }
    fn set_dr6(&mut self, value: u64) { self.Dr6 = value as u32; }
    fn dr7(&self) -> u64 { self.Dr7 as u64 }
    fn set_dr7(&mut self, value: u64) { self.Dr7 = value as u32; }
    fn pc(&self) -> u64 { self.Eip as u64 }
    fn set_trap_flag(&mut self, on: bool) {
        if on { self.EFlags |= 0x100 } else { self.EFlags &= !0x100 }
    }
}

#[cfg(target_arch = "x86_64")]
impl X86DebugRegs for CONTEXT {
    fn set_dr(&mut self, index: u8, value: u64) {
        match index { 0 => self.Dr0 = value, 1 => self.Dr1 = value, 2 => self.Dr2 = value, 3 => self.Dr3 = value, _ => {} }
    }
    fn dr6(&self) -> u64 { self.Dr6 }
    fn set_dr6(&mut self, value: u64) { self.Dr6 = value; }
    fn dr7(&self) -> u64 { self.Dr7 }
    fn set_dr7(&mut self, value: u64) { self.Dr7 = value; }
    fn pc(&self) -> u64 { self.Rip }
    fn set_trap_flag(&mut self, on: bool) {
        if on { self.EFlags |= 0x100 } else { self.EFlags &= !0x100 }
    }
}

/// Encode the DR7 condition bits for a hardware breakpoint type.
/// Returns the 2-bit condition value:
///   00 = execute, 01 = write, 11 = read/write
fn x86_bp_type_to_condition(bp_type: HardwareBreakpointType) -> u64 {
    match bp_type {
        HardwareBreakpointType::Execute => 0b00,
        HardwareBreakpointType::Write => 0b01,
        HardwareBreakpointType::ReadWrite => 0b11,
    }
}

/// Encode the DR7 length bits for a hardware breakpoint size.
/// Returns the 2-bit length value:
///   00 = 1 byte, 01 = 2 bytes, 11 = 4 bytes, 10 = 8 bytes
fn x86_bp_size_to_length(size: HardwareBreakpointSize) -> u64 {
    match size {
        HardwareBreakpointSize::Byte1 => 0b00,
        HardwareBreakpointSize::Byte2 => 0b01,
        HardwareBreakpointSize::Byte4 => 0b11,
        HardwareBreakpointSize::Byte8 => 0b10,
    }
}

/// Program DR<index> + its DR7 enable/condition/length fields.
pub(super) fn x86_set_hw_bp<C: X86DebugRegs + ?Sized>(
    ctx: &mut C,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) {
    if dr_index > 3 {
        return;
    }
    ctx.set_dr(dr_index, address);
    let condition = x86_bp_type_to_condition(bp_type);
    // Execute breakpoints must use 1-byte size
    let length = if bp_type == HardwareBreakpointType::Execute { 0b00 } else { x86_bp_size_to_length(size) };
    // DR7 bit layout per debug register:
    //   Local enable: bit (dr_index * 2)
    //   Condition (RW): bits (16 + dr_index * 4) to (17 + dr_index * 4)
    //   Length (LEN):   bits (18 + dr_index * 4) to (19 + dr_index * 4)
    let idx = dr_index as u64;
    let mut dr7 = ctx.dr7();
    dr7 |= 1 << (idx * 2);
    let cond_shift = 16 + idx * 4;
    dr7 &= !(0b11 << cond_shift);
    dr7 |= condition << cond_shift;
    let len_shift = 18 + idx * 4;
    dr7 &= !(0b11 << len_shift);
    dr7 |= length << len_shift;
    ctx.set_dr7(dr7);
}

/// Zero DR<index> and clear its DR7 fields.
pub(super) fn x86_clear_hw_bp<C: X86DebugRegs + ?Sized>(ctx: &mut C, dr_index: u8) {
    if dr_index > 3 {
        return;
    }
    ctx.set_dr(dr_index, 0);
    let idx = dr_index as u64;
    let mut dr7 = ctx.dr7();
    dr7 &= !(1 << (idx * 2));
    dr7 &= !(0b11 << (16 + idx * 4));
    dr7 &= !(0b11 << (18 + idx * 4));
    ctx.set_dr7(dr7);
}

/// Which breakpoint DR6 reports as hit (bits 0-3); clears DR6 when one is.
pub(super) fn x86_check_dr6<C: X86DebugRegs + ?Sized>(ctx: &mut C) -> Option<u8> {
    let dr6 = ctx.dr6();
    for i in 0..4u8 {
        if dr6 & (1 << i) != 0 {
            ctx.set_dr6(0);
            return Some(i);
        }
    }
    None
}

pub(super) fn x86_disable_enable_bit<C: X86DebugRegs + ?Sized>(ctx: &mut C, dr_index: u8) {
    ctx.set_dr7(ctx.dr7() & !(1 << (dr_index as u64 * 2)));
}

pub(super) fn x86_enable_enable_bit<C: X86DebugRegs + ?Sized>(ctx: &mut C, dr_index: u8) {
    ctx.set_dr7(ctx.dr7() | (1 << (dr_index as u64 * 2)));
}

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

    fn regs(&mut self) -> &mut dyn X86DebugRegs {
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
    x86_set_hw_bp(ctx, dr_index, address, bp_type, size);
}

/// Clear a hardware breakpoint from a CONTEXT structure.
/// Zeros the DR address register and clears DR7 enable/condition/length bits.
#[cfg(target_arch = "x86_64")]
pub(super) fn clear_hw_bp_in_context(ctx: &mut CONTEXT, dr_index: u8) {
    x86_clear_hw_bp(ctx, dr_index);
}


/// Apply a single hardware breakpoint to a thread by getting/setting its context.
/// Uses CONTEXT_DEBUG_REGISTERS only — we only need DR0-DR7, and CONTEXT_ALL
/// can fail on threads in certain states (kernel transitions, uninitialized, etc.)
/// with ERROR_GEN_FAILURE ("A device attached to the system is not functioning").
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

/// Number of bytes covered by a watchpoint size.
#[cfg(target_arch = "aarch64")]
fn bp_size_bytes(size: HardwareBreakpointSize) -> u32 {
    match size {
        HardwareBreakpointSize::Byte1 => 1,
        HardwareBreakpointSize::Byte2 => 2,
        HardwareBreakpointSize::Byte4 => 4,
        HardwareBreakpointSize::Byte8 => 8,
    }
}

/// Program one hardware breakpoint/watchpoint into an ARM64 CONTEXT.
///
/// Execute -> Bvr/Bcr (DBGBVR/DBGBCR), data -> Wvr/Wcr (DBGWVR/DBGWCR).
/// Control register fields used (EL0 user-mode debug):
///   DBGBCR: E=bit0, PMC=bits[2:1]=0b10 (EL0), BAS=bits[8:5]=0b1111 (4-byte instr)
///   DBGWCR: E=bit0, PAC=bits[2:1]=0b10 (EL0), LSC=bits[4:3], BAS=bits[12:5]
///     LSC: 0b01=load, 0b10=store, 0b11=load+store
#[cfg(target_arch = "aarch64")]
pub(super) fn set_hw_bp_in_context(
    ctx: &mut CONTEXT,
    dr_index: u8,
    address: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) {
    let i = dr_index as usize;
    match bp_type {
        HardwareBreakpointType::Execute => {
            if i >= ctx.Bvr.len() {
                return;
            }
            // Instruction address must be word-aligned.
            ctx.Bvr[i] = address & !0x3;
            // E=1, PMC=0b10 (EL0), BAS=0b1111 → 0x1 | 0x4 | 0x1E0 = 0x1E5
            ctx.Bcr[i] = 0b1 | (0b10 << 1) | (0b1111 << 5);
        }
        HardwareBreakpointType::Write | HardwareBreakpointType::ReadWrite => {
            if i >= ctx.Wvr.len() {
                return;
            }
            let lsc: u32 = match bp_type {
                HardwareBreakpointType::Write => 0b10,      // store only
                HardwareBreakpointType::ReadWrite => 0b11,  // load + store
                HardwareBreakpointType::Execute => unreachable!(),
            };
            // WVR holds a doubleword-aligned base; BAS selects bytes within it.
            let aligned = address & !0x7u64;
            let byte_offset = (address & 0x7) as u32;
            let nbytes = bp_size_bytes(size);
            let bas = (((1u32 << nbytes) - 1) << byte_offset) & 0xFF;
            ctx.Wvr[i] = aligned;
            ctx.Wcr[i] = 0b1 | (0b10 << 1) | (lsc << 3) | (bas << 5);
        }
    }
}

/// Clear one hardware breakpoint/watchpoint from an ARM64 CONTEXT.
#[cfg(target_arch = "aarch64")]
pub(super) fn clear_hw_bp_in_context(
    ctx: &mut CONTEXT,
    dr_index: u8,
    bp_type: HardwareBreakpointType,
) {
    let i = dr_index as usize;
    match bp_type {
        HardwareBreakpointType::Execute => {
            if i < ctx.Bvr.len() {
                ctx.Bvr[i] = 0;
                ctx.Bcr[i] = 0;
            }
        }
        _ => {
            if i < ctx.Wvr.len() {
                ctx.Wvr[i] = 0;
                ctx.Wcr[i] = 0;
            }
        }
    }
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

/// Zero every ARM64 hardware breakpoint/watchpoint register so no stale bits
/// linger in unused slots before (re-)applying the active set or stepping past one.
#[cfg(target_arch = "aarch64")]
pub(super) fn clear_all_hw_bp_in_context(ctx: &mut CONTEXT) {
    for i in 0..ctx.Bcr.len() {
        ctx.Bcr[i] = 0;
        ctx.Bvr[i] = 0;
    }
    for i in 0..ctx.Wcr.len() {
        ctx.Wcr[i] = 0;
        ctx.Wvr[i] = 0;
    }
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
