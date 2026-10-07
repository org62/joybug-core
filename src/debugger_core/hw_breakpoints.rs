//! Hardware breakpoint register math, shared by every backend.
//!
//! x86 family: the DR0-DR7 model. The encoding helpers are generic over
//! [`X86DebugRegs`], implemented for the Windows `CONTEXT`/`WOW64_CONTEXT`
//! structs and for [`X86DebugRegsRaw`], the plain-value form a ptrace backend
//! fills from `PTRACE_PEEKUSER`. ARM64: the DBGBVR/DBGBCR/DBGWVR/DBGWCR
//! encoding over a `CONTEXT`. Nothing here talks to the OS.

use crate::protocol::{HardwareBreakpointSize, HardwareBreakpointType};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::protocol::CONTEXT;
use crate::protocol::WOW64_CONTEXT;

/// A hardware breakpoint as the debugger tracks it: its slot (`dr_index`) and
/// whether it is currently programmed into the threads (`is_active` goes false
/// while stepping past a hit).
#[derive(Debug, Clone)]
pub struct InternalHardwareBreakpoint {
    pub address: u64,
    pub bp_type: HardwareBreakpointType,
    pub size: HardwareBreakpointSize,
    pub dr_index: u8,
    pub is_active: bool,
}

// ============================================================================
// x86 family: the DR0-DR7 model shared by a native x64 thread (`CONTEXT`, x64
// host only) and a WOW64 thread (`WOW64_CONTEXT`, either host). The encoding
// helpers are generic over this trait; the per-host `CONTEXT` wrappers below
// and the WOW64 path both delegate to them.
// ============================================================================

pub trait X86DebugRegs {
    fn set_dr(&mut self, index: u8, value: u64);
    fn dr6(&self) -> u64;
    fn set_dr6(&mut self, value: u64);
    fn dr7(&self) -> u64;
    fn set_dr7(&mut self, value: u64);
    /// Instruction pointer (RIP / EIP).
    fn pc(&self) -> u64;
    fn set_trap_flag(&mut self, on: bool);

    // Provided, so the operations are reachable through `&mut dyn X86DebugRegs`.
    fn set_bp(&mut self, dr_index: u8, address: u64, bp_type: HardwareBreakpointType, size: HardwareBreakpointSize) {
        x86_set_hw_bp(self, dr_index, address, bp_type, size);
    }
    fn clear_bp(&mut self, dr_index: u8) {
        x86_clear_hw_bp(self, dr_index);
    }
    /// Which breakpoint DR6 reports as hit (bits 0-3); clears DR6 when one is.
    fn check_dr6(&mut self) -> Option<u8> {
        x86_check_dr6(self)
    }
    fn enable_bit(&mut self, dr_index: u8) {
        x86_enable_enable_bit(self, dr_index);
    }
    fn disable_bit(&mut self, dr_index: u8) {
        x86_disable_enable_bit(self, dr_index);
    }
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
pub fn x86_set_hw_bp<C: X86DebugRegs + ?Sized>(
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
pub fn x86_clear_hw_bp<C: X86DebugRegs + ?Sized>(ctx: &mut C, dr_index: u8) {
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
pub fn x86_check_dr6<C: X86DebugRegs + ?Sized>(ctx: &mut C) -> Option<u8> {
    let dr6 = ctx.dr6();
    for i in 0..4u8 {
        if dr6 & (1 << i) != 0 {
            ctx.set_dr6(0);
            return Some(i);
        }
    }
    None
}

pub fn x86_disable_enable_bit<C: X86DebugRegs + ?Sized>(ctx: &mut C, dr_index: u8) {
    ctx.set_dr7(ctx.dr7() & !(1 << (dr_index as u64 * 2)));
}

pub fn x86_enable_enable_bit<C: X86DebugRegs + ?Sized>(ctx: &mut C, dr_index: u8) {
    ctx.set_dr7(ctx.dr7() | (1 << (dr_index as u64 * 2)));
}


/// The x86 debug-register block as plain values, for a backend that reads the
/// registers one at a time (ptrace `PEEKUSER`) rather than as part of a
/// `CONTEXT`. `pc`/`eflags` are only meaningful when the backend filled them.
#[derive(Debug, Clone, Copy, Default)]
pub struct X86DebugRegsRaw {
    pub dr: [u64; 4],
    pub dr6: u64,
    pub dr7: u64,
    pub pc: u64,
    pub eflags: u64,
}

impl X86DebugRegs for X86DebugRegsRaw {
    fn set_dr(&mut self, index: u8, value: u64) {
        if let Some(slot) = self.dr.get_mut(index as usize) {
            *slot = value;
        }
    }
    fn dr6(&self) -> u64 { self.dr6 }
    fn set_dr6(&mut self, value: u64) { self.dr6 = value; }
    fn dr7(&self) -> u64 { self.dr7 }
    fn set_dr7(&mut self, value: u64) { self.dr7 = value; }
    fn pc(&self) -> u64 { self.pc }
    fn set_trap_flag(&mut self, on: bool) {
        if on { self.eflags |= 0x100 } else { self.eflags &= !0x100 }
    }
}

// ============================================================================
// ARM64: DBGBVR/DBGBCR (instruction) and DBGWVR/DBGWCR (data) over a CONTEXT.
// ============================================================================

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
pub fn arm64_set_hw_bp(
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
pub fn arm64_clear_hw_bp(
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

/// Zero every ARM64 hardware breakpoint/watchpoint register so no stale bits
/// linger in unused slots before (re-)applying the active set or stepping past one.
#[cfg(target_arch = "aarch64")]
pub fn arm64_clear_all_hw_bps(ctx: &mut CONTEXT) {
    for i in 0..ctx.Bcr.len() {
        ctx.Bcr[i] = 0;
        ctx.Bvr[i] = 0;
    }
    for i in 0..ctx.Wcr.len() {
        ctx.Wcr[i] = 0;
        ctx.Wvr[i] = 0;
    }
}


// ============================================================================
// The slots a process has programmed.
// ============================================================================

use crate::interfaces::Architecture;

/// The hardware breakpoints of one process and their slot assignment.
#[derive(Debug, Default)]
pub struct HwBpTable(Vec<InternalHardwareBreakpoint>);

impl HwBpTable {
    /// Find a free debug-register slot for a breakpoint of the given type.
    ///
    /// x86: a single shared bank of 4 registers (DR0-DR3) serves every type.
    /// ARM64: two independent banks - 8 breakpoint slots (Bvr/Bcr, Execute) and
    /// 2 watchpoint slots (Wvr/Wcr, Write/ReadWrite). Returns the slot index
    /// within the relevant bank, or None if that bank is full.
    pub fn find_free_slot(&self, arch: Architecture, bp_type: HardwareBreakpointType) -> Option<u8> {
        match arch {
            Architecture::X86 | Architecture::X64 => {
                let used: std::collections::HashSet<u8> = self.0.iter().map(|bp| bp.dr_index).collect();
                (0..4u8).find(|i| !used.contains(i))
            }
            Architecture::Arm64 => {
                let is_exec = matches!(bp_type, HardwareBreakpointType::Execute);
                let max = if is_exec { 8u8 } else { 2u8 };
                let used: std::collections::HashSet<u8> = self
                    .0
                    .iter()
                    .filter(|bp| matches!(bp.bp_type, HardwareBreakpointType::Execute) == is_exec)
                    .map(|bp| bp.dr_index)
                    .collect();
                (0..max).find(|i| !used.contains(i))
            }
        }
    }

    pub fn add(&mut self, bp: InternalHardwareBreakpoint) {
        self.0.push(bp);
    }

    /// Remove a hardware breakpoint by address. Returns the removed BP if found.
    pub fn remove_by_addr(&mut self, addr: u64) -> Option<InternalHardwareBreakpoint> {
        let pos = self.0.iter().position(|bp| bp.address == addr)?;
        Some(self.0.remove(pos))
    }

    pub fn find_by_dr_index(&self, dr_index: u8) -> Option<&InternalHardwareBreakpoint> {
        self.0.iter().find(|bp| bp.dr_index == dr_index)
    }

    pub fn find_by_dr_index_mut(&mut self, dr_index: u8) -> Option<&mut InternalHardwareBreakpoint> {
        self.0.iter_mut().find(|bp| bp.dr_index == dr_index)
    }

    pub fn has_at(&self, addr: u64) -> bool {
        self.0.iter().any(|bp| bp.address == addr)
    }

    /// Every active hardware breakpoint.
    pub fn active(&self) -> Vec<InternalHardwareBreakpoint> {
        self.0.iter().filter(|bp| bp.is_active).cloned().collect()
    }

    /// Find the active hardware breakpoint/watchpoint responsible for an access
    /// at `addr` (ARM64 hit detection).
    ///
    /// For watchpoints (`is_watchpoint`), the OS reports the accessed data
    /// address; match it to the watched variable's doubleword-aligned window.
    /// For execute breakpoints, match the instruction address exactly.
    pub fn active_for_access(&self, addr: u64, is_watchpoint: bool) -> Option<InternalHardwareBreakpoint> {
        self.0
            .iter()
            .filter(|bp| bp.is_active)
            .find(|bp| {
                let is_exec = matches!(bp.bp_type, HardwareBreakpointType::Execute);
                if is_watchpoint {
                    !is_exec && (addr & !0x7) == (bp.address & !0x7)
                } else {
                    is_exec && bp.address == addr
                }
            })
            .cloned()
    }
}

// ============================================================================
// Arming and disarming across a process's threads.
// ============================================================================

use super::ops::ProcessOps;
use super::DebugBook;
use crate::interfaces::PlatformError;
use tracing::{info, trace, warn};

/// Allocate a slot and program the breakpoint on every live thread. Returns
/// the slot index.
pub fn set_hardware_breakpoint<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    addr: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) -> Result<u8, PlatformError> {
    trace!(pid, addr, ?bp_type, ?size, "set_hardware_breakpoint called");

    // Check for duplicate
    if book.hw.has_at(addr) {
        return Err(PlatformError::Other(format!(
            "Hardware breakpoint already exists at 0x{:X}", addr
        )));
    }

    // A WOW64 target's debug registers are 32-bit: no 8-byte length, no
    // address above 4 GB.
    let arch = book.arch;
    if arch == Architecture::X86 {
        if size == HardwareBreakpointSize::Byte8 {
            return Err(PlatformError::Other("32-bit targets have no 8-byte hardware breakpoint length".into()));
        }
        if addr > u32::MAX as u64 {
            return Err(PlatformError::Other(format!("0x{:X} is outside the 32-bit address space", addr)));
        }
    }

    // Allocate a free debug register slot from the appropriate bank
    let dr_index = book.hw.find_free_slot(arch, bp_type)
        .ok_or_else(|| PlatformError::Other(
            "No free hardware debug register slot available for this breakpoint type".to_string()
        ))?;

    // Apply to all threads (skip threads that fail - they may be exiting or
    // in a kernel transition where the register read fails)
    let threads = ops.live_threads(pid);
    let mut applied_count = 0u32;
    for &tid in &threads {
        match ops.apply_hw_bp(pid, tid, dr_index, addr, bp_type, size) {
            Ok(()) => applied_count += 1,
            Err(e) => {
                warn!(tid, addr, error = %e, "Failed to apply HW BP to thread (may have exited or be in kernel transition)");
            }
        }
    }
    if applied_count == 0 && !threads.is_empty() {
        return Err(PlatformError::Other(format!(
            "Failed to set hardware breakpoint: could not apply to any of {} threads", threads.len()
        )));
    }

    // Store in process state
    book.hw.add(InternalHardwareBreakpoint { address: addr, bp_type, size, dr_index, is_active: true });

    info!(pid, addr, dr_index, "Hardware breakpoint set");
    Ok(dr_index)
}

/// Forget the breakpoint at `addr` and clear it from every live thread.
pub fn remove_hardware_breakpoint<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    addr: u64,
) -> Result<(), PlatformError> {
    trace!(pid, addr, "remove_hardware_breakpoint called");
    let bp = book.hw.remove_by_addr(addr)
        .ok_or_else(|| PlatformError::Other(format!(
            "No hardware breakpoint at 0x{:X}", addr
        )))?;

    // Clear from all threads
    for tid in ops.live_threads(pid) {
        let _ = ops.clear_hw_bp(pid, tid, bp.dr_index, bp.bp_type);
    }

    info!(pid, addr, dr_index = bp.dr_index, "Hardware breakpoint removed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dr7_fields_round_trip() {
        let mut r = X86DebugRegsRaw::default();
        x86_set_hw_bp(&mut r, 2, 0x1234, HardwareBreakpointType::Write, HardwareBreakpointSize::Byte4);
        assert_eq!(r.dr[2], 0x1234);
        assert_eq!(r.dr7 & (1 << 4), 1 << 4, "local enable for DR2");
        assert_eq!((r.dr7 >> 24) & 0b11, 0b01, "RW=write");
        assert_eq!((r.dr7 >> 26) & 0b11, 0b11, "LEN=4 bytes");
        // Execute breakpoints always use the 1-byte length encoding.
        x86_set_hw_bp(&mut r, 0, 0x4000, HardwareBreakpointType::Execute, HardwareBreakpointSize::Byte8);
        assert_eq!((r.dr7 >> 16) & 0b1111, 0);
        x86_clear_hw_bp(&mut r, 2);
        assert_eq!(r.dr[2], 0);
        assert_eq!(r.dr7 & (1 << 4), 0);
        r.dr6 = 0b0001;
        assert_eq!(x86_check_dr6(&mut r), Some(0));
        assert_eq!(r.dr6, 0, "DR6 is cleared once the hit is reported");
        assert_eq!(x86_check_dr6(&mut r), None);
    }
}
