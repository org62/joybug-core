//! Software breakpoints: which addresses carry an int3/brk, the original bytes
//! under them, and the temporary breakpoints the stepper plants. The table is
//! plain data; the functions that touch the tracee take a [`ProcessOps`].

use super::ops::ProcessOps;
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::StepKind;
use std::collections::{HashMap, HashSet};
use tracing::warn;

// Kernel-transition ("syscall") instruction encodings, used by
// [`instruction_is_syscall`] to recognise a syscall stub.
//
// x64 - two-byte opcodes, no operands:
/// `syscall` - the AMD64 fast system call used by every modern ntdll stub.
const X64_SYSCALL: [u8; 2] = [0x0F, 0x05];
/// `sysenter` - the Intel equivalent, still reachable in WOW64/legacy stubs.
const X64_SYSENTER: [u8; 2] = [0x0F, 0x34];
/// `int 2Eh` - the pre-XP system call gate, kept as a fallback in some stubs.
const X64_INT_2E: [u8; 2] = [0xCD, 0x2E];

// ARM64 - fixed-width 32-bit instruction. `svc #imm16` encodes as
//   31                 21 20            5 4   0
//   1 1 0 1 0 1 0 0 0 0 0 | i(16 bits)   | 0 0 0 0 1
// so mask off the immediate and compare the fixed bits.
/// Bits of an ARM64 instruction word that are fixed for `svc` (the immediate is masked out).
const ARM64_SVC_MASK: u32 = 0xFFE0_001F;
/// Value those fixed bits must have for the instruction to be `svc #imm16`.
const ARM64_SVC_OPCODE: u32 = 0xD400_0001;

/// True when `word` (a little-endian ARM64 instruction) is `svc #imm16`.
pub fn arm64_word_is_svc(word: u32) -> bool {
    word & ARM64_SVC_MASK == ARM64_SVC_OPCODE
}

/// The architecture-appropriate bytes of a breakpoint instruction.
pub fn breakpoint_bytes(arch: Architecture) -> Vec<u8> {
    match arch {
        Architecture::X86 | Architecture::X64 => vec![0xCC],
        Architecture::Arm64 => vec![0x00, 0x00, 0x3e, 0xD4],
    }
}

#[derive(Debug, Default)]
pub struct BreakpointTable {
    single_shot: HashMap<u64, Vec<u8>>,
    persistent: HashMap<u64, Vec<u8>>,
    tid_filters: HashMap<u64, Option<u32>>,
    /// Every address where a software breakpoint of ours was ever armed. When one
    /// is removed while the target runs, another thread can trap on the INT3 in
    /// the window before the removal lands - the kernel queues that event and
    /// delivers it to us after the byte is already back to the original
    /// instruction - so such a hit has to be recognized as ours (see
    /// [`is_stale_hit`]) instead of being reported as an unknown breakpoint with
    /// the IP left past the INT3. Recording at arm time (not removal time) means
    /// no removal path can forget the bookkeeping; the live breakpoint paths
    /// claim hits on still-armed addresses before the stale check runs, and the
    /// byte check rejects addresses where an INT3 is present. Never cleared while
    /// the process lives: there is no bound on how long a queued event can take
    /// to arrive.
    ever_armed: HashSet<u64>,
    /// Step-over breakpoints by address -> (tid, kind).
    step_over: HashMap<u64, (u32, StepKind)>,
    /// Step-out breakpoints by address -> (tid, original return address).
    step_out: HashMap<u64, (u32, u64)>,
    /// A backend's own breakpoints (stored as persistent entries so the
    /// restore / re-arm / patch machinery applies), by address -> hook id.
    internal: HashMap<u64, u32>,
}

impl BreakpointTable {
    pub fn insert_single_shot(&mut self, address: u64, original_bytes: Vec<u8>) {
        self.ever_armed.insert(address);
        self.single_shot.insert(address, original_bytes);
    }

    pub fn insert_persistent(&mut self, address: u64, original_bytes: Vec<u8>, tid: Option<u32>) {
        self.ever_armed.insert(address);
        self.persistent.insert(address, original_bytes);
        self.tid_filters.insert(address, tid);
    }

    /// Register a backend-internal hook at `address` (see
    /// [`ProcessOps::on_internal_hook`](super::ops::ProcessOps::on_internal_hook)).
    pub fn insert_internal(&mut self, address: u64, original_bytes: Vec<u8>, hook_id: u32) {
        self.insert_persistent(address, original_bytes, None);
        self.internal.insert(address, hook_id);
    }

    pub fn internal_hook_at(&self, address: u64) -> Option<u32> {
        self.internal.get(&address).copied()
    }

    /// Put the original bytes back under the backend's own hooks in a memory
    /// read: a user never set them, so they must not show as patches or as
    /// `int3` in a disassembly (user breakpoints stay visible; the UI knows
    /// those from its own list).
    pub fn hide_internal_bytes(&self, base_address: u64, data: &mut [u8]) {
        let range_end = base_address + data.len() as u64;
        for (bp_start, original) in self.internal.keys().filter_map(|a| self.persistent.get(a).map(|o| (*a, o))) {
            let bp_end = bp_start + original.len() as u64;
            if bp_start < range_end && bp_end > base_address {
                let copy_start = bp_start.max(base_address);
                let copy_end = bp_end.min(range_end);
                let buf_offset = (copy_start - base_address) as usize;
                let src_offset = (copy_start - bp_start) as usize;
                let len = (copy_end - copy_start) as usize;
                data[buf_offset..buf_offset + len].copy_from_slice(&original[src_offset..src_offset + len]);
            }
        }
    }

    /// Remove and return original bytes for a single-shot breakpoint at `address` if present.
    pub fn remove_single_shot(&mut self, address: u64) -> Option<Vec<u8>> {
        self.single_shot.remove(&address)
    }

    pub fn has_single_shot(&self, address: u64) -> bool {
        self.single_shot.contains_key(&address)
    }

    pub fn is_persistent(&self, address: u64) -> bool {
        self.persistent.contains_key(&address)
    }

    /// The saved original bytes under the persistent breakpoint at `address`.
    pub fn persistent_original(&self, address: u64) -> Option<&Vec<u8>> {
        self.persistent.get(&address)
    }

    /// Determine if the persistent breakpoint at `address` is allowed for `tid` (filter passes).
    pub fn persistent_allowed_for_tid(&self, address: u64, tid: u32) -> bool {
        if let Some(filter_opt) = self.tid_filters.get(&address) {
            if let Some(filter_tid) = *filter_opt {
                return filter_tid == tid;
            }
        }
        true
    }

    pub fn ever_armed(&self, address: u64) -> bool {
        self.ever_armed.contains(&address)
    }

    pub fn remove_step_over(&mut self, address: u64) -> Option<(u32, StepKind)> {
        self.step_over.remove(&address)
    }

    pub fn insert_step_over(&mut self, address: u64, tid: u32, kind: StepKind) {
        self.step_over.insert(address, (tid, kind));
    }

    pub fn has_step_over(&self, address: u64) -> bool {
        self.step_over.contains_key(&address)
    }

    /// Clear all step-over breakpoints. Returns how many were removed.
    pub fn clear_step_over(&mut self) -> usize {
        let before = self.step_over.len();
        self.step_over.clear();
        before
    }

    /// Retain only step-over breakpoints not owned by `tid`. Returns number removed.
    pub fn retain_step_over_excluding_tid(&mut self, tid: u32) -> usize {
        let before = self.step_over.len();
        self.step_over.retain(|_, (t, _)| *t != tid);
        before - self.step_over.len()
    }

    pub fn has_step_out(&self, address: u64) -> bool {
        self.step_out.contains_key(&address)
    }

    pub fn remove_step_out(&mut self, address: u64) -> Option<(u32, u64)> {
        self.step_out.remove(&address)
    }

    pub fn insert_step_out(&mut self, address: u64, tid: u32, original_return_address: u64) {
        self.step_out.insert(address, (tid, original_return_address));
    }

    /// Clear all step-out breakpoints. Returns how many were removed.
    pub fn clear_step_out(&mut self) -> usize {
        let before = self.step_out.len();
        self.step_out.clear();
        before
    }

    /// Retain only step-out breakpoints not owned by `tid`. Returns number removed.
    pub fn retain_step_out_excluding_tid(&mut self, tid: u32) -> usize {
        let before = self.step_out.len();
        self.step_out.retain(|_, (t, _)| *t != tid);
        before - self.step_out.len()
    }

    /// Forget the breakpoint at `address` (persistent or single-shot) and hand
    /// back its original bytes for the caller to restore. `None` when nothing
    /// is registered there, or when the address is owned by an in-flight
    /// step-over: the stepper parked its saved bytes in the single-shot map and
    /// still needs them to complete the step. `ever_armed` is deliberately
    /// kept - a thread that trapped just before the removal still needs
    /// [`is_stale_hit`] to recognise its event and rewind it.
    pub fn take_for_removal(&mut self, address: u64) -> Option<Vec<u8>> {
        match self.persistent.remove(&address) {
            Some(original) => {
                self.tid_filters.remove(&address);
                self.internal.remove(&address);
                Some(original)
            }
            // A step-over parks its saved bytes in the single-shot map; leave those.
            None if self.step_over.contains_key(&address) => None,
            None => self.single_shot.remove(&address),
        }
    }

    /// Every armed breakpoint's address and original bytes (persistent and
    /// single-shot), e.g. to undo the patches in a forked child's copy.
    pub fn iter_originals(&self) -> impl Iterator<Item = (u64, &Vec<u8>)> + '_ {
        self.persistent.iter().chain(self.single_shot.iter()).map(|(a, b)| (*a, b))
    }

    /// Forget every persistent and single-shot breakpoint, handing back
    /// `(address, original bytes)` for the caller to restore.
    pub fn drain_all(&mut self) -> Vec<(u64, Vec<u8>)> {
        let all: Vec<(u64, Vec<u8>)> = self
            .persistent
            .drain()
            .chain(self.single_shot.drain())
            .collect();
        self.tid_filters.clear();
        self.internal.clear();
        all
    }

    /// Patch a memory buffer to replace breakpoint instruction bytes with the
    /// original bytes that were saved when each breakpoint was set.
    /// This should be used before disassembling memory so the user sees
    /// original instructions rather than int3/brk.
    pub fn patch_breakpoint_bytes(&self, base_address: u64, data: &mut [u8]) {
        let range_end = base_address + data.len() as u64;
        for (bp_addr, original) in self.persistent.iter().chain(self.single_shot.iter()) {
            let bp_start = *bp_addr;
            let bp_end = bp_start + original.len() as u64;
            // Check for overlap with buffer range
            if bp_start < range_end && bp_end > base_address {
                let copy_start = bp_start.max(base_address);
                let copy_end = bp_end.min(range_end);
                let buf_offset = (copy_start - base_address) as usize;
                let src_offset = (copy_start - bp_start) as usize;
                let len = (copy_end - copy_start) as usize;
                data[buf_offset..buf_offset + len]
                    .copy_from_slice(&original[src_offset..src_offset + len]);
            }
        }
    }
}

/// Plant a single-shot breakpoint at `address`, saving exactly the bytes the
/// breakpoint instruction overwrites.
pub fn arm_single_shot<O: ProcessOps + ?Sized>(
    bps: &mut BreakpointTable,
    ops: &O,
    pid: u32,
    address: u64,
) -> Result<(), PlatformError> {
    // `int3` on x86/x64, `BRK #0` on ARM64; save exactly the bytes it overwrites.
    let breakpoint_bytes = breakpoint_bytes(ops.arch());
    let original_bytes = ops.read(pid, address, breakpoint_bytes.len())?;
    bps.insert_single_shot(address, original_bytes);
    ops.write(pid, address, &breakpoint_bytes)
}

/// Plant a persistent breakpoint at `address` (idempotent), optionally
/// filtered to `tid`.
pub fn arm_persistent<O: ProcessOps + ?Sized>(
    bps: &mut BreakpointTable,
    ops: &O,
    pid: u32,
    address: u64,
    tid: Option<u32>,
) -> Result<(), PlatformError> {
    if bps.is_persistent(address) {
        return Ok(());
    }
    let breakpoint_bytes = breakpoint_bytes(ops.arch());
    let original_bytes = ops.read(pid, address, breakpoint_bytes.len())?;
    bps.insert_persistent(address, original_bytes, tid);
    ops.write(pid, address, &breakpoint_bytes)
}

/// Restore the original instruction bytes for the persistent breakpoint at
/// `address`, if one exists. Borrows the stored bytes directly (no clone) -
/// this runs on the silent coverage auto-continue hot path.
pub fn restore_persistent_original<O: ProcessOps + ?Sized>(
    bps: &BreakpointTable,
    ops: &O,
    pid: u32,
    address: u64,
) -> Result<(), PlatformError> {
    if let Some(original) = bps.persistent.get(&address) {
        ops.write(pid, address, original)?;
    }
    Ok(())
}

/// Whether the instruction currently at `address` is a kernel transition
/// (`svc` on ARM64, `syscall`/`sysenter`/`int 2Eh` on x64). Call this *after*
/// the original bytes have been restored.
///
/// Such an instruction can block for an unbounded time - an ntdll syscall stub
/// like `NtWaitForAlertByThreadId` sleeps until another thread wakes it - so
/// its step-over must not freeze (or defer the events of) the other threads:
/// the thread that would wake it is one of them, and the single-step that
/// thaws everyone can only arrive after the syscall returns. On ARM64 this is
/// not a corner case: an ntdll syscall stub is literally `svc #n; ret`, so the
/// function entry that coverage arms *is* the syscall (493 of ntdll's 7859
/// `RUNTIME_FUNCTION` entries). On x64 the stub prologue sits at the entry and
/// the `syscall` is a few instructions in, so it is only reachable by a
/// breakpoint set directly on it.
///
/// This runs on every software-breakpoint hit, so it must stay cheap: on ARM64
/// the saved original word classifies with no debuggee read at all; on x64 the
/// single saved byte prefilters (almost no instruction starts with 0x0F/0xCD),
/// so the cross-process read for the second opcode byte is almost always
/// skipped.
pub fn instruction_is_syscall<O: ProcessOps + ?Sized>(
    bps: &BreakpointTable,
    ops: &O,
    pid: u32,
    address: u64,
) -> bool {
    let saved = bps.persistent.get(&address);
    match ops.arch() {
        Architecture::Arm64 => {
            // The 4 original bytes are already saved, so no read is needed.
            let word = match saved.and_then(|original| original.first_chunk::<4>()) {
                Some(&bytes) => u32::from_le_bytes(bytes),
                None => {
                    let read = ops.read(pid, address, 4).unwrap_or_default();
                    let Some(&bytes) = read.first_chunk::<4>() else {
                        return false;
                    };
                    u32::from_le_bytes(bytes)
                }
            };
            arm64_word_is_svc(word)
        }
        Architecture::X86 | Architecture::X64 => {
            // Only the first byte is saved (0xCC overwrote exactly one byte).
            if let Some(original) = saved {
                if !matches!(original.first(), Some(0x0F | 0xCD)) {
                    return false;
                }
            }
            let opcode = ops.read(pid, address, 2).unwrap_or_default();
            opcode == X64_SYSCALL || opcode == X64_SYSENTER || opcode == X64_INT_2E
        }
    }
}

/// If current memory matches the original instruction bytes for a persistent
/// breakpoint at `address`, re-arm the breakpoint by writing the breakpoint
/// instruction back.
pub fn rearm_if_matches_original<O: ProcessOps + ?Sized>(
    bps: &BreakpointTable,
    ops: &O,
    pid: u32,
    address: u64,
) -> Result<(), PlatformError> {
    if let Some(original) = bps.persistent.get(&address) {
        let current = ops.read(pid, address, original.len()).unwrap_or_default();
        if current == *original {
            let bp_bytes = breakpoint_bytes(ops.arch());
            let _ = ops.write(pid, address, &bp_bytes);
        }
    }
    Ok(())
}

/// Remove a software breakpoint, persistent or single-shot, restoring the
/// original instruction bytes.
///
/// Both kinds must be handled here: single-shot breakpoints (module entry /
/// TLS callback rows, `set_single_shot_breakpoint`) live in their own map, so
/// looking only at the persistent map silently left their INT3 armed and the
/// client kept trapping on a breakpoint it believed it had removed.
pub fn remove_breakpoint<O: ProcessOps + ?Sized>(
    bps: &mut BreakpointTable,
    ops: &O,
    pid: u32,
    address: u64,
) -> Result<(), PlatformError> {
    match bps.take_for_removal(address) {
        Some(original) => ops.write(pid, address, &original),
        None => {
            warn!(address, "Breakpoint not found");
            Ok(())
        }
    }
}

/// Whether a breakpoint trap at `address` is a *stale* hit on a software
/// breakpoint we have already removed: a thread trapped on the INT3 just before
/// (or while) the removal happened and the kernel only delivered its event
/// afterwards. The removal wrote the original instruction back, so the thread
/// merely needs its IP rewound to re-execute it.
///
/// Verifying that the breakpoint instruction is *gone* from `address` is what
/// makes this safe: if the debuggee has its own `int3`/`brk` there (including the
/// case where that was the original byte we saved), the bytes still match the
/// breakpoint pattern and the hit is reported to the client as usual. A hit on
/// a *still-armed* address never gets here - the live breakpoint paths claim it
/// first - and would fail the byte check anyway.
pub fn is_stale_hit<O: ProcessOps + ?Sized>(
    bps: &BreakpointTable,
    ops: &O,
    pid: u32,
    address: u64,
) -> bool {
    if !bps.ever_armed.contains(&address) {
        return false;
    }
    let bp_bytes = breakpoint_bytes(ops.arch());
    match ops.read(pid, address, bp_bytes.len()) {
        Ok(current) => current != bp_bytes,
        // Unreadable (freed/unmapped code): nothing sensible to rewind into.
        Err(_) => false,
    }
}

/// Restore the original bytes for every software breakpoint (persistent and
/// single-shot) and forget them. Used on detach so the target keeps running
/// without executing leftover int3/brk instructions.
pub fn restore_all<O: ProcessOps + ?Sized>(bps: &mut BreakpointTable, ops: &O, pid: u32) {
    for (addr, original) in bps.drain_all() {
        if let Err(e) = ops.write(pid, addr, &original) {
            warn!(address = addr, error = %e, "Failed to restore breakpoint byte on detach");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real encodings taken from ARM64 ntdll syscall stubs, which are literally
    /// `svc #n; ret` - this is why a coverage breakpoint on a function entry can
    /// land on a blocking syscall (see `instruction_is_syscall`).
    #[test]
    fn recognizes_arm64_svc_stub_encodings() {
        // ntdll!NtWaitForAlertByThreadId: svc #0x1E3
        assert!(arm64_word_is_svc(0xD400_3C61));
        // ntdll!NtWaitForWorkViaWorkerFactory: svc #0x1E6
        assert!(arm64_word_is_svc(0xD400_3CC1));
        // First stub in the table: svc #0
        assert!(arm64_word_is_svc(0xD400_0001));
    }

    #[test]
    fn rejects_non_svc_arm64_instructions() {
        // ret (the instruction right after every syscall stub)
        assert!(!arm64_word_is_svc(0xD65F_03C0));
        // brk #0x3e - our own breakpoint instruction, same encoding family as svc
        assert!(!arm64_word_is_svc(0xD43E_0000));
        // hvc #0 / smc #0 - sibling exception-generating instructions
        assert!(!arm64_word_is_svc(0xD400_0002));
        assert!(!arm64_word_is_svc(0xD400_0003));
        // nop
        assert!(!arm64_word_is_svc(0xD503_201F));
    }

    #[test]
    fn removal_leaves_step_over_bytes_alone_and_keeps_ever_armed() {
        let mut t = BreakpointTable::default();
        t.insert_single_shot(0x10, vec![0x90]);
        t.insert_step_over(0x10, 7, StepKind::Over);
        assert_eq!(t.take_for_removal(0x10), None, "owned by the step-over");
        t.remove_step_over(0x10);
        assert_eq!(t.take_for_removal(0x10), Some(vec![0x90]));
        assert!(t.ever_armed(0x10));
        t.insert_persistent(0x20, vec![0x55], Some(3));
        assert!(t.persistent_allowed_for_tid(0x20, 3));
        assert!(!t.persistent_allowed_for_tid(0x20, 4));
        assert_eq!(t.take_for_removal(0x20), Some(vec![0x55]));
        assert!(t.persistent_allowed_for_tid(0x20, 4), "filter is gone with the breakpoint");
    }
}
