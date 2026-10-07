//! Hardware access traces: a watchpoint in silent "collect accessors" mode.
//! The watchpoint's DR/register state lives in the hardware-breakpoint table;
//! this only accumulates who touched the watched address.

use super::hw_breakpoints::{remove_hardware_breakpoint, set_hardware_breakpoint};
use super::ops::ProcessOps;
use super::DebugBook;
use crate::interfaces::{Architecture, PlatformAPI, PlatformError};
use crate::protocol::{HardwareBreakpointSize, HardwareBreakpointType, WatchpointAccess};
use std::collections::HashMap;
use tracing::{info, trace, warn};

/// One distinct accessor of a watched address, keyed by raw trap instruction
/// pointer, and how often it hit. On x86 the trap fires *after* the accessing
/// instruction, so the raw RIP points at the following instruction (the
/// platform back-steps to attribute it when snapshotting); on ARM64 it is the
/// exact faulting PC.
#[derive(Debug, Clone)]
pub struct WatchpointAccessEntry {
    pub hit_count: u64,
    pub first_seq: u64,
    pub thread_ids: Vec<u32>,
}

/// One active hardware access trace. Presence of an entry for a watched
/// address means the hardware watchpoint there is in silent "collect
/// accessors" mode: on a hit the server records the accessor and
/// auto-continues instead of forwarding a `HardwareBreakpoint` event.
#[derive(Debug, Clone, Default)]
pub struct WatchpointTraceEntry {
    pub accessors: HashMap<u64 /*raw rip*/, WatchpointAccessEntry>,
}

#[derive(Debug, Default)]
pub struct WatchBook {
    traces: HashMap<u64, WatchpointTraceEntry>,
    /// Monotonic first-access counter backing `WatchpointAccessEntry::first_seq`.
    seq: u64,
}

impl WatchBook {
    /// Mark the watched `address` as an active access trace (idempotent).
    pub fn arm_trace(&mut self, address: u64) {
        self.traces.entry(address).or_default();
    }

    /// If an access trace is active for `watched_addr`, record an access from
    /// `raw_rip` by thread `tid` and return `true` (the caller then silently
    /// auto-continues); return `false` if the address is not being traced (a
    /// normal hardware breakpoint that should break into the client). Runs on
    /// the silent auto-continue hot path.
    pub fn record_access(&mut self, watched_addr: u64, raw_rip: u64, tid: u32) -> bool {
        let Some(trace) = self.traces.get_mut(&watched_addr) else { return false; };
        let entry = trace
            .accessors
            .entry(raw_rip)
            .or_insert(WatchpointAccessEntry { hit_count: 0, first_seq: 0, thread_ids: Vec::new() });
        if entry.hit_count == 0 {
            self.seq += 1;
            entry.first_seq = self.seq;
        }
        entry.hit_count += 1;
        if !entry.thread_ids.contains(&tid) {
            entry.thread_ids.push(tid);
        }
        true
    }

    /// Snapshot of every distinct instruction that accessed `address` at least
    /// once. Empty if no trace is (or was) active for that address. `accessor`
    /// is filled with the raw trap RIP; the platform layer attributes it (x86
    /// back-step).
    pub fn snapshot(&self, address: u64) -> Vec<WatchpointAccess> {
        let Some(trace) = self.traces.get(&address) else { return Vec::new(); };
        trace
            .accessors
            .iter()
            .map(|(rip, e)| WatchpointAccess {
                accessor: *rip,
                accessor_raw_rip: *rip,
                hit_count: e.hit_count,
                first_seq: e.first_seq,
                thread_ids: e.thread_ids.clone(),
            })
            .collect()
    }

    /// Stop tracing `address`: drop the accumulated accessors. Removing the
    /// underlying hardware watchpoint is the caller's job.
    pub fn clear(&mut self, address: u64) {
        self.traces.remove(&address);
    }
}

/// Arm the underlying hardware watchpoint (allocates a slot, applies to all
/// threads), then mark it as a silent access trace.
pub fn start_trace<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    addr: u64,
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
) -> Result<(), PlatformError> {
    trace!(pid, addr, ?bp_type, ?size, "start_watchpoint_trace called");
    set_hardware_breakpoint(book, ops, pid, addr, bp_type, size)?;
    book.watch.arm_trace(addr);
    info!(pid, addr, "Hardware access trace started");
    Ok(())
}

/// Remove the hardware watchpoint (ignoring "no breakpoint" so stop is
/// idempotent even if it was already cleared, e.g. on module unload) and drop
/// the accumulated accessors.
pub fn stop_trace<O: ProcessOps + ?Sized>(book: &mut DebugBook, ops: &O, pid: u32, addr: u64) -> Result<(), PlatformError> {
    trace!(pid, addr, "stop_watchpoint_trace called");
    if let Err(e) = remove_hardware_breakpoint(book, ops, pid, addr) {
        warn!(pid, addr, error = %e, "stop_watchpoint_trace: hardware watchpoint already gone");
    }
    book.watch.clear(addr);
    Ok(())
}

/// Attribute a watchpoint trap instruction pointer to the accessing
/// instruction. On x86 the hardware traps *after* the access, so the accessor
/// is the instruction ending exactly at `raw_rip`. Uses the shared backward
/// disassembler (self-resynchronizing decode) to find the instruction ending at
/// `raw_rip`. ARM64 reports the exact faulting PC. Falls back to `raw_rip` when
/// no instruction ends exactly there (misaligned/undecodable window).
pub fn attribute_accessor<P: PlatformAPI + ?Sized>(platform: &P, pid: u32, raw_rip: u64) -> u64 {
    if cfg!(target_arch = "aarch64") || raw_rip < 16 {
        return raw_rip;
    }
    // Use the cheap self-resync decode, not the anchored `disassemble_backward`
    // override: this runs on every watchpoint trap in an auto-continue trace
    // loop, and the anchored path can decode kilobytes from the function start
    // (with symbol/line enrichment) just to yield one instruction.
    match platform.disassemble_backward_resync(pid, raw_rip, 1, Architecture::X64) {
        Ok(ins) => ins
            .last()
            .filter(|i| i.address + i.size as u64 == raw_rip)
            .map(|i| i.address)
            .unwrap_or(raw_rip),
        Err(_) => raw_rip,
    }
}
