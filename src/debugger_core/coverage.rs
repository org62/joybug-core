//! Code-coverage breakpoints. The INT3 bytes themselves live in the
//! [`BreakpointTable`] as persistent breakpoints (so they reuse the restore /
//! re-arm / step-over / patch machinery); this book adds the per-address hit
//! counter and auto-remove limit.

use super::breakpoints::{breakpoint_bytes, remove_breakpoint, BreakpointTable};
use super::ops::ProcessOps;
use super::DebugBook;
use crate::interfaces::PlatformError;
use crate::protocol::CoverageHit;
use std::collections::HashMap;
use std::time::Instant;
use tracing::{trace, warn};

/// A single code-coverage breakpoint's counter. `limit == 0` means never
/// auto-remove; `1` removes on the first hit (pure coverage). `active` goes
/// false once the INT3 has been removed (limit reached), while the final
/// `hit_count` is kept for reporting.
#[derive(Debug, Clone)]
pub struct CoverageEntry {
    pub hit_count: u64,
    pub limit: u64,
    pub active: bool,
    /// 1-based first-execution order across the coverage run (0 = never hit).
    /// Assigned once when `hit_count` transitions 0 -> 1.
    pub first_hit_seq: u64,
    /// Microseconds from the coverage epoch to the first hit, stamped alongside
    /// `first_hit_seq` (0 = never hit, same as the first address executed -
    /// `first_hit_seq` is what distinguishes the two).
    pub first_hit_us: u64,
    /// Distinct thread ids that hit this address, in first-hit order.
    pub thread_ids: Vec<u32>,
}

#[derive(Debug, Default)]
pub struct CoverageBook {
    entries: HashMap<u64, CoverageEntry>,
    /// Monotonic first-hit counter backing `CoverageEntry::first_hit_seq`.
    /// Reset (with the map) by [`forget`](Self::forget), not by re-arming mid-run.
    seq: u64,
    /// Time origin the `CoverageEntry::first_hit_us` stamps are measured from.
    /// Set when the first breakpoint of a run is armed - arming thousands of
    /// INT3s takes long enough that timing from the *request* would fold the
    /// arming cost into the first function's timestamp. Cleared with the map by
    /// [`forget`](Self::forget).
    epoch: Option<Instant>,
}

impl CoverageBook {
    /// Register a coverage breakpoint at `address`: store its original bytes as a
    /// persistent breakpoint (no tid filter) and start a counter with `limit`.
    pub fn arm(&mut self, bps: &mut BreakpointTable, address: u64, original_bytes: Vec<u8>, limit: u64) {
        bps.insert_persistent(address, original_bytes, None);
        // First arm of a run starts the clock. `get_or_insert_with` (not a plain
        // set) so re-arming more addresses mid-run keeps the existing origin and
        // the timestamps stay on one timeline.
        self.epoch.get_or_insert_with(Instant::now);
        self.entries.insert(
            address,
            CoverageEntry { hit_count: 0, limit, active: true, first_hit_seq: 0, first_hit_us: 0, thread_ids: Vec::new() },
        );
    }

    /// If an *active* coverage breakpoint exists at `address`, increment its hit
    /// counter (recording first-hit order and the hitting thread) and return
    /// `(new_hit_count, limit)`; `None` otherwise. One map lookup for both the
    /// "is this a coverage hit?" test and the count - this runs on the silent
    /// auto-continue hot path.
    pub fn record_hit(&mut self, address: u64, tid: u32) -> Option<(u64, u64)> {
        // Sampled before the map lookup so the stamp reflects when the trap was
        // handled, not how long the borrow took; only read on the 0 -> 1 edge.
        let now = Instant::now();
        let epoch = self.epoch;
        let entry = self.entries.get_mut(&address).filter(|e| e.active)?;
        if entry.hit_count == 0 {
            self.seq += 1;
            entry.first_hit_seq = self.seq;
            entry.first_hit_us = epoch
                .map(|e| now.saturating_duration_since(e).as_micros() as u64)
                .unwrap_or(0);
        }
        entry.hit_count += 1;
        if !entry.thread_ids.contains(&tid) {
            entry.thread_ids.push(tid);
        }
        Some((entry.hit_count, entry.limit))
    }

    /// Keep the entry (now `active == false`) so its final count is still reported.
    pub fn mark_inactive(&mut self, address: u64) {
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.active = false;
        }
    }

    /// Snapshot of every coverage breakpoint hit at least once (active or
    /// already auto-removed). Never-hit addresses are omitted - the client
    /// knows the armed set and fills zeros - so a poll doesn't serialize
    /// thousands of zero entries.
    pub fn snapshot(&self) -> Vec<CoverageHit> {
        self.entries
            .iter()
            .filter(|(_, e)| e.hit_count > 0)
            .map(|(addr, e)| CoverageHit {
                address: *addr,
                hit_count: e.hit_count,
                first_hit_seq: e.first_hit_seq,
                first_hit_us: e.first_hit_us,
                thread_ids: e.thread_ids.clone(),
            })
            .collect()
    }

    pub fn active_addresses(&self) -> Vec<u64> {
        self.entries.iter().filter(|(_, e)| e.active).map(|(addr, _)| *addr).collect()
    }

    /// Forget all coverage bookkeeping (counters and the first-hit sequence).
    /// Restoring the INT3 bytes is the caller's job - the single owner of what
    /// "coverage state" consists of, shared by [`clear_coverage`] and detach.
    pub fn forget(&mut self) {
        self.entries.clear();
        self.seq = 0;
        self.epoch = None;
    }
}

/// Arm coverage breakpoints at `addrs`, skipping addresses already covered by
/// a user/persistent breakpoint so we never collide with (or double-handle)
/// an existing INT3. Unreadable/unwritable addresses are skipped with a warning.
pub fn start_code_coverage<O: ProcessOps + ?Sized>(
    book: &mut DebugBook,
    ops: &O,
    pid: u32,
    addrs: &[u64],
    limit: u64,
) -> Result<(), PlatformError> {
    trace!(pid, count = addrs.len(), limit, "start_code_coverage called");
    let bp_bytes = breakpoint_bytes(ops.arch());
    let bp_len = bp_bytes.len();
    let mut armed = 0usize;
    for &addr in addrs {
        if book.bps.is_persistent(addr) {
            continue;
        }
        let original_bytes = match ops.read(pid, addr, bp_len) {
            Ok(b) => b,
            Err(e) => {
                warn!(pid, addr, error = %e, "Skipping coverage breakpoint: failed to read original bytes");
                continue;
            }
        };
        if let Err(e) = ops.write(pid, addr, &bp_bytes) {
            warn!(pid, addr, error = %e, "Failed to write coverage breakpoint byte");
            continue;
        }
        let DebugBook { bps, coverage, .. } = book;
        coverage.arm(bps, addr, original_bytes, limit);
        armed += 1;
    }
    trace!(pid, armed, requested = addrs.len(), "Coverage breakpoints armed");
    Ok(())
}

/// Permanently remove the INT3 for a coverage breakpoint (limit reached) but
/// keep the entry (now inactive) so its final count is still reported.
pub fn deactivate_coverage<O: ProcessOps + ?Sized>(book: &mut DebugBook, ops: &O, pid: u32, address: u64) {
    if let Err(e) = remove_breakpoint(&mut book.bps, ops, pid, address) {
        warn!(address, error = %e, "Failed to remove coverage breakpoint at limit");
    }
    book.coverage.mark_inactive(address);
}

/// Remove all coverage breakpoints (restoring original bytes for any still
/// active) and clear the coverage map.
pub fn clear_coverage<O: ProcessOps + ?Sized>(book: &mut DebugBook, ops: &O, pid: u32) {
    for addr in book.coverage.active_addresses() {
        if let Err(e) = remove_breakpoint(&mut book.bps, ops, pid, addr) {
            warn!(address = addr, error = %e, "Failed to remove coverage breakpoint on clear");
        }
    }
    book.coverage.forget();
}
