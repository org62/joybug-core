//! The traced process tree: which pids belong to the run the tracer is
//! observing.
//!
//! The ETW session itself is system-wide — the kernel providers deliver every
//! process/file/registry/network event on the machine. Narrowing that to "the
//! target and everything it spawned" is done entirely in the tracer's callback,
//! against the set kept here. That makes tree membership load-bearing: a child
//! must be tracked even when process events aren't being emitted, because it is
//! what attributes the child's *file* and *registry* events to the run.
//!
//! Lives in the lib (not in `bin/tracer.rs`) so it can be unit-tested without
//! `ferrisetw`, ETW privileges, or a sandbox.

use std::collections::HashSet;

/// Cap on buffered pre-root `ProcessStart` events, so a delayed target launch
/// can't grow `pending` without bound on a busy machine.
const MAX_PENDING: usize = 8192;

/// A `ProcessStart` seen before the root pid was registered. We can't yet decide
/// whether it belongs to the tree (the callback thread doesn't know the root pid
/// until `main` has spawned or attached to the target), so it is buffered and
/// resolved once the root is known — closing the race where the target forks
/// children faster than `main` can register its pid.
#[derive(Debug, Clone)]
pub struct PendingStart {
    pub child: u32,
    pub parent: u32,
    pub ts: i64,
    pub image: Option<String>,
    pub session: Option<u32>,
}

/// The set of pids in the traced tree, plus the pre-root buffer.
#[derive(Debug, Default)]
pub struct ProcessTree {
    tracked: HashSet<u32>,
    /// The traced tree's root pid, set once `main` has spawned/attached.
    /// While `None`, `ProcessStart`s are buffered in `pending`.
    root_pid: Option<u32>,
    pending: Vec<PendingStart>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.tracked.contains(&pid)
    }

    pub fn len(&self) -> usize {
        self.tracked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tracked.is_empty()
    }

    /// The live members of the tree, for diagnostics.
    pub fn pids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.tracked.iter().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn root_pid(&self) -> Option<u32> {
        self.root_pid
    }

    /// Register the root pid and drain `pending`: any buffered start that
    /// descends (transitively) from the root becomes tracked and is returned for
    /// the caller to emit; the rest are discarded.
    ///
    /// Returning the starts rather than emitting them keeps this type free of the
    /// writer and the `--capture` gate, which live in the tracer binary.
    pub fn set_root(&mut self, root: u32) -> Vec<PendingStart> {
        self.root_pid = Some(root);
        self.tracked.insert(root);

        let mut to_emit = Vec::new();
        loop {
            let mut progressed = false;
            let mut remaining = Vec::with_capacity(self.pending.len());
            for ps in std::mem::take(&mut self.pending) {
                if self.tracked.contains(&ps.parent) {
                    if self.tracked.insert(ps.child) {
                        to_emit.push(ps);
                    }
                    progressed = true;
                } else {
                    remaining.push(ps);
                }
            }
            self.pending = remaining;
            if !progressed {
                break;
            }
        }
        self.pending = Vec::new();
        to_emit
    }

    /// Re-root the tree at a new pid (resident mode, after a debuggee restart).
    /// Drops the old tree and its buffer so the fresh run starts clean; the ETW
    /// session itself is untouched (filtering is purely in-callback).
    pub fn retarget(&mut self, root: u32) -> Vec<PendingStart> {
        self.tracked.clear();
        self.root_pid = None;
        self.pending.clear();
        self.set_root(root)
    }

    /// Record a `ProcessStart`. Returns true when it belongs to the tree and the
    /// caller should emit it.
    ///
    /// The child is tracked whenever its parent is, regardless of whether process
    /// events are being emitted — membership is what attributes the child's later
    /// file/registry/network events to the run.
    pub fn note_start(&mut self, ps: PendingStart) -> bool {
        if self.tracked.contains(&ps.parent) {
            self.tracked.insert(ps.child);
            return true;
        }
        if self.root_pid.is_none() && self.pending.len() < MAX_PENDING {
            self.pending.push(ps);
        }
        false
    }

    /// Record a `ProcessStop`. Returns true when the pid belonged to the tree
    /// (and the caller should emit it). The pid stops being tracked, so a later
    /// reuse of the same number by an unrelated process isn't misattributed.
    pub fn note_stop(&mut self, pid: u32) -> bool {
        self.tracked.remove(&pid)
    }

    /// Drop `pids` from the tree. The safety net for a `ProcessStop` that never
    /// arrives: the caller decides which pids are conclusively gone (see
    /// `follow_tree` in the tracer, which requires a pid to look dead for a grace
    /// period first, so a still-buffered ETW event is never outrun).
    pub fn remove_all(&mut self, pids: &HashSet<u32>) {
        self.tracked.retain(|pid| !pids.contains(pid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(child: u32, parent: u32) -> PendingStart {
        PendingStart { child, parent, ts: 0, image: None, session: None }
    }

    fn set(pids: &[u32]) -> HashSet<u32> {
        pids.iter().copied().collect()
    }

    #[test]
    fn set_root_drains_pending_transitively_out_of_order() {
        let mut t = ProcessTree::new();
        // Grandchild seen before the child, both before the root is known.
        assert!(!t.note_start(start(30, 20)));
        assert!(!t.note_start(start(20, 10)));
        assert!(!t.note_start(start(99, 98))); // unrelated

        let mut emitted: Vec<u32> = t.set_root(10).iter().map(|p| p.child).collect();
        emitted.sort_unstable();
        assert_eq!(emitted, vec![20, 30], "both generations resolve from the root");
        assert_eq!(t.pids(), vec![10, 20, 30]);
        assert!(!t.contains(99), "a start outside the tree is discarded");
    }

    #[test]
    fn note_start_tracks_descendants_after_their_parent_exits() {
        let mut t = ProcessTree::new();
        t.set_root(10);
        assert!(t.note_start(start(20, 10)));
        // The root exits; its child is still tracked and can still parent a
        // grandchild. This is the whole point of following the tree.
        assert!(t.note_stop(10));
        assert!(!t.contains(10));
        assert!(t.note_start(start(30, 20)), "grandchild of a dead root is in the tree");
        assert_eq!(t.pids(), vec![20, 30]);
    }

    #[test]
    fn note_start_ignores_unrelated_processes_once_rooted() {
        let mut t = ProcessTree::new();
        t.set_root(10);
        assert!(!t.note_start(start(40, 41)));
        assert!(!t.contains(40));
        // Rooted, so it is not buffered either.
        assert_eq!(t.set_root(10).len(), 0);
    }

    #[test]
    fn note_stop_reports_only_tree_members() {
        let mut t = ProcessTree::new();
        t.set_root(10);
        assert!(t.note_stop(10));
        assert!(!t.note_stop(10), "already removed");
        assert!(!t.note_stop(777), "never in the tree");
    }

    #[test]
    fn remove_all_drops_exactly_the_named_pids() {
        let mut t = ProcessTree::new();
        t.set_root(10);
        t.note_start(start(20, 10));
        t.note_start(start(30, 20));

        t.remove_all(&set(&[10, 999]));
        assert_eq!(t.pids(), vec![20, 30], "10 dropped; an unknown pid is a no-op");
    }

    #[test]
    fn remove_all_can_empty_the_tree() {
        let mut t = ProcessTree::new();
        t.set_root(10);
        t.note_start(start(20, 10));
        t.remove_all(&set(&[10, 20]));
        assert!(t.is_empty());
    }

    #[test]
    fn retarget_clears_the_old_tree() {
        let mut t = ProcessTree::new();
        t.set_root(10);
        t.note_start(start(20, 10));
        t.retarget(50);
        assert_eq!(t.pids(), vec![50]);
        assert_eq!(t.root_pid(), Some(50));
        assert!(!t.contains(20));
    }

    #[test]
    fn pending_is_capped() {
        let mut t = ProcessTree::new();
        for i in 0..(MAX_PENDING as u32 + 100) {
            t.note_start(start(i + 1000, 1));
        }
        // Every buffered start names pid 1 as its parent, so rooting there
        // resolves exactly the cap — the overflow was dropped, not queued.
        assert_eq!(t.set_root(1).len(), MAX_PENDING);
    }
}
