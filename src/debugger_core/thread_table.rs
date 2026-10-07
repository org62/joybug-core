use crate::protocol::ThreadInfo;
use std::collections::HashMap;

/// The threads of a debugged process, keyed by tid, each with a backend-owned
/// payload `H` (a Win32 thread handle on Windows, nothing on Linux).
#[derive(Debug)]
pub struct ThreadTable<H> {
    threads: HashMap<u32, (ThreadInfo, H)>, // tid -> (ThreadInfo, payload)
    /// Threads whose exit event has been seen. The entry stays usable (e.g.
    /// for the exiting thread's context) until the debugger continues past
    /// the exit event, so it is only hidden from [`list_threads`](Self::list_threads)
    /// / payload sweeps here and dropped by [`purge_exited`](Self::purge_exited)
    /// once the next event arrives.
    exited: Vec<u32>,
}

impl<H> Default for ThreadTable<H> {
    fn default() -> Self {
        Self { threads: HashMap::new(), exited: Vec::new() }
    }
}

impl<H> ThreadTable<H> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tid: u32, start_address: u64, payload: H) {
        let info = ThreadInfo { tid, start_address, ..Default::default() };
        self.threads.insert(tid, (info, payload));
    }

    /// Mark a thread as exited; see [`exited`](Self::exited).
    pub fn remove_thread(&mut self, tid: u32) {
        if self.threads.contains_key(&tid) && !self.exited.contains(&tid) {
            self.exited.push(tid);
        }
    }

    /// Drop every thread marked exited. Called when a new debug event arrives,
    /// i.e. after the exit event was continued and the payload is no longer needed.
    pub fn purge_exited(&mut self) {
        for tid in self.exited.drain(..) {
            self.threads.remove(&tid);
        }
    }

    fn is_live(&self, tid: u32) -> bool {
        !self.exited.contains(&tid)
    }

    /// Every thread that has not been marked exited. The one place the
    /// live/exited rule is applied, so a new accessor cannot forget it.
    /// [`get`](Self::get) deliberately bypasses it: the exiting thread's own
    /// payload must stay reachable by tid.
    fn live(&self) -> impl Iterator<Item = (u32, &(ThreadInfo, H))> + '_ {
        self.threads
            .iter()
            .filter(|(tid, _)| self.is_live(**tid))
            .map(|(tid, entry)| (*tid, entry))
    }

    /// The payload of `tid`, exited or not.
    pub fn get(&self, tid: u32) -> Option<&H> {
        self.threads.get(&tid).map(|(_, payload)| payload)
    }

    pub fn contains(&self, tid: u32) -> bool {
        self.threads.contains_key(&tid)
    }

    pub fn list_threads(&self) -> Vec<ThreadInfo> {
        self.live().map(|(_, (info, _))| info.clone()).collect()
    }

    /// Mutable access to a live thread's info (e.g. its suspend count).
    pub fn info_mut(&mut self, tid: u32) -> Option<&mut ThreadInfo> {
        self.threads.get_mut(&tid).map(|(info, _)| info)
    }

    /// Borrowing iterator over the live threads and their payloads - no
    /// per-call allocation.
    pub fn iter_live(&self) -> impl Iterator<Item = (u32, &H)> + '_ {
        self.live().map(|(tid, (_, payload))| (tid, payload))
    }

    pub fn live_tids(&self) -> Vec<u32> {
        self.live().map(|(tid, _)| tid).collect()
    }

    pub fn clear(&mut self) {
        self.threads.clear();
        // Both halves, or a recycled tid in the next process incarnation would
        // stay filtered out of `live()` forever.
        self.exited.clear();
    }
}
