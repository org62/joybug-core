use crate::protocol::ThreadInfo;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::HANDLE;
use super::HandleSafe;

#[derive(Debug, Default)]
pub struct ThreadManager {
    threads: HashMap<u32, (ThreadInfo, HandleSafe)>, // tid -> (ThreadInfo, Handle)
    /// Threads whose `EXIT_THREAD` event has been seen. The handle stays
    /// usable (e.g. for the exiting thread's context) until the debugger
    /// continues past the exit event, so the entry is only hidden from
    /// [`list_threads`](Self::list_threads)/handle sweeps here and dropped
    /// by [`purge_exited`](Self::purge_exited) once the next event arrives.
    exited: Vec<u32>,
}

impl ThreadManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_thread(&mut self, tid: u32, start_address: u64, handle: HANDLE) {
        let info = ThreadInfo { tid, start_address, ..Default::default() };
        self.threads.insert(tid, (info, HandleSafe(handle)));
    }

    /// Mark a thread as exited; see [`exited`](Self::exited).
    pub fn remove_thread(&mut self, tid: u32) {
        if self.threads.contains_key(&tid) && !self.exited.contains(&tid) {
            self.exited.push(tid);
        }
    }

    /// Drop every thread marked exited. Called when a new debug event arrives,
    /// i.e. after the exit event was continued and the handle is no longer needed.
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
    /// [`get_thread_handle`](Self::get_thread_handle) deliberately bypasses it:
    /// the exiting thread's own handle must stay reachable by tid.
    fn live(&self) -> impl Iterator<Item = (u32, &(ThreadInfo, HandleSafe))> + '_ {
        self.threads
            .iter()
            .filter(|(tid, _)| self.is_live(**tid))
            .map(|(tid, entry)| (*tid, entry))
    }

    pub fn get_thread_handle(&self, tid: u32) -> Option<HANDLE> {
        self.threads.get(&tid).map(|(_, handle)| handle.0)
    }

    pub fn list_threads(&self) -> Vec<ThreadInfo> {
        self.live().map(|(_, (info, _))| info.clone()).collect()
    }

    /// Borrowing variant of [`all_thread_handles`](Self::all_thread_handles) for
    /// hot paths — no per-call allocation.
    pub fn iter_handles(&self) -> impl Iterator<Item = (u32, HANDLE)> + '_ {
        self.live().map(|(tid, (_, handle))| (tid, handle.0))
    }

    pub fn all_thread_handles(&self) -> Vec<(u32, HANDLE)> {
        self.iter_handles().collect()
    }

    pub fn clear(&mut self) {
        self.threads.clear();
        // Both halves, or a recycled tid in the next process incarnation would
        // stay filtered out of `live()` forever.
        self.exited.clear();
    }
} 