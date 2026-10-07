//! The Windows view of the shared [`ThreadTable`]: each thread's payload is
//! its open `HANDLE`, closed when the entry is dropped.

use crate::debugger_core::thread_table::ThreadTable;
use super::HandleSafe;
use windows_sys::Win32::Foundation::HANDLE;

pub(super) type ThreadManager = ThreadTable<HandleSafe>;

impl ThreadTable<HandleSafe> {
    pub fn add_thread(&mut self, tid: u32, start_address: u64, handle: HANDLE) {
        self.insert(tid, start_address, HandleSafe(handle));
    }

    /// The thread's handle, exited or not: the exiting thread's own handle
    /// must stay reachable by tid.
    pub fn get_thread_handle(&self, tid: u32) -> Option<HANDLE> {
        self.get(tid).map(|handle| handle.0)
    }

    /// Borrowing variant of [`all_thread_handles`](Self::all_thread_handles) for
    /// hot paths - no per-call allocation.
    pub fn iter_handles(&self) -> impl Iterator<Item = (u32, HANDLE)> + '_ {
        self.iter_live().map(|(tid, handle)| (tid, handle.0))
    }

    pub fn all_thread_handles(&self) -> Vec<(u32, HANDLE)> {
        self.iter_handles().collect()
    }
}
