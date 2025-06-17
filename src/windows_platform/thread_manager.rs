use crate::protocol::ThreadInfo;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};

// Safe wrapper for HANDLE that automatically closes it
#[derive(Debug)]
pub struct ThreadHandleSafe(pub HANDLE);
unsafe impl Send for ThreadHandleSafe {}
unsafe impl Sync for ThreadHandleSafe {}

impl Drop for ThreadHandleSafe {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 as isize != -1 {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Debug, Default)]
pub struct ThreadManager {
    threads: HashMap<u32, (ThreadInfo, ThreadHandleSafe)>, // tid -> (ThreadInfo, Handle)
}

impl ThreadManager {
    pub fn new() -> Self {
        Self {
            threads: HashMap::new(),
        }
    }

    pub fn add_thread(&mut self, tid: u32, start_address: u64, handle: HANDLE) {
        let info = ThreadInfo { tid, start_address };
        self.threads.insert(tid, (info, ThreadHandleSafe(handle)));
    }

    pub fn remove_thread(&mut self, tid: u32) {
        self.threads.remove(&tid);
    }

    pub fn get_thread_handle(&self, tid: u32) -> Option<HANDLE> {
        self.threads.get(&tid).map(|(_, handle)| handle.0)
    }

    pub fn list_threads(&self) -> Vec<ThreadInfo> {
        self.threads.values().map(|(info, _)| info.clone()).collect()
    }

    pub fn clear(&mut self) {
        self.threads.clear();
    }
} 