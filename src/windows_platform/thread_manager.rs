use crate::protocol::ThreadInfo;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::HANDLE;
use super::HandleSafe;

#[derive(Debug, Default)]
pub struct ThreadManager {
    threads: HashMap<u32, (ThreadInfo, HandleSafe)>, // tid -> (ThreadInfo, Handle)
}

impl ThreadManager {
    pub fn new() -> Self {
        Self {
            threads: HashMap::new(),
        }
    }

    pub fn add_thread(&mut self, tid: u32, start_address: u64, handle: HANDLE) {
        let info = ThreadInfo { tid, start_address };
        self.threads.insert(tid, (info, HandleSafe(handle)));
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