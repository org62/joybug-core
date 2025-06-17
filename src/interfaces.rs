#![allow(dead_code)]
use thiserror::Error;
use crate::protocol::{ModuleInfo, ProcessInfo, ThreadInfo};

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("OS error: {0}")]
    OsError(String),
    #[error("Not implemented")]
    NotImplemented,
    #[error("Other: {0}")]
    Other(String),
}

pub trait PlatformAPI: Send + Sync {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn set_breakpoint(&mut self, addr: u64) -> Result<(), PlatformError>;
    fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError>;
    fn write_memory(&mut self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError>;
    fn get_thread_context(&mut self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError>;
    fn set_thread_context(&mut self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError>;
    fn list_modules(&self, pid: u32) -> Result<Vec<ModuleInfo>, PlatformError>;
    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError>;
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError>;
    // ... add more as needed
} 