#![allow(dead_code)]
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("OS error: {0}")]
    OsError(String),
    #[error("Not implemented")]
    NotImplemented,
    #[error("Other: {0}")]
    Other(String),
}

#[async_trait]
pub trait PlatformAPI: Send + Sync {
    async fn attach(&mut self, pid: u32) -> Result<(), PlatformError>;
    async fn continue_exec(&mut self) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    async fn set_breakpoint(&mut self, addr: u64) -> Result<(), PlatformError>;
    async fn launch(&mut self, command: &str) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    async fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError>;
    async fn write_memory(&mut self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError>;
    // ... add more as needed
} 