//! Emulator error types

use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum EmulatorError {
    #[error("Unicorn error: {0}")]
    UnicornError(String),

    #[error("Platform error: {0}")]
    PlatformError(String),

    #[error("Register error: {0}")]
    RegisterError(String),

    #[error("Memory error: {0}")]
    MemoryError(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}
