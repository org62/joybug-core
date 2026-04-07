use std::fmt;

#[derive(Debug)]
pub enum InlineHookError {
    DisassemblyFailed(String),
    PrologueTooShort { needed: usize, available: usize },
    AllocationFailed(String),
    RelocationFailed(String),
    ThreadError(String),
    OsError(String, u32),
    InvalidHandle,
    InvalidState(String),
}

impl fmt::Display for InlineHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisassemblyFailed(msg) => write!(f, "disassembly failed: {msg}"),
            Self::PrologueTooShort { needed, available } => {
                write!(f, "prologue too short: need {needed} bytes but only {available} safe bytes")
            }
            Self::AllocationFailed(msg) => write!(f, "memory allocation failed: {msg}"),
            Self::RelocationFailed(msg) => write!(f, "instruction relocation failed: {msg}"),
            Self::ThreadError(msg) => write!(f, "thread operation failed: {msg}"),
            Self::OsError(msg, code) => write!(f, "OS error: {msg} (code {code})"),
            Self::InvalidHandle => write!(f, "invalid hook handle"),
            Self::InvalidState(state) => write!(f, "hook already {state}"),
        }
    }
}

impl std::error::Error for InlineHookError {}
