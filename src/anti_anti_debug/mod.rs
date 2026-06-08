//! Anti-anti-debug subsystem.
//!
//! Defeats common anti-debug techniques that probe the target process for
//! evidence of a debugger. Today there is one feature — PEB hiding (see
//! `peb::hide_peb`); future additions (API hooks, thread-hide,
//! `NtQueryInformationProcess` interception) will live in sibling modules.
//!
//! The feature set is exposed through:
//!   * the `DebuggerRequest::HidePeb` protocol message,
//!   * `DebugSession::hide_peb` on the client,
//!   * the `dbg:hide_peb` Lua binding,
//!   * and (in joybug-tauri) the "Debugger Hiding" Settings tab.

pub mod peb;

use serde::{Deserialize, Serialize};

/// Which PEB-resident anti-debug indicators to overwrite.
///
/// Each field selects one independent technique; missing fields default to
/// `false`. Use [`PebHideOptions::all`] to enable every supported technique.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PebHideOptions {
    #[serde(default)]
    pub being_debugged: bool,
    #[serde(default)]
    pub heap_flags: bool,
    #[serde(default)]
    pub nt_global_flag: bool,
    #[serde(default)]
    pub startup_info: bool,
    #[serde(default)]
    pub os_build_number: bool,
}

impl PebHideOptions {
    /// Enable every supported PEB-hiding technique.
    pub fn all() -> Self {
        Self {
            being_debugged: true,
            heap_flags: true,
            nt_global_flag: true,
            startup_info: true,
            os_build_number: true,
        }
    }

    pub fn any(&self) -> bool {
        self.being_debugged
            || self.heap_flags
            || self.nt_global_flag
            || self.startup_info
            || self.os_build_number
    }
}

/// Per-call result of [`peb::hide_peb`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PebHideReport {
    /// Resolved PEB base address (0 if not resolved, e.g. on WOW64 skip).
    pub peb_address: u64,
    /// Technique names that were successfully written (e.g. `"being_debugged"`).
    pub applied: Vec<String>,
    /// `(technique, error_message)` for techniques that failed.
    pub failures: Vec<(String, String)>,
    /// True if the target is WOW64 (32-bit on 64-bit Windows) — patching was
    /// skipped because v1 only supports 64-bit native PEB layout.
    pub wow64_skipped: bool,
}
