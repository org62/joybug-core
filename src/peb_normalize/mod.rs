//! PEB normalization.
//!
//! When Windows launches a process under a debugger, the loader leaves a few PEB
//! fields in their "debugger attached" state. This subsystem rewrites those
//! fields so the target runs the way it would with no debugger attached.
//!
//! This is *not* about hiding the debugger or evading protections — it is about
//! removing side effects the debugger's mere presence imposes on the target, so
//! an issue can be reproduced as it happens without a debugger attached:
//!   * The process heap: under a debugger the loader enables the debug heap
//!     (tail/free checks, parameter validation), whose exhaustive per-allocation
//!     verification can slow an allocation-heavy target by orders of magnitude.
//!     Restoring `HEAP.Flags` to its normal value removes that penalty.
//!   * `BeingDebugged` (what `IsDebuggerPresent` reports): code that reads it
//!     takes a different path when it thinks a debugger is attached — crash
//!     reporters change behavior, and exception handlers may fire a breakpoint
//!     (`int3`) straight away instead of running their normal logic, which hides
//!     the very behavior you are trying to observe.
//!
//! The feature set is exposed through:
//!   * the `DebuggerRequest::NormalizePeb` protocol message,
//!   * `DebugSession::normalize_peb` on the client,
//!   * the `dbg:normalize_peb` Lua binding,
//!   * and (in joybug-tauri) the "PEB Normalization" Settings tab.

pub mod peb;

use serde::{Deserialize, Serialize};

/// Which PEB-resident fields to restore to their non-debugged state.
///
/// Each field selects one independent field group; missing fields default to
/// `false`. Use [`PebNormalizeOptions::all`] to restore every supported field.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PebNormalizeOptions {
    #[serde(default)]
    pub being_debugged: bool,
    #[serde(default)]
    pub heap_flags: bool,
}

impl PebNormalizeOptions {
    /// Restore every supported PEB field.
    pub fn all() -> Self {
        Self {
            being_debugged: true,
            heap_flags: true,
        }
    }

    pub fn any(&self) -> bool {
        self.being_debugged || self.heap_flags
    }
}

/// Per-call result of [`peb::normalize_peb`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PebNormalizeReport {
    /// Resolved PEB base address (0 if not resolved, e.g. on WOW64 skip).
    pub peb_address: u64,
    /// Field names that were successfully written (e.g. `"being_debugged"`).
    pub applied: Vec<String>,
    /// `(field, error_message)` for fields that failed.
    pub failures: Vec<(String, String)>,
}
