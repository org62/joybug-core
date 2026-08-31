//! The trace event shape and the shared helpers for reading it back: the JSONL
//! record type, the default capture set, the access-mask formatter and the path
//! prettifier. The collector that produces these events lives in
//! [`crate::tracer`]; orchestration lives in `joybug_core::sandbox`.

use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::{RunAs, Result, Sandbox};

/// The per-op tokens the tracer emits when no `--capture` flag is given: the
/// historical default of modifications + process + network, no reads/queries.
/// Single source of truth for both the tracer binary and host-side drivers that
/// need to know when an explicit op set equals the built-in default.
pub const DEFAULT_OPS: &[&str] = &[
    "process.start",
    "process.stop",
    "file.create",
    "file.write",
    "file.delete",
    "file.rename",
    "registry.create_key",
    "registry.set_value",
    "registry.delete_key",
    "registry.delete_value",
    "network.connect",
    "network.accept",
];

/// One event captured by the guest tracer.
///
/// Fields are populated per `kind`/`op`; unused ones are `None`/default.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TraceEvent {
    /// "process" | "file" | "registry" | "network" | "tracer" (control records).
    pub kind: String,
    /// Operation within the kind (e.g. "start", "write", "set_value", "connect").
    #[serde(default)]
    pub op: String,
    /// The acting process id (absent on tracer control records).
    #[serde(default)]
    pub pid: Option<u32>,
    /// Raw ETW timestamp (100 ns ticks); use only for ordering.
    #[serde(default)]
    pub ts: i64,
    /// Process image path (process events).
    #[serde(default)]
    pub image: Option<String>,
    /// Parent pid (process start).
    #[serde(default)]
    pub ppid: Option<u32>,
    /// File or registry path.
    #[serde(default)]
    pub path: Option<String>,
    /// Bytes written / value size / image size.
    #[serde(default)]
    pub size: Option<u64>,
    /// "ip:port" destination (network connect).
    #[serde(default)]
    pub dest: Option<String>,
    /// Process exit code (process stop).
    #[serde(default)]
    pub exit: Option<u32>,
    /// Captured callstack as hex return addresses (`--stacks`); None otherwise.
    #[serde(default)]
    pub stack: Option<Vec<String>>,
    /// The process acted upon (audit events): the process opened, or the owner
    /// of the thread opened. Distinct from `pid`, which is the actor.
    #[serde(default)]
    pub target_pid: Option<u32>,
    /// Decoded DesiredAccess mask (audit events), e.g. "VM_READ|VM_WRITE".
    #[serde(default)]
    pub access: Option<String>,
    /// NTSTATUS returned by the audited call; 0 is success. A non-zero value on
    /// an open is the interesting case — something was attempted and refused.
    #[serde(default)]
    pub status: Option<u32>,
}

impl TraceEvent {
    /// Parse one JSONL line into a [`TraceEvent`], or `None` if it isn't valid
    /// JSON of the expected shape. Lets consumers deserialize tracer output
    /// without taking a direct `serde_json` dependency.
    pub fn from_json_line(line: &str) -> Option<Self> {
        serde_json::from_str(line).ok()
    }
}

/// Rights that mean the same thing on any securable object.
const STANDARD_RIGHTS: &[(u32, &str)] = &[
    (0x0001_0000, "DELETE"),
    (0x0002_0000, "READ_CONTROL"),
    (0x0004_0000, "WRITE_DAC"),
    (0x0008_0000, "WRITE_OWNER"),
    (0x0010_0000, "SYNCHRONIZE"),
];

/// `PROCESS_*` access rights (winnt.h).
const PROCESS_RIGHTS: &[(u32, &str)] = &[
    (0x0001, "TERMINATE"),
    (0x0002, "CREATE_THREAD"),
    (0x0008, "VM_OPERATION"),
    (0x0010, "VM_READ"),
    (0x0020, "VM_WRITE"),
    (0x0040, "DUP_HANDLE"),
    (0x0080, "CREATE_PROCESS"),
    (0x0100, "SET_QUOTA"),
    (0x0200, "SET_INFORMATION"),
    (0x0400, "QUERY_INFORMATION"),
    (0x0800, "SUSPEND_RESUME"),
    (0x1000, "QUERY_LIMITED_INFORMATION"),
    (0x2000, "SET_LIMITED_INFORMATION"),
];

/// `THREAD_*` access rights (winnt.h). The low bits collide with `PROCESS_*`
/// but mean different things, which is why the caller must say which it is.
const THREAD_RIGHTS: &[(u32, &str)] = &[
    (0x0001, "TERMINATE"),
    (0x0002, "SUSPEND_RESUME"),
    (0x0008, "GET_CONTEXT"),
    (0x0010, "SET_CONTEXT"),
    (0x0020, "SET_INFORMATION"),
    (0x0040, "QUERY_INFORMATION"),
    (0x0080, "SET_THREAD_TOKEN"),
    (0x0100, "IMPERSONATE"),
    (0x0200, "DIRECT_IMPERSONATION"),
    (0x0400, "SET_LIMITED_INFORMATION"),
    (0x0800, "QUERY_LIMITED_INFORMATION"),
    (0x1000, "RESUME"),
];

const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// `PROCESS_ALL_ACCESS` / `THREAD_ALL_ACCESS` — the same value for both.
const ALL_ACCESS: u32 = 0x001F_FFFF;

/// Render a `DesiredAccess` mask as readable rights, e.g.
/// `VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION`.
///
/// `thread` selects the `THREAD_*` vocabulary over `PROCESS_*` — the low bits
/// are the same numbers with different meanings, so an OpenThread mask decoded
/// as a process mask would read as plausible nonsense. Bits outside both tables
/// are kept as a hex remainder rather than dropped, so nothing is silently lost.
pub fn format_access_mask(mask: u32, thread: bool) -> String {
    if mask == 0 {
        return "NONE".to_string();
    }
    if mask == MAXIMUM_ALLOWED {
        return "MAXIMUM_ALLOWED".to_string();
    }
    if mask == ALL_ACCESS {
        return "ALL_ACCESS".to_string();
    }
    let specific = if thread { THREAD_RIGHTS } else { PROCESS_RIGHTS };
    let mut parts: Vec<String> = Vec::new();
    let mut rest = mask;
    for (bit, name) in specific.iter().chain(STANDARD_RIGHTS.iter()) {
        if mask & bit == *bit {
            parts.push((*name).to_string());
            rest &= !bit;
        }
    }
    if rest != 0 {
        parts.push(format!("0x{rest:x}"));
    }
    parts.join("|")
}

/// Whether `line` is the tracer's `tracer/done` terminal marker (written when
/// its target exits), parsed rather than substring-matched so field order and
/// path contents can't confuse it.
pub fn is_tracer_done(line: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    v.get("kind").and_then(|k| k.as_str()) == Some("tracer")
        && v.get("op").and_then(|o| o.as_str()) == Some("done")
}

impl Sandbox {
    /// Block until the guest accepts commands, or `timeout` elapses.
    pub fn wait_until_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.exec(r"cmd.exe /c exit 0", RunAs::System, None) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_secs(3));
                }
            }
        }
    }

}




/// Make an NT object path readable: strip the `\Device\HarddiskVolumeN\` prefix
/// and collapse the sandbox's VSMB share path to `[share]`.
pub fn pretty_path(p: &str) -> String {
    if let Some(rest) = p.strip_prefix(r"\Device\vmsmb\") {
        // \Device\vmsmb\VSMB-{guid}\<hash-or-os>\rest...
        let after: Vec<&str> = rest.splitn(3, '\\').collect();
        if after.len() == 3 {
            return format!(r"[share]\{}", after[2]);
        }
        return format!(r"[share]\{rest}");
    }
    if let Some(idx) = p.find(r"\Device\HarddiskVolume") {
        if let Some(slash) = p[idx + 1..].find('\\').map(|i| idx + 1 + i) {
            // skip "\Device\HarddiskVolumeN"
            if let Some(next) = p[slash + 1..].find('\\').map(|i| slash + 1 + i) {
                return p[next..].to_string();
            }
        }
    }
    p.to_string()
}

#[cfg(test)]
mod access_mask_tests {
    use super::*;

    #[test]
    fn decodes_the_vm_access_an_injector_asks_for() {
        // 0x438 — exactly what tests/test_programs/open_remote.c requests, and
        // what the confirmed Kernel-Audit-API-Calls id 5 reported for it.
        assert_eq!(
            format_access_mask(0x438, false),
            "VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION"
        );
    }

    #[test]
    fn thread_and_process_vocabularies_differ_for_the_same_bits() {
        // 0x1A — open_remote's OpenThread mask, per confirmed id 6.
        assert_eq!(format_access_mask(0x1A, true), "SUSPEND_RESUME|GET_CONTEXT|SET_CONTEXT");
        // Same bits, process vocabulary: entirely different rights.
        assert_eq!(format_access_mask(0x1A, false), "CREATE_THREAD|VM_OPERATION|VM_READ");
    }

    #[test]
    fn recognizes_the_wildcard_masks() {
        assert_eq!(format_access_mask(0x1F_FFFF, false), "ALL_ACCESS");
        assert_eq!(format_access_mask(0x1F_FFFF, true), "ALL_ACCESS");
        assert_eq!(format_access_mask(0x0200_0000, false), "MAXIMUM_ALLOWED");
        assert_eq!(format_access_mask(0, false), "NONE");
    }

    #[test]
    fn includes_standard_rights_and_keeps_unknown_bits() {
        assert_eq!(format_access_mask(0x0010_0400, false), "QUERY_INFORMATION|SYNCHRONIZE");
        // An unmapped bit survives as hex instead of vanishing.
        assert_eq!(format_access_mask(0x0400_0010, false), "VM_READ|0x4000000");
    }
}
