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

/// Every op token the tracer can emit, grouped by kind in the order the tracer
/// documents them. The single source of truth for `--capture` validation, the
/// `kind.*`/`all` groups ([`expand_ops`]) and the `sbx.ops()`/`etw.ops()`
/// introspection calls. A drift test in this module checks that the tracer's
/// gates and this list never disagree.
pub const ALL_OPS: &[&str] = &[
    "process.start",
    "process.stop",
    "process.thread_start",
    "process.thread_stop",
    "process.image_load",
    "process.image_unload",
    "file.create",
    "file.write",
    "file.delete",
    "file.rename",
    "file.open",
    "file.read",
    "file.close",
    "file.dir_enum",
    "registry.create_key",
    "registry.set_value",
    "registry.delete_key",
    "registry.delete_value",
    "registry.open_key",
    "registry.query_value",
    "registry.query_key",
    "registry.enum_key",
    "registry.enum_value",
    "network.connect",
    "network.accept",
    "network.send",
    "network.recv",
    "network.disconnect",
    "network.retransmit",
    "network.udp_send",
    "network.udp_recv",
    "audit.open_process",
    "audit.open_thread",
];

/// The event kinds (`kind` field values) — each is also a group token.
pub const OP_KINDS: &[&str] = &["process", "file", "registry", "network", "audit"];

/// Historical spellings still accepted by [`expand_ops`], mapped to the
/// canonical token. `registry.query` never round-tripped (it emitted
/// `op:"query_value"`, RETRO B7); the canonical name now matches the emitted op.
pub const OP_ALIASES: &[(&str, &str)] = &[("registry.query", "registry.query_value")];

/// Expand a user-supplied op list into canonical tokens: `all`/`*` → every op;
/// `<kind>` or `<kind>.*` → that kind's ops; aliases → their canonical token;
/// a canonical token → itself. Output is deduplicated and in [`ALL_OPS`] order.
/// Unknown tokens are an error naming them and the valid vocabulary — better a
/// refused capture than one that silently records nothing.
pub fn expand_ops<S: AsRef<str>>(tokens: &[S]) -> std::result::Result<Vec<String>, String> {
    let mut wanted: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
    let mut unknown: Vec<String> = Vec::new();
    for raw in tokens {
        let t = raw.as_ref().trim().to_ascii_lowercase();
        if t.is_empty() {
            continue;
        }
        if t == "all" || t == "*" {
            wanted.extend(ALL_OPS.iter().copied());
            continue;
        }
        let group = t.strip_suffix(".*").unwrap_or(&t);
        if OP_KINDS.contains(&group) {
            let prefix = format!("{group}.");
            wanted.extend(ALL_OPS.iter().copied().filter(|op| op.starts_with(&prefix)));
            continue;
        }
        if let Some((_, canonical)) = OP_ALIASES.iter().find(|(alias, _)| *alias == t) {
            wanted.insert(canonical);
            continue;
        }
        match ALL_OPS.iter().find(|op| **op == t) {
            Some(op) => {
                wanted.insert(op);
            }
            None => unknown.push(raw.as_ref().trim().to_string()),
        }
    }
    if !unknown.is_empty() {
        return Err(format!(
            "unknown ETW op token(s): {}. Valid tokens: {}; groups: {}, all",
            unknown.join(", "),
            ALL_OPS.join(", "),
            OP_KINDS.iter().map(|k| format!("{k}.*")).collect::<Vec<_>>().join(", "),
        ));
    }
    Ok(ALL_OPS.iter().filter(|op| wanted.contains(*op)).map(|op| op.to_string()).collect())
}

/// A loaded module of a traced process, for symbolizing stack frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRange {
    pub base: u64,
    pub size: u64,
    /// File name only (`unholydragon.exe`), lower-cased.
    pub name: String,
}

/// First address of the kernel half of the canonical address space on every
/// 64-bit Windows architecture. A frame at or above it is kernel code.
const KERNEL_SPACE: u64 = 0xFFFF_8000_0000_0000;

/// Render one raw return address against a module list: `name+0x<rva>` inside a
/// known module, `kernel` for a kernel-mode frame, otherwise the bare address.
pub fn symbolize_frame(addr: u64, modules: &[ModuleRange]) -> String {
    if addr >= KERNEL_SPACE {
        return "kernel".to_string();
    }
    match modules.iter().find(|m| addr >= m.base && addr < m.base.saturating_add(m.size)) {
        Some(m) => format!("{}+0x{:x}", m.name, addr - m.base),
        None => format!("0x{addr:x}"),
    }
}

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
    /// `stack`, resolved frame by frame to `module+0xrva` / `kernel` / bare
    /// address (see [`symbolize_frame`]). Parallel to `stack`.
    #[serde(default)]
    pub frames: Option<Vec<String>>,
    /// `tracer.error` / `tracer.lost`: human-readable detail.
    #[serde(default)]
    pub message: Option<String>,
    /// `tracer.lost` / `tracer.stats`: cumulative events ETW dropped.
    #[serde(default)]
    pub events_lost: Option<u64>,
    /// `tracer.lost` / `tracer.stats`: cumulative buffers ETW dropped.
    #[serde(default)]
    pub buffers_lost: Option<u64>,
    /// `tracer.stats`: events the tracer wrote to this file.
    #[serde(default)]
    pub events_written: Option<u64>,
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

/// The `op` of a tracer control record (`kind = "tracer"`: `start`, `done`,
/// `error`, `lost`, `stats`, `tree_timeout`), or `None` for any other line.
/// Parsed rather than substring-matched so field order and path contents can't
/// confuse it.
pub fn tracer_record(line: &str) -> Option<String> {
    let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
    if v.get("kind").and_then(|k| k.as_str()) != Some("tracer") {
        return None;
    }
    v.get("op").and_then(|o| o.as_str()).map(str::to_string)
}

/// Whether `line` is the tracer's `tracer/done` terminal marker (written when
/// its target exits).
pub fn is_tracer_done(line: &str) -> bool {
    tracer_record(line).as_deref() == Some("done")
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

#[cfg(test)]
mod ops_tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn default_ops_are_all_canonical() {
        for op in DEFAULT_OPS {
            assert!(ALL_OPS.contains(op), "{op} missing from ALL_OPS");
        }
        assert_eq!(expand_ops(DEFAULT_OPS).unwrap(), v(DEFAULT_OPS));
    }

    #[test]
    fn all_and_star_expand_to_everything() {
        assert_eq!(expand_ops(&["all"]).unwrap(), v(ALL_OPS));
        assert_eq!(expand_ops(&["*"]).unwrap(), v(ALL_OPS));
    }

    #[test]
    fn kind_groups_expand_in_canonical_order_and_dedupe() {
        let got = expand_ops(&["registry.*", "file.write", "file", "registry.set_value"]).unwrap();
        let expected: Vec<String> = ALL_OPS
            .iter()
            .filter(|op| op.starts_with("file.") || op.starts_with("registry."))
            .map(|s| s.to_string())
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn registry_query_alias_round_trips_to_query_value() {
        assert_eq!(expand_ops(&["registry.query"]).unwrap(), v(&["registry.query_value"]));
        assert_eq!(expand_ops(&["registry.query_value"]).unwrap(), v(&["registry.query_value"]));
    }

    #[test]
    fn unknown_tokens_are_refused_and_named() {
        let err = expand_ops(&["file.create", "file.wriet", "bogus"]).unwrap_err();
        assert!(err.contains("file.wriet"), "{err}");
        assert!(err.contains("bogus"), "{err}");
        assert!(err.contains("file.create"), "the valid vocabulary is listed: {err}");
    }

    #[test]
    fn empty_and_whitespace_expand_to_nothing() {
        assert!(expand_ops(&["", "  "]).unwrap().is_empty());
        assert!(expand_ops::<&str>(&[]).unwrap().is_empty());
    }

    /// Drift guard: every `kind.op` token literal in the tracer source must be
    /// in ALL_OPS, and every ALL_OPS token must be gated somewhere in the
    /// tracer — so adding an op to one side without the other fails here.
    #[test]
    fn tracer_source_and_all_ops_agree() {
        let src = include_str!("tracer.rs");
        let mut in_source = std::collections::BTreeSet::new();
        let mut rest = src;
        while let Some(start) = rest.find('"') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('"') else { break };
            let lit = &after[..end];
            if let Some((kind, op)) = lit.split_once('.') {
                if OP_KINDS.contains(&kind)
                    && !op.is_empty()
                    && op.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                {
                    in_source.insert(lit.to_string());
                }
            }
            rest = &after[end + 1..];
        }
        let all: std::collections::BTreeSet<String> = ALL_OPS.iter().map(|s| s.to_string()).collect();
        assert_eq!(in_source, all, "tracer.rs token literals vs ALL_OPS");
    }

    #[test]
    fn tracer_records_are_recognised() {
        assert_eq!(tracer_record(r#"{"kind":"tracer","op":"start"}"#).as_deref(), Some("start"));
        assert_eq!(tracer_record(r#"{"kind":"tracer","op":"lost","events_lost":5}"#).as_deref(), Some("lost"));
        assert_eq!(tracer_record(r#"{"kind":"file","op":"create"}"#), None);
        assert_eq!(tracer_record("not json"), None);
        assert!(is_tracer_done(r#"{"op":"done","kind":"tracer"}"#));
    }

    #[test]
    fn lost_and_stats_records_parse_into_trace_event() {
        let lost = TraceEvent::from_json_line(
            r#"{"kind":"tracer","op":"lost","events_lost":42,"buffers_lost":1,"message":"x"}"#,
        )
        .unwrap();
        assert_eq!(lost.events_lost, Some(42));
        assert_eq!(lost.buffers_lost, Some(1));
        assert_eq!(lost.message.as_deref(), Some("x"));
        let stats = TraceEvent::from_json_line(
            r#"{"kind":"tracer","op":"stats","events_written":10,"events_lost":0,"buffers_lost":0}"#,
        )
        .unwrap();
        assert_eq!(stats.events_written, Some(10));
        let ev = TraceEvent::from_json_line(
            r#"{"kind":"file","op":"create","pid":1,"ts":0,"stack":["0x1"],"frames":["a.exe+0x1"]}"#,
        )
        .unwrap();
        assert_eq!(ev.frames.unwrap(), vec!["a.exe+0x1".to_string()]);
    }

    #[test]
    fn frames_resolve_to_module_kernel_or_bare() {
        let mods = vec![
            ModuleRange { base: 0x400000, size: 0x29d000, name: "unholydragon.exe".into() },
            ModuleRange { base: 0x7ff8_0000_0000, size: 0x1000, name: "ntdll.dll".into() },
        ];
        assert_eq!(symbolize_frame(0x4a554f, &mods), "unholydragon.exe+0xa554f");
        assert_eq!(symbolize_frame(0x7ff8_0000_0010, &mods), "ntdll.dll+0x10");
        assert_eq!(symbolize_frame(0xfffff802_1234_5678, &mods), "kernel");
        assert_eq!(symbolize_frame(0x69d000, &mods), "0x69d000");
        assert_eq!(symbolize_frame(0x400000 + 0x29d000, &mods), "0x69d000", "end is exclusive");
    }
}
