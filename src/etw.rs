//! Host ETW: run the ETW collector on the HOST (outside a sandbox VM).
//!
//! This is the host-machine counterpart to [`crate::sandbox`], which runs the
//! same tracer *inside* a disposable Windows Sandbox. Like that module, this one
//! is **host-application-agnostic**: it owns no data-directory layout and never
//! embeds the guest binaries — the tracer exe path, the JSONL output path, and
//! the control-file path all arrive from the caller (the Tauri app, `jlua`).
//!
//! Two shapes, both reusing the tracer's existing CLI:
//!  * **attached / resident** — [`HostTracer::launch_attached`] launches an
//!    elevated tracer with `--control` and `--attach-pid`. The same elevated
//!    process is reused across debuggee restarts: [`HostTracer::attach`] rewrites
//!    the control file to re-target it (no new UAC prompt), and
//!    [`HostTracer::stop`] asks it to drain and exit.
//!  * **spawn** — [`launch_spawn`] launches a target *under* the tracer
//!    (`-- <program> [args]`, "procmon-lite"); the tracer's `tracer/done` marker
//!    (see [`tracer_done`]) signals the target exited.
//!
//! Kernel ETW providers need admin, so the tracer is launched ELEVATED via a UAC
//! `runas` prompt (auto-skipped when already admin) using PowerShell's
//! `Start-Process` — see [`launch_elevated`]. The tracer writes newline-delimited
//! JSON; [`read_events`] is an incremental, cursor-based reader over that growing
//! file.
//!
//! Not to be confused with [`crate::windows_platform::tracer`], which is
//! single-step instruction tracing (trap flag), unrelated to ETW.

use std::path::{Path, PathBuf};

// The winsandbox event surface, re-exported so host applications and the `etw`
// Lua bindings depend only on `joybug_core::etw::*` — never on the winsandbox
// crate, and never on `crate::sandbox` (which the `sandbox` feature may gate off
// while `etw` alone is on).
pub use winsandbox::{
    expand_ops, is_tracer_done, pretty_path, tracer_record, TraceEvent, ALL_OPS, DEFAULT_OPS,
    OP_ALIASES, OP_KINDS,
};
/// Run the ETW collector in this process, consuming it: the hosting executable
/// dispatches here when launched with the collector's flags instead of shipping
/// a separate tracer binary. Never returns.
pub use winsandbox::tracer::run as run_collector;

/// `CREATE_NO_WINDOW` — keep the transient PowerShell launcher off-screen.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// FILETIME epoch (1601-01-01) → Unix epoch (1970-01-01) offset, in 100ns ticks.
const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;

/// What the ETW tracer records. `ops` is the per-operation token set — canonical
/// tokens, `kind.*` groups, `all`, or a documented alias (see [`expand_ops`]);
/// empty means the tracer's built-in default ([`DEFAULT_OPS`]). Owned here (not
/// in `sandbox`) so it is available whenever the `etw` feature is on, with or
/// without `sandbox`; `crate::sandbox` re-exports it for compatibility.
#[derive(Debug, Clone, Default)]
pub struct EtwCaptureSpec {
    pub ops: Vec<String>,
    pub callstacks: bool,
    /// ETW buffer size in KB; `None` = the tracer's default. Raise it (or
    /// `buffers`) when a capture reports `tracer.lost` records.
    pub buffer_kb: Option<u32>,
    /// Cap on the ETW buffer pool; `None` = the tracer's default.
    pub buffers: Option<u32>,
}

impl EtwCaptureSpec {
    /// Reject unknown op tokens up front, with the valid vocabulary in the
    /// message — before a VM is booted or a UAC prompt is paid.
    pub fn validate(&self) -> Result<(), String> {
        expand_ops(&self.ops).map(|_| ())
    }

    /// The canonical, expanded token list (groups and aliases resolved). An
    /// invalid list is passed through unchanged — `validate` is where it fails.
    pub fn expanded_ops(&self) -> Vec<String> {
        expand_ops(&self.ops).unwrap_or_else(|_| self.ops.clone())
    }

    /// The `--capture` value (csv of canonical op tokens), or `None` when the set
    /// is empty or equals the tracer's built-in default — then the flag is
    /// omitted and the tracer's own default applies.
    pub fn capture_ops(&self) -> Option<String> {
        let ops = self.expanded_ops();
        let is_default = ops.is_empty()
            || (ops.len() == DEFAULT_OPS.len()
                && DEFAULT_OPS.iter().all(|d| ops.iter().any(|o| o == d)));
        if is_default {
            None
        } else {
            Some(ops.join(","))
        }
    }

    /// The tracer argv tokens for this spec (`--capture a,b --stacks
    /// --buffer-kb N --buffers N`); default ops, callstacks-off and unset
    /// buffer options each omit their flag. None of the tokens contains a
    /// space, so [`Self::cmd_flags`] can join them into a command line.
    pub fn capture_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(csv) = self.capture_ops() {
            args.push("--capture".to_string());
            args.push(csv);
        }
        if self.callstacks {
            args.push("--stacks".to_string());
        }
        if let Some(kb) = self.buffer_kb {
            args.push("--buffer-kb".to_string());
            args.push(kb.to_string());
        }
        if let Some(n) = self.buffers {
            args.push("--buffers".to_string());
            args.push(n.to_string());
        }
        args
    }

    /// [`Self::capture_args`] as a guest-command fragment with a leading space
    /// (so it splices into a command line), empty when nothing is set. Only
    /// `crate::sandbox` uses it: it builds a single command string, not an argv.
    pub(crate) fn cmd_flags(&self) -> String {
        self.capture_args().iter().map(|a| format!(" {a}")).collect()
    }
}

/// Everything needed to launch a host tracer. All paths are caller-supplied.
#[derive(Debug, Clone)]
pub struct HostTracerConfig {
    /// Host path to the executable hosting the collector (normally this exe,
    /// re-launched with the collector's flags — see `winsandbox::tracer`).
    pub tracer_exe: PathBuf,
    /// JSONL output path. Its parent directory must already exist (caller creates).
    pub out_path: PathBuf,
    /// ETW session name (e.g. `etw-<sid>`); distinguishes concurrent sessions.
    pub session_name: String,
    /// What the tracer records (ops + callstacks).
    pub capture: EtwCaptureSpec,
}

/// A resident attach-mode host tracer, controlled through its control file.
///
/// Holds only the control path: the elevated tracer process can't be killed by a
/// non-elevated caller, so writing `stop` into the control file is the clean-exit
/// path. The tracer is deliberately designed to outlive a debuggee restart (a
/// stop+start) so the same elevated process — and its single UAC prompt — is
/// reused; [`HostTracer::attach`] re-targets it in place.
pub struct HostTracer {
    control_path: PathBuf,
}

impl HostTracer {
    /// Launch the elevated resident tracer (`--control`) attached to `pid`. One
    /// UAC prompt (auto-skipped when already admin). Writes an empty control file
    /// first so a stale command can't be re-applied by the fresh tracer.
    pub fn launch_attached(
        cfg: &HostTracerConfig,
        control_path: PathBuf,
        pid: u32,
    ) -> Result<HostTracer, String> {
        cfg.capture.validate()?;
        write_control(&control_path, "")?;
        let mut args = tracer_args(cfg);
        args.push("--attach-pid".to_string());
        args.push(pid.to_string());
        args.push("--control".to_string());
        args.push(control_path.to_string_lossy().into_owned());
        launch_elevated(&cfg.tracer_exe, &args)?;
        Ok(HostTracer { control_path })
    }

    /// Re-target the running tracer to `pid` (`attach <pid>`) — no new elevation.
    pub fn attach(&self, pid: u32) -> Result<(), String> {
        write_control(&self.control_path, &format!("attach {pid}"))
    }

    /// Ask the tracer to drain and exit (`stop`).
    pub fn stop(&self) -> Result<(), String> {
        write_control(&self.control_path, "stop")
    }

    /// The control-file path this tracer polls.
    pub fn control_path(&self) -> &Path {
        &self.control_path
    }
}

/// Spawn mode ("procmon-lite"): launch `target_argv` under the elevated tracer
/// (`-- <program> [args]`). Returns once the launcher is spawned; observe
/// completion via [`tracer_done`] on `cfg.out_path`.
pub fn launch_spawn(cfg: &HostTracerConfig, target_argv: &[String]) -> Result<(), String> {
    cfg.capture.validate()?;
    let mut args = tracer_args(cfg);
    args.push("--".to_string());
    args.extend(target_argv.iter().cloned());
    launch_elevated(&cfg.tracer_exe, &args)
}

/// The shared `--out`/`--session-name`/`--capture`/`--stacks` argv for a config.
/// Attach/spawn callers append their own mode flags (`--attach-pid`/`--control`
/// or `-- <argv>`). The hand-rolled tracer parser is order-insensitive except
/// that `--` must come last.
fn tracer_args(cfg: &HostTracerConfig) -> Vec<String> {
    let mut args = vec![
        "--out".to_string(),
        cfg.out_path.to_string_lossy().into_owned(),
        "--session-name".to_string(),
        cfg.session_name.clone(),
    ];
    args.extend(cfg.capture.capture_args());
    args
}

/// Overwrite the control file with a single command line for the resident tracer.
fn write_control(ctl: &Path, cmd: &str) -> Result<(), String> {
    std::fs::write(ctl, cmd).map_err(|e| format!("write etw control: {e}"))
}

/// Launch `exe` elevated (UAC `runas`; no prompt when already admin) with the
/// given argv, via PowerShell `Start-Process` — no Win32 `ShellExecuteEx` FFI.
pub fn launch_elevated(exe: &Path, args: &[String]) -> Result<(), String> {
    let ps_quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let arg_list = args.iter().map(|a| ps_quote(a)).collect::<Vec<_>>().join(",");
    let ps = format!(
        "$ErrorActionPreference='Stop'; Start-Process -FilePath {} -ArgumentList @({}) -Verb RunAs -WindowStyle Hidden",
        ps_quote(&exe.to_string_lossy()),
        arg_list,
    );
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps]);
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn().map_err(|e| format!("launch elevated tracer: {e}"))?;
    Ok(())
}

/// Whether the tracer has written its `tracer/done` terminal marker (its target
/// exited). Reads only the file's tail so a long-running poll never rescans a
/// multi-MB trace, and parses the candidate lines rather than substring-matching.
pub fn tracer_done(out_path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL: u64 = 4096;
    let Ok(mut f) = std::fs::File::open(out_path) else {
        return false;
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if f.seek(SeekFrom::Start(len.saturating_sub(TAIL))).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&buf);
    text.lines().rev().take(8).any(is_tracer_done)
}

/// Convert an ETW real-time timestamp (FILETIME: 100ns ticks since 1601-01-01
/// UTC) to `HH:MM:SS.mmm` (UTC time-of-day). Best-effort; empty before the Unix
/// epoch. Pure modular arithmetic — no calendar, no dependency.
pub fn filetime_to_hms(ts: i64) -> String {
    let unix_100ns = ts - EPOCH_DIFF_100NS;
    if unix_100ns < 0 {
        return String::new();
    }
    let secs = unix_100ns / 10_000_000;
    let millis = (unix_100ns % 10_000_000) / 10_000;
    let sod = secs.rem_euclid(86_400);
    let (h, m, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}

/// A cursor into a growing JSONL trace: the byte offset just past the last
/// complete line consumed, and the 1-based `seq` of that line. Callers persist it
/// between polls (in a map, or a stateful handle) so each poll seeks instead of
/// rescanning the whole file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventCursor {
    pub offset: u64,
    pub seq: u64,
}

/// Incrementally read events with `seq > from_seq`, returning them paired with
/// their 1-based seq plus the advanced cursor to pass to the next call.
///
/// The supplied `cursor` is honored only when `cursor.seq == from_seq` AND
/// `cursor.offset <= file_len` (a restarted tracer truncates the file); otherwise
/// the read restarts from the top. Only complete (newline-terminated) lines are
/// consumed — the tracer may be mid-write on the last line, so its unterminated
/// tail is left for the next poll. On any I/O failure or a file with no complete
/// line yet, returns no rows and the cursor unchanged.
pub fn read_events(
    path: &Path,
    from_seq: u64,
    cursor: EventCursor,
) -> (Vec<(u64, TraceEvent)>, EventCursor) {
    read_events_capped(path, from_seq, cursor, u64::MAX)
}

/// [`read_events`], but reading at most `max_bytes` per call. Bounds the
/// read/parse/allocation cost of one poll against a large backlog (e.g. the
/// first poll of a long-running trace); the advanced cursor stops at the last
/// complete line inside the cap, so repeated polls drain the backlog
/// incrementally. `max_bytes` must exceed the longest possible line, or a poll
/// could return no rows without advancing.
pub fn read_events_capped(
    path: &Path,
    from_seq: u64,
    cursor: EventCursor,
    max_bytes: u64,
) -> (Vec<(u64, TraceEvent)>, EventCursor) {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return (Vec::new(), cursor), // not created yet
    };
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    // Resume from the cursor only when the caller continues where the last read
    // ended AND the file hasn't shrunk; otherwise full scan from the start.
    let (offset, mut seq) = if cursor.seq == from_seq && cursor.offset <= file_len {
        (cursor.offset, cursor.seq)
    } else {
        (0, 0)
    };

    if file.seek(SeekFrom::Start(offset)).is_err() {
        return (Vec::new(), cursor);
    }
    let mut bytes = Vec::new();
    if file.take(max_bytes).read_to_end(&mut bytes).is_err() {
        return (Vec::new(), cursor);
    }
    // Process only complete lines; leave any unterminated tail for the next poll.
    // The truncation happens at the byte level BEFORE UTF-8 conversion: the byte
    // cap can split a multi-byte character, and that split can only sit in the
    // dropped tail, so cursor offsets stay exact and the conversion stays clean.
    let complete_len = match bytes.iter().rposition(|&b| b == b'\n') {
        Some(i) => i + 1,
        None => return (Vec::new(), cursor),
    };
    let complete = String::from_utf8_lossy(&bytes[..complete_len]);

    let mut rows = Vec::new();
    for line in complete.lines() {
        seq += 1;
        if seq <= from_seq {
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(ev) = TraceEvent::from_json_line(line) {
            rows.push((seq, ev));
        }
    }
    // `complete_len`, not `complete.len()`: lossy conversion may have changed
    // the string's length, but the cursor tracks raw file bytes.
    let new_cursor = EventCursor { offset: offset + complete_len as u64, seq };
    (rows, new_cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_jsonl(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("joybug-etw-test-{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn ev_line(op: &str) -> String {
        format!("{{\"kind\":\"file\",\"op\":\"{op}\",\"pid\":10,\"ts\":0}}\n")
    }

    #[test]
    fn read_events_incremental() {
        let path = tmp_jsonl("incremental");
        std::fs::write(&path, format!("{}{}", ev_line("create"), ev_line("write"))).unwrap();

        let (rows, cur) = read_events(&path, 0, EventCursor::default());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, 1);
        assert_eq!(rows[1].0, 2);
        assert_eq!(cur.seq, 2);

        // Append; poll with the returned cursor and from_seq = last seq.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(ev_line("delete").as_bytes()).unwrap();

        let (rows2, cur2) = read_events(&path, 2, cur);
        assert_eq!(rows2.len(), 1);
        assert_eq!(rows2[0].0, 3);
        assert_eq!(rows2[0].1.op, "delete");
        assert_eq!(cur2.seq, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_partial_trailing_line_withheld() {
        let path = tmp_jsonl("partial");
        // One complete line + an unterminated partial line.
        std::fs::write(&path, format!("{}{{\"kind\":\"file\"", ev_line("create"))).unwrap();
        let (rows, cur) = read_events(&path, 0, EventCursor::default());
        assert_eq!(rows.len(), 1, "partial line must be withheld");
        assert_eq!(cur.seq, 1);

        // Complete the partial line; it is delivered on the next poll.
        std::fs::write(&path, format!("{}{}", ev_line("create"), ev_line("write"))).unwrap();
        let (rows2, _) = read_events(&path, 1, cur);
        assert_eq!(rows2.len(), 1);
        assert_eq!(rows2[0].0, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_capped_drains_incrementally() {
        let path = tmp_jsonl("capped");
        std::fs::write(
            &path,
            format!("{}{}{}", ev_line("create"), ev_line("write"), ev_line("delete")),
        )
        .unwrap();

        // Cap that fits two complete lines but cuts the third mid-line: the cut
        // line is withheld and the cursor stops at the last complete one.
        let cap = (ev_line("create").len() + ev_line("write").len() + 5) as u64;
        let (rows, cur) = read_events_capped(&path, 0, EventCursor::default(), cap);
        assert_eq!(rows.len(), 2);
        assert_eq!(cur.seq, 2);

        // The next poll resumes from the cursor and delivers the rest.
        let (rows2, cur2) = read_events_capped(&path, 2, cur, cap);
        assert_eq!(rows2.len(), 1);
        assert_eq!(rows2[0].0, 3);
        assert_eq!(rows2[0].1.op, "delete");
        assert_eq!(cur2.seq, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_capped_split_utf8_char_withheld() {
        let path = tmp_jsonl("capped-utf8");
        // A non-ASCII path ("é" = 2 bytes in UTF-8) on the second line.
        let line2 = "{\"kind\":\"file\",\"op\":\"read\",\"pid\":10,\"ts\":0,\"path\":\"C:\\\\é.txt\"}\n";
        std::fs::write(&path, format!("{}{}", ev_line("create"), line2)).unwrap();

        // Cap the read one byte into the multi-byte character: the split line is
        // withheld cleanly (no rows lost, no stuck cursor) and delivered whole on
        // the next uncapped poll.
        let cap = (ev_line("create").len() + line2.find('é').unwrap() + 1) as u64;
        let (rows, cur) = read_events_capped(&path, 0, EventCursor::default(), cap);
        assert_eq!(rows.len(), 1);
        assert_eq!(cur.seq, 1);

        let (rows2, _) = read_events(&path, 1, cur);
        assert_eq!(rows2.len(), 1);
        assert_eq!(rows2[0].1.path.as_deref(), Some("C:\\é.txt"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_truncation_resets() {
        let path = tmp_jsonl("truncate");
        std::fs::write(&path, format!("{}{}", ev_line("create"), ev_line("write"))).unwrap();
        let (_, cur) = read_events(&path, 0, EventCursor::default());
        assert_eq!(cur.seq, 2);

        // Tracer restarts → file truncated shorter than the stored offset. Feeding
        // the stale cursor back (offset > file_len) must NOT seek past EOF; the
        // offset guard invalidates it and the scan restarts from the top. The
        // single new line (seq 1) is still filtered by the stale from_seq = 2 —
        // the reset only fixes the byte offset, not the caller's high-water mark.
        std::fs::write(&path, ev_line("rename")).unwrap();
        let (rows, _) = read_events(&path, 2, cur);
        assert!(rows.is_empty(), "stale from_seq still filters the re-read line");

        // On a real restart the caller resets from_seq to 0 (the app does this on
        // the target's pid change); then the truncated file re-reads from seq 1.
        let (rows2, cur2) = read_events(&path, 0, cur);
        assert_eq!(rows2.len(), 1);
        assert_eq!(rows2[0].0, 1, "seq restarts after truncation");
        assert_eq!(cur2.seq, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_from_seq_mismatch_rescans() {
        let path = tmp_jsonl("mismatch");
        std::fs::write(&path, format!("{}{}{}", ev_line("a"), ev_line("b"), ev_line("c"))).unwrap();
        // Cursor seq (2) != from_seq (0) → full rescan honoring from_seq filter.
        let stale = EventCursor { offset: 999, seq: 2 };
        let (rows, cur) = read_events(&path, 0, stale);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, 1);
        assert_eq!(cur.seq, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_missing_file() {
        let path = tmp_jsonl("missing");
        let (rows, cur) = read_events(&path, 0, EventCursor::default());
        assert!(rows.is_empty());
        assert_eq!(cur, EventCursor::default());
    }

    #[test]
    fn filetime_epoch_and_midday() {
        assert_eq!(filetime_to_hms(EPOCH_DIFF_100NS), "00:00:00.000");
        // 12:34:56.789 past a day boundary: seconds-of-day = 45296, +789ms.
        let sod_100ns = (45_296i64 * 10_000_000) + (789 * 10_000);
        assert_eq!(filetime_to_hms(EPOCH_DIFF_100NS + sod_100ns), "12:34:56.789");
    }

    #[test]
    fn filetime_before_epoch_empty() {
        assert_eq!(filetime_to_hms(0), "");
        assert_eq!(filetime_to_hms(EPOCH_DIFF_100NS - 1), "");
    }

    #[test]
    fn tracer_args_default_ops_omit_capture() {
        let cfg = HostTracerConfig {
            tracer_exe: PathBuf::from("t.exe"),
            out_path: PathBuf::from("o.jsonl"),
            session_name: "s".to_string(),
            capture: EtwCaptureSpec::default(),
        };
        let args = tracer_args(&cfg);
        assert!(!args.iter().any(|a| a == "--capture"));
        assert!(!args.iter().any(|a| a == "--stacks"));
    }

    #[test]
    fn tracer_args_ops_and_callstacks() {
        let cfg = HostTracerConfig {
            tracer_exe: PathBuf::from("t.exe"),
            out_path: PathBuf::from("o.jsonl"),
            session_name: "s".to_string(),
            capture: EtwCaptureSpec {
                ops: vec!["file.read".to_string()],
                callstacks: true,
                buffer_kb: Some(64),
                buffers: Some(8),
            },
        };
        let args = tracer_args(&cfg);
        let cap = args.iter().position(|a| a == "--capture").expect("--capture present");
        assert_eq!(args[cap + 1], "file.read");
        assert_eq!(args.iter().filter(|a| *a == "--stacks").count(), 1, "exactly one --stacks");
        let kb = args.iter().position(|a| a == "--buffer-kb").expect("--buffer-kb present");
        assert_eq!(args[kb + 1], "64");
        let n = args.iter().position(|a| a == "--buffers").expect("--buffers present");
        assert_eq!(args[n + 1], "8");
    }

    #[test]
    fn capture_ops_expands_groups_and_aliases() {
        let spec = EtwCaptureSpec { ops: vec!["registry.query".into(), "audit.*".into()], ..Default::default() };
        assert!(spec.validate().is_ok());
        assert_eq!(
            spec.capture_ops().as_deref(),
            Some("registry.query_value,audit.open_process,audit.open_thread")
        );
        // A spelling of the default set through a group is still "the default".
        let all_default = EtwCaptureSpec { ops: DEFAULT_OPS.iter().map(|s| s.to_string()).collect(), ..Default::default() };
        assert_eq!(all_default.capture_ops(), None);
        let bad = EtwCaptureSpec { ops: vec!["file.wriet".into()], ..Default::default() };
        assert!(bad.validate().unwrap_err().contains("file.wriet"));
    }

    #[test]
    fn tracer_done_marker() {
        let path = tmp_jsonl("done");
        std::fs::write(&path, ev_line("create")).unwrap();
        assert!(!tracer_done(&path));
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"kind\":\"tracer\",\"op\":\"done\"}\n").unwrap();
        assert!(tracer_done(&path));
        let _ = std::fs::remove_file(&path);
    }
}
