//! The ETW collector: enables the Kernel providers (Process / File / Registry /
//! Network / Audit-API-Calls), launches or attaches to a target, tracks its whole
//! process tree, and writes matching events as JSON lines to an output file.
//!
//! This is a *library* module, not a binary. It runs inside a Windows Sandbox as
//! SYSTEM, and on the host (elevated) for sandbox-less tracing — but in both
//! cases the process hosting it is a joybug executable (`joybug-core.exe`,
//! `jlua.exe`, or the Joybug app) that dispatches into [`run`] when it sees the
//! collector's `--out` flag. There is no separate tracer binary to build,
//! stage, or keep in sync.
//!
//! Argument form (as built by [`crate::Sandbox`] callers and `joybug_core::etw`):
//!   --out <file> [--discover] [--tree-timeout <secs>] -- <program> [args...]
//!   --out <file> [--discover] [--tree-timeout <secs>] --attach-pid <pid>
//!   --out <file> --attach-pid <pid> --control <file>   (resident)
//!   common: [--capture <csv>] [--stacks] [--buffer-kb <n>] [--buffers <n>]
//!
//! ## Control records
//! Besides events, the JSONL carries `kind:"tracer"` records a host driver can
//! act on: `start` (the ETW session is up — its absence means the collector
//! never ran), `lost` (ETW dropped events; see [`crate::etw_stats`]),
//! `tree_timeout`, `error`, `stats` and the terminal `done`.
//!
//! Two modes: it can *spawn* a target (`-- <program>`) and root the traced tree
//! at that child, or *attach* to an already-running process tree (`--attach-pid`,
//! used when another component — e.g. the joybug debug server — owns the target).
//!
//! ## The run ends with the TREE, not with the root
//! Waiting only for the root pid would truncate the common "dropper" shape — a
//! process that spawns a successor and immediately exits — and, because `wsb exec`
//! runs us inside a job object that dies with us, would *kill* those survivors
//! rather than merely stop recording them. So after the root goes away we keep
//! tracing while any tracked descendant is alive (`follow_tree`), bounded by
//! `--tree-timeout` so a target that leaves a service behind can't hang the run.
//!
//! ## Resident mode (`--control <file>`)
//! For host attach where the debuggee may restart many times, `--control` keeps
//! one (elevated) tracer alive across restarts: instead of exiting when the root
//! pid dies, it polls the control file for `attach <pid>` (re-target the tree,
//! reusing the same ETW session — no new UAC) or `stop` (drain + exit). This is
//! why UAC prompts only once per host-ETW session, not once per restart.
//!
//! ## Dispatch is name-based, not id-based
//! Event semantics are keyed off the manifest's *names* obtained from TDH
//! (`schema.task_name()` for File, `schema.opcode_name()` for Registry), which
//! are far more stable across Windows builds than numeric event ids. Numeric
//! ids are kept only as a fallback. Property names are manifest fields and are
//! likewise stable. With `--discover`, any event type we don't handle (from the
//! traced tree) is emitted once as an `unhandled` probe carrying its
//! task/opcode/id — a built-in drift detector for new Windows versions.

use std::collections::{HashMap, HashSet};
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrisetw::native::ExtendedDataItem;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{Provider, TraceFlags};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceProperties, UserTrace};
use ferrisetw::EventRecord;
use crate::etw_stats::{query_session, SessionStats};
use crate::{symbolize_frame, ModuleRange, PendingStart, ProcessTree};

const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
const KERNEL_REGISTRY: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
/// Microsoft-Windows-Kernel-Audit-API-Calls: a handful of sensitive kernel
/// APIs, including OpenProcess/OpenThread with their DesiredAccess mask.
const KERNEL_AUDIT: &str = "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23";

/// Which individual event *operations* to emit, by token. The providers still
/// deliver everything for the tracked tree (opens/queries are needed to resolve
/// paths and track the process tree); this only gates what is written to the
/// JSONL. Per-op tokens (kind.op):
///   process.start process.stop process.thread_start process.thread_stop
///   process.image_load process.image_unload
///   file.create file.write file.delete file.rename file.open
///   file.read file.close file.dir_enum
///   registry.create_key registry.set_value registry.delete_key
///   registry.delete_value registry.open_key registry.query_value
///   registry.query_key registry.enum_key registry.enum_value
///   network.connect network.accept network.send network.recv
///   network.disconnect network.retransmit network.udp_send network.udp_recv
///   audit.open_process audit.open_thread
/// The default (no `--capture` flag) = the historical set: modifications +
/// process + network, no reads/queries. `--capture <csv>` sets an explicit set;
/// the canonical list is [`crate::ALL_OPS`], groups/aliases via
/// [`crate::expand_ops`].
#[derive(Clone)]
struct Capture(HashSet<String>);

impl Default for Capture {
    fn default() -> Self {
        // The shared default lives in the winsandbox lib so host drivers that
        // compare against it can never drift from the tracer.
        Capture(crate::DEFAULT_OPS.iter().map(|s| s.to_string()).collect())
    }
}

impl Capture {
    /// Parse an explicit `--capture` csv: canonical `kind.op` tokens, `kind.*`
    /// groups, `all`, and the documented aliases (see [`crate::expand_ops`]).
    /// An unknown token is an error, never silently ignored.
    fn parse(spec: &str) -> Result<Self, String> {
        let tokens: Vec<&str> = spec.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()).collect();
        Ok(Capture(crate::expand_ops(&tokens)?.into_iter().collect()))
    }
    fn has(&self, op: &str) -> bool {
        self.0.contains(op)
    }
    /// The enabled tokens, in canonical order (for the `tracer.start` record).
    fn sorted(&self) -> Vec<&'static str> {
        crate::ALL_OPS.iter().copied().filter(|op| self.0.contains(*op)).collect()
    }
}

struct State {
    /// Which pids belong to the traced run (and the pre-root start buffer).
    /// Lives in the lib so its logic is unit-testable without ETW — see
    /// [`crate::ProcessTree`].
    tree: ProcessTree,
    /// FileObject/FileKey -> path, so name-less Write events can be resolved.
    file_names: HashMap<u64, String>,
    /// KeyObject -> full registry path, built from Create/Open events.
    key_paths: HashMap<u64, String>,
    /// (op, path) already emitted for create/delete/rename — dedup repeats.
    emitted: HashSet<(String, String)>,
    /// (provider, event_id) already reported as unhandled (discover dedup).
    unknown_seen: HashSet<(u8, u16)>,
    writer: BufWriter<std::fs::File>,
    discover: bool,
    count: u64,
    /// Which categories to emit (the providers still deliver everything).
    capture: Capture,
    /// The callstack (raw return addresses) of the event currently being
    /// dispatched, when stack tracing is enabled. `emit` attaches it as a hex
    /// `stack` array. Set per-event in `dispatch`, cleared after.
    pending_stack: Option<Vec<u64>>,
    /// `--stacks` was requested — lets `dispatch` skip scanning every event's
    /// extended data when no stacks were armed in the first place.
    stacks: bool,
    /// Loaded modules per tracked pid, for symbolizing `--stacks` frames. Fed by
    /// ImageLoad/ImageUnload (always delivered for the tree, whether or not
    /// `process.image_load` is emitted) and seeded from a toolhelp snapshot
    /// when a pid joins the tree, which covers attach mode where the loads
    /// pre-date the session.
    modules: HashMap<u32, Vec<ModuleRange>>,
    /// Last ETW loss counters reported, so `lost` records are written on change
    /// only — never per event.
    last_stats: SessionStats,
}

impl State {
    fn emit(&mut self, mut v: serde_json::Value) {
        if let Some(stack) = &self.pending_stack {
            if let Some(obj) = v.as_object_mut() {
                let raw: Vec<String> = stack.iter().map(|a| format!("0x{a:x}")).collect();
                // Resolve against the acting process's module list. Kernel frames
                // and unknown user addresses keep a compact marker; the raw
                // addresses stay in `stack` for consumers that want them.
                let pid = obj.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32);
                let empty = Vec::new();
                let mods = pid.and_then(|p| self.modules.get(&p)).unwrap_or(&empty);
                let frames: Vec<String> = stack.iter().map(|a| symbolize_frame(*a, mods)).collect();
                obj.insert("stack".to_string(), serde_json::json!(raw));
                obj.insert("frames".to_string(), serde_json::json!(frames));
            }
        }
        let _ = writeln!(self.writer, "{v}");
        self.count += 1;
    }

    /// Compare fresh session counters against the last report and write a
    /// `tracer.lost` record when ETW has dropped more since. Returns whether it
    /// did. A stderr warning goes with it: silent truncation is the worst
    /// failure mode of a behaviour tracer.
    fn note_stats(&mut self, stats: SessionStats) {
        let grew = stats.events_lost > self.last_stats.events_lost
            || stats.buffers_lost() > self.last_stats.buffers_lost();
        if grew {
            let delta = stats.events_lost.saturating_sub(self.last_stats.events_lost);
            let message = format!(
                "ETW dropped {} event(s) so far ({delta} new; {} buffer(s) lost): the capture is \
                 truncated — trim the op set, or raise --buffer-kb / --buffers",
                stats.events_lost,
                stats.buffers_lost()
            );
            eprintln!("{message}");
            self.pending_stack = None;
            self.emit(serde_json::json!({
                "kind": "tracer", "op": "lost",
                "events_lost": stats.events_lost,
                "buffers_lost": stats.buffers_lost(),
                "delta": delta,
                "message": message,
            }));
            let _ = self.writer.flush();
        }
        self.last_stats = stats;
    }

    /// Seed `pid`'s module list from a toolhelp snapshot (attach mode: the
    /// image loads happened before the session existed). ImageLoad events keep
    /// it current from here on. A no-op without `--stacks`, the only consumer of
    /// the module map — and a foreign-process snapshot is not cheap.
    fn seed_modules(&mut self, pid: u32) {
        if !self.stacks {
            return;
        }
        if let Some(mods) = snapshot_modules(pid) {
            self.modules.entry(pid).or_default().extend(mods);
        }
    }

    fn note_image_load(&mut self, pid: u32, base: u64, size: u64, path: &str) {
        if !self.stacks {
            return;
        }
        let name = module_name(path);
        let list = self.modules.entry(pid).or_default();
        if !list.iter().any(|m| m.base == base) {
            list.push(ModuleRange { base, size, name });
        }
    }

    fn note_image_unload(&mut self, pid: u32, base: u64) {
        if !self.stacks {
            return;
        }
        if let Some(list) = self.modules.get_mut(&pid) {
            list.retain(|m| m.base != base);
        }
    }
    /// Emit only the first time this (op, path) is seen. Kernel-File repeats
    /// NameDelete/NameCreate on cache churn; we want one line per change.
    fn emit_once(&mut self, op: &str, path: &str, v: serde_json::Value) {
        if self.emitted.insert((op.to_string(), path.to_string())) {
            self.emit(v);
        }
    }

    /// Register the root pid, emitting any buffered child starts the tree
    /// resolves from it (see `ProcessTree::set_root`).
    fn set_root(&mut self, root: u32) {
        let resolved = self.tree.set_root(root);
        self.adopt(root, resolved);
    }

    /// Re-root the traced tree at a new pid (resident mode, after a debuggee
    /// restart). Also drops the resolution/dedup maps so the fresh run starts
    /// clean and can re-emit the same paths; the ETW session itself is untouched
    /// (filtering is purely in-callback via the tree).
    fn retarget(&mut self, root: u32) {
        let resolved = self.tree.retarget(root);
        self.file_names.clear();
        self.key_paths.clear();
        self.emitted.clear();
        self.modules.clear();
        self.adopt(root, resolved);
    }

    /// Bookkeeping for a (re-)rooted tree: seed the module maps of the root and
    /// every buffered child, then emit those children's starts.
    fn adopt(&mut self, root: u32, resolved: Vec<PendingStart>) {
        self.seed_modules(root);
        for ps in &resolved {
            self.seed_modules(ps.child);
        }
        self.emit_starts(resolved);
    }

    fn emit_starts(&mut self, starts: Vec<PendingStart>) {
        if !self.capture.has("process.start") {
            return;
        }
        for ps in starts {
            let v = json_proc_start(&ps);
            self.emit(v);
        }
    }
}

fn json_proc_start(ps: &PendingStart) -> serde_json::Value {
    serde_json::json!({
        "kind": "process", "op": "start", "ts": ps.ts,
        "pid": ps.child, "ppid": ps.parent,
        "image": ps.image, "session": ps.session,
    })
}

/// Write a fatal-error record the host driver can read back (since `wsb exec`
/// discards our stdout/stderr), flush, and exit with `code`.
fn fatal(state: &Arc<Mutex<State>>, code: i32, message: String) -> ! {
    eprintln!("{message}");
    if let Ok(mut s) = state.lock() {
        s.emit(serde_json::json!({
            "kind": "tracer", "op": "error", "message": message,
        }));
        let _ = s.writer.flush();
    }
    std::process::exit(code);
}

/// How long to keep tracing after the root pid exits, waiting for the rest of
/// the tree to drain. Generous enough for a multi-stage dropper, short enough
/// that a target which leaves a service running cannot hang the run forever.
const TREE_TIMEOUT_DEFAULT_SECS: u64 = 120;

/// How long a tracked pid must look dead in a process snapshot before we drop it
/// on the snapshot's word alone. The tree normally shrinks via `ProcessStop`;
/// this is only the backstop for a stop event that never arrives. The grace
/// matters because ETW delivery lags reality by up to a buffer flush: pruning a
/// pid the instant it leaves the snapshot can drop a parent *before* its child's
/// still-buffered `ProcessStart` is dispatched, orphaning the rest of the tree.
const PRUNE_GRACE: Duration = Duration::from_secs(5);

/// `CREATE_NEW_CONSOLE` — the spawned target gets its own console window rather
/// than inheriting the tracer's (which `wsb exec` never renders).
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

#[derive(Clone, Copy)]
enum Kind {
    Process,
    File,
    Registry,
    Network,
    Audit,
}

impl Kind {
    /// The `kind` string this provider's events are tagged with. A method rather
    /// than an index into a literal array, so adding a variant cannot silently
    /// mismatch (or panic) the way `[..][kind as usize]` would.
    fn as_str(self) -> &'static str {
        match self {
            Kind::Process => "process",
            Kind::File => "file",
            Kind::Registry => "registry",
            Kind::Network => "network",
            Kind::Audit => "audit",
        }
    }
}

/// Run the ETW collector to completion and exit the process.
///
/// Never returns: the collector owns the process for its whole lifetime, and
/// both callers (the in-guest launch and the elevated host tracer) want the exit
/// code to be the traced target's. `args` is the argument list *after* the
/// program name.
pub fn run(args: impl Iterator<Item = String>) -> ! {
    let mut args = args;
    let mut out_path = String::from("events.jsonl");
    let mut discover = false;
    let mut attach_pid: Option<u32> = None;
    let mut target: Vec<String> = Vec::new();
    // Parsed after the output file exists, so a bad token becomes a
    // `tracer.error` record the host can read back, not just a stderr line
    // `wsb exec` would discard.
    let mut capture_spec: Option<String> = None;
    let mut stacks = false;
    let mut session_name = String::from("SbxGuestTracer");
    // ETW buffer pool. ferrisetw's default (32 KB buffers, kernel-chosen count)
    // overran on a registry-heavy target and dropped 88% of the events silently
    // (RETRO B8); these defaults give the session real headroom and both are
    // overridable. Memory cost is buffer_kb * buffers at the high-water mark.
    let mut buffer_kb: u32 = DEFAULT_BUFFER_KB;
    let mut buffers: u32 = DEFAULT_BUFFERS;
    // Resident-mode control file: when set, the tracer stays alive across target
    // exits and re-targets (or stops) on commands written here by the host —
    // letting one elevated tracer serve many debuggee restarts with a single UAC.
    let mut control: Option<String> = None;
    // Post-root tree following: how long to keep tracing once the root pid is
    // gone. `--tree-timeout 0` means "until the tree drains, however long that
    // takes"; `--no-follow-tree` restores the pre-tree-following behaviour of
    // ending the run the moment the root exits (a diagnostics escape hatch).
    let mut tree_timeout_secs = TREE_TIMEOUT_DEFAULT_SECS;
    let mut follow_tree_enabled = true;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out_path = args.next().expect("--out needs a value"),
            "--discover" => discover = true,
            "--stacks" => stacks = true,
            "--session-name" => session_name = args.next().expect("--session-name needs a value"),
            "--control" => control = Some(args.next().expect("--control needs a value")),
            "--no-follow-tree" => follow_tree_enabled = false,
            "--tree-timeout" => {
                let v = args.next().expect("--tree-timeout needs a value");
                tree_timeout_secs = v.parse().expect("--tree-timeout must be seconds");
            }
            "--capture" => {
                capture_spec = Some(args.next().expect("--capture needs a value"));
            }
            "--buffer-kb" => {
                let v = args.next().expect("--buffer-kb needs a value");
                buffer_kb = v.parse().expect("--buffer-kb must be a number");
            }
            "--buffers" => {
                let v = args.next().expect("--buffers needs a value");
                buffers = v.parse().expect("--buffers must be a number");
            }
            "--attach-pid" => {
                let v = args.next().expect("--attach-pid needs a value");
                attach_pid = Some(v.parse().expect("--attach-pid must be a number"));
            }
            "--" => {
                target.extend(args.by_ref());
                break;
            }
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }
    if attach_pid.is_none() && target.is_empty() && control.is_none() {
        eprintln!("no target: pass --attach-pid <pid>, --control <file>, or -- <program> [args]");
        std::process::exit(2);
    }
    if attach_pid.is_some() && !target.is_empty() {
        eprintln!("--attach-pid and -- <program> are mutually exclusive");
        std::process::exit(2);
    }

    let file = std::fs::File::create(&out_path).expect("create output file");
    let state = Arc::new(Mutex::new(State {
        tree: ProcessTree::new(),
        file_names: HashMap::new(),
        key_paths: HashMap::new(),
        emitted: HashSet::new(),
        unknown_seen: HashSet::new(),
        writer: BufWriter::new(file),
        discover,
        count: 0,
        capture: Capture::default(),
        pending_stack: None,
        stacks,
        modules: HashMap::new(),
        last_stats: SessionStats::default(),
    }));
    if let Some(spec) = capture_spec {
        match Capture::parse(&spec) {
            Ok(c) => state.lock().unwrap().capture = c,
            Err(e) => fatal(&state, 2, format!("bad --capture: {e}")),
        }
    }
    let mode = if control.is_some() {
        "resident"
    } else if attach_pid.is_some() {
        "attach"
    } else {
        "spawn"
    };

    // Keywords: process 0x70 = PROCESS|THREAD|IMAGE (so thread + image/DLL
    // events are delivered, gated per-op);
    // file 0x1F90 = FILENAME|CREATE|WRITE|READ|DELETE_PATH|RENAME|CREATE_NEW_FILE;
    // registry 0 = all (we need Create/Open events to resolve key paths);
    // network 0x30 = IPv4|IPv6.
    let trace = UserTrace::new()
        .named(session_name.clone())
        .set_trace_properties(TraceProperties {
            buffer_size: buffer_kb.max(4),
            min_buffer: (buffers / 4).max(2),
            max_buffer: buffers.max(2),
            ..TraceProperties::default()
        })
        .enable(provider(KERNEL_PROCESS, Kind::Process, &state, 0x70, stacks))
        .enable(provider(KERNEL_FILE, Kind::File, &state, 0x1F90, stacks))
        .enable(provider(KERNEL_REGISTRY, Kind::Registry, &state, 0, stacks))
        .enable(provider(KERNEL_NETWORK, Kind::Network, &state, 0x30, stacks))
        .enable(provider(KERNEL_AUDIT, Kind::Audit, &state, 0, stacks))
        .start_and_process();
    let trace = match trace {
        Ok(t) => t,
        Err(e) => fatal(&state, 4, format!("failed to start ETW trace (need SYSTEM/admin): {e:?}")),
    };

    // The session is up: say so. A host that finds no `tracer.start` in the
    // output knows the collector never ran (wrong guest binary, RETRO B3) rather
    // than that the target was merely quiet.
    {
        let mut s = state.lock().unwrap();
        let ops = s.capture.sorted();
        s.emit(serde_json::json!({
            "kind": "tracer", "op": "start",
            "session": session_name, "mode": mode,
            "ops": ops, "stacks": stacks,
            "buffer_kb": buffer_kb, "buffers": buffers,
        }));
        let _ = s.writer.flush();
    }

    std::thread::sleep(Duration::from_millis(800));

    // Periodic flush so a host tailing the shared output file sees events while
    // the target is still running (the writer is otherwise only flushed at exit).
    // The same thread polls the session's loss counters every few ticks.
    let flush_stop = Arc::new(AtomicBool::new(false));
    let flush_handle = {
        let st = Arc::clone(&state);
        let stop = Arc::clone(&flush_stop);
        let session = session_name.clone();
        std::thread::spawn(move || {
            let mut tick: u32 = 0;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                tick += 1;
                let stats = if tick % STATS_POLL_TICKS == 0 { query_session(&session) } else { None };
                if let Ok(mut s) = st.lock() {
                    if let Some(stats) = stats {
                        s.note_stats(stats);
                    }
                    let _ = s.writer.flush();
                }
            }
        })
    };

    let exit_code = if let Some(ctl) = control.clone() {
        // Resident mode: root at the initial pid (if given) and then obey the
        // control file — re-targeting across debuggee restarts without a new UAC,
        // and exiting only on `stop`. The ETW session/providers stay up the whole
        // time (pid filtering is purely in-callback, so re-targeting is cheap).
        if let Some(pid) = attach_pid {
            state.lock().unwrap().set_root(pid);
            eprintln!("tracing existing pid {pid} (resident)");
        } else {
            eprintln!("resident tracer waiting for an attach command");
        }
        run_control_loop(&ctl, &state);
        0
    } else {
        match attach_pid {
        // Attach mode: another component owns the target. Root the tree at the
        // given pid (set_root also drains any children already buffered) and
        // trace until it exits.
        Some(pid) => {
            state.lock().unwrap().set_root(pid);
            eprintln!("tracing existing pid {pid}");
            wait_for_pid_exit(pid);
            follow_tree(&state, follow_tree_enabled, tree_timeout_secs);
            0
        }
        // Spawn mode: we launch and own the target.
        None => {
            use std::os::windows::process::CommandExt;
            let mut cmd = std::process::Command::new(&target[0]);
            cmd.args(&target[1..]);
            // Give the target its own console so a console app is VISIBLE on the
            // sandbox desktop. Without this it inherits ours, and ours came from
            // `wsb exec` — which has no window — so a console target would run
            // completely unseen while a GUI target (making its own window) shows
            // up fine. Mirrors the CREATE_NEW_CONSOLE joybug-core passes when it
            // launches a debuggee. Harmless for GUI targets: they never write to
            // the console they are handed.
            cmd.creation_flags(CREATE_NEW_CONSOLE);
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => fatal(&state, 3, format!("failed to launch target {target:?}: {e}")),
            };
            let root_pid = child.id();
            // Registering the root also drains any child starts that arrived in
            // the window between spawn and here (see State::set_root).
            state.lock().unwrap().set_root(root_pid);
            eprintln!("tracing target pid {root_pid}: {target:?}");
            let status = child.wait().expect("wait target");
            follow_tree(&state, follow_tree_enabled, tree_timeout_secs);
            status.code().unwrap_or(0)
        }
        }
    };

    std::thread::sleep(Duration::from_millis(1500)); // drain trailing events
    // Final counters, read while the session still exists.
    let final_stats = query_session(&session_name);
    let _ = trace.stop();
    flush_stop.store(true, Ordering::Relaxed);
    let _ = flush_handle.join();

    let mut s = state.lock().unwrap();
    s.pending_stack = None;
    if let Some(stats) = final_stats {
        s.note_stats(stats);
    }
    let stats = s.last_stats;
    let written = s.count;
    s.emit(serde_json::json!({
        "kind": "tracer", "op": "stats",
        "events_written": written,
        "events_lost": stats.events_lost,
        "buffers_lost": stats.buffers_lost(),
        "buffers_written": stats.buffers_written,
        "buffers": stats.number_of_buffers,
        "buffer_kb": stats.buffer_size_kb,
    }));
    // A terminal marker so a host driver can detect the tracer exited (e.g. a
    // standalone ETW session ending when its target exits).
    s.emit(serde_json::json!({ "kind": "tracer", "op": "done" }));
    let _ = s.writer.flush();
    eprintln!("wrote {} events to {out_path} ({} lost by ETW)", s.count, stats.events_lost);
    std::process::exit(exit_code);
}

/// Default ETW buffer size (KB) and buffer-pool cap. See `run`.
const DEFAULT_BUFFER_KB: u32 = 512;
const DEFAULT_BUFFERS: u32 = 256;
/// Poll the session's loss counters every N flush ticks (500 ms each).
const STATS_POLL_TICKS: u32 = 4;

/// File name of an image path, lower-cased, for `frames` (`\Device\...\x.exe`
/// from ETW or a plain path from toolhelp).
fn module_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_ascii_lowercase()
}

/// The modules currently mapped in `pid` (both bitnesses of a WOW64 process),
/// or `None` if the snapshot failed — e.g. the process is already gone.
fn snapshot_modules(pid: u32) -> Option<Vec<ModuleRange>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid).ok()?;
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        let mut out = Vec::new();
        if Module32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry.szModule.iter().position(|&c| c == 0).unwrap_or(entry.szModule.len());
                let name = String::from_utf16_lossy(&entry.szModule[..len]).to_ascii_lowercase();
                out.push(ModuleRange {
                    base: entry.modBaseAddr as usize as u64,
                    size: entry.modBaseSize as u64,
                    name,
                });
                if Module32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        Some(out)
    }
}

/// Resident-mode control loop: poll `path` for one-line commands from the host
/// and act until told to stop. Commands (the file is overwritten each time):
///   `attach <pid>` — re-root the traced tree at `<pid>` (debuggee restarted)
///   `stop`         — drain and exit
/// Polling a small file avoids any elevated IPC (named pipe) surface; the host
/// can't kill this elevated process directly, so `stop` is how it ends cleanly.
fn run_control_loop(path: &str, state: &Arc<Mutex<State>>) {
    let mut last = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let cmd = content.trim();
        if cmd.is_empty() || cmd == last {
            continue;
        }
        last = cmd.to_string();
        if let Some(rest) = cmd.strip_prefix("attach ") {
            if let Ok(pid) = rest.trim().parse::<u32>() {
                if let Ok(mut s) = state.lock() {
                    s.retarget(pid);
                }
                eprintln!("resident tracer re-targeted to pid {pid}");
            }
        } else if cmd == "stop" {
            eprintln!("resident tracer stopping (control)");
            return;
        }
    }
}

/// After the root pid is gone, keep tracing while any tracked descendant is
/// still alive — the "parent spawns a successor and exits" shape, which a
/// root-only wait would both truncate and (via the `wsb exec` job object we run
/// in) kill outright.
///
/// Liveness is reconciled against a toolhelp snapshot rather than trusting
/// `ProcessStop` alone, so a dropped or never-delivered stop event cannot wedge
/// the run until the timeout. `timeout_secs == 0` means no cap; when a cap is
/// reached a `tracer/tree_timeout` record makes the truncation visible rather
/// than silent.
fn follow_tree(state: &Arc<Mutex<State>>, enabled: bool, timeout_secs: u64) {
    if !enabled {
        return;
    }
    let deadline = (timeout_secs > 0).then(|| Instant::now() + Duration::from_secs(timeout_secs));
    let mut announced = false;
    // pid -> when it first went missing from a snapshot, for PRUNE_GRACE.
    let mut dead_since: HashMap<u32, Instant> = HashMap::new();
    loop {
        let members: HashSet<u32> = state.lock().unwrap().tree.pids().into_iter().collect();
        // The normal exit: every member reported a ProcessStop.
        if members.is_empty() {
            eprintln!("traced tree fully exited");
            return;
        }
        if !announced {
            eprintln!("root exited; following {} live tree member(s)", members.len());
            announced = true;
        }
        // A failed snapshot is "no new information", not "everything died": skip
        // the liveness check rather than ending the run early.
        if let Some(alive) = snapshot_pids() {
            let now = Instant::now();
            dead_since.retain(|pid, _| members.contains(pid) && !alive.contains(pid));
            let doomed: HashSet<u32> = members
                .iter()
                .filter(|pid| !alive.contains(pid))
                .filter(|pid| now.duration_since(*dead_since.entry(**pid).or_insert(now)) >= PRUNE_GRACE)
                .copied()
                .collect();
            if !doomed.is_empty() {
                eprintln!("dropping {doomed:?}: gone for {PRUNE_GRACE:?} with no ProcessStop");
                state.lock().unwrap().tree.remove_all(&doomed);
            }
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let mut s = state.lock().unwrap();
            let pids = s.tree.pids();
            eprintln!("tree-follow timed out after {timeout_secs}s; still alive: {pids:?}");
            s.emit(serde_json::json!({
                "kind": "tracer", "op": "tree_timeout", "pids": pids,
            }));
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Block until the process `pid` exits. Used by attach mode, where the debugger
/// — not the tracer — owns the target's lifetime.
///
/// Liveness is checked with a toolhelp process snapshot rather than a wait on an
/// `OpenProcess` handle: the target is often owned by a debugger, and opening it
/// can be denied, which would make a handle-based wait return immediately and
/// stop the tracer far too early (capturing nothing). A snapshot enumerates all
/// pids and needs no per-process access. If the sandbox is torn down first, the
/// whole tracer is killed anyway.
fn wait_for_pid_exit(pid: u32) {
    while pid_alive(pid) {
        std::thread::sleep(Duration::from_millis(1000));
    }
}

/// Whether `pid` currently exists. A failed snapshot reads as "alive" so a
/// transient failure never stops the trace prematurely.
fn pid_alive(pid: u32) -> bool {
    snapshot_pids().is_none_or(|pids| pids.contains(&pid))
}

/// Every pid currently on the machine, via a toolhelp snapshot, or `None` if the
/// snapshot failed. Deliberately not an `OpenProcess` wait: the target is often
/// owned by a debugger and opening it can be denied, which would make a
/// handle-based wait return immediately and stop the tracer having captured
/// nothing. A snapshot enumerates all pids and needs no per-process access.
fn snapshot_pids() -> Option<HashSet<u32>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut pids = HashSet::new();
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                pids.insert(entry.th32ProcessID);
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        Some(pids)
    }
}

fn provider(guid: &str, kind: Kind, state: &Arc<Mutex<State>>, any: u64, stacks: bool) -> Provider {
    let st = Arc::clone(state);
    let flags = if stacks {
        TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE
    } else {
        TraceFlags::empty()
    };
    Provider::by_guid(guid)
        .add_callback(move |record: &EventRecord, sl: &SchemaLocator| {
            if let Ok(mut s) = st.lock() {
                dispatch(kind, record, sl, &mut s);
            }
        })
        .any(any)
        .level(5)
        .trace_flags(flags)
        .build()
}

/// Extract a captured user/kernel callstack (return addresses) from an event's
/// extended data, if stack tracing is enabled and this event carries one.
fn extract_stack(record: &EventRecord) -> Option<Vec<u64>> {
    for ext in record.extended_data() {
        if let ExtendedDataItem::StackTrace64(item) = ext.to_extended_data_item() {
            let addrs = item.addresses();
            if !addrs.is_empty() {
                return Some(addrs.to_vec());
            }
        }
    }
    None
}

fn dispatch(kind: Kind, record: &EventRecord, sl: &SchemaLocator, s: &mut State) {
    // File/registry/audit ownership is decided by the header pid alone, so
    // filter foreign processes BEFORE the schema/parser/name-string work below:
    // these providers are enabled machine-wide, and on a busy system almost
    // every delivered event is from an untracked process. Process events must
    // pass (starts/stops mutate the tree, and thread/image owner can sit in the
    // properties); network events carry their owning pid in the properties too.
    match kind {
        Kind::File | Kind::Registry | Kind::Audit => {
            if !s.tree.contains(record.process_id()) {
                return;
            }
        }
        Kind::Process | Kind::Network => {}
    }

    let schema = match sl.event_schema(record) {
        Ok(sc) => sc,
        Err(_) => return,
    };
    let p = Parser::create(record, &schema);
    let task = schema.task_name();
    let opcode = schema.opcode_name();
    let task = task.trim();
    let opcode = opcode.trim();

    // A captured callstack (present only when `--stacks` armed the providers and
    // this event carries one). `emit` attaches it to whatever the handler writes.
    s.pending_stack = if s.stacks { extract_stack(record) } else { None };

    let handled = match kind {
        Kind::Process => on_process(record, &p, task, s),
        Kind::File => on_file(record, &p, task, s),
        Kind::Registry => on_registry(record, &p, opcode, s),
        Kind::Network => on_network(record, &p, s),
        Kind::Audit => on_audit(record, &p, s),
    };
    s.pending_stack = None;

    // Drift detector: surface any event type from our tree we don't handle.
    if s.discover && !handled {
        let key = (kind as u8, record.event_id());
        if s.unknown_seen.insert(key) {
            s.emit(serde_json::json!({
                "op": "unhandled", "kind": kind.as_str(), "event_id": record.event_id(),
                "task": task, "opcode": opcode,
                "pid": record.process_id(),
                "props": discover_props(&p),
            }));
        }
    }
}

/// Returns true if the event was recognized (handled or intentionally ignored),
/// false if it's an unknown type from a tracked process (drift candidate).
fn on_process(record: &EventRecord, p: &Parser, task: &str, s: &mut State) -> bool {
    let id = record.event_id();
    // Kernel-Process manifest ids (stable): 1/2 process, 3/4 thread, 5/6 image.
    // Key on id first (opcodes collide — thread/image also use "Start"/"Stop"),
    // with the task name as a build-drift fallback.
    let is_start = id == 1 || task.eq_ignore_ascii_case("ProcessStart");
    let is_stop = id == 2 || task.eq_ignore_ascii_case("ProcessStop");

    // Thread start/stop — only meaningful for a tracked process (owner pid).
    if id == 3 || id == 4 || task.eq_ignore_ascii_case("ThreadStart") || task.eq_ignore_ascii_case("ThreadStop") {
        // Static tokens (not format!): this runs per event under the global lock.
        let (op, token) = if id == 3 || task.eq_ignore_ascii_case("ThreadStart") {
            ("thread_start", "process.thread_start")
        } else {
            ("thread_stop", "process.thread_stop")
        };
        let owner = u32p(p, "ProcessID").unwrap_or_else(|| record.process_id());
        if s.tree.contains(owner) && s.capture.has(token) {
            s.emit(serde_json::json!({
                "kind": "process", "op": op, "ts": record.raw_timestamp(),
                "pid": owner, "tid": u32p(p, "ThreadID"),
            }));
        }
        return true;
    }
    // Image (DLL/module) load/unload — DLL path in `path`, base/size for context.
    if id == 5 || id == 6 || task.eq_ignore_ascii_case("ImageLoad") || task.eq_ignore_ascii_case("ImageUnload") {
        let (op, token) = if id == 5 || task.eq_ignore_ascii_case("ImageLoad") {
            ("image_load", "process.image_load")
        } else {
            ("image_unload", "process.image_unload")
        };
        let owner = u32p(p, "ProcessID").unwrap_or_else(|| record.process_id());
        // Parse the image fields only when something consumes them — the
        // module map (which symbolizes `--stacks` frames) or the emitted
        // event — and once for both. The default capture wants neither, and
        // this runs per DLL load across the whole tree.
        let want_emit = s.tree.contains(owner) && s.capture.has(token);
        if want_emit || (s.stacks && s.tree.contains(owner)) {
            let base = u64p(p, "ImageBase");
            let size = u64p(p, "ImageSize");
            let path = strp(p, "ImageName");
            if id == 5 || task.eq_ignore_ascii_case("ImageLoad") {
                s.note_image_load(owner, base.unwrap_or(0), size.unwrap_or(0), path.as_deref().unwrap_or(""));
            } else {
                s.note_image_unload(owner, base.unwrap_or(0));
            }
            if want_emit {
                s.emit(serde_json::json!({
                    "kind": "process", "op": op, "ts": record.raw_timestamp(),
                    "pid": owner, "path": path, "base": base, "size": size,
                }));
            }
        }
        return true;
    }

    if is_start {
        let child = u32p(p, "ProcessID");
        let parent = u32p(p, "ParentProcessID").unwrap_or_else(|| record.process_id());
        if let Some(cpid) = child {
            // The tree tracks the child whenever its parent is tracked (needed
            // to attribute file/registry events), buffers it while the root is
            // still unknown, and ignores it otherwise. We only decide whether to
            // EMIT the process event.
            let ps = PendingStart {
                child: cpid,
                parent,
                ts: record.raw_timestamp(),
                image: strp(p, "ImageName"),
                session: u32p(p, "SessionID"),
            };
            if s.tree.note_start(ps) {
                s.seed_modules(cpid);
                if s.capture.has("process.start") {
                    s.emit(serde_json::json!({
                        "kind": "process", "op": "start", "ts": record.raw_timestamp(),
                        "pid": cpid, "ppid": parent,
                        "image": strp(p, "ImageName"), "session": u32p(p, "SessionID"),
                    }));
                }
            }
        }
        return true;
    }
    if is_stop {
        let pid = u32p(p, "ProcessID").unwrap_or_else(|| record.process_id());
        // `note_stop` also drops the pid from the tree, so a later reuse of the
        // same number by an unrelated process isn't misattributed to this run.
        if s.tree.note_stop(pid) {
            if s.capture.has("process.stop") {
                s.emit(serde_json::json!({
                    "kind": "process", "op": "stop", "ts": record.raw_timestamp(),
                    "pid": pid, "exit": u32p(p, "ExitCode"), "image": strp(p, "ImageName"),
                }));
            }
            s.modules.remove(&pid);
        }
        return true;
    }
    // Unknown process event: only a drift candidate if it concerns our tree.
    !s.tree.contains(record.process_id())
}

/// Kernel-Audit-API-Calls: the handle-acquisition half of cross-process access.
///
/// This is as close as ordinary (non-PPL) ETW gets to "process A read process
/// B's memory". The reads and writes themselves — NtReadVirtualMemory and
/// friends — live in Microsoft-Windows-Threat-Intelligence, which only a
/// Protected Process Light with an anti-malware ELAM signature may consume, so
/// they are out of reach here. What we do get is the `OpenProcess`/`OpenThread`
/// that must precede them, with the rights requested: no handle carrying
/// `VM_READ`/`VM_WRITE` means no cross-process memory access. What is lost is
/// the address, the size, and the count — one handle serves unlimited reads.
///
/// Ids 5 and 6 are CONFIRMED on build 26200: `open_remote.exe` requested 0x438
/// (VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION) and 0x1A
/// (SUSPEND_RESUME|GET_CONTEXT|SET_CONTEXT) and the provider reported exactly
/// those masks under those ids. This provider carries no task/opcode names (both
/// are empty, opcode "Info"), so unlike the other kinds there is no name-based
/// fallback — the ids are all we have.
///
/// The other ids this provider emits are deliberately left unhandled, so
/// `--discover` still probes them: 1 = SetLoadImageNotifyRoutine,
/// 2 = TerminateRemoteProcess (observed: TargetProcessId + ReturnCode, no
/// DesiredAccess), 3 = NtCreateSymbolicLink (observed), 4 = SetThreadContext.
/// They are the same injection family and worth adding, but none is covered by
/// a test yet.
fn on_audit(record: &EventRecord, p: &Parser, s: &mut State) -> bool {
    let pid = record.process_id();
    if !s.tree.contains(pid) {
        return true; // not ours: ignored, not "unknown"
    }
    let (op, token, thread) = match record.event_id() {
        5 => ("open_process", "audit.open_process", false),
        6 => ("open_thread", "audit.open_thread", true),
        _ => return false, // drift candidate; --discover will describe it
    };
    if !s.capture.has(token) {
        return true;
    }
    let mask = u32p(p, "DesiredAccess").unwrap_or(0);
    s.emit(serde_json::json!({
        "kind": "audit", "op": op, "ts": record.raw_timestamp(),
        "pid": pid,
        "target_pid": u32p(p, "TargetProcessId"),
        "access": crate::format_access_mask(mask, thread),
        "status": u32p(p, "ReturnCode"),
    }));
    true
}

/// Discovery aid: `Schema::properties()` is `pub(crate)` in ferrisetw, so we
/// cannot enumerate an event's fields generically. Probe a candidate list
/// instead and report the ones that parse — enough, with the task/opcode names,
/// to pin down an unfamiliar event's shape.
fn discover_props(p: &Parser) -> serde_json::Value {
    const CANDIDATES: &[&str] = &[
        "ProcessId", "ProcessID", "TargetProcessId", "TargetProcessID",
        "CallingProcessId", "SubjectProcessId", "SourceProcessId", "PID",
        "ThreadId", "ThreadID", "TargetThreadId", "TargetThreadID",
        "TargetTid", "Tid", "TID", "ClientId", "TargetThread", "ThreadHandle",
        "TargetProcessSequenceNumber", "TargetProcessStartKey", "Handle",
        "DesiredAccess", "GrantedAccess", "AccessMask", "ReturnCode", "Status",
    ];
    let mut obj = serde_json::Map::new();
    for name in CANDIDATES {
        if let Ok(v) = p.try_parse::<u32>(name) {
            obj.insert((*name).to_string(), serde_json::json!(v));
        } else if let Ok(v) = p.try_parse::<u64>(name) {
            obj.insert((*name).to_string(), serde_json::json!(v));
        } else if let Ok(v) = p.try_parse::<String>(name) {
            obj.insert((*name).to_string(), serde_json::json!(v));
        }
    }
    serde_json::Value::Object(obj)
}

fn on_file(record: &EventRecord, p: &Parser, task: &str, s: &mut State) -> bool {
    let pid = record.process_id();
    if !s.tree.contains(pid) {
        return true; // not ours: ignored, not "unknown"
    }
    let id = record.event_id();
    let ts = record.raw_timestamp();

    // Events carrying a name feed the object->name map; some are modifications.
    if let Some(name) = strp(p, "FileName") {
        if let Some(fo) = u64p(p, "FileObject") {
            s.file_names.insert(fo, name.clone());
        }
        if let Some(fk) = u64p(p, "FileKey") {
            s.file_names.insert(fk, name.clone());
        }

        if task == "CreateNewFile" || id == 30 {
            if s.capture.has("file.create") {
                s.emit_once("create", &name, json_file("create", ts, pid, &name, None));
            }
            return true;
        }
        if task == "RenamePath" || id == 28 {
            if s.capture.has("file.rename") {
                s.emit_once("rename", &name, json_file("rename", ts, pid, &name, None));
            }
            return true;
        }
        if task == "DeletePath" || id == 27 {
            if s.capture.has("file.delete") {
                s.emit_once("delete", &name, json_file("delete", ts, pid, &name, None));
            }
            return true;
        }
        if task == "NameDelete" || id == 11 {
            // NameDelete fires on final handle close AND on real deletion, with
            // no field distinguishing them, so it is NOT a reliable delete
            // signal (a created-then-closed file looks identical to a deleted
            // one). We deliberately do not emit here; the host driver instead
            // detects deletion of shared-folder files by existence check, and
            // real deletions on disk surface via DeletePath below when present.
            return true;
        }
        // Directory enumeration carrying a search path — opt-in (noisy).
        if task == "DirEnum" || task == "DirNotify" {
            if s.capture.has("file.dir_enum") {
                s.emit(json_file("dir_enum", ts, pid, &name, None));
            }
            return true;
        }
        // "Create" (open) / "NameCreate": not a modification. With reads enabled,
        // report it as an "open" — "what the target touches" — deduped by path.
        if s.capture.has("file.open") {
            s.emit_once("open", &name, json_file("open", ts, pid, &name, None));
        }
        return true;
    }

    // Name-less Write: resolve path via the object->name map.
    if task == "Write" || id == 16 {
        if s.capture.has("file.write") {
            let path = file_path(s, p).unwrap_or_else(|| "<unresolved>".to_string());
            s.emit(json_file("write", ts, pid, &path, u32p(p, "IOSize")));
        }
        return true;
    }
    // Name-less Read (opt-in — very high volume): resolve via the object map.
    if task == "Read" || id == 15 {
        if s.capture.has("file.read") {
            let path = file_path(s, p).unwrap_or_else(|| "<unresolved>".to_string());
            s.emit(json_file("read", ts, pid, &path, u32p(p, "IOSize")));
        }
        return true;
    }
    // Name-less directory enumeration.
    if task == "DirEnum" || task == "DirNotify" {
        if s.capture.has("file.dir_enum") {
            let path = file_path(s, p).unwrap_or_else(|| "<unresolved>".to_string());
            s.emit(json_file("dir_enum", ts, pid, &path, None));
        }
        return true;
    }
    // Cleanup/Close: end of a handle. Emit if enabled, then evict the name entry
    // to keep the object→name map bounded over long-lived traces.
    if task == "Close" || task == "Cleanup" {
        if s.capture.has("file.close") {
            let path = file_path(s, p).unwrap_or_else(|| "<unresolved>".to_string());
            s.emit(json_file("close", ts, pid, &path, None));
        }
        if let Some(fo) = u64p(p, "FileObject") {
            s.file_names.remove(&fo);
        }
        if let Some(fk) = u64p(p, "FileKey") {
            s.file_names.remove(&fk);
        }
        return true;
    }

    false // QueryInformation, SetInformation, ...: unhandled
}

fn on_registry(record: &EventRecord, p: &Parser, opcode: &str, s: &mut State) -> bool {
    let pid = record.process_id();
    if !s.tree.contains(pid) {
        return true;
    }
    let id = record.event_id();
    let ts = record.raw_timestamp();

    // CreateKey / OpenKey: build the KeyObject -> path map (and emit creations).
    if opcode == "CreateKey" || opcode == "OpenKey" || id == 1 || id == 2 {
        let ko = u64p(p, "KeyObject").unwrap_or(0);
        let status = u32p(p, "Status").unwrap_or(0);
        let rel = strp(p, "RelativeName").unwrap_or_default();
        let base = u64p(p, "BaseObject").unwrap_or(0);
        let full = if rel.starts_with('\\') {
            rel.clone()
        } else if let Some(b) = s.key_paths.get(&base) {
            format!("{b}\\{rel}")
        } else if base != 0 {
            format!("<key {base}>\\{rel}")
        } else {
            rel.clone()
        };
        // Always maintain the KeyObject->path map (needed to resolve later ops).
        if ko != 0 && status == 0 && !full.is_empty() {
            s.key_paths.insert(ko, full.clone());
        }
        let created = opcode == "CreateKey" || id == 1;
        if created && u32p(p, "Disposition") == Some(1) {
            if s.capture.has("registry.create_key") {
                s.emit_once("create_key", &full, json_reg("create_key", ts, pid, &full, None));
            }
        } else if s.capture.has("registry.open_key") && status == 0 && !full.is_empty() {
            // An open of an existing key (or a create that only opened) — "what the
            // target touches", deduped by path.
            s.emit_once("open_key", &full, json_reg("open_key", ts, pid, &full, None));
        }
        return true;
    }
    if opcode == "DeleteKey" || id == 3 {
        if s.capture.has("registry.delete_key") {
            let path = key_path(s, p);
            s.emit_once("delete_key", &path, json_reg("delete_key", ts, pid, &path, None));
        }
        return true;
    }
    if opcode == "SetValueKey" || id == 5 {
        if s.capture.has("registry.set_value") {
            let path = format!("{}\\{}", key_path(s, p), strp(p, "ValueName").unwrap_or_default());
            s.emit(json_reg("set_value", ts, pid, &path, u32p(p, "DataSize")));
        }
        return true;
    }
    if opcode == "DeleteValueKey" || id == 6 {
        if s.capture.has("registry.delete_value") {
            let path = format!("{}\\{}", key_path(s, p), strp(p, "ValueName").unwrap_or_default());
            s.emit(json_reg("delete_value", ts, pid, &path, None));
        }
        return true;
    }
    // Value queries (RegQueryValue) — a "read". Opcode "QueryValueKey" / id 7.
    // Not deduped: a program re-reading a value over time is meaningful, but this
    // is noisy, so it's opt-in via the `registry.query_value` token (the emitted
    // op; `registry.query` is accepted as an alias).
    if opcode == "QueryValueKey" || id == 7 {
        if s.capture.has("registry.query_value") {
            let path = format!("{}\\{}", key_path(s, p), strp(p, "ValueName").unwrap_or_default());
            s.emit(json_reg("query_value", ts, pid, &path, u32p(p, "DataSize")));
        }
        return true;
    }
    // Key queries/enumerations — reads on a key (not a value). Opt-in (noisy):
    // browsing a key in regedit fires these for every subkey/value listed.
    if opcode == "QueryKey" {
        if s.capture.has("registry.query_key") {
            let path = key_path(s, p);
            s.emit(json_reg("query_key", ts, pid, &path, None));
        }
        return true;
    }
    if opcode == "EnumerateKey" {
        if s.capture.has("registry.enum_key") {
            let path = key_path(s, p);
            s.emit(json_reg("enum_key", ts, pid, &path, None));
        }
        return true;
    }
    if opcode == "EnumerateValueKey" {
        if s.capture.has("registry.enum_value") {
            let path = key_path(s, p);
            s.emit(json_reg("enum_value", ts, pid, &path, None));
        }
        return true;
    }
    false // other registry ops
}

fn on_network(record: &EventRecord, p: &Parser, s: &mut State) -> bool {
    // Network events are logged in a deferred context, so record.process_id()
    // is unreliable; the real owner is the "PID" property.
    let owner = u32p(p, "PID").unwrap_or_else(|| record.process_id());
    if !s.tree.contains(owner) {
        return true;
    }
    // Kernel-Network ids (classic TcpIp/UdpIp numbering, confirmed 12/15 on
    // 26200). IPv6 variants carry different ids and surface via `--discover`.
    let (op, token) = match record.event_id() {
        10 => ("send", "network.send"),
        11 => ("recv", "network.recv"),
        12 => ("connect", "network.connect"),
        13 => ("disconnect", "network.disconnect"),
        14 => ("retransmit", "network.retransmit"),
        15 => ("accept", "network.accept"),
        26 => ("udp_send", "network.udp_send"),
        27 => ("udp_recv", "network.udp_recv"),
        _ => return false,
    };
    if s.capture.has(token) {
        s.emit(serde_json::json!({
            "kind": "network", "op": op, "ts": record.raw_timestamp(), "pid": owner,
            "dest": format!("{}:{}", fmt_ip(p, "daddr"), fmt_port(p, "dport")),
            "src": format!("{}:{}", fmt_ip(p, "saddr"), fmt_port(p, "sport")),
        }));
    }
    true
}

// ---- json builders ----

fn json_file(op: &str, ts: i64, pid: u32, path: &str, size: Option<u32>) -> serde_json::Value {
    serde_json::json!({ "kind": "file", "op": op, "ts": ts, "pid": pid, "path": path, "size": size })
}
fn json_reg(op: &str, ts: i64, pid: u32, path: &str, size: Option<u32>) -> serde_json::Value {
    serde_json::json!({ "kind": "registry", "op": op, "ts": ts, "pid": pid, "path": path, "size": size })
}

// ---- parse helpers ----

/// Resolve a name-less file event's path via the FileKey/FileObject → name map.
fn file_path(s: &State, p: &Parser) -> Option<String> {
    u64p(p, "FileKey")
        .or_else(|| u64p(p, "FileObject"))
        .and_then(|k| s.file_names.get(&k).cloned())
}
fn key_path(s: &State, p: &Parser) -> String {
    u64p(p, "KeyObject")
        .and_then(|k| s.key_paths.get(&k).cloned())
        .unwrap_or_else(|| "<unresolved>".to_string())
}
fn u32p(p: &Parser, name: &str) -> Option<u32> {
    p.try_parse::<u32>(name).ok()
}
fn u64p(p: &Parser, name: &str) -> Option<u64> {
    p.try_parse::<u64>(name).ok()
}
fn strp(p: &Parser, name: &str) -> Option<String> {
    match p.try_parse::<String>(name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
/// Kernel-Network stores an address as a UInt32 whose 4 bytes are the octets in
/// order, so `to_le_bytes` recovers a.b.c.d. Ports are UInt16 in network order.
fn fmt_ip(p: &Parser, name: &str) -> String {
    match p.try_parse::<u32>(name) {
        Ok(v) => {
            let b = v.to_le_bytes();
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        Err(_) => "?".to_string(),
    }
}
fn fmt_port(p: &Parser, name: &str) -> u16 {
    p.try_parse::<u16>(name).map(|v| v.swap_bytes()).unwrap_or(0)
}
