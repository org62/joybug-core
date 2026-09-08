//! Host ETW tracing bindings, exposed as a global `etw` table.
//!
//! Where `sbx` boots a whole Windows Sandbox VM, `etw` runs the ETW collector
//! directly on the host machine — no VM. A script starts a tracer (attached to a
//! live pid, or spawning a target), then polls events incrementally:
//!
//! ```lua
//! local h = etw.spawn{ args = { "C:/Windows/System32/notepad.exe" },
//!                      out = os.getenv("TEMP") .. "/notepad-etw.jsonl" }
//! local seq = 0
//! while not h:done() do
//!     for _, e in ipairs(h:events()) do
//!         print(e.time, e.kind, e.op, e.path or e.image or "")
//!         seq = e.seq
//!     end
//! end
//! ```
//!
//! **Elevation caveat:** kernel ETW needs admin, so `etw.start`/`etw.spawn` pop a
//! UAC prompt when jlua is not already elevated (run jlua elevated for unattended
//! scripts). The launch is asynchronous — `Start-Process` returns before the
//! tracer initializes, so poll `h:events()` with retries rather than expecting
//! data immediately. A cancelled UAC surfaces no error to the script; events
//! simply never arrive (guard with a `h:done()`/timeout loop).
//!
//! Gated behind the `etw` feature (Windows-only).

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use mlua::prelude::*;

use crate::etw::{self, EtwCaptureSpec, EventCursor, HostTracer, HostTracerConfig, TraceEvent};

/// A live host tracer exposed to Lua. Holds the resident [`HostTracer`] for
/// attach mode (`None` for spawn mode, which has no control file), the output
/// path, and this handle's own read cursor for incremental `events()`.
///
/// Unlike `sbx`'s `SbxHandle`, this deliberately has **no `Drop` teardown**: a
/// resident host tracer is designed to outlive the script (and app restarts) so
/// its single UAC prompt is never re-paid — `stop()` is explicit only.
pub struct EtwHandle {
    tracer: Option<HostTracer>,
    out: PathBuf,
    control: Option<PathBuf>,
    session_name: String,
    pid: Option<u32>,
    cursor: RefCell<EventCursor>,
}

impl LuaUserData for EtwHandle {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // Re-target the resident tracer to `pid` (no new UAC). Spawn-mode errors.
        methods.add_method("attach", |_lua, this, pid: u32| {
            match this.tracer.as_ref() {
                Some(t) => t.attach(pid).map_err(mlua::Error::external),
                None => Err(mlua::Error::external(
                    "etw handle: attach is only valid for etw.start (attached) tracers",
                )),
            }
        });

        // Ask the resident tracer to drain and exit. Spawn-mode tracers exit with
        // their target, so there is nothing to stop.
        methods.add_method("stop", |_lua, this, ()| match this.tracer.as_ref() {
            Some(t) => t.stop().map_err(mlua::Error::external),
            None => Err(mlua::Error::external(
                "etw handle: stop is only valid for etw.start (attached) tracers; \
                 a spawn-mode tracer exits with its target",
            )),
        });

        // Incremental poll. With no arg, continues from this handle's cursor;
        // an explicit `from_seq` that differs triggers a rescan (core's rule).
        methods.add_method("events", |lua, this, from_seq: Option<u64>| {
            let cur = *this.cursor.borrow();
            let from = from_seq.unwrap_or(cur.seq);
            let (rows, new_cur) = etw::read_events(&this.out, from, cur);
            *this.cursor.borrow_mut() = new_cur;
            rows_to_table(lua, rows)
        });

        methods.add_method("done", |_lua, this, ()| Ok(etw::tracer_done(&this.out)));

        methods.add_method("info", |lua, this, ()| {
            let t = lua.create_table()?;
            t.set("out", this.out.to_string_lossy().into_owned())?;
            t.set("session_name", this.session_name.clone())?;
            t.set("pid", this.pid)?;
            t.set("control", this.control.as_ref().map(|p| p.to_string_lossy().into_owned()))?;
            t.set("mode", if this.tracer.is_some() { "attached" } else { "spawn" })?;
            Ok(t)
        });
    }
}

/// Read a required, non-empty string field from an options table.
fn req_str(opts: &LuaTable, fname: &str, key: &str) -> mlua::Result<String> {
    opts.get::<Option<String>>(key)?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| mlua::Error::external(format!("{fname}: missing required `{key}`")))
}

/// Optional string field, treating empty as absent.
fn opt_str(opts: &LuaTable, key: &str) -> mlua::Result<Option<String>> {
    Ok(opts.get::<Option<String>>(key)?.filter(|s| !s.is_empty()))
}

/// The collector is a *mode* of the hosting executable, not a separate binary,
/// so the default is simply this process's own exe re-launched with the
/// collector's flags. A caller can still point `tracer_exe` elsewhere.
fn default_tracer_exe() -> mlua::Result<PathBuf> {
    std::env::current_exe().map_err(mlua::Error::external)
}

/// Build the capture spec (`ops`, `callstacks`, `buffer_kb`, `buffers`) from an
/// options table (the top-level `etw.start`/`etw.spawn` table, or the `etw = {}`
/// sub-table of `sbx.provision`). Unknown op tokens are refused here, before
/// anything is launched. Shared with `sbx`.
pub(crate) fn capture_from(opts: &LuaTable) -> mlua::Result<EtwCaptureSpec> {
    let ops = match opts.get::<Option<LuaTable>>("ops")? {
        Some(list) => list.sequence_values::<String>().collect::<mlua::Result<Vec<_>>>()?,
        None => Vec::new(),
    };
    let spec = EtwCaptureSpec {
        ops,
        callstacks: opts.get::<Option<bool>>("callstacks")?.unwrap_or(false),
        buffer_kb: opts.get::<Option<u32>>("buffer_kb")?,
        buffers: opts.get::<Option<u32>>("buffers")?,
    };
    spec.validate().map_err(mlua::Error::external)?;
    Ok(spec)
}

/// `{ all = {...}, default = {...}, groups = {...}, aliases = { old = new } }`
/// — the tracer's op vocabulary, for scripts that want to enumerate it instead
/// of grepping the source. Shared by `etw.ops()` and `sbx.ops()`.
pub(crate) fn ops_table(lua: &Lua) -> mlua::Result<LuaTable> {
    let t = lua.create_table()?;
    let all = lua.create_table()?;
    for op in etw::ALL_OPS {
        all.push(*op)?;
    }
    t.set("all", all)?;
    let default = lua.create_table()?;
    for op in etw::DEFAULT_OPS {
        default.push(*op)?;
    }
    t.set("default", default)?;
    let groups = lua.create_table()?;
    for kind in etw::OP_KINDS {
        groups.push(format!("{kind}.*"))?;
    }
    groups.push("all")?;
    t.set("groups", groups)?;
    let aliases = lua.create_table()?;
    for (alias, canonical) in etw::OP_ALIASES {
        aliases.set(*alias, *canonical)?;
    }
    t.set("aliases", aliases)?;
    Ok(t)
}

/// Common config decode for `etw.start`/`etw.spawn` (everything but the mode).
/// Returns the config plus the resolved out/session_name for the handle.
fn tracer_cfg_from(
    opts: &LuaTable,
    fname: &str,
    default_session: &str,
) -> mlua::Result<HostTracerConfig> {
    let out_path = PathBuf::from(req_str(opts, fname, "out")?);
    // Best-effort: create the output directory so the tracer can write.
    if let Some(parent) = out_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tracer_exe = match opt_str(opts, "tracer_exe")? {
        Some(s) => PathBuf::from(s),
        None => default_tracer_exe()?,
    };
    let session_name = opt_str(opts, "session_name")?.unwrap_or_else(|| default_session.to_string());
    Ok(HostTracerConfig { tracer_exe, out_path, session_name, capture: capture_from(opts)? })
}

/// Register the `etw` global table.
pub fn register_etw_functions(lua: &Lua) -> mlua::Result<()> {
    let etw_tbl = lua.create_table()?;

    // etw.start{ pid=, out=, [tracer_exe=], [control=], [session_name=], [ops=], [callstacks=] } -> handle
    etw_tbl.set(
        "start",
        lua.create_function(|lua, opts: LuaTable| {
            let pid = opts
                .get::<Option<u32>>("pid")?
                .ok_or_else(|| mlua::Error::external("etw.start: missing required `pid`"))?;
            let cfg = tracer_cfg_from(&opts, "etw.start", &format!("jlua-etw-{pid}"))?;
            let control = match opt_str(&opts, "control")? {
                Some(s) => PathBuf::from(s),
                None => default_control(&cfg.out_path),
            };
            let out = cfg.out_path.clone();
            let session_name = cfg.session_name.clone();
            let tracer =
                HostTracer::launch_attached(&cfg, control.clone(), pid).map_err(mlua::Error::external)?;
            lua.create_userdata(EtwHandle {
                tracer: Some(tracer),
                out,
                control: Some(control),
                session_name,
                pid: Some(pid),
                cursor: RefCell::new(EventCursor::default()),
            })
        })?,
    )?;

    // etw.spawn{ args={...}, out=, [tracer_exe=], [session_name=], [ops=], [callstacks=] } -> handle
    etw_tbl.set(
        "spawn",
        lua.create_function(|lua, opts: LuaTable| {
            let args: Vec<String> = match opts.get::<Option<LuaTable>>("args")? {
                Some(list) => list.sequence_values::<String>().collect::<mlua::Result<Vec<_>>>()?,
                None => Vec::new(),
            };
            if args.is_empty() {
                return Err(mlua::Error::external("etw.spawn: `args` must be a non-empty list"));
            }
            let cfg = tracer_cfg_from(&opts, "etw.spawn", "jlua-etw-spawn")?;
            let out = cfg.out_path.clone();
            let session_name = cfg.session_name.clone();
            etw::launch_spawn(&cfg, &args).map_err(mlua::Error::external)?;
            lua.create_userdata(EtwHandle {
                tracer: None,
                out,
                control: None,
                session_name,
                pid: None,
                cursor: RefCell::new(EventCursor::default()),
            })
        })?,
    )?;

    // etw.events(path[, from_seq]) -> list of event tables (stateless; module cursor)
    etw_tbl.set(
        "events",
        lua.create_function(|lua, (path, from_seq): (String, Option<u64>)| {
            events_to_table(lua, Path::new(&path), from_seq.unwrap_or(0))
        })?,
    )?;

    // etw.done(path) -> bool
    etw_tbl.set(
        "done",
        lua.create_function(|_lua, path: String| Ok(etw::tracer_done(Path::new(&path))))?,
    )?;

    // etw.time(ts) -> "HH:MM:SS.mmm" (FILETIME 100ns ticks -> UTC time-of-day)
    etw_tbl.set("time", lua.create_function(|_lua, ts: i64| Ok(etw::filetime_to_hms(ts)))?)?;

    // etw.ops() -> { all, default, groups, aliases }
    etw_tbl.set("ops", lua.create_function(|lua, ()| ops_table(lua))?)?;

    // etw.expand_ops({ "file.*", "registry.query" }) -> canonical list (errors on unknown)
    etw_tbl.set("expand_ops", lua.create_function(expand_ops_lua)?)?;

    lua.globals().set("etw", etw_tbl)?;
    Ok(())
}

/// `expand_ops(list) -> list`: the canonical op tokens for a user-supplied
/// list (errors on an unknown token). Shared by the `etw` and `sbx` tables.
pub(crate) fn expand_ops_lua(lua: &Lua, list: LuaTable) -> mlua::Result<LuaTable> {
    let tokens = list.sequence_values::<String>().collect::<mlua::Result<Vec<_>>>()?;
    let expanded = etw::expand_ops(&tokens).map_err(mlua::Error::external)?;
    let t = lua.create_table()?;
    for op in expanded {
        t.push(op)?;
    }
    Ok(t)
}

/// Default control-file path for an attached tracer: `<out>.control.txt`.
fn default_control(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".control.txt");
    PathBuf::from(s)
}

/// Module-held per-path read cursors, backing the stateless `etw.events` /
/// `sbx.events` helpers so repeated polls of the same file seek incrementally.
fn cursors() -> &'static Mutex<HashMap<PathBuf, EventCursor>> {
    static CURSORS: OnceLock<Mutex<HashMap<PathBuf, EventCursor>>> = OnceLock::new();
    CURSORS.get_or_init(Default::default)
}

/// Stateless incremental read of `path` (events with seq > from_seq) into a Lua
/// list, using the module cursor map. Shared by `etw.events` and `sbx.events`.
pub(crate) fn events_to_table(lua: &Lua, path: &Path, from_seq: u64) -> mlua::Result<LuaTable> {
    let stored = cursors().lock().unwrap().get(path).copied().unwrap_or_default();
    let (rows, new_cur) = etw::read_events(path, from_seq, stored);
    cursors().lock().unwrap().insert(path.to_path_buf(), new_cur);
    rows_to_table(lua, rows)
}

/// Convert (seq, event) rows into a Lua array of event tables, consuming the
/// events so their strings move into Lua rather than being cloned.
fn rows_to_table(lua: &Lua, rows: Vec<(u64, TraceEvent)>) -> mlua::Result<LuaTable> {
    let out = lua.create_table()?;
    for (seq, ev) in rows {
        out.push(event_table(lua, seq, ev)?)?;
    }
    Ok(out)
}

/// One ETW event as a Lua table (paths prettified like the app's viewer, plus a
/// formatted `time` alongside the raw `ts`). Shared with `sbx.events`.
pub(crate) fn event_table(lua: &Lua, seq: u64, ev: TraceEvent) -> mlua::Result<LuaTable> {
    let t = lua.create_table()?;
    t.set("seq", seq)?;
    t.set("time", etw::filetime_to_hms(ev.ts))?;
    t.set("kind", ev.kind)?;
    t.set("op", ev.op)?;
    t.set("pid", ev.pid)?;
    t.set("ts", ev.ts)?;
    t.set("image", ev.image)?;
    t.set("ppid", ev.ppid)?;
    t.set("path", ev.path.as_deref().map(etw::pretty_path))?;
    t.set("size", ev.size)?;
    t.set("dest", ev.dest)?;
    t.set("exit", ev.exit)?;
    t.set("stack", ev.stack)?;
    t.set("frames", ev.frames)?;
    t.set("target_pid", ev.target_pid)?;
    t.set("access", ev.access)?;
    t.set("status", ev.status)?;
    // Tracer control records (`kind == "tracer"`).
    t.set("message", ev.message)?;
    t.set("events_lost", ev.events_lost)?;
    t.set("buffers_lost", ev.buffers_lost)?;
    t.set("events_written", ev.events_written)?;
    Ok(t)
}
