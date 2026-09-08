//! In-process Windows Sandbox bindings, exposed as a global `sbx` table.
//!
//! Unlike `dbg` (which talks to a debug server over TCP), these are host-side
//! orchestration calls that boot/stop a sandbox VM in-process. A typical script
//! provisions a sandbox, connects a `dbg` client to the in-guest server it
//! returns, debugs, then stops the VM:
//!
//! ```lua
//! local h, info = sbx.provision{ guest_bin_dir = "...", io_dir = "...",
//!                                debug = true, launch_command = "C:/mounts/app/t.exe" }
//! local dbg = sbx.connect(info.server_url)
//! dbg:set_breakpoint(...) ; dbg:run()
//! h:stop()   -- explicit; dropping the handle also stops it (GC backstop)
//! ```
//!
//! Recovery and introspection: `sbx.list()`, `sbx.stop(id)`, `sbx.stop_all()`,
//! `sbx.attach(id)` (adopt a VM a crashed script left behind) and `sbx.ops()`
//! (the ETW op vocabulary). Guest desktop access lives on the handle:
//! `h:exec`, `h:screenshot`, `h:list_windows`, `h:window_text`.
//!
//! Windows-only.

use std::cell::RefCell;
use std::path::PathBuf;

use mlua::prelude::*;

use super::opt;

use crate::sandbox::{
    self, default_symbols_dir, MountSpec, ProvisionConfig, SandboxHandle, DEFAULT_ETW_OUT_FILE,
    DEFAULT_MEMORY_MB, DEFAULT_SERVER_PORT,
};
use crate::scripting::bindings::LuaDebugClient;
use crate::scripting::debug_client::DebugClient;

/// Default guest server port when the caller doesn't specify one. The guest IP
/// disambiguates it host-side, so a fixed default is fine.

/// A live sandbox VM exposed to Lua. Holds the core [`SandboxHandle`] whose inner
/// RAII guard runs `wsb stop` on drop (for a provisioned VM; an `attach`ed one
/// is left running). `stop()` takes the handle out and drops it explicitly; if
/// the script never calls `stop()`, Lua GC drops this userdata and the same
/// teardown runs as a backstop. `take()` makes the two paths idempotent (never
/// a double `wsb stop`).
///
/// This is the first UserData-with-`Drop` in the crate: the resource lifetime is
/// tied to Lua's garbage collector, so a script that loses its reference will
/// have the VM torn down at the next GC — call `stop()` for deterministic timing.
pub struct SbxHandle(RefCell<Option<SandboxHandle>>);

impl SbxHandle {
    fn new(handle: SandboxHandle) -> Self {
        SbxHandle(RefCell::new(Some(handle)))
    }

    /// Run `f` against the live handle, or error once stopped.
    fn with<R>(&self, f: impl FnOnce(&SandboxHandle) -> mlua::Result<R>) -> mlua::Result<R> {
        let guard = self.0.borrow();
        let h = guard.as_ref().ok_or_else(|| mlua::Error::external("sbx handle already stopped"))?;
        f(h)
    }
}

/// `run_as` option: `"user"` (the interactive session — default) or `"system"`.
fn run_as_from(opts: Option<&LuaTable>) -> mlua::Result<sandbox::RunAs> {
    let s: Option<String> = opt(opts, "run_as")?;
    match s.as_deref().unwrap_or("user") {
        "user" | "login" | "interactive" => Ok(sandbox::RunAs::ExistingLogin),
        "system" => Ok(sandbox::RunAs::System),
        other => Err(mlua::Error::external(format!(
            "run_as must be \"user\" or \"system\", got {other:?}"
        ))),
    }
}

impl LuaUserData for SbxHandle {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // Stop the VM now (`wsb stop`). Idempotent — a second call, or the GC
        // drop, is a no-op once the handle has been taken. Works for attached
        // handles too (explicit stop is the one way they end a VM).
        methods.add_method("stop", |_lua, this, ()| {
            if let Some(mut handle) = this.0.borrow_mut().take() {
                // Explicit stop surfaces the wsb error (the bare Drop swallows it).
                handle.sandbox.stop().map_err(mlua::Error::external)?;
            }
            Ok(())
        });

        methods.add_method("server_url", |_lua, this, ()| {
            Ok(this.0.borrow().as_ref().map(|h| h.server_url.clone()))
        });

        methods.add_method("id", |_lua, this, ()| {
            Ok(this.0.borrow().as_ref().map(|h| h.id().to_string()))
        });

        methods.add_method("info", |lua, this, ()| {
            let guard = this.0.borrow();
            match guard.as_ref() {
                Some(h) => Ok(LuaValue::Table(handle_info_table(lua, h)?)),
                None => Ok(LuaValue::Nil), // already stopped
            }
        });

        // Run-only ("just launch") mode: launch the target under the in-guest ETW
        // tracer and BLOCK until it exits (the tracer is the launcher, so its exit
        // means the target tree is done and the JSONL is fully written). Read the
        // results with `sbx.events(info.io_dir, info.etw_out_file)`. Errors unless
        // this handle came from a `debug = false` provision, and errors — with the
        // tracer's own message — if the collector never started. No UAC — kernel
        // ETW runs as the sandbox's built-in admin (`ExistingLogin`), the whole
        // point of collecting ETW in the sandbox rather than on the host. Returns
        // the exec's exit code.
        methods.add_method("run_traced", |_lua, this, ()| {
            this.with(|h| sandbox::run_traced(h).map_err(mlua::Error::external))
        });

        // h:exec(cmd[, { run_as = "user"|"system" }]) -> code, output
        methods.add_method("exec", |_lua, this, (cmd, opts): (String, Option<LuaTable>)| {
            let run_as = run_as_from(opts.as_ref())?;
            this.with(|h| sandbox::exec_capture(h, &cmd, run_as).map_err(mlua::Error::external))
        });

        // h:screenshot([host_path]) -> host_path of the PNG
        methods.add_method("screenshot", |_lua, this, path: Option<String>| {
            let dest = path.filter(|s| !s.is_empty()).map(PathBuf::from);
            this.with(|h| {
                sandbox::guest_ui::screenshot(h, dest.as_deref())
                    .map(|p| p.to_string_lossy().into_owned())
                    .map_err(mlua::Error::external)
            })
        });

        // h:list_windows() -> { { hwnd, parent, pid, tid, class, title, visible, rect = {l,t,r,b} }, ... }
        methods.add_method("list_windows", |lua, this, ()| {
            let wins = this.with(|h| sandbox::guest_ui::list_windows(h).map_err(mlua::Error::external))?;
            let out = lua.create_table()?;
            for w in wins {
                let t = lua.create_table()?;
                t.set("hwnd", w.hwnd)?;
                t.set("parent", w.parent)?;
                t.set("pid", w.pid)?;
                t.set("tid", w.tid)?;
                t.set("class", w.class)?;
                t.set("title", w.title)?;
                t.set("visible", w.visible)?;
                let rect = lua.create_table()?;
                rect.set("left", w.left)?;
                rect.set("top", w.top)?;
                rect.set("right", w.right)?;
                rect.set("bottom", w.bottom)?;
                t.set("rect", rect)?;
                out.push(t)?;
            }
            Ok(out)
        });

        // h:window_text(hwnd) -> string (WM_GETTEXT: works on edit controls too)
        methods.add_method("window_text", |_lua, this, hwnd: u64| {
            this.with(|h| sandbox::guest_ui::window_text(h, hwnd).map_err(mlua::Error::external))
        });
    }
}

/// Wrap a core [`SandboxHandle`] into the Lua `(handle, info)` pair that
/// `sbx.provision`/`sbx.attach` return — reused by `jlua --sandbox` so its `h`
/// global behaves identically. The userdata owns the handle (GC stops the VM
/// unless it was `attach`ed).
pub fn wrap_handle(lua: &Lua, handle: SandboxHandle) -> mlua::Result<(LuaAnyUserData, LuaTable)> {
    let info = handle_info_table(lua, &handle)?;
    let ud = lua.create_userdata(SbxHandle::new(handle))?;
    Ok((ud, info))
}

/// The `info` table describing a provisioned sandbox.
fn handle_info_table(lua: &Lua, h: &SandboxHandle) -> mlua::Result<LuaTable> {
    let t = lua.create_table()?;
    t.set("id", h.id().to_string())?;
    t.set("server_url", h.server_url.clone())?;
    t.set("guest_launch_command", h.guest_launch_command.clone())?;
    t.set("guest_working_directory", h.guest_working_directory.clone())?;
    t.set("io_dir", h.io_dir.to_string_lossy().into_owned())?;
    t.set("staged_bin_dir", h.staged_bin_dir.to_string_lossy().into_owned())?;
    t.set("etw_out_file", h.etw_out_file.clone())?;
    t.set("etw_enabled", h.etw_enabled)?;
    t.set("debug", h.debug)?;
    t.set("owned", h.owns_vm())?;
    Ok(t)
}

/// Read a required string field from the `provision` options table.
fn req_str(opts: &LuaTable, key: &str) -> mlua::Result<String> {
    opts.get::<Option<String>>(key)?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| mlua::Error::external(format!("sbx.provision: missing required `{key}`")))
}

/// Build a [`ProvisionConfig`] from the Lua options table.
fn provision_config_from(opts: &LuaTable) -> mlua::Result<ProvisionConfig> {
    let guest_bin_dir = PathBuf::from(req_str(opts, "guest_bin_dir")?);
    // One exe provides both the debug server and the ETW collector; the default
    // matches what the Joybug app stages. A script pointing at its own build
    // (joybug-core.exe, jlua.exe) overrides it. `provision` verifies the file
    // carries this build's guest marker before booting anything.
    let guest_exe = opts
        .get::<Option<String>>("guest_exe")?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "joybug.exe".to_string());
    let io_dir = PathBuf::from(req_str(opts, "io_dir")?);
    // symbols_dir defaults to a `symbols` sibling of io_dir when omitted.
    let symbols_dir = match opts.get::<Option<String>>("symbols_dir")? {
        Some(s) if !s.is_empty() => PathBuf::from(s),
        _ => default_symbols_dir(&io_dir),
    };

    let mounts = match opts.get::<Option<LuaTable>>("mounts")? {
        Some(list) => list
            .sequence_values::<LuaTable>()
            .map(|m| {
                let m = m?;
                Ok(MountSpec {
                    host_path: m.get::<String>("host_path")?,
                    read_only: m.get::<Option<bool>>("read_only")?.unwrap_or(true),
                })
            })
            .collect::<mlua::Result<Vec<_>>>()?,
        None => Vec::new(),
    };

    // `etw = { ops = {...}, callstacks = bool, buffer_kb = n, buffers = n }`;
    // unknown op tokens are refused here, before any VM boots.
    let etw = match opts.get::<Option<LuaTable>>("etw")? {
        Some(e) => crate::scripting::etw::capture_from(&e)?,
        None => Default::default(),
    };

    let debug = opts.get::<Option<bool>>("debug")?.unwrap_or(true);
    // Run-only needs a launch command (the tracer launches it); a debug session
    // may leave it out and drive `dbg:launch` itself.
    let launch_command = match opts.get::<Option<String>>("launch_command")? {
        Some(s) if !s.is_empty() => s,
        _ if debug => String::new(),
        _ => return Err(mlua::Error::external(
            "sbx.provision: missing required `launch_command` (run-only mode launches it under the tracer)",
        )),
    };
    Ok(ProvisionConfig {
        guest_bin_dir,
        guest_exe,
        io_dir,
        symbols_dir,
        etw_out_file: opts
            .get::<Option<String>>("etw_out_file")?
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_ETW_OUT_FILE.to_string()),
        server_port: opts.get::<Option<u16>>("server_port")?.unwrap_or(DEFAULT_SERVER_PORT),
        mounts,
        memory_mb: opts.get::<Option<u32>>("memory_mb")?.unwrap_or(DEFAULT_MEMORY_MB),
        debug,
        // Run-only always traces; debug mode honors the flag (default on).
        collect_etw: opts.get::<Option<bool>>("collect_etw")?.unwrap_or(true),
        etw,
        symbol_offline: opts.get::<Option<bool>>("symbol_offline")?.unwrap_or(false),
        launch_command,
        working_directory: opts
            .get::<Option<String>>("working_directory")?
            .filter(|s| !s.is_empty()),
    })
}

/// Register the `sbx` global table.
pub fn register_sbx_functions(lua: &Lua) -> mlua::Result<()> {
    let sbx = lua.create_table()?;

    // sbx.provision(opts) -> (handle, info)
    sbx.set(
        "provision",
        lua.create_function(|lua, opts: LuaTable| {
            let cfg = provision_config_from(&opts)?;
            // Blocks while the VM boots (tens of seconds). Errors — including the
            // one-sandbox-per-user conflict — are catchable via pcall.
            let handle = sandbox::provision(&cfg).map_err(mlua::Error::external)?;
            wrap_handle(lua, handle)
        })?,
    )?;

    // sbx.status() -> { supported, build, wsb_present, reason }
    sbx.set(
        "status",
        lua.create_function(|lua, ()| {
            let s = sandbox::status();
            let t = lua.create_table()?;
            t.set("supported", s.supported)?;
            t.set("build", s.build)?;
            t.set("wsb_present", s.wsb_present)?;
            t.set("reason", s.reason)?;
            Ok(t)
        })?,
    )?;

    // sbx.connect(url) -> dbg  (a debug client bound to the in-guest server;
    // fails with a protocol-mismatch message for a guest of another revision)
    sbx.set(
        "connect",
        lua.create_function(|lua, url: String| {
            let client = DebugClient::connect(&url).map_err(mlua::Error::external)?;
            lua.create_userdata(LuaDebugClient::new(client))
        })?,
    )?;

    // sbx.events(io_dir, out_file[, from_seq]) -> list of event tables. Delegates
    // to the shared incremental reader in `scripting::etw` (cursor-based, so a
    // repeated poll of the same file seeks instead of rescanning); events now
    // also carry a formatted `time` field.
    sbx.set(
        "events",
        lua.create_function(|lua, (io_dir, out_file, from_seq): (String, String, Option<u64>)| {
            let path = PathBuf::from(io_dir).join(out_file);
            crate::scripting::etw::events_to_table(lua, &path, from_seq.unwrap_or(0))
        })?,
    )?;

    // sbx.list() -> { id, ... }  (every running sandbox of this user)
    sbx.set(
        "list",
        lua.create_function(|lua, ()| {
            let ids = sandbox::list().map_err(mlua::Error::external)?;
            let t = lua.create_table()?;
            for id in ids {
                t.push(id)?;
            }
            Ok(t)
        })?,
    )?;

    // sbx.stop(id)
    sbx.set(
        "stop",
        lua.create_function(|_lua, id: String| sandbox::stop(&id).map_err(mlua::Error::external))?,
    )?;

    // sbx.stop_all() -> count
    sbx.set(
        "stop_all",
        lua.create_function(|_lua, ()| sandbox::stop_all().map_err(mlua::Error::external))?,
    )?;

    // sbx.attach(id[, { server_port = 9000, io_dir = ..., guest_exe = ... }]) -> (handle, info)
    // Adopts a running VM without owning it: dropping the handle leaves it up,
    // `h:stop()` stops it. `info.server_url` is set when a joybug server of this
    // build answers on the port. `io_dir` enables h:exec; `guest_exe` (the
    // staged file name) enables the desktop probes.
    sbx.set(
        "attach",
        lua.create_function(|lua, (id, opts): (String, Option<LuaTable>)| {
            let port = opt::<u16>(opts.as_ref(), "server_port")?.unwrap_or(DEFAULT_SERVER_PORT);
            let io_dir = opt::<String>(opts.as_ref(), "io_dir")?.filter(|s| !s.is_empty()).map(PathBuf::from);
            let guest_exe = opt::<String>(opts.as_ref(), "guest_exe")?.filter(|s| !s.is_empty());
            let handle = sandbox::attach(&id, port, io_dir, guest_exe).map_err(mlua::Error::external)?;
            wrap_handle(lua, handle)
        })?,
    )?;

    // sbx.ops() -> { all, default, groups, aliases }; sbx.expand_ops(list) -> list
    sbx.set("ops", lua.create_function(|lua, ()| crate::scripting::etw::ops_table(lua))?)?;
    sbx.set(
        "expand_ops",
        lua.create_function(crate::scripting::etw::expand_ops_lua)?,
    )?;

    lua.globals().set("sbx", sbx)?;
    Ok(())
}
