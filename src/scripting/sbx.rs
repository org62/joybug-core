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
//! Gated behind the `sandbox` feature (Windows-only).

use std::cell::RefCell;
use std::path::PathBuf;

use mlua::prelude::*;

use crate::sandbox::{self, EtwCaptureSpec, MountSpec, ProvisionConfig, SandboxHandle};
use crate::scripting::bindings::LuaDebugClient;
use crate::scripting::debug_client::DebugClient;

/// Default guest server port when the caller doesn't specify one. The guest IP
/// disambiguates it host-side, so a fixed default is fine.
const DEFAULT_SERVER_PORT: u16 = 9000;

/// A live sandbox VM exposed to Lua. Holds the core [`SandboxHandle`] whose inner
/// RAII guard runs `wsb stop` on drop. `stop()` takes the handle out and drops it
/// explicitly; if the script never calls `stop()`, Lua GC drops this userdata and
/// the same teardown runs as a backstop. `take()` makes the two paths idempotent
/// (never a double `wsb stop`).
///
/// This is the first UserData-with-`Drop` in the crate: the resource lifetime is
/// tied to Lua's garbage collector, so a script that loses its reference will
/// have the VM torn down at the next GC — call `stop()` for deterministic timing.
pub struct SbxHandle(RefCell<Option<SandboxHandle>>);

impl SbxHandle {
    fn new(handle: SandboxHandle) -> Self {
        SbxHandle(RefCell::new(Some(handle)))
    }
}

impl LuaUserData for SbxHandle {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // Stop the VM now (`wsb stop`). Idempotent — a second call, or the GC
        // drop, is a no-op once the handle has been taken.
        methods.add_method("stop", |_lua, this, ()| {
            if let Some(handle) = this.0.borrow_mut().take() {
                // Explicit stop surfaces the wsb error (the bare Drop swallows it).
                // `RunningSandbox::stop` consumes the guard by value.
                handle.sandbox.stop().map_err(mlua::Error::external)?;
            }
            Ok(())
        });

        methods.add_method("server_url", |_lua, this, ()| {
            Ok(this.0.borrow().as_ref().map(|h| h.server_url.clone()))
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
        // this handle came from a `debug = false` provision. No UAC — kernel ETW
        // runs as the sandbox's built-in admin (`ExistingLogin`), the whole point
        // of collecting ETW in the sandbox rather than on the host.
        methods.add_method("run_traced", |_lua, this, ()| {
            let (id, cmd) = {
                let guard = this.0.borrow();
                let h = guard
                    .as_ref()
                    .ok_or_else(|| mlua::Error::external("sbx handle already stopped"))?;
                let cmd = h.run_only_launch_cmd.clone().ok_or_else(|| {
                    mlua::Error::external(
                        "run_traced is only valid for a run-only sandbox \
                         (provision with debug = false)",
                    )
                })?;
                (h.sandbox.id().to_string(), cmd)
            };
            sandbox::exec_blocking(&id, &cmd, sandbox::RunAs::ExistingLogin);
            Ok(())
        });
    }
}

/// The `info` table describing a provisioned sandbox.
fn handle_info_table(lua: &Lua, h: &SandboxHandle) -> mlua::Result<LuaTable> {
    let t = lua.create_table()?;
    t.set("server_url", h.server_url.clone())?;
    t.set("guest_launch_command", h.guest_launch_command.clone())?;
    t.set("guest_working_directory", h.guest_working_directory.clone())?;
    t.set("io_dir", h.io_dir.to_string_lossy().into_owned())?;
    t.set("etw_out_file", h.etw_out_file.clone())?;
    t.set("etw_enabled", h.etw_enabled)?;
    t.set("debug", h.debug)?;
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
    // matches what Joybug stages. A script pointing at its own build can override.
    let guest_exe = opts
        .get::<Option<String>>("guest_exe")?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "joybug.exe".to_string());
    let io_dir = PathBuf::from(req_str(opts, "io_dir")?);
    // symbols_dir defaults to a `symbols` sibling of io_dir when omitted.
    let symbols_dir = match opts.get::<Option<String>>("symbols_dir")? {
        Some(s) if !s.is_empty() => PathBuf::from(s),
        _ => io_dir
            .parent()
            .map(|p| p.join("symbols"))
            .unwrap_or_else(|| io_dir.join("symbols")),
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

    let etw = match opts.get::<Option<LuaTable>>("etw")? {
        Some(e) => {
            let ops = match e.get::<Option<LuaTable>>("ops")? {
                Some(list) => list.sequence_values::<String>().collect::<mlua::Result<Vec<_>>>()?,
                None => Vec::new(),
            };
            EtwCaptureSpec { ops, callstacks: e.get::<Option<bool>>("callstacks")?.unwrap_or(false) }
        }
        None => EtwCaptureSpec::default(),
    };

    let debug = opts.get::<Option<bool>>("debug")?.unwrap_or(true);
    Ok(ProvisionConfig {
        guest_bin_dir,
        guest_exe,
        io_dir,
        symbols_dir,
        etw_out_file: opts
            .get::<Option<String>>("etw_out_file")?
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "events.jsonl".to_string()),
        server_port: opts.get::<Option<u16>>("server_port")?.unwrap_or(DEFAULT_SERVER_PORT),
        mounts,
        memory_mb: opts.get::<Option<u32>>("memory_mb")?.unwrap_or(4096),
        debug,
        // Run-only always traces; debug mode honors the flag (default on).
        collect_etw: opts.get::<Option<bool>>("collect_etw")?.unwrap_or(true),
        etw,
        symbol_offline: opts.get::<Option<bool>>("symbol_offline")?.unwrap_or(false),
        launch_command: req_str(opts, "launch_command")?,
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
            let info = handle_info_table(lua, &handle)?;
            let ud = lua.create_userdata(SbxHandle::new(handle))?;
            Ok((ud, info))
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

    // sbx.connect(url) -> dbg  (a debug client bound to the in-guest server)
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

    lua.globals().set("sbx", sbx)?;
    Ok(())
}
