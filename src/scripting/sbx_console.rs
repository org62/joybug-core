//! Interactive guest console userdata, retaining its Lua sandbox owner safely.

use std::path::PathBuf;

use mlua::prelude::*;

use super::{opt, sbx::SbxHandle};
use crate::console_protocol::{ConsoleConfig, ConsoleSnapshot, ConsoleStart};
use crate::sandbox::{console::ConsoleSession, guest_ui, SandboxHandle};

const DEFAULT_TIMEOUT_MS: u32 = 5000;

/// Field order closes the broker before releasing the last VM reference on GC.
struct LuaConsole {
    session: ConsoleSession,
    parent: Option<LuaAnyUserData>,
}

impl LuaConsole {
    fn with<R>(
        &mut self,
        f: impl FnOnce(&SandboxHandle, &mut ConsoleSession) -> mlua::Result<R>,
    ) -> mlua::Result<R> {
        let parent = self.parent.as_ref()
            .ok_or_else(|| mlua::Error::external("console session already closed"))?
            .borrow::<SbxHandle>()?;
        // An explicit h:stop takes its underlying handle. Do not enter a mailbox
        // wait against a VM we already know is stopped.
        parent.with(|h| f(h, &mut self.session))
    }

    fn close(&mut self) -> mlua::Result<()> {
        if self.session.is_closed() {
            self.parent.take();
            return Ok(());
        }
        let result = match self.parent.as_ref() {
            Some(parent) => {
                let handle = parent.borrow::<SbxHandle>()?;
                if handle.with(|_| Ok(())).is_ok() {
                    self.session.close().map_err(mlua::Error::external)
                } else {
                    // Close remains safe and idempotent after explicit VM stop.
                    self.session.close_without_wait();
                    Ok(())
                }
            }
            None => Ok(()),
        };
        self.session.close_without_wait();
        self.parent.take();
        result
    }
}

impl LuaUserData for LuaConsole {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("read", |lua, this, ()| {
            let snapshot = this.with(|_, session| session.read().map_err(mlua::Error::external))?;
            snapshot_table(lua, snapshot)
        });
        methods.add_method_mut("write", |_lua, this, text: String| {
            this.with(|_, session| session.write(text).map_err(mlua::Error::external))
        });
        methods.add_method_mut("send_line", |_lua, this, text: String| {
            this.with(|_, session| session.send_line(text).map_err(mlua::Error::external))
        });
        methods.add_method_mut("set_ansi", |_lua, this, enabled: bool| {
            this.with(|_, session| session.set_ansi(enabled).map_err(mlua::Error::external))
        });
        methods.add_method_mut("wait_text", |lua, this, (text, timeout): (String, Option<u32>)| {
            let snapshot = this.with(|_, session| {
                session.wait_text(text, timeout.unwrap_or(DEFAULT_TIMEOUT_MS))
                    .map_err(mlua::Error::external)
            })?;
            snapshot_table(lua, snapshot)
        });
        methods.add_method_mut("wait_exit", |lua, this, timeout: Option<u32>| {
            let snapshot = this.with(|_, session| {
                session.wait_exit(timeout.unwrap_or(DEFAULT_TIMEOUT_MS))
                    .map_err(mlua::Error::external)
            })?;
            snapshot_table(lua, snapshot)
        });
        methods.add_method_mut("screenshot", |_lua, this, path: Option<String>| {
            let destination = path.filter(|s| !s.is_empty()).map(PathBuf::from);
            this.with(|h, session| {
                // Resolve the actual console HWND afresh, never from a process's
                // arbitrary top-level window or a stale cached snapshot.
                let snapshot = session.read().map_err(mlua::Error::external)?;
                guest_ui::screenshot_window(h, snapshot.hwnd, destination.as_deref())
                    .map(|p| p.to_string_lossy().into_owned())
                    .map_err(mlua::Error::external)
            })
        });
        methods.add_method_mut("close", |_lua, this, ()| this.close());
    }
}

/// Functions receive the original userdata (rather than just &SbxHandle), so
/// every console can retain a strong Lua reference to its owning VM handle.
pub(super) fn add_handle_methods<M: LuaUserDataMethods<SbxHandle>>(methods: &mut M) {
    methods.add_function("console", |lua, (parent, command, options): (LuaAnyUserData, String, Option<LuaTable>)| {
        let mut environment = Vec::new();
        if let Some(table) = opt::<LuaTable>(options.as_ref(), "environment")? {
            for entry in table.pairs::<String, String>() {
                environment.push(entry?);
            }
        }
        let config = ConsoleConfig {
            start: ConsoleStart::Launch {
                command,
                cwd: opt(options.as_ref(), "cwd")?,
                environment,
            },
            ansi: opt(options.as_ref(), "ansi")?,
        };
        create_console(lua, parent, config)
    });
    methods.add_function("attach_console", |lua, (parent, pid, options): (LuaAnyUserData, u32, Option<LuaTable>)| {
        let config = ConsoleConfig {
            start: ConsoleStart::Attach { pid },
            ansi: opt(options.as_ref(), "ansi")?,
        };
        create_console(lua, parent, config)
    });
}

fn create_console(lua: &Lua, parent: LuaAnyUserData, config: ConsoleConfig) -> mlua::Result<LuaAnyUserData> {
    let session = parent.borrow::<SbxHandle>()?.with(|h| {
        ConsoleSession::start(h, config).map_err(mlua::Error::external)
    })?;
    lua.create_userdata(LuaConsole { session, parent: Some(parent) })
}

fn snapshot_table(lua: &Lua, snapshot: ConsoleSnapshot) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("pid", snapshot.pid)?;
    table.set("hwnd", snapshot.hwnd)?;
    table.set("text", snapshot.text)?;
    table.set("running", snapshot.running)?;
    table.set("exit_code", snapshot.exit_code)?;
    table.set("input_mode", snapshot.input_mode)?;
    table.set("output_mode", snapshot.output_mode)?;
    table.set("columns", snapshot.columns)?;
    table.set("rows", snapshot.rows)?;
    table.set("cursor_x", snapshot.cursor_x)?;
    table.set("cursor_y", snapshot.cursor_y)?;
    Ok(table)
}
