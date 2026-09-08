//! Lua scripting engine for joybug-core debugger.
//!
//! Provides an embedded Lua 5.4 scripting interface over the debugger's TCP protocol,
//! with an interactive REPL and script file execution.

pub mod colors;
pub mod debug_client;
pub mod bindings;
pub mod repl;
/// Host ETW tracing bindings (`etw` global). Behind the `etw` feature so the
/// default build never pulls the winsandbox/`windows` deps.
pub mod etw;
/// In-process Windows Sandbox bindings (`sbx` global). Behind the `sandbox`
/// feature so the default build never pulls the winsandbox/`windows` deps.
pub mod sbx;

use mlua::{FromLua, Lua, Table as LuaTable};

/// Read `key` from an optional Lua options table (`nil` and a missing table
/// both give `None`), so bindings can `opt(opts, "x")?.unwrap_or(default)`.
pub(crate) fn opt<T: FromLua>(opts: Option<&LuaTable>, key: &str) -> mlua::Result<Option<T>> {
    match opts {
        Some(t) => t.get::<Option<T>>(key),
        None => Ok(None),
    }
}

/// Embedded Lua helper library (hex formatting, register printing, etc.)
const LUA_HELPERS: &str = include_str!("lua_helpers.lua");

/// Create a new Lua state with the debugger API registered.
///
/// The returned Lua state has the helper library loaded and is ready
/// to create a `dbg` session object via `debug_client::create_debug_client()`.
pub fn create_lua() -> mlua::Result<Lua> {
    let lua = Lua::new();

    // Default: no color (overridden by jlua binary based on --no-color flag)
    lua.globals().set("_jlua_color", false)?;

    // Load helper library
    lua.load(LUA_HELPERS).set_name("lua_helpers").exec()?;

    // Register memory formatting globals
    bindings::register_memory_formatters(&lua)?;

    // Register in-process memory access (mem.read, mem.write, etc.)
    bindings::register_mem_functions(&lua)?;

    // Register the host ETW table (etw.start, etw.spawn, etw.events, etc.).
    etw::register_etw_functions(&lua)?;

    // Register the in-process Windows Sandbox table (sbx.provision, etc.).
    sbx::register_sbx_functions(&lua)?;

    Ok(lua)
}
