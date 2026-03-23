//! Lua scripting engine for joybug2 debugger.
//!
//! Provides an embedded Lua 5.4 scripting interface over the debugger's TCP protocol,
//! with an interactive REPL and script file execution.

pub mod colors;
pub mod debug_client;
pub mod bindings;
pub mod repl;

use mlua::Lua;

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

    Ok(lua)
}
