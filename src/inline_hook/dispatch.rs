/// Global hook registry and dispatch callback for Lua hook handlers.
///
/// When a detour stub fires, it calls `hook_dispatch` with a pointer to the
/// saved register context and a hook_id. This module looks up the Lua callback
/// and invokes it, allowing the Lua handler to inspect and modify registers.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use mlua::prelude::*;

use super::hook_context::HookContext;

/// Per-hook entry in the global registry.
struct HookEntry {
    lua_callback: LuaRegistryKey,
    /// Raw pointer to the Lua VM that owns the callback.
    /// Valid for the lifetime of the Lua VM — hooks MUST be removed before
    /// the Lua VM is dropped.
    lua: *const Lua,
}

// SAFETY: LuaRegistryKey with mlua's `send` feature is Send.
// The raw Lua pointer is only accessed while holding the registry Mutex.
unsafe impl Send for HookEntry {}

static HOOK_REGISTRY: LazyLock<Mutex<HashMap<u64, HookEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static NEXT_HOOK_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new unique hook ID.
pub fn alloc_hook_id() -> u64 {
    NEXT_HOOK_ID.fetch_add(1, Ordering::Relaxed)
}

/// Register a Lua callback for the given hook_id.
pub fn register_hook(hook_id: u64, lua: &Lua, callback: LuaFunction) -> LuaResult<()> {
    let key = lua.create_registry_value(callback)?;
    let mut registry = HOOK_REGISTRY.lock().unwrap();
    registry.insert(hook_id, HookEntry {
        lua_callback: key,
        lua: lua as *const Lua,
    });
    Ok(())
}

/// Unregister a hook, removing its Lua callback from the registry.
pub fn unregister_hook(hook_id: u64) {
    let mut registry = HOOK_REGISTRY.lock().unwrap();
    registry.remove(&hook_id);
}

/// The extern "C" dispatch function called from detour stub shellcode.
///
/// # Safety
/// - `context` must point to a valid `HookContext` on the stack (written by the detour stub).
/// - `hook_id` must be a valid registered hook ID.
/// - The Lua VM pointer stored during `register_hook` must still be valid.
pub extern "C" fn hook_dispatch(context: *mut HookContext, hook_id: u64) {
    let registry = HOOK_REGISTRY.lock().unwrap();
    let Some(entry) = registry.get(&hook_id) else {
        return;
    };

    // SAFETY: The Lua pointer was set during register_hook and the caller
    // guarantees the Lua VM is still alive (hooks are removed before Lua drops).
    let lua: &Lua = unsafe { &*entry.lua };

    let Ok(func) = lua.registry_value::<LuaFunction>(&entry.lua_callback) else {
        return;
    };

    let ctx = unsafe { &mut *context };

    // Build a Lua table with all registers
    let Ok(ctx_table) = context_to_lua_table(lua, ctx) else {
        return;
    };

    // Drop the registry lock before calling Lua (handler might re-enter)
    drop(registry);

    // Call the Lua handler — ignore errors (don't crash the hooked process)
    let _ = func.call::<()>(ctx_table.clone());

    // Write back any register modifications
    let _ = write_back_context(lua, &ctx_table, ctx);
}

/// Convert a HookContext to a Lua table with named register fields.
#[cfg(target_arch = "x86_64")]
fn context_to_lua_table(lua: &Lua, ctx: &HookContext) -> LuaResult<LuaTable> {
    let t = lua.create_table()?;
    t.set("rax", ctx.rax)?;
    t.set("rcx", ctx.rcx)?;
    t.set("rdx", ctx.rdx)?;
    t.set("rbx", ctx.rbx)?;
    t.set("rbp", ctx.rbp)?;
    t.set("rsi", ctx.rsi)?;
    t.set("rdi", ctx.rdi)?;
    t.set("r8", ctx.r8)?;
    t.set("r9", ctx.r9)?;
    t.set("r10", ctx.r10)?;
    t.set("r11", ctx.r11)?;
    t.set("r12", ctx.r12)?;
    t.set("r13", ctx.r13)?;
    t.set("r14", ctx.r14)?;
    t.set("r15", ctx.r15)?;
    t.set("rflags", ctx.rflags)?;
    Ok(t)
}

/// Write back register values from a Lua table into the HookContext struct.
/// Only writes fields that are present in the table (allows partial updates).
#[cfg(target_arch = "x86_64")]
fn write_back_context(_lua: &Lua, table: &LuaTable, ctx: &mut HookContext) -> LuaResult<()> {
    if let Ok(v) = table.get::<u64>("rax") { ctx.rax = v; }
    if let Ok(v) = table.get::<u64>("rcx") { ctx.rcx = v; }
    if let Ok(v) = table.get::<u64>("rdx") { ctx.rdx = v; }
    if let Ok(v) = table.get::<u64>("rbx") { ctx.rbx = v; }
    if let Ok(v) = table.get::<u64>("rbp") { ctx.rbp = v; }
    if let Ok(v) = table.get::<u64>("rsi") { ctx.rsi = v; }
    if let Ok(v) = table.get::<u64>("rdi") { ctx.rdi = v; }
    if let Ok(v) = table.get::<u64>("r8") { ctx.r8 = v; }
    if let Ok(v) = table.get::<u64>("r9") { ctx.r9 = v; }
    if let Ok(v) = table.get::<u64>("r10") { ctx.r10 = v; }
    if let Ok(v) = table.get::<u64>("r11") { ctx.r11 = v; }
    if let Ok(v) = table.get::<u64>("r12") { ctx.r12 = v; }
    if let Ok(v) = table.get::<u64>("r13") { ctx.r13 = v; }
    if let Ok(v) = table.get::<u64>("r14") { ctx.r14 = v; }
    if let Ok(v) = table.get::<u64>("r15") { ctx.r15 = v; }
    if let Ok(v) = table.get::<u64>("rflags") { ctx.rflags = v; }
    Ok(())
}

/// Convert an AArch64 HookContext to a Lua table with `x0`..`x30` fields.
#[cfg(target_arch = "aarch64")]
fn context_to_lua_table(lua: &Lua, ctx: &HookContext) -> LuaResult<LuaTable> {
    let t = lua.create_table()?;
    for (i, v) in ctx.x.iter().enumerate() {
        t.set(format!("x{i}"), *v)?;
    }
    Ok(t)
}

/// Write back `x0`..`x30` from a Lua table into the AArch64 HookContext.
#[cfg(target_arch = "aarch64")]
fn write_back_context(_lua: &Lua, table: &LuaTable, ctx: &mut HookContext) -> LuaResult<()> {
    for i in 0..31usize {
        if let Ok(v) = table.get::<u64>(format!("x{i}")) {
            ctx.x[i] = v;
        }
    }
    Ok(())
}
