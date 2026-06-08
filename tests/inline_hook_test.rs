#![cfg(windows)]

use joybug2::inline_hook::allocator::{CodeAllocator, WindowsCodeAllocator};
use joybug2::inline_hook::thread::NoopThreadFreezer;
use joybug2::inline_hook::{HookEngine, LuaHookEngine};
use std::sync::atomic::{AtomicPtr, Ordering};

// Target function to hook.
#[unsafe(no_mangle)]
extern "C" fn test_add(a: i32, b: i32) -> i32 {
    a + b
}

// Store the trampoline (original function) pointer.
static ORIGINAL_ADD: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

// Detour function — calls original and multiplies result.
#[unsafe(no_mangle)]
extern "C" fn hooked_add(a: i32, b: i32) -> i32 {
    let orig: extern "C" fn(i32, i32) -> i32 =
        unsafe { std::mem::transmute(ORIGINAL_ADD.load(Ordering::SeqCst)) };
    orig(a, b) * 10
}

#[test]
fn test_basic_hook_and_unhook() {
    let allocator = WindowsCodeAllocator::new();
    let freezer = NoopThreadFreezer;
    let mut engine = HookEngine::new(allocator, freezer);

    // Before hooking.
    assert_eq!(test_add(2, 3), 5);

    // Create hook.
    let (handle, trampoline) = engine
        .create(test_add as *const u8, hooked_add as *const u8)
        .expect("create hook");

    ORIGINAL_ADD.store(trampoline as *mut u8, Ordering::SeqCst);

    // Still not enabled.
    assert_eq!(test_add(2, 3), 5);

    // Enable.
    engine.enable(&handle).expect("enable hook");
    assert_eq!(test_add(2, 3), 50); // (2+3) * 10

    // Disable.
    engine.disable(&handle).expect("disable hook");
    assert_eq!(test_add(2, 3), 5);

    // Re-enable.
    engine.enable(&handle).expect("re-enable hook");
    assert_eq!(test_add(2, 3), 50);

    // Remove.
    engine.remove(handle).expect("remove hook");
    assert_eq!(test_add(2, 3), 5);
}

#[test]
fn test_allocator_near_allocation() {
    let mut allocator = WindowsCodeAllocator::new();
    let target = test_add as *const u8 as usize;

    let slot = allocator
        .alloc_near(target, 64)
        .expect("alloc near");

    let slot_addr = slot as usize;
    let distance = if slot_addr > target {
        slot_addr - target
    } else {
        target - slot_addr
    };

    // Must be within 2GB.
    assert!(distance < 0x7FFF_0000, "slot too far: distance = 0x{distance:X}");

    allocator.free(slot);
}

// Serialize Lua hook tests — the Lua VM and hook engine have shared global state
// (HOOK_REGISTRY) and the detour stubs call into Lua from the calling thread,
// so these tests cannot safely run in parallel.
use std::sync::Mutex;
static LUA_HOOK_LOCK: Mutex<()> = Mutex::new(());

// Separate targets for each Lua hook test.
#[unsafe(no_mangle)]
extern "C" fn test_multiply(a: i32, b: i32) -> i32 {
    a * b
}

#[unsafe(no_mangle)]
extern "C" fn test_sub(a: i32, b: i32) -> i32 {
    a - b
}

#[test]
fn test_lua_hook_basic() {
    let _guard = LUA_HOOK_LOCK.lock().unwrap();
    let lua = joybug2::scripting::create_lua().expect("create lua");

    let mut engine = LuaHookEngine::new();

    // Before hook.
    assert_eq!(std::hint::black_box(test_multiply)(3, 4), 12);

    // Hook with a Lua callback that doubles the first argument.
    let callback = lua
        .load(r#"
            function(ctx)
                ctx.rcx = ctx.rcx * 2
            end
        "#)
        .eval::<mlua::Function>()
        .expect("parse lua callback");

    let (hook_id, _trampoline) = engine
        .hook(test_multiply as *const u8, &lua, callback)
        .expect("hook");

    assert!(hook_id > 0);

    // Now test_multiply(3, 4) should act like test_multiply(6, 4) = 24
    // because the Lua callback doubles RCX (first arg in Windows x64 fastcall).
    assert_eq!(std::hint::black_box(test_multiply)(3, 4), 24);

    // Unhook.
    engine
        .unhook(test_multiply as *const u8 as u64)
        .expect("unhook");

    // Original behavior restored.
    assert_eq!(std::hint::black_box(test_multiply)(3, 4), 12);
}

#[test]
fn test_lua_hook_read_only() {
    let _guard = LUA_HOOK_LOCK.lock().unwrap();
    let lua = joybug2::scripting::create_lua().expect("create lua");
    let mut engine = LuaHookEngine::new();

    // Register a global for the Lua callback to write into.
    lua.globals().set("captured", 0u64).unwrap();

    let callback = lua
        .load(r#"
            function(ctx)
                captured = ctx.rcx
            end
        "#)
        .eval::<mlua::Function>()
        .expect("parse callback");

    let (_hook_id, _trampoline) = engine
        .hook(test_sub as *const u8, &lua, callback)
        .expect("hook");

    // Call the function — the hook should capture RCX (first arg = 100).
    let result = std::hint::black_box(test_sub)(100, 30);
    assert_eq!(result, 70); // original behavior unchanged

    let captured: u64 = lua.globals().get("captured").unwrap();
    assert_eq!(captured, 100);

    engine.unhook(test_sub as *const u8 as u64).expect("unhook");
}

#[test]
fn test_lua_hook_memory_access() {
    let _guard = LUA_HOOK_LOCK.lock().unwrap();
    let lua = joybug2::scripting::create_lua().expect("create lua");
    let mut engine = LuaHookEngine::new();

    lua.globals().set("read_val", 0u64).unwrap();

    // Store a known value at a global address, pass that address to the Lua callback.
    static TEST_VALUE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    TEST_VALUE.store(0xDEAD, Ordering::SeqCst);
    let val_addr = &TEST_VALUE as *const _ as u64;
    lua.globals().set("test_addr", val_addr).unwrap();

    // The callback reads a u32 from a known global address.
    let callback = lua
        .load(r#"
            function(ctx)
                read_val = mem.read_u32(test_addr)
            end
        "#)
        .eval::<mlua::Function>()
        .expect("parse callback");

    let (_hook_id, _trampoline) = engine
        .hook(test_sub as *const u8, &lua, callback)
        .expect("hook");

    // Call the hooked function — the callback reads from the global address.
    let result = std::hint::black_box(test_sub)(100, 30);
    assert_eq!(result, 70);

    let read_val: u64 = lua.globals().get("read_val").unwrap();
    assert_eq!(read_val, 0xDEAD);

    engine.unhook(test_sub as *const u8 as u64).expect("unhook");
}
