#![cfg(windows)]

use joybug_core::inline_hook::allocator::{CodeAllocator, WindowsCodeAllocator};
use joybug_core::inline_hook::thread::NoopThreadFreezer;
use joybug_core::inline_hook::{HookEngine, LuaHookEngine};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

// Every test in this binary that installs a hook mutates process-global state:
// it patches live `.text` (with a `NoopThreadFreezer`, so nothing suspends the
// other test threads) and the Lua tests also share the global `HOOK_REGISTRY`
// and run their detour callbacks on the calling thread. None of that is safe to
// run in parallel, so all of them take this one lock and run serially. Poison-
// tolerant (`into_inner`) so a genuine failure in one test surfaces as that one
// failure, instead of poisoning the lock and cascading into misleading
// `PoisonError` panics in the others. Matches `scripting_test.rs`'s
// `SANDBOX_LOCK`.
static HOOK_TEST_LOCK: Mutex<()> = Mutex::new(());

type BinOp = extern "C" fn(i32, i32) -> i32;

/// Call `f` through an opaque function pointer.
///
/// These tests only mean anything if the call actually executes the machine code
/// at the target's address — the code the hook patches. In a release build the
/// optimizer will otherwise inline these one-line targets into the caller and
/// constant-fold the result, so every assertion sees the *unhooked* answer no
/// matter what the hook did.
///
/// `black_box(test_add)(2, 3)` does NOT prevent that: a fn item is a zero-sized
/// type, so the barrier has no runtime value to obscure and the callee stays
/// statically known. Passing it as a `BinOp` function pointer first gives
/// `black_box` a real value to launder, which forces an indirect call.
fn call_opaque(f: BinOp, a: i32, b: i32) -> i32 {
    let f = std::hint::black_box(f);
    std::hint::black_box(f(std::hint::black_box(a), std::hint::black_box(b)))
}

/// Pad a hook target's prologue to at least the 5-byte patch-jump size.
///
/// A one-line `extern "C"` target like `a + b` optimizes to a 3-byte
/// `lea eax, [rcx+rdx]; ret` in release — shorter than the engine's 5-byte
/// `E9` patch jump, so hooking it fails with `PrologueTooShort` (the engine
/// correctly refusing to overwrite past a 4-byte function). Emitting a handful
/// of leading `nop`s (real, un-foldable instructions) guarantees >= 5
/// relocatable bytes before any control flow, in every build. Unlike a naked
/// function this keeps a normal, optimizer-visible `extern "C" fn` with proper
/// frame/unwind info — naked targets tripped a release-only miscompile here.
///
/// x86 `nop` and ARM64 `nop` are both 1 instruction; five is comfortably over
/// the 5-byte (x86) / 4-byte (ARM64) minimum.
macro_rules! prologue_pad {
    () => {
        // SAFETY: pure padding — touches no memory, stack or flags.
        unsafe {
            core::arch::asm!("nop", "nop", "nop", "nop", "nop", options(nomem, nostack, preserves_flags));
        }
    };
}

// Target function to hook. `inline(never)` keeps a real, patchable body in
// release; `prologue_pad!` keeps that body long enough to hook. See
// `call_opaque` for why the call sites matter too.
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn test_add(a: i32, b: i32) -> i32 {
    prologue_pad!();
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
    let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let allocator = WindowsCodeAllocator::new();
    let freezer = NoopThreadFreezer;
    let mut engine = HookEngine::new(allocator, freezer);

    // Before hooking.
    assert_eq!(call_opaque(test_add, 2, 3), 5);

    // Create hook.
    let (handle, trampoline) = engine
        .create(test_add as *const u8, hooked_add as *const u8)
        .expect("create hook");

    ORIGINAL_ADD.store(trampoline as *mut u8, Ordering::SeqCst);

    // Still not enabled.
    assert_eq!(call_opaque(test_add, 2, 3), 5);

    // Enable.
    engine.enable(&handle).expect("enable hook");
    assert_eq!(call_opaque(test_add, 2, 3), 50); // (2+3) * 10

    // Disable.
    engine.disable(&handle).expect("disable hook");
    assert_eq!(call_opaque(test_add, 2, 3), 5);

    // Re-enable.
    engine.enable(&handle).expect("re-enable hook");
    assert_eq!(call_opaque(test_add, 2, 3), 50);

    // Remove.
    engine.remove(handle).expect("remove hook");
    assert_eq!(call_opaque(test_add, 2, 3), 5);
}

#[test]
fn test_allocator_near_allocation() {
    let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

// Separate targets for each Lua hook test. Padded like `test_add` above.
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn test_multiply(a: i32, b: i32) -> i32 {
    prologue_pad!();
    a * b
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn test_sub(a: i32, b: i32) -> i32 {
    prologue_pad!();
    a - b
}

#[test]
fn test_lua_hook_basic() {
    let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let lua = joybug_core::scripting::create_lua().expect("create lua");

    let mut engine = LuaHookEngine::new();

    // Before hook.
    assert_eq!(call_opaque(test_multiply, 3, 4), 12);

    // Hook with a Lua callback that doubles the first argument.
    // First integer arg register: RCX on Win64, X0 on AArch64.
    #[cfg(target_arch = "x86_64")]
    let callback_src = r#"function(ctx) ctx.rcx = ctx.rcx * 2 end"#;
    #[cfg(target_arch = "aarch64")]
    let callback_src = r#"function(ctx) ctx.x0 = ctx.x0 * 2 end"#;
    let callback = lua
        .load(callback_src)
        .eval::<mlua::Function>()
        .expect("parse lua callback");

    let (hook_id, _trampoline) = engine
        .hook(test_multiply as *const u8, &lua, callback)
        .expect("hook");

    assert!(hook_id > 0);

    // Now test_multiply(3, 4) should act like test_multiply(6, 4) = 24
    // because the Lua callback doubles RCX (first arg in Windows x64 fastcall).
    assert_eq!(call_opaque(test_multiply, 3, 4), 24);

    // Unhook.
    engine
        .unhook(test_multiply as *const u8 as u64)
        .expect("unhook");

    // Original behavior restored.
    assert_eq!(call_opaque(test_multiply, 3, 4), 12);
}

#[test]
fn test_lua_hook_read_only() {
    let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let lua = joybug_core::scripting::create_lua().expect("create lua");
    let mut engine = LuaHookEngine::new();

    // Register a global for the Lua callback to write into.
    lua.globals().set("captured", 0u64).unwrap();

    // First integer arg register: RCX on Win64, X0 on AArch64.
    #[cfg(target_arch = "x86_64")]
    let callback_src = r#"function(ctx) captured = ctx.rcx end"#;
    #[cfg(target_arch = "aarch64")]
    let callback_src = r#"function(ctx) captured = ctx.x0 end"#;
    let callback = lua
        .load(callback_src)
        .eval::<mlua::Function>()
        .expect("parse callback");

    let (_hook_id, _trampoline) = engine
        .hook(test_sub as *const u8, &lua, callback)
        .expect("hook");

    // Call the function — the hook should capture the first arg (= 100).
    let result = call_opaque(test_sub, 100, 30);
    assert_eq!(result, 70); // original behavior unchanged

    let captured: u64 = lua.globals().get("captured").unwrap();
    assert_eq!(captured, 100);

    engine.unhook(test_sub as *const u8 as u64).expect("unhook");
}

#[test]
fn test_lua_hook_memory_access() {
    let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let lua = joybug_core::scripting::create_lua().expect("create lua");
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
    let result = call_opaque(test_sub, 100, 30);
    assert_eq!(result, 70);

    let read_val: u64 = lua.globals().get("read_val").unwrap();
    assert_eq!(read_val, 0xDEAD);

    engine.unhook(test_sub as *const u8 as u64).expect("unhook");
}
