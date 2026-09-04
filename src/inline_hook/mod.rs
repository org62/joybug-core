pub mod error;
pub mod allocator;
pub mod trampoline;
pub mod thread;
pub mod detour_stub;
pub mod hook_context;
pub mod dispatch;

use error::InlineHookError;
use allocator::CodeAllocator;
use thread::ThreadFreezer;

const SLOT_SIZE: usize = 64;

/// Maximum bytes we'll read from the target prologue for analysis.
const MAX_PROLOGUE_READ: usize = 32;

struct HookEntry {
    target: *mut u8,
    #[allow(dead_code)]
    detour: *const u8,
    slot: *mut u8,
    layout: trampoline::TrampolineLayout,
    original_bytes: Vec<u8>,
    patch_size: usize,
    enabled: bool,
}

// SAFETY: HookEntry contains raw pointers to code memory. The pointers are valid
// for the lifetime of the HookEngine that owns them and are only accessed through
// the HookEngine's &mut self methods.
unsafe impl Send for HookEntry {}

#[derive(Clone, Copy)]
pub struct HookHandle(usize);

pub struct HookEngine<A: CodeAllocator, T: ThreadFreezer> {
    hooks: Vec<HookEntry>,
    allocator: A,
    freezer: T,
}

impl<A: CodeAllocator, T: ThreadFreezer> HookEngine<A, T> {
    pub fn new(allocator: A, freezer: T) -> Self {
        Self {
            hooks: Vec::new(),
            allocator,
            freezer,
        }
    }

    /// Prepare a hook: analyze the target prologue, allocate a slot, build the
    /// relay + trampoline. Does NOT patch the target yet.
    ///
    /// Returns a handle and a pointer to the trampoline (callable as the original function).
    pub fn create(
        &mut self,
        target: *const u8,
        detour: *const u8,
    ) -> Result<(HookHandle, *const u8), InlineHookError> {
        let prologue = trampoline::analyze_prologue(target, MAX_PROLOGUE_READ)?;

        let slot = self.allocator.alloc_near(target as usize, SLOT_SIZE)?;

        let layout = trampoline::build_trampoline(
            slot,
            SLOT_SIZE,
            target,
            detour,
            &prologue,
        )?;

        let trampoline_ptr = unsafe { slot.add(layout.trampoline_offset) } as *const u8;

        let idx = self.hooks.len();
        self.hooks.push(HookEntry {
            target: target as *mut u8,
            detour,
            slot,
            layout,
            original_bytes: prologue.original_bytes,
            patch_size: prologue.patch_size,
            enabled: false,
        });

        Ok((HookHandle(idx), trampoline_ptr))
    }

    /// Patch the target function to redirect to the detour.
    /// Freezes threads, writes the jump, adjusts RIPs, thaws.
    pub fn enable(&mut self, handle: &HookHandle) -> Result<(), InlineHookError> {
        let entry = self.hooks.get(handle.0).ok_or(InlineHookError::InvalidHandle)?;
        if entry.enabled {
            return Err(InlineHookError::InvalidState("enabled".into()));
        }

        let target = entry.target;
        let relay_addr = unsafe { entry.slot.add(entry.layout.relay_offset) };
        let trampoline_addr = unsafe { entry.slot.add(entry.layout.trampoline_offset) };
        let patch_size = entry.patch_size;

        // Build the full patch: the 5-byte relative jump to the relay, then NOP
        // padding out to `patch_size` (when the prologue's instruction
        // boundaries don't land exactly on 5). The whole thing is written in one
        // `write_code` call: `write_code` uses `WriteProcessMemory`, which makes
        // the read-only `.text` page writable for the write. A raw-pointer store
        // for the NOP fill would fault on that page (this bug only surfaced for a
        // prologue longer than the jump — one summing to exactly 5 skipped the
        // fill entirely).
        let mut patch = trampoline::build_rel_jmp(target as u64, relay_addr as u64)?;
        patch.resize(patch_size, 0x90); // NOP fill

        self.freezer.freeze()?;

        // Adjust any threads currently executing in the patched area.
        self.freezer.adjust_rips(
            (target as usize, target as usize + patch_size),
            trampoline_addr as usize,
        )?;

        // Patch the target.
        unsafe {
            write_code(target, &patch);
            flush_icache(target, patch_size);
        }

        self.freezer.thaw()?;

        self.hooks[handle.0].enabled = true;
        Ok(())
    }

    /// Restore the original bytes at the target function.
    pub fn disable(&mut self, handle: &HookHandle) -> Result<(), InlineHookError> {
        let entry = self.hooks.get(handle.0).ok_or(InlineHookError::InvalidHandle)?;
        if !entry.enabled {
            return Err(InlineHookError::InvalidState("disabled".into()));
        }

        let target = entry.target;
        let original = entry.original_bytes.clone();
        let patch_size = entry.patch_size;
        let trampoline_addr = unsafe { entry.slot.add(entry.layout.trampoline_offset) };

        self.freezer.freeze()?;

        // Adjust any threads in the trampoline back to the original code.
        self.freezer.adjust_rips(
            (trampoline_addr as usize, trampoline_addr as usize + patch_size),
            target as usize,
        )?;

        unsafe {
            write_code(target, &original);
            flush_icache(target, patch_size);
        }

        self.freezer.thaw()?;

        self.hooks[handle.0].enabled = false;
        Ok(())
    }

    /// Disable the hook (if enabled) and free the trampoline slot.
    pub fn remove(&mut self, handle: HookHandle) -> Result<(), InlineHookError> {
        if handle.0 >= self.hooks.len() {
            return Err(InlineHookError::InvalidHandle);
        }
        if self.hooks[handle.0].enabled {
            self.disable(&handle)?;
        }
        let slot = self.hooks[handle.0].slot;
        self.allocator.free(slot);
        // Mark as removed by nulling the slot.
        self.hooks[handle.0].slot = std::ptr::null_mut();
        Ok(())
    }
}

// ---------- LuaHookEngine ----------

#[cfg(windows)]
use allocator::WindowsCodeAllocator;

/// Tracks a single Lua hook's resources.
struct LuaHookHandle {
    hook_handle: HookHandle,
    hook_id: u64,
    detour_stub: *mut u8,
}

// SAFETY: detour_stub is a process-global RWX allocation, not thread-bound.
unsafe impl Send for LuaHookHandle {}

/// High-level hook engine for Lua callbacks.
///
/// Combines `HookEngine` (relay + trampoline) with per-hook detour stubs that
/// save registers and call `hook_dispatch` to invoke the Lua handler.
#[cfg(windows)]
pub struct LuaHookEngine {
    engine: HookEngine<WindowsCodeAllocator, thread::NoopThreadFreezer>,
    detour_allocator: WindowsCodeAllocator,
    hooks: std::collections::HashMap<u64, LuaHookHandle>, // target_addr -> handle
}

#[cfg(windows)]
impl LuaHookEngine {
    pub fn new() -> Self {
        Self {
            engine: HookEngine::new(
                WindowsCodeAllocator::new(),
                thread::NoopThreadFreezer,
            ),
            detour_allocator: WindowsCodeAllocator::with_slot_size(
                detour_stub::DETOUR_STUB_SIZE,
            ),
            hooks: std::collections::HashMap::new(),
        }
    }

    /// Install a hook at `target` that invokes `callback` on every call.
    ///
    /// Returns `(hook_id, trampoline_ptr)`. The trampoline can be used to call
    /// the original function from Lua if needed.
    pub fn hook(
        &mut self,
        target: *const u8,
        lua: &mlua::Lua,
        callback: mlua::Function,
    ) -> Result<(u64, *const u8), InlineHookError> {
        let hook_id = dispatch::alloc_hook_id();

        // 1. Allocate RWX memory for the detour stub (near target for relay reach).
        let detour_mem = self.detour_allocator.alloc_near(
            target as usize,
            detour_stub::DETOUR_STUB_SIZE,
        )?;

        // 2. Build detour shellcode (trampoline addr TBD).
        let mut stub = detour_stub::build_detour_stub(
            hook_id,
            dispatch::hook_dispatch as *const () as u64,
        );

        // 3. Create hook — builds relay + trampoline, returns trampoline ptr.
        let (handle, trampoline) =
            self.engine.create(target, detour_mem as *const u8)?;

        // 4. Patch the trampoline address into the detour stub.
        detour_stub::patch_trampoline_addr(&mut stub, trampoline as u64);

        // 5. Write shellcode into the allocated RWX page.
        unsafe {
            std::ptr::copy_nonoverlapping(stub.as_ptr(), detour_mem, stub.len());
            flush_icache(detour_mem, stub.len());
        }

        // 6. Register the Lua callback in the global dispatch table.
        dispatch::register_hook(hook_id, lua, callback)
            .map_err(|e| InlineHookError::AllocationFailed(format!("Lua registry: {e}")))?;

        // 7. Enable the hook (patches the target prologue).
        self.engine.enable(&handle)?;

        self.hooks.insert(target as u64, LuaHookHandle {
            hook_handle: handle,
            hook_id,
            detour_stub: detour_mem,
        });

        Ok((hook_id, trampoline))
    }

    /// Remove a hook, restoring the original function.
    pub fn unhook(&mut self, target: u64) -> Result<(), InlineHookError> {
        let entry = self.hooks.remove(&target)
            .ok_or(InlineHookError::InvalidHandle)?;

        // Disable and remove the inline hook (restores original bytes).
        self.engine.remove(entry.hook_handle)?;

        // Free the detour stub memory.
        self.detour_allocator.free(entry.detour_stub);

        // Unregister from the Lua dispatch table.
        dispatch::unregister_hook(entry.hook_id);

        Ok(())
    }
}

#[cfg(windows)]
impl Drop for LuaHookEngine {
    fn drop(&mut self) {
        // Remove all active hooks to restore original code and clean up.
        let targets: Vec<u64> = self.hooks.keys().copied().collect();
        for target in targets {
            let _ = self.unhook(target);
        }
    }
}

/// Write bytes to a code page, handling page protection.
///
/// Uses WriteProcessMemory to self, which automatically handles PAGE_EXECUTE_READ pages.
#[cfg(windows)]
unsafe fn write_code(target: *mut u8, bytes: &[u8]) {
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let process = GetCurrentProcess();
        WriteProcessMemory(
            process,
            target as *const _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            std::ptr::null_mut(),
        );
    }
}

#[cfg(windows)]
unsafe fn flush_icache(target: *mut u8, size: usize) {
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        FlushInstructionCache(GetCurrentProcess(), target as *const _, size);
    }
}
