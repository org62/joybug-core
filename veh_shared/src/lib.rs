//! Shared types and constants for VEH debugging IPC between the injected DLL
//! and the joybug2 debugger process.

pub const VEH_VERSION: u32 = 1;

/// VEH handler return values (matches Windows `EXCEPTION_CONTINUE_*`).
pub const VEH_CONTINUE_EXECUTION: i32 = -1;
pub const VEH_CONTINUE_SEARCH: i32 = 0;

/// How long the DLL waits for the debugger to handle one exception.
/// Must exceed the debugger's per-event processing time but stay bounded
/// so a crashed debugger doesn't hang the target forever.
pub const DLL_HANDLER_TIMEOUT_MS: u32 = 5_000;

/// How long the debugger waits for the initial breakpoint after DLL injection.
pub const INIT_BREAKPOINT_TIMEOUT_MS: u32 = 10_000;

/// Shared memory layout for VEH debugger IPC.
///
/// The debugger creates a named file mapping with this struct.
/// The injected DLL opens it and uses it to communicate exceptions.
#[repr(C)]
pub struct VehSharedMem {
    /// Protocol version (must match VEH_VERSION)
    pub version: u32,
    /// VEH handler return value — `VEH_CONTINUE_EXECUTION` or `VEH_CONTINUE_SEARCH`.
    pub continue_status: i32,
    /// Thread ID of the faulting thread
    pub thread_id: u32,
    /// Exception code (e.g. EXCEPTION_BREAKPOINT = 0x80000003)
    pub exception_code: u32,
    /// Exception address from EXCEPTION_RECORD (address of the faulting instruction)
    pub exception_address: u64,
    /// RIP from CONTEXT - the debugger can modify this before signaling "handled"
    pub context_rip: u64,
    /// Unique nonce to avoid collisions with stale named objects from crashed
    /// debuggers. The DLL reads this from shared memory and uses it to
    /// construct event names.
    pub nonce: u64,
}

/// Generate the name for the shared file mapping (keyed by PID only, since we
/// need the DLL to find it without knowing the nonce yet).
pub fn shared_mem_name(pid: u32) -> String {
    format!("Local\\JoybugVeh_{pid}")
}

/// Generate the name for the "has debug event" event (DLL -> debugger).
pub fn has_event_name(pid: u32, nonce: u64) -> String {
    format!("Local\\JoybugVeh_{pid}_{nonce:X}_evt")
}

/// Generate the name for the "event handled" event (debugger -> DLL).
pub fn handled_event_name(pid: u32, nonce: u64) -> String {
    format!("Local\\JoybugVeh_{pid}_{nonce:X}_done")
}
