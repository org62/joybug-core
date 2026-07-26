//! VEH debugging DLL - injected into the target process.
//!
//! Registers a Vectored Exception Handler that forwards exceptions to the
//! joybug-core debugger via shared memory IPC.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use joybug_core_veh_shared::{VehSharedMem, DLL_HANDLER_TIMEOUT_MS, VEH_VERSION};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

type HANDLE = *mut core::ffi::c_void;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Pointer to the mapped shared memory (set during init, read by VEH handler).
static SHARED_MEM: AtomicPtr<VehSharedMem> = AtomicPtr::new(std::ptr::null_mut());

/// Whether VEH debugging is active.
static VEH_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Handle for the "has debug event" event (DLL -> debugger).
static HAS_EVENT: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Handle for the "event handled" event (debugger -> DLL).
static HANDLED_EVENT: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

// Critical section for serializing VEH handler access to shared memory.
// Only one faulting thread can be in the handler at a time.
static CS_INIT: std::sync::Once = std::sync::Once::new();
static CS: AtomicPtr<CRITICAL_SECTION> = AtomicPtr::new(std::ptr::null_mut());

unsafe fn enter_cs() {
    let cs = CS.load(Ordering::Acquire);
    if !cs.is_null() {
        unsafe { EnterCriticalSection(cs) };
    }
}

unsafe fn leave_cs() {
    let cs = CS.load(Ordering::Acquire);
    if !cs.is_null() {
        unsafe { LeaveCriticalSection(cs) };
    }
}

// ---------------------------------------------------------------------------
// VEH handler
// ---------------------------------------------------------------------------

unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if !VEH_ACTIVE.load(Ordering::Acquire) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let shared = SHARED_MEM.load(Ordering::Acquire);
    if shared.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let info = unsafe { &*exception_info };
    let record = unsafe { &*info.ExceptionRecord };
    let context = unsafe { &mut *info.ContextRecord };

    let exception_code = record.ExceptionCode;

    if exception_code != EXCEPTION_BREAKPOINT && exception_code != STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let has_event: HANDLE = HAS_EVENT.load(Ordering::Acquire);
    let handled_event: HANDLE = HANDLED_EVENT.load(Ordering::Acquire);
    if has_event.is_null() || handled_event.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Serialize concurrent faulting threads: the shared memory + has_event
    // pair only describes one exception at a time, so two threads faulting
    // simultaneously would corrupt each other's shared-mem write without this.
    unsafe { enter_cs() };

    let shared_ref = unsafe { &mut *shared };
    shared_ref.thread_id = unsafe { GetCurrentThreadId() };
    shared_ref.exception_code = exception_code as u32;
    shared_ref.exception_address = record.ExceptionAddress as u64;

    #[cfg(target_arch = "x86_64")]
    {
        shared_ref.context_rip = context.Rip;
    }
    #[cfg(target_arch = "aarch64")]
    {
        shared_ref.context_rip = context.Pc;
    }

    unsafe { SetEvent(has_event) };

    let wait_result = unsafe { WaitForSingleObject(handled_event, DLL_HANDLER_TIMEOUT_MS) };
    if wait_result != WAIT_OBJECT_0 {
        // Debugger didn't respond — pass to next handler so we don't hang the target.
        unsafe { leave_cs() };
        return EXCEPTION_CONTINUE_SEARCH;
    }

    #[cfg(target_arch = "x86_64")]
    {
        context.Rip = shared_ref.context_rip;
    }
    #[cfg(target_arch = "aarch64")]
    {
        context.Pc = shared_ref.context_rip;
    }

    let status = shared_ref.continue_status;
    unsafe { leave_cs() };
    status
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Initialize VEH debugging. Called from a spawned thread after DLL load.
fn veh_init() {
    let pid = unsafe { GetCurrentProcessId() };

    let mapping_name = to_wide(&joybug_core_veh_shared::shared_mem_name(pid));
    let mapping: HANDLE =
        unsafe { OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mapping_name.as_ptr()) };
    if mapping.is_null() {
        return;
    }

    let shared_ptr = unsafe {
        MapViewOfFile(
            mapping,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            std::mem::size_of::<VehSharedMem>(),
        )
    };
    if shared_ptr.Value.is_null() {
        unsafe { CloseHandle(mapping) };
        return;
    }

    let shared = shared_ptr.Value as *mut VehSharedMem;
    if unsafe { (*shared).version } != VEH_VERSION {
        unsafe {
            UnmapViewOfFile(shared_ptr);
            CloseHandle(mapping);
        }
        return;
    }

    let nonce = unsafe { (*shared).nonce };

    let has_event_name_w = to_wide(&joybug_core_veh_shared::has_event_name(pid, nonce));
    let handled_event_name_w = to_wide(&joybug_core_veh_shared::handled_event_name(pid, nonce));

    let has_event: HANDLE =
        unsafe { OpenEventW(EVENT_ALL_ACCESS, FALSE, has_event_name_w.as_ptr()) };
    let handled_event: HANDLE =
        unsafe { OpenEventW(EVENT_ALL_ACCESS, FALSE, handled_event_name_w.as_ptr()) };

    if has_event.is_null() || handled_event.is_null() {
        unsafe {
            if !has_event.is_null() {
                CloseHandle(has_event);
            }
            if !handled_event.is_null() {
                CloseHandle(handled_event);
            }
            UnmapViewOfFile(shared_ptr);
            CloseHandle(mapping);
        }
        return;
    }

    CS_INIT.call_once(|| {
        let cs = Box::into_raw(Box::new(unsafe { std::mem::zeroed::<CRITICAL_SECTION>() }));
        unsafe { InitializeCriticalSection(cs) };
        CS.store(cs, Ordering::Release);
    });

    SHARED_MEM.store(shared, Ordering::Release);
    HAS_EVENT.store(has_event, Ordering::Release);
    HANDLED_EVENT.store(handled_event, Ordering::Release);

    // First = 1 means highest priority.
    let _handler = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };

    VEH_ACTIVE.store(true, Ordering::Release);

    // Fire int3 (not DebugBreak) so we don't depend on IsDebuggerPresent —
    // there's no debug port. The debugger is already waiting on has_event,
    // so this initial breakpoint doubles as the "VEH ready" signal.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("int3");
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("brk #0xF000");
    }
}

// ---------------------------------------------------------------------------
// DLL entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut core::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Spawn init thread to avoid loader lock issues.
            // The thread will start after DllMain returns.
            std::thread::spawn(veh_init);
        }
        DLL_PROCESS_DETACH => {
            VEH_ACTIVE.store(false, Ordering::Release);
            // Clean up the critical section
            let cs = CS.swap(std::ptr::null_mut(), Ordering::AcqRel);
            if !cs.is_null() {
                unsafe {
                    DeleteCriticalSection(cs);
                    drop(Box::from_raw(cs));
                }
            }
            // TODO: RemoveVectoredExceptionHandler, unmap shared memory, close handles
        }
        _ => {}
    }
    TRUE
}
