//! VEH (Vectored Exception Handler) debugging platform.
//!
//! Instead of using the Windows Debug API, this platform injects a DLL into the
//! target process. The DLL registers a VEH handler that catches exceptions and
//! forwards them to the debugger via shared memory IPC.

mod injection;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use joybug_core_veh_shared::{
    VehSharedMem, INIT_BREAKPOINT_TIMEOUT_MS, VEH_CONTINUE_EXECUTION, VEH_CONTINUE_SEARCH,
    VEH_VERSION,
};
use tracing::{debug, info, trace};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

use crate::env_block::EnvironmentBlock;
use crate::interfaces::*;
use crate::protocol;

type HANDLE = *mut core::ffi::c_void;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Per-process state for VEH debugging.
struct VehProcess {
    process_handle: HANDLE,
    /// Handle to the shared file mapping
    mapping_handle: HANDLE,
    /// Pointer to the mapped shared memory in our (debugger) address space
    shared_mem: *mut VehSharedMem,
    /// "has debug event" event (DLL -> debugger)
    has_event: HANDLE,
    /// "event handled" event (debugger -> DLL)
    handled_event: HANDLE,
    /// Single-shot breakpoints: address -> the single original byte we replaced with 0xCC.
    single_shot_breakpoints: HashMap<u64, u8>,
    /// Whether we've already seen the initial breakpoint
    has_hit_initial_breakpoint: bool,
}

// SAFETY: VEHPlatform is wrapped in an Arc<RwLock<_>> by the server, so the
// RwLock ensures exclusive access for &mut methods and shared access for &
// methods. The *mut VehSharedMem aliases memory shared with the injected DLL,
// but cross-process access is serialized via Windows auto-reset events.
unsafe impl Send for VehProcess {}
unsafe impl Sync for VehProcess {}

impl Drop for VehProcess {
    fn drop(&mut self) {
        unsafe {
            if !self.shared_mem.is_null() {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.shared_mem as *mut _,
                });
            }
            if !self.mapping_handle.is_null() {
                CloseHandle(self.mapping_handle);
            }
            if !self.has_event.is_null() {
                CloseHandle(self.has_event);
            }
            if !self.handled_event.is_null() {
                CloseHandle(self.handled_event);
            }
            if !self.process_handle.is_null() {
                CloseHandle(self.process_handle);
            }
        }
    }
}

pub struct VEHPlatform {
    processes: HashMap<u32, VehProcess>,
}

impl VEHPlatform {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    /// Find the VEH DLL path. Looks next to the joybug-core executable in the
    /// target directory, or uses VEH_DLL_PATH env var.
    fn find_veh_dll() -> Result<String, PlatformError> {
        // Check env var first
        if let Ok(path) = std::env::var("VEH_DLL_PATH") {
            if std::path::Path::new(&path).exists() {
                return Ok(path);
            }
        }

        // Look relative to the current exe, walking up a few directories.
        // For test binaries the exe lives in `target/<profile>/deps/`, while the
        // cdylib is emitted one level up in `target/<profile>/`. Walking ancestors
        // covers both that case and the plain `target/<profile>/` exe location,
        // regardless of how the workspace target dir is nested (e.g. when joybug-core
        // is a submodule the target dir lives at the outer workspace root).
        if let Ok(exe_path) = std::env::current_exe() {
            let mut dir = exe_path.parent();
            for _ in 0..3 {
                let Some(d) = dir else { break };
                let dll_path = d.join("joybug_core_veh_dll.dll");
                if dll_path.exists() {
                    return Ok(dll_path.to_string_lossy().into_owned());
                }
                dir = d.parent();
            }
        }

        // Look in target/debug (single-crate workspace build, manifest-relative)
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        for profile in &["debug", "release"] {
            let candidate =
                format!("{}/target/{}/joybug_core_veh_dll.dll", manifest_dir, profile);
            if std::path::Path::new(&candidate).exists() {
                return Ok(candidate);
            }
        }

        Err(PlatformError::OsError(
            "Could not find joybug_core_veh_dll.dll. Set VEH_DLL_PATH env var.".into(),
        ))
    }

    /// Generate a nonce to disambiguate this debugger session from any previous
    /// crashed session that left named kernel objects behind for the same PID.
    /// 100ns resolution is enough — we only need uniqueness across re-debugs.
    fn generate_nonce() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Create shared memory and events, inject DLL into an already-opened process.
    ///
    /// `process_handle` is owned by this function on success (stored in VehProcess).
    /// On error, the caller is responsible for closing it.
    fn setup_veh_for_process(
        &mut self,
        pid: u32,
        process_handle: HANDLE,
    ) -> Result<(), PlatformError> {
        let dll_path = Self::find_veh_dll()?;
        info!(pid, dll_path = %dll_path, "Setting up VEH debugging");

        let nonce = Self::generate_nonce();

        // Create named shared memory
        let mapping_name = to_wide(&joybug_core_veh_shared::shared_mem_name(pid));
        let mapping_size = std::mem::size_of::<VehSharedMem>() as u32;
        let mapping: HANDLE = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                mapping_size,
                mapping_name.as_ptr(),
            )
        };
        if mapping.is_null() {
            return Err(PlatformError::OsError(format!(
                "CreateFileMappingW failed: {}",
                unsafe { GetLastError() }
            )));
        }

        let shared_view = unsafe {
            MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size as usize)
        };
        if shared_view.Value.is_null() {
            unsafe { CloseHandle(mapping) };
            return Err(PlatformError::OsError("MapViewOfFile failed".into()));
        }

        let shared = shared_view.Value as *mut VehSharedMem;

        unsafe {
            (*shared).version = VEH_VERSION;
            (*shared).continue_status = VEH_CONTINUE_EXECUTION;
            (*shared).nonce = nonce;
        }

        // Create named events with nonce (auto-reset: bManualReset = FALSE)
        let has_event_name_w =
            to_wide(&joybug_core_veh_shared::has_event_name(pid, nonce));
        let handled_event_name_w =
            to_wide(&joybug_core_veh_shared::handled_event_name(pid, nonce));

        let has_event: HANDLE =
            unsafe { CreateEventW(std::ptr::null(), FALSE, FALSE, has_event_name_w.as_ptr()) };
        let handled_event: HANDLE =
            unsafe { CreateEventW(std::ptr::null(), FALSE, FALSE, handled_event_name_w.as_ptr()) };

        if has_event.is_null() || handled_event.is_null() {
            unsafe {
                if !has_event.is_null() {
                    CloseHandle(has_event);
                }
                if !handled_event.is_null() {
                    CloseHandle(handled_event);
                }
                UnmapViewOfFile(shared_view);
                CloseHandle(mapping);
            }
            return Err(PlatformError::OsError("CreateEventW failed".into()));
        }

        // Inject the VEH DLL
        debug!(pid, "Injecting VEH DLL");
        if let Err(e) = injection::inject_dll(process_handle, &dll_path) {
            unsafe {
                CloseHandle(has_event);
                CloseHandle(handled_event);
                UnmapViewOfFile(shared_view);
                CloseHandle(mapping);
            }
            return Err(e);
        }

        info!(pid, "VEH DLL injected, waiting for initial breakpoint");

        self.processes.insert(
            pid,
            VehProcess {
                process_handle,
                mapping_handle: mapping,
                shared_mem: shared,
                has_event,
                handled_event,
                single_shot_breakpoints: HashMap::new(),
                has_hit_initial_breakpoint: false,
            },
        );

        Ok(())
    }

    /// Wait for the next VEH event from the target process.
    /// `timeout_ms` — use `INFINITE` for blocking, or a finite value for timed waits.
    fn wait_for_event_timeout(
        &mut self,
        pid: u32,
        timeout_ms: u32,
    ) -> Result<Option<protocol::DebugEvent>, PlatformError> {
        let proc = self.processes.get_mut(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;

        // Wait for either has_event or process exit
        let handles = [proc.has_event, proc.process_handle];
        let wait_result =
            unsafe { WaitForMultipleObjects(2, handles.as_ptr(), FALSE, timeout_ms) };

        match wait_result {
            WAIT_OBJECT_0 => {
                // has_event signaled - read exception info from shared memory
                let shared = unsafe { &*proc.shared_mem };
                let tid = shared.thread_id;
                let code = shared.exception_code;
                let address = shared.exception_address;
                let rip = shared.context_rip;

                trace!(
                    pid, tid, code = %format!("0x{:X}", code),
                    address = %format!("0x{:X}", address),
                    rip = %format!("0x{:X}", rip),
                    "VEH event received"
                );

                self.process_veh_event(pid, tid, code, address)
            }
            w if w == WAIT_OBJECT_0 + 1 => {
                // Process exited
                let mut exit_code = 0u32;
                unsafe { GetExitCodeProcess(proc.process_handle, &mut exit_code) };
                info!(pid, exit_code, "Target process exited");
                Ok(Some(protocol::DebugEvent::ProcessExited {
                    pid,
                    tid: 0,
                    exit_code,
                }))
            }
            WAIT_TIMEOUT => Err(PlatformError::OsError(format!(
                "Timed out waiting for VEH event from pid {} ({}ms)",
                pid, timeout_ms
            ))),
            _ => Err(PlatformError::OsError(format!(
                "WaitForMultipleObjects failed: {}",
                unsafe { GetLastError() }
            ))),
        }
    }

    /// Wait for the next VEH event, blocking indefinitely.
    fn wait_for_event(&mut self, pid: u32) -> Result<Option<protocol::DebugEvent>, PlatformError> {
        self.wait_for_event_timeout(pid, INFINITE)
    }

    /// Process a VEH exception event and produce the appropriate DebugEvent.
    fn process_veh_event(
        &mut self,
        pid: u32,
        tid: u32,
        code: u32,
        address: u64,
    ) -> Result<Option<protocol::DebugEvent>, PlatformError> {
        const EXCEPTION_BREAKPOINT_U32: u32 = EXCEPTION_BREAKPOINT as u32;

        if code == EXCEPTION_BREAKPOINT_U32 {
            if let Some(original_byte) = self
                .processes
                .get_mut(&pid)
                .and_then(|p| p.single_shot_breakpoints.remove(&address))
            {
                debug!(
                    pid, tid,
                    address = %format!("0x{:X}", address),
                    "Single-shot breakpoint hit via VEH"
                );

                let proc = self.processes.get(&pid).unwrap();

                let mut written = 0usize;
                unsafe {
                    WriteProcessMemory(
                        proc.process_handle,
                        address as *const _,
                        &original_byte as *const u8 as *const _,
                        1,
                        &mut written,
                    );
                    windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                        proc.process_handle,
                        address as *const _,
                        1,
                    );
                }

                // Rewind RIP so the now-restored instruction executes next.
                let shared = unsafe { &mut *proc.shared_mem };
                shared.context_rip = address;
                shared.continue_status = VEH_CONTINUE_EXECUTION;

                return Ok(Some(protocol::DebugEvent::SingleShotBreakpoint {
                    pid,
                    tid,
                    address,
                }));
            }

            // Not our breakpoint - check if it's the initial breakpoint
            let proc = self.processes.get_mut(&pid).unwrap();
            let shared = unsafe { &mut *proc.shared_mem };
            shared.continue_status = VEH_CONTINUE_EXECUTION;

            // The exception address is AT the breakpoint instruction; skip past
            // it so we don't re-execute the trap on continue. int3 is 1 byte on
            // x86; brk is a 4-byte instruction on AArch64 (advancing by 1 would
            // land mid-instruction and fault with STATUS_ILLEGAL_INSTRUCTION).
            #[cfg(target_arch = "x86_64")]
            { shared.context_rip = address + 1; }
            #[cfg(target_arch = "aarch64")]
            { shared.context_rip = address + 4; }

            if !proc.has_hit_initial_breakpoint {
                proc.has_hit_initial_breakpoint = true;
                debug!(
                    pid, tid,
                    address = %format!("0x{:X}", address),
                    "Initial breakpoint via VEH"
                );
                return Ok(Some(protocol::DebugEvent::InitialBreakpoint {
                    pid,
                    tid,
                    address,
                }));
            }

            // Subsequent unknown breakpoints are generic exceptions
            debug!(
                pid, tid,
                address = %format!("0x{:X}", address),
                "Unknown breakpoint via VEH (not ours)"
            );
            return Ok(Some(protocol::DebugEvent::Breakpoint {
                pid,
                tid,
                address,
            }));
        }

        // TODO: Handle STATUS_SINGLE_STEP for persistent breakpoint rearm, stepping, etc.

        let proc = self.processes.get(&pid).unwrap();
        let shared = unsafe { &mut *proc.shared_mem };
        shared.continue_status = VEH_CONTINUE_SEARCH;
        Ok(Some(protocol::DebugEvent::Exception {
            pid,
            tid,
            code,
            address,
            first_chance: true,
            parameters: vec![],
        }))
    }

    /// Signal the VEH handler to resume execution.
    fn signal_continue(&self, pid: u32) -> Result<(), PlatformError> {
        let proc = self.processes.get(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;
        unsafe { SetEvent(proc.handled_event) };
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PlatformAPI implementation
// ---------------------------------------------------------------------------

impl PlatformAPI for VEHPlatform {
    fn attach(&mut self, pid: u32) -> Result<Option<protocol::DebugEvent>, PlatformError> {
        // Open the target process
        let process_handle: HANDLE = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
        };
        if process_handle.is_null() {
            return Err(PlatformError::OsError(format!(
                "OpenProcess({}) failed: {}",
                pid,
                unsafe { GetLastError() }
            )));
        }

        // Set up VEH: create shared memory, inject DLL
        if let Err(e) = self.setup_veh_for_process(pid, process_handle) {
            unsafe { CloseHandle(process_handle) };
            return Err(e);
        }

        // The DLL fires int3 once VEH is registered; that initial breakpoint
        // doubles as the "ready" signal. If injection silently fails (wrong
        // arch, missing deps), the bounded timeout prevents hanging forever.
        self.wait_for_event_timeout(pid, INIT_BREAKPOINT_TIMEOUT_MS)
    }

    fn detach(&mut self, pid: u32) -> Result<(), PlatformError> {
        // TODO: signal DLL to unload VEH handler and unload itself
        self.processes.remove(&pid);
        Ok(())
    }

    fn continue_exec(
        &mut self,
        pid: u32,
        _tid: u32,
    ) -> Result<Option<protocol::DebugEvent>, PlatformError> {
        self.signal_continue(pid)?;
        self.wait_for_event(pid)
    }

    fn set_breakpoint(
        &mut self,
        _pid: u32,
        _addr: u64,
        _tid: Option<u32>,
    ) -> Result<(), PlatformError> {
        // TODO: persistent breakpoints with rearm via single-step
        Err(PlatformError::NotImplemented)
    }

    fn remove_breakpoint(&mut self, _pid: u32, _addr: u64) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn set_single_shot_breakpoint(
        &mut self,
        pid: u32,
        addr: u64,
    ) -> Result<(), PlatformError> {
        let proc = self.processes.get_mut(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;

        let mut original: u8 = 0;
        let mut bytes_read = 0usize;
        let ok = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                proc.process_handle,
                addr as *const _,
                &mut original as *mut u8 as *mut _,
                1,
                &mut bytes_read,
            )
        };
        if ok == 0 {
            return Err(PlatformError::OsError(format!(
                "ReadProcessMemory at 0x{:X} failed: {}",
                addr,
                unsafe { GetLastError() }
            )));
        }

        let int3: u8 = 0xCC;
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                proc.process_handle,
                addr as *const _,
                &int3 as *const u8 as *const _,
                1,
                &mut written,
            )
        };
        if ok == 0 {
            return Err(PlatformError::OsError(format!(
                "WriteProcessMemory (int3) at 0x{:X} failed: {}",
                addr,
                unsafe { GetLastError() }
            )));
        }

        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                proc.process_handle,
                addr as *const _,
                1,
            );
        }

        proc.single_shot_breakpoints.insert(addr, original);
        debug!(pid, addr = %format!("0x{:X}", addr), "Single-shot breakpoint set via VEH");

        Ok(())
    }

    fn set_hardware_breakpoint(
        &mut self,
        _pid: u32,
        _addr: u64,
        _bp_type: protocol::HardwareBreakpointType,
        _size: protocol::HardwareBreakpointSize,
    ) -> Result<u8, PlatformError> {
        // TODO: modify debug registers via shared memory context
        Err(PlatformError::NotImplemented)
    }

    fn remove_hardware_breakpoint(&mut self, _pid: u32, _addr: u64) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn launch(
        &mut self,
        command: &str,
        _debug_children: bool,
        working_directory: Option<&str>,
        environment: Option<&[(String, String)]>,
    ) -> Result<Option<protocol::DebugEvent>, PlatformError> {
        // Start suspended so we can inject the VEH DLL before any user code runs.
        let mut cmd_wide: Vec<u16> = OsStr::new(command)
            .encode_wide()
            .chain(Some(0))
            .collect();

        // Wide buffer must outlive the CreateProcessW call; null pointer => inherit debugger CWD.
        let working_dir_wide = working_directory.map(to_wide);
        let working_dir_ptr = working_dir_wide
            .as_ref()
            .map_or(std::ptr::null(), |w| w.as_ptr());

        // Must outlive the CreateProcessW call; carries its own creation flag.
        let env_block = EnvironmentBlock::new(environment);
        let create_flags = CREATE_SUSPENDED | env_block.create_flags();

        let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmd_wide.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                create_flags,
                env_block.as_ptr(),
                working_dir_ptr,
                &startup_info,
                &mut process_info,
            )
        };
        if ok == 0 {
            return Err(PlatformError::OsError(format!(
                "CreateProcessW failed: {}",
                unsafe { GetLastError() }
            )));
        }

        let pid = process_info.dwProcessId;
        let main_thread = process_info.hThread;
        let process_handle = process_info.hProcess;

        info!(pid, "Created suspended process, injecting VEH DLL");

        // CreateRemoteThread spawns a new thread that loads the DLL; the main
        // thread stays suspended so it doesn't race past entrypoint.
        if let Err(e) = self.setup_veh_for_process(pid, process_handle) {
            unsafe {
                TerminateProcess(process_handle, 1);
                CloseHandle(main_thread);
                CloseHandle(process_handle);
            }
            return Err(e);
        }

        // Wait for the initial breakpoint BEFORE resuming main: receiving it
        // proves VEH is active and ready to catch exceptions from main().
        let event = self.wait_for_event_timeout(pid, INIT_BREAKPOINT_TIMEOUT_MS)?;

        unsafe { ResumeThread(main_thread) };
        unsafe { CloseHandle(main_thread) };

        Ok(event)
    }

    fn read_memory(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, PlatformError> {
        let proc = self.processes.get(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;

        let mut buf = vec![0u8; size];
        let mut bytes_read = 0usize;
        let ok = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                proc.process_handle,
                address as *const _,
                buf.as_mut_ptr() as *mut _,
                size,
                &mut bytes_read,
            )
        };
        if ok == 0 {
            return Err(PlatformError::OsError(format!(
                "ReadProcessMemory at 0x{:X} failed: {}",
                address,
                unsafe { GetLastError() }
            )));
        }
        buf.truncate(bytes_read);
        Ok(buf)
    }

    fn write_memory(
        &self,
        pid: u32,
        address: u64,
        data: &[u8],
    ) -> Result<(), PlatformError> {
        let proc = self.processes.get(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;

        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                proc.process_handle,
                address as *const _,
                data.as_ptr() as *const _,
                data.len(),
                &mut written,
            )
        };
        if ok == 0 {
            return Err(PlatformError::OsError(format!(
                "WriteProcessMemory at 0x{:X} failed: {}",
                address,
                unsafe { GetLastError() }
            )));
        }
        Ok(())
    }

    fn read_wide_string(
        &self,
        _pid: u32,
        _address: u64,
        _max_len: Option<usize>,
    ) -> Result<String, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn get_thread_context(
        &self,
        _pid: u32,
        _tid: u32,
    ) -> Result<protocol::ThreadContext, PlatformError> {
        // TODO: read context from shared memory when paused
        Err(PlatformError::NotImplemented)
    }

    fn set_thread_context(
        &self,
        _pid: u32,
        _tid: u32,
        _context: protocol::ThreadContext,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn get_function_arguments(
        &self,
        _pid: u32,
        _tid: u32,
        _count: usize,
    ) -> Result<Vec<u64>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn list_modules(&self, _pid: u32) -> Result<Vec<protocol::ModuleInfo>, PlatformError> {
        // TODO: enumerate via CreateToolhelp32Snapshot
        Err(PlatformError::NotImplemented)
    }

    fn list_threads(&self, _pid: u32) -> Result<Vec<protocol::ThreadInfo>, PlatformError> {
        // TODO: enumerate via CreateToolhelp32Snapshot
        Err(PlatformError::NotImplemented)
    }

    fn list_processes(&self) -> Result<Vec<protocol::ProcessInfo>, PlatformError> {
        // TODO: enumerate via CreateToolhelp32Snapshot
        Err(PlatformError::NotImplemented)
    }

    fn find_symbol(
        &self,
        _symbol_name: &str,
        _max_results: usize,
    ) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        Err(SymbolError::SymbolsNotFound(
            "VEH platform: not implemented".into(),
        ))
    }

    fn list_symbols(&self, _module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        Err(SymbolError::SymbolsNotFound(
            "VEH platform: not implemented".into(),
        ))
    }

    fn resolve_rva_to_symbol(
        &self,
        _module_path: &str,
        _rva: u32,
    ) -> Result<Option<ModuleSymbol>, SymbolError> {
        Err(SymbolError::SymbolsNotFound(
            "VEH platform: not implemented".into(),
        ))
    }

    fn resolve_address_to_symbol(
        &self,
        _pid: u32,
        _address: u64,
    ) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError> {
        Err(SymbolError::SymbolsNotFound(
            "VEH platform: not implemented".into(),
        ))
    }

    fn disassemble_memory(
        &self,
        _pid: u32,
        _address: u64,
        _count: usize,
        _arch: Architecture,
    ) -> Result<Vec<Instruction>, DisassemblerError> {
        Err(DisassemblerError::CapstoneError(
            "VEH platform: not implemented".into(),
        ))
    }

    fn get_call_stack(
        &self,
        _pid: u32,
        _tid: u32,
    ) -> Result<Vec<CallFrame>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn terminate_process(&self, pid: u32) -> Result<(), PlatformError> {
        let proc = self.processes.get(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;
        let ok = unsafe { TerminateProcess(proc.process_handle, 1) };
        if ok == 0 {
            return Err(PlatformError::OsError(format!(
                "TerminateProcess failed: {}",
                unsafe { GetLastError() }
            )));
        }
        Ok(())
    }

    fn break_into(&self, _pid: u32) -> Result<(), PlatformError> {
        // TODO: inject int3 or use DebugBreakProcess equivalent
        Err(PlatformError::NotImplemented)
    }

    fn get_module_extra_info(
        &self,
        _pid: u32,
        _module_base: u64,
    ) -> Result<crate::pe_types::ModuleExtraInfo, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn query_memory_region(
        &self,
        _pid: u32,
        _address: u64,
    ) -> Result<protocol::MemoryRegionInfo, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn enumerate_memory_regions(
        &self,
        _pid: u32,
    ) -> Result<Vec<protocol::MemoryRegionInfo>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn dereference(
        &self,
        _pid: u32,
        _address: u64,
        _count: usize,
        _reference_base: Option<u64>,
    ) -> Result<Vec<protocol::DereferenceEntry>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn get_peb_address(&self, pid: u32) -> Result<u64, PlatformError> {
        let proc = self.processes.get(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;

        #[repr(C)]
        struct ProcessBasicInformation {
            exit_status: i32,
            peb_base_address: *mut std::ffi::c_void,
            affinity_mask: usize,
            base_priority: i32,
            unique_process_id: usize,
            inherited_from_unique_process_id: usize,
        }

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process_handle: HANDLE,
                process_information_class: u32,
                process_information: *mut std::ffi::c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

        let mut info: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                proc.process_handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            )
        };

        if status >= 0 {
            Ok(info.peb_base_address as u64)
        } else {
            Err(PlatformError::OsError(format!(
                "NtQueryInformationProcess(ProcessBasicInformation) failed: 0x{:08X}",
                status
            )))
        }
    }

    fn is_wow64(&self, pid: u32) -> Result<bool, PlatformError> {
        let proc = self.processes.get(&pid).ok_or_else(|| {
            PlatformError::OsError(format!("No VEH process with pid {}", pid))
        })?;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process_handle: HANDLE,
                process_information_class: u32,
                process_information: *mut std::ffi::c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        // ProcessWow64Information returns the WOW64 PEB pointer; non-NULL = WOW64.
        const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;

        let mut wow64_peb: usize = 0;
        let mut return_length: u32 = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                proc.process_handle,
                PROCESS_WOW64_INFORMATION_CLASS,
                &mut wow64_peb as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                &mut return_length,
            )
        };

        if status >= 0 {
            Ok(wow64_peb != 0)
        } else {
            Err(PlatformError::OsError(format!(
                "NtQueryInformationProcess(ProcessWow64Information) failed: 0x{:08X}",
                status
            )))
        }
    }
}

impl Stepper for VEHPlatform {
    fn step(
        &mut self,
        _pid: u32,
        _tid: u32,
        _kind: protocol::StepKind,
    ) -> Result<Option<protocol::DebugEvent>, PlatformError> {
        // TODO: set trap flag via shared memory context
        Err(PlatformError::NotImplemented)
    }
}
