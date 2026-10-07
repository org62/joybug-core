//! The ptrace/procfs side of the shared bookkeeping: [`LinuxOps`] implements
//! `ProcessOps` for one process.

use std::collections::VecDeque;
use std::sync::{Mutex, RwLock};

use tracing::{debug, trace, warn};

use super::loader::{self, LoaderState, HOOK_ENTRY, HOOK_LOADER};
use super::memory::ProcessMemory;
use super::regs::{self, RegisterImage};
use super::tracer::Tracer;
use crate::debugger_core::hw_breakpoints::{x86_clear_hw_bp, x86_set_hw_bp, InternalHardwareBreakpoint, X86DebugRegs, X86DebugRegsRaw};
use crate::debugger_core::ops::{HookDisposition, InitialBpPolicy, ProcessOps};
use crate::debugger_core::thread_table::ThreadTable;
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::{DebugEvent, HardwareBreakpointSize, HardwareBreakpointType, ModuleInfo, ThreadContext};

#[derive(Debug)]
pub struct LinuxOps {
    pub pid: u32,
    pub tracer: Tracer,
    /// Re-opened after an exec (the descriptor is bound to the old address space).
    pub mem: RwLock<ProcessMemory>,
    pub threads: Mutex<ThreadTable<()>>,
    /// Events produced outside the trap ladder (loader hooks, attach
    /// synthesis), delivered one per continue by the platform.
    pub queued: Mutex<VecDeque<DebugEvent>>,
    pub loader: Mutex<LoaderState>,
    /// The vdso's `(base, size)` from the maps, for the loader diff.
    pub vdso: Mutex<Option<(u64, u64)>>,
    /// Runtime entry point (`AT_ENTRY`), the address of the entry hook.
    /// Replaced after an exec.
    pub entry: std::sync::atomic::AtomicU64,
    /// Set after an exec: the next entry hook is an ordinary breakpoint, the
    /// one `InitialBreakpoint` was already reported for the first image.
    pub after_exec: std::sync::atomic::AtomicBool,
}

impl LinuxOps {
    pub fn new(pid: u32, tracer: Tracer, mem: ProcessMemory, threads: ThreadTable<()>, vdso: Option<(u64, u64)>, entry: u64) -> Self {
        Self {
            pid,
            tracer,
            mem: RwLock::new(mem),
            threads: Mutex::new(threads),
            queued: Mutex::new(VecDeque::new()),
            loader: Mutex::new(LoaderState::default()),
            vdso: Mutex::new(vdso),
            entry: std::sync::atomic::AtomicU64::new(entry),
            after_exec: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Rewrite the address and control debug registers (DR0-3, DR7) of `tid`.
    fn with_dr(&self, tid: u32, f: impl FnOnce(&mut X86DebugRegsRaw)) -> Result<(), PlatformError> {
        let dr = self.tracer.get_debug_regs(tid)?;
        let mut raw = X86DebugRegsRaw { dr: [dr[0], dr[1], dr[2], dr[3]], dr6: dr[6], dr7: dr[7], ..Default::default() };
        f(&mut raw);
        let mut out = dr;
        out[..4].copy_from_slice(&raw.dr);
        out[7] = raw.dr7;
        self.tracer.set_debug_regs(tid, out)
    }

    /// Write `context` over `current`, the thread's register image.
    fn write_context(&self, tid: u32, context: ThreadContext, current: &RegisterImage) -> Result<(), PlatformError> {
        let ThreadContext::Win32RawContext(ctx) = context else {
            return Err(PlatformError::Other("a WOW64 context has no meaning on Linux".into()));
        };
        self.tracer.set_regs(tid, regs::from_context(&ctx, current))
    }

    pub fn queue(&self, event: DebugEvent) {
        self.queued.lock().unwrap().push_back(event);
    }

    pub fn image(&self, tid: u32) -> Result<RegisterImage, PlatformError> {
        self.tracer.get_regs(tid)
    }

    /// Diff the loader's link map against what was reported, queueing
    /// `DllLoaded`/`DllUnloaded`.
    pub fn sync_modules(&self) -> Result<(), PlatformError> {
        let mut st = self.loader.lock().unwrap();
        let Some(r_debug) = st.r_debug else { return Ok(()) };
        let mem = self.mem.read().unwrap();
        let entries = loader::read_link_map(&mem, r_debug)?;
        let vdso = *self.vdso.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        for e in &entries {
            seen.insert(e.l_addr);
            if e.name.is_empty() {
                continue; // the executable, reported as ProcessCreated
            }
            if st.known.contains_key(&e.l_addr) {
                continue;
            }
            let Some(module) = loader::module_for_entry(e, vdso) else { continue };
            trace!(pid = self.pid, name = %module.name, base = %format!("{:#x}", module.base), "module appeared");
            self.queue(DebugEvent::DllLoaded {
                pid: self.pid,
                tid: self.pid,
                dll_name: Some(module.name.clone()),
                base_of_dll: module.base,
                size_of_dll: module.size,
            });
            st.known.insert(e.l_addr, module);
        }
        let gone: Vec<u64> = st.known.keys().filter(|k| !seen.contains(k)).copied().collect();
        for l_addr in gone {
            if let Some(module) = st.known.remove(&l_addr) {
                trace!(pid = self.pid, name = %module.name, "module gone");
                self.queue(DebugEvent::DllUnloaded { pid: self.pid, tid: self.pid, base_of_dll: module.base });
            }
        }
        Ok(())
    }

    /// Record a module the loader diff should consider already reported.
    pub fn note_known_module(&self, l_addr: u64, module: ModuleInfo) {
        self.loader.lock().unwrap().known.insert(l_addr, module);
    }
}

impl ProcessOps for LinuxOps {
    fn arch(&self) -> Architecture {
        Architecture::X64
    }

    fn read(&self, _pid: u32, address: u64, len: usize) -> Result<Vec<u8>, PlatformError> {
        self.mem.read().unwrap().read(address, len)
    }

    fn write(&self, _pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        self.mem.read().unwrap().write(address, data)
    }

    fn live_threads(&self, _pid: u32) -> Vec<u32> {
        self.threads.lock().unwrap().live_tids()
    }

    fn freeze_thread(&self, _pid: u32, tid: u32) -> Result<(), PlatformError> {
        self.tracer.hold(tid)
    }

    fn thaw_thread(&self, _pid: u32, tid: u32) -> Result<(), PlatformError> {
        self.tracer.release(tid)
    }

    fn get_context(&self, _pid: u32, tid: u32) -> Result<ThreadContext, PlatformError> {
        let image = self.tracer.get_regs(tid)?;
        Ok(regs::to_context(&image, image.trap_flag_pending))
    }

    fn set_context(&self, _pid: u32, tid: u32, context: ThreadContext) -> Result<(), PlatformError> {
        let current = self.tracer.get_regs(tid)?;
        self.write_context(tid, context, &current)
    }

    /// The default reads the registers twice (once for `get_context`, again
    /// as `set_context`'s base image); one read serves both.
    fn modify_context(
        &self,
        _pid: u32,
        tid: u32,
        f: &mut dyn FnMut(&mut ThreadContext) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        let image = self.tracer.get_regs(tid)?;
        let mut context = regs::to_context(&image, image.trap_flag_pending);
        f(&mut context)?;
        self.write_context(tid, context, &image)
    }

    fn modify_debug_regs(
        &self,
        _pid: u32,
        tid: u32,
        with_control: bool,
        f: &mut dyn FnMut(&mut dyn X86DebugRegs) -> bool,
    ) -> Result<(), PlatformError> {
        let dr = self.tracer.get_debug_regs(tid)?;
        let image = if with_control { Some(self.tracer.get_regs(tid)?) } else { None };
        let mut raw = X86DebugRegsRaw {
            dr: [dr[0], dr[1], dr[2], dr[3]],
            dr6: dr[6],
            dr7: dr[7],
            pc: image.as_ref().map(|i| i.regs.rip).unwrap_or(0),
            eflags: image
                .as_ref()
                .map(|i| i.regs.eflags | if i.trap_flag_pending { regs::TRAP_FLAG } else { 0 })
                .unwrap_or(0),
        };
        if !f(&mut raw) {
            return Ok(());
        }
        let mut out = dr;
        out[..4].copy_from_slice(&raw.dr);
        out[6] = raw.dr6;
        out[7] = raw.dr7;
        self.tracer.set_debug_regs(tid, out)?;
        if let Some(image) = image {
            let want_tf = raw.eflags & regs::TRAP_FLAG != 0;
            if want_tf != image.trap_flag_pending {
                self.tracer.set_want_step(tid, want_tf)?;
            }
        }
        Ok(())
    }

    fn apply_hw_bp(&self, _pid: u32, tid: u32, dr_index: u8, address: u64, bp_type: HardwareBreakpointType, size: HardwareBreakpointSize) -> Result<(), PlatformError> {
        self.with_dr(tid, |raw| x86_set_hw_bp(raw, dr_index, address, bp_type, size))
    }

    fn clear_hw_bp(&self, _pid: u32, tid: u32, dr_index: u8, _bp_type: HardwareBreakpointType) -> Result<(), PlatformError> {
        self.with_dr(tid, |raw| x86_clear_hw_bp(raw, dr_index))
    }

    fn apply_all_hw_bps(&self, _pid: u32, tid: u32, bps: &[InternalHardwareBreakpoint]) -> Result<(), PlatformError> {
        self.with_dr(tid, |raw| {
            for bp in bps {
                x86_set_hw_bp(raw, bp.dr_index, bp.address, bp.bp_type, bp.size);
            }
        })
    }

    fn on_internal_hook(&self, pid: u32, tid: u32, hook_id: u32) -> Result<(Option<DebugEvent>, HookDisposition), PlatformError> {
        match hook_id {
            HOOK_LOADER => {
                // Only a consistent chain is worth diffing; the loader also
                // calls this with RT_ADD/RT_DELETE before the change lands.
                let consistent = {
                    let st = self.loader.lock().unwrap();
                    let mem = self.mem.read().unwrap();
                    st.r_debug.is_some_and(|r| loader::is_consistent(&mem, r))
                };
                if consistent {
                    if let Err(e) = self.sync_modules() {
                        warn!(pid, error = %e, "link-map walk failed");
                    }
                }
                // Queued events are drained by the platform (which also
                // registers the modules), not returned from here.
                Ok((None, HookDisposition::Keep))
            }
            HOOK_ENTRY => {
                use std::sync::atomic::Ordering;
                let entry = self.entry.load(Ordering::Relaxed);
                debug!(pid, tid, entry = %format!("{:#x}", entry), "entry point reached");
                // Libraries the loader mapped before running the program are
                // reported first; the initial breakpoint goes behind them.
                if let Err(e) = self.sync_modules() {
                    warn!(pid, error = %e, "link-map walk failed at entry");
                }
                if self.after_exec.load(Ordering::Relaxed) {
                    self.queue(DebugEvent::Breakpoint { pid, tid, address: entry });
                } else {
                    self.queue(DebugEvent::InitialBreakpoint { pid, tid, address: entry });
                }
                Ok((None, HookDisposition::Remove))
            }
            other => {
                warn!(pid, tid, hook = other, "unknown internal hook");
                Ok((None, HookDisposition::Remove))
            }
        }
    }

    fn initial_breakpoint_policy(&self) -> InitialBpPolicy {
        InitialBpPolicy::InternalHook
    }
}
