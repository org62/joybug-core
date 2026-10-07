//! The Linux debugger backend: ptrace for control, procfs for memory and
//! inspection, ELF/DWARF for symbols. See the module docs of `tracer.rs` for
//! the threading model and `events.rs` for the stop-to-event mapping.

pub mod coredump;
pub mod events;
pub mod launch;
pub mod loader;
pub mod maps;
pub mod memory;
pub mod objects;
pub mod ops;
pub mod procfs;
pub mod ptrace;
pub mod regs;
pub mod signals;
pub mod tracer;
pub mod unwind;
pub mod unwind_cfi;

// The ELF/DWARF parsers are OS-neutral (`crate::elf`); these names keep
// the platform code reading naturally.
pub(crate) use crate::elf::info as elf_info;
pub(crate) use crate::elf::layout as elf;
pub(crate) use crate::elf::symbols as elf_symbols;

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use tracing::{debug, info, trace, warn};

use crate::debugger_core::breakpoints;
use crate::debugger_core::disassembler::CapstoneDisassembler;
use crate::debugger_core::ops::ProcessOps;
use crate::debugger_core::thread_table::ThreadTable;
use crate::debugger_core::{coverage, dereference, disasm, function_args, hw_breakpoints, stepping, strings, watchpoints, DebugBook};
use crate::interfaces::{
    Architecture, CallFrame, DisassemblerError, Instruction, ModuleSymbol, PlatformAPI, PlatformError, ResolvedSymbol, Stepper,
    SymbolConfig, SymbolError,
};
use crate::protocol::{DebugEvent, MemoryRegionInfo, ModuleInfo, ProcessInfo, StepKind, ThreadContext, ThreadInfo};
use crate::symbols::symbol_manager::SymbolManager;

use memory::ProcessMemory;
use ops::LinuxOps;
use tracer::{StopKind, Tracer};

/// One debugged process.
#[derive(Debug)]
pub struct LinuxProcess {
    pub(crate) os: LinuxOps,
    pub(crate) book: DebugBook,
    /// The last reported signal per thread, delivered on `pass_exception`.
    pub(crate) last_fault: HashMap<u32, PendingSignal>,
    /// Children it forks are debugged too (`launch` with `debug_children`;
    /// inherited down the tree).
    pub(crate) debug_children: bool,
    /// A fork stop arrived: `(child, vfork)`, for `LinuxPlatform::on_fork`.
    pub(crate) pending_fork: Option<(u32, bool)>,
    /// A vfork child is borrowing this address space, so the breakpoint
    /// patches are out of it until `PTRACE_EVENT_VFORK_DONE`.
    pub(crate) vfork_lifted: bool,
    /// Set once `ProcessExited` was reported (the exit code).
    pub(crate) exited: Option<u32>,
    /// The kernel already reaped it (killed): nothing left to finalize.
    pub(crate) reaped: bool,
    /// An exec stop arrived; the image is re-read on the next step.
    pub(crate) exec_pending: bool,
    /// Opened non-invasively (`open_process`): /proc access only, never
    /// traced. `attach` upgrades it; nothing else may ptrace it.
    pub(crate) open_only: bool,
    /// The executable (`/proc/pid/exe`); re-read after an exec.
    pub(crate) exe: PathBuf,
}

impl LinuxProcess {
    fn new(os: LinuxOps, book: DebugBook, exe: PathBuf, open_only: bool) -> Self {
        Self {
            os,
            book,
            last_fault: HashMap::new(),
            debug_children: false,
            pending_fork: None,
            vfork_lifted: false,
            exited: None,
            reaped: false,
            exec_pending: false,
            open_only,
            exe,
        }
    }
}

/// A signal whose stop was reported as an `Exception` and is waiting for the
/// continue to decide: deliver it (`pass_exception`) or drop it.
#[derive(Debug, Clone)]
pub struct PendingSignal {
    pub signo: i32,
    pub code: u32,
    pub address: u64,
    pub parameters: Vec<u64>,
    /// The "nobody will handle this" stop was already given.
    pub second_chance_reported: bool,
}

/// What a tracer stop turned into.
enum Dispatch {
    Event(DebugEvent),
    /// Nothing to report: set `(pid, tid)` running again, delivering `signal`.
    Kick(u32, u32, i32),
    /// Nothing to report and nothing to resume.
    Wait,
}

/// Where the kernel put a process's executable, from `/proc` and the ELF
/// headers.
struct ImageProbe {
    exe: PathBuf,
    layout: elf::ElfLayout,
    /// `AT_ENTRY`: the runtime entry point.
    at_entry: u64,
    /// `AT_BASE`: the interpreter's load bias, 0 for a static executable.
    at_base: u64,
    load_bias: u64,
    /// `load_bias + layout.min_vaddr`.
    base: u64,
    vdso: Option<(u64, u64)>,
}

fn probe_image(pid: u32) -> Result<ImageProbe, PlatformError> {
    let exe = procfs::exe_path(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/exe: {e}")))?;
    if elf::is_elf32(&exe) {
        return Err(PlatformError::Other(format!("{} is a 32-bit executable; only x86-64 targets are supported", exe.display())));
    }
    let layout = elf::read_layout(&exe)?;
    let auxv = procfs::auxv(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/auxv: {e}")))?;
    let at_entry = procfs::auxv_value(&auxv, libc::AT_ENTRY as u64).unwrap_or(layout.entry);
    let at_base = procfs::auxv_value(&auxv, libc::AT_BASE as u64).unwrap_or(0);
    let at_phdr = procfs::auxv_value(&auxv, libc::AT_PHDR as u64);
    let maps = maps::read_maps(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/maps: {e}")))?;
    let load_bias = match (at_phdr, layout.phdr_vaddr) {
        (Some(phdr), Some(vaddr)) => phdr.wrapping_sub(vaddr),
        _ => maps
            .iter()
            .find(|m| m.offset == 0 && procfs::clean_map_path(&m.path) == exe)
            .map(|m| m.start.wrapping_sub(layout.min_vaddr))
            .unwrap_or(0),
    };
    let base = load_bias.wrapping_add(layout.min_vaddr);
    let vdso = maps::vdso_range(&maps);
    Ok(ImageProbe { exe, layout, at_entry, at_base, load_bias, base, vdso })
}

/// Arm the loader hook (`_dl_debug_state` in the interpreter, which ld.so
/// calls around every map change; static executables have none) and report
/// the modules that are there from the start: the interpreter and the vdso.
/// Each is noted as known to the loader diff and queued as a `DllLoaded`.
fn arm_loader_hook(bps: &mut breakpoints::BreakpointTable, os: &LinuxOps, pid: u32, probe: &ImageProbe) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    let at_base = probe.at_base;
    if let (true, Some(interp)) = (at_base != 0, probe.layout.interp.as_deref()) {
        let interp_path = Path::new(interp);
        match (elf::dynamic_symbol_value(interp_path, "_dl_debug_state"), elf::dynamic_symbol_value(interp_path, "_r_debug")) {
            (Ok(Some(brk)), Ok(Some(r_debug))) => {
                os.loader.lock().unwrap().r_debug = Some(at_base + r_debug);
                if let Err(e) = arm_internal(bps, os, pid, at_base + brk, loader::HOOK_LOADER) {
                    warn!(pid, error = %e, "arming the loader hook failed; module events will be missed");
                }
            }
            _ => warn!(pid, interp, "the interpreter exports no _dl_debug_state/_r_debug; module events will be missed"),
        }
        if let Ok(il) = elf::read_layout(interp_path) {
            let name = std::fs::canonicalize(interp_path).map(|p| p.display().to_string()).unwrap_or_else(|_| interp.to_string());
            let m = ModuleInfo { name, base: at_base + il.min_vaddr, size: Some(il.size) };
            os.note_known_module(at_base, m.clone());
            modules.push(m);
        }
    }
    if let Some((vbase, vsize)) = probe.vdso {
        register_vdso_image(os, vbase, vsize);
        let m = ModuleInfo { name: "[vdso]".to_string(), base: vbase, size: Some(vsize) };
        // The loader lists it as `linux-vdso.so.1` with l_addr = its base.
        os.note_known_module(vbase, m.clone());
        modules.push(m);
    }
    for m in &modules {
        os.queue(DebugEvent::DllLoaded { pid, tid: pid, dll_name: Some(m.name.clone()), base_of_dll: m.base, size_of_dll: m.size });
    }
    modules
}

pub struct LinuxPlatform {
    tracer: Tracer,
    processes: HashMap<u32, LinuxProcess>,
    symbol_manager: Option<SymbolManager>,
    disassembler: Option<CapstoneDisassembler>,
    unwinder: Mutex<unwind::Unwinder>,
    /// Signals reported as exceptions instead of delivered unseen.
    reported_signals: Arc<HashSet<i32>>,
    /// Debugged vfork children that have not exec'd yet (child -> parent).
    /// Until then they run in their parent's address space and are nobody's
    /// process; the exec makes them one.
    vfork_children: HashMap<u32, u32>,
}

impl std::fmt::Debug for LinuxPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxPlatform").field("processes", &self.processes.keys().collect::<Vec<_>>()).finish()
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self::new_with_config(SymbolConfig::default())
    }

    pub fn new_with_config(symbol_config: SymbolConfig) -> Self {
        let symbol_manager = SymbolManager::new_with_backend(symbol_config, Arc::new(elf_symbols::ElfBackend)).ok();
        let disassembler = CapstoneDisassembler::new().ok();
        Self {
            tracer: Tracer::spawn(),
            processes: HashMap::new(),
            symbol_manager,
            disassembler,
            unwinder: Mutex::new(unwind::Unwinder::default()),
            reported_signals: Arc::new(HashSet::new()),
            vfork_children: HashMap::new(),
        }
    }

    fn process(&self, pid: u32) -> Result<&LinuxProcess, PlatformError> {
        self.processes.get(&pid).ok_or_else(|| PlatformError::Other(format!("Process {} not found", pid)))
    }

    fn process_mut(&mut self, pid: u32) -> Result<&mut LinuxProcess, PlatformError> {
        self.processes.get_mut(&pid).ok_or_else(|| PlatformError::Other(format!("Process {} not found", pid)))
    }

    fn symbols(&self) -> Result<&SymbolManager, SymbolError> {
        self.symbol_manager
            .as_ref()
            .ok_or_else(|| SymbolError::SymbolsNotFound("Symbol manager not initialized".to_string()))
    }

    fn modules_for(&self, pid: u32) -> Vec<ModuleInfo> {
        self.process(pid).map(|p| p.book.modules.list_modules()).unwrap_or_default()
    }

    fn module_at(&self, pid: u32, module_base: u64) -> Result<ModuleInfo, SymbolError> {
        self.modules_for(pid)
            .into_iter()
            .find(|m| m.base == module_base)
            .ok_or_else(|| SymbolError::ModuleNotLoaded(format!("No module at base 0x{:X}", module_base)))
    }

    fn type_query_modules(&self, pid: u32, module_base: Option<u64>) -> Vec<ModuleInfo> {
        let mut modules = self.modules_for(pid);
        match module_base {
            Some(base) => modules.retain(|m| m.base == base),
            None => modules.sort_by_key(|m| m.base),
        }
        modules
    }

    fn nonblocking_symbol_resolver(&self, pid: u32) -> impl Fn(u64) -> Option<crate::interfaces::SymbolInfo> + '_ {
        disasm::nonblocking_symbol_resolver(self.symbol_manager.as_ref(), self.modules_for(pid))
    }

    // ---- process bring-up --------------------------------------------------

    /// Register a just-stopped process (at its exec stop, or freshly
    /// attached) and build its `ProcessCreated`.
    fn init_process(&mut self, pid: u32, created_by_launch: bool) -> Result<DebugEvent, PlatformError> {
        let probe = probe_image(pid)?;
        let ImageProbe { at_entry, load_bias, base, .. } = probe;
        let size = probe.layout.size;
        let mem = ProcessMemory::open(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/mem: {e}")))?;

        let mut threads = ThreadTable::new();
        let tids = procfs::thread_ids(pid).unwrap_or_else(|_| vec![pid]);
        for tid in &tids {
            threads.insert(*tid, if *tid == pid { at_entry } else { 0 }, ());
        }
        let os = LinuxOps::new(pid, self.tracer.clone(), mem, threads, probe.vdso, at_entry);
        let mut book = DebugBook::new(Architecture::X64);
        book.created_by_launch = created_by_launch;
        let exe_str = probe.exe.display().to_string();
        let main_module = ModuleInfo { name: exe_str.clone(), base, size: Some(size) };
        book.modules.add_module(main_module.clone());
        if let Some(sm) = &self.symbol_manager {
            sm.start_loading_symbols(&main_module);
        }
        // The loader lists the executable under its load bias (0 unless PIE).
        os.note_known_module(load_bias, main_module);

        for m in arm_loader_hook(&mut book.bps, &os, pid, &probe) {
            book.modules.add_module(m.clone());
            if let Some(sm) = &self.symbol_manager {
                sm.start_loading_symbols(&m);
            }
        }
        if created_by_launch {
            // The entry hook becomes the `InitialBreakpoint`, once the loader
            // has mapped the program's libraries.
            if let Err(e) = arm_internal(&mut book.bps, &os, pid, at_entry, loader::HOOK_ENTRY) {
                warn!(pid, error = %e, "arming the entry hook failed");
            }
        }

        let event = DebugEvent::ProcessCreated {
            pid,
            tid: pid,
            image_file_name: Some(exe_str),
            base_of_image: base,
            size_of_image: Some(size),
            start_address: at_entry,
        };
        self.processes.insert(pid, LinuxProcess::new(os, book, probe.exe, false));
        Ok(event)
    }

    /// Pull one queued event (loader diff, attach synthesis), applying any
    /// module-table change it implies.
    fn next_queued(&mut self, pid: u32) -> Option<DebugEvent> {
        let process = self.processes.get_mut(&pid)?;
        let event = process.os.queued.lock().unwrap().pop_front()?;
        match &event {
            DebugEvent::InitialBreakpoint { .. } => {
                process.book.has_hit_initial_breakpoint = true;
            }
            DebugEvent::DllLoaded { dll_name: Some(name), base_of_dll, size_of_dll, .. } => {
                let m = ModuleInfo { name: name.clone(), base: *base_of_dll, size: *size_of_dll };
                process.book.modules.add_module(m.clone());
                // Includes `[vdso]`: its image was registered with the symbol
                // loader when the process was set up.
                if let Some(sm) = &self.symbol_manager {
                    sm.start_loading_symbols(&m);
                }
            }
            DebugEvent::DllUnloaded { base_of_dll, .. } => {
                process.book.modules.remove_module(*base_of_dll);
            }
            _ => {}
        }
        Some(event)
    }

    /// Pull a queued event of any debugged process (lowest pid first).
    fn next_queued_any(&mut self) -> Option<DebugEvent> {
        let mut pids: Vec<u32> = self.processes.iter().filter(|(_, p)| !p.open_only).map(|(pid, _)| *pid).collect();
        pids.sort_unstable();
        pids.into_iter().find_map(|pid| self.next_queued(pid))
    }

    /// The continue loop behind `server_continue`: release `(pid, tid)` from
    /// the event it reported, then wait for the next event of any debugged
    /// process, the way `ContinueDebugEvent` + `WaitForDebugEvent` do.
    fn run_until_event(
        platform: &Arc<RwLock<Self>>,
        pid: u32,
        tid: u32,
        pass_exception: bool,
    ) -> Result<Option<DebugEvent>, PlatformError> {
        let tracer;
        // The process to set running before the next wait.
        let mut kick: Option<(u32, u32, i32)> = None;
        {
            let mut p = platform.write().unwrap();
            tracer = p.tracer.clone();
            if let Some(event) = p.next_queued(pid) {
                return Ok(Some(event));
            }
            match p.processes.get_mut(&pid) {
                Some(process) if process.open_only => {
                    return Err(PlatformError::Other(format!("process {pid} is open, not debugged")));
                }
                // Continuing past a reported exit releases the process, like
                // `ContinueDebugEvent` on EXIT_PROCESS: a debugged child's
                // exit is continued, not finalized, by the client.
                Some(process) if process.exited.is_some() => {
                    let reaped = process.reaped;
                    if let Err(e) = if reaped { tracer.forget(pid) } else { tracer.reap(pid) } {
                        warn!(pid, error = %e, "releasing the exited process failed");
                    }
                    p.remove_process(pid);
                    if !p.has_debugged_processes() {
                        return Err(PlatformError::Other(format!("process {pid} has exited")));
                    }
                }
                Some(process) => {
                    let mut signal = 0;
                    match process.last_fault.remove(&tid) {
                        Some(mut pending) if pass_exception => {
                            // Passing a signal nobody handles kills the process:
                            // stop once more first, as a second-chance exception.
                            if !pending.second_chance_reported && signals::kills_if_delivered(pid, pending.signo) {
                                pending.second_chance_reported = true;
                                let event = DebugEvent::Exception {
                                    pid,
                                    tid,
                                    code: pending.code,
                                    address: pending.address,
                                    first_chance: false,
                                    parameters: pending.parameters.clone(),
                                };
                                process.last_fault.insert(tid, pending);
                                return Ok(Some(event));
                            }
                            signal = pending.signo;
                        }
                        _ => {}
                    }
                    process.step_over_breakpoint_at_pc(pid, tid)?;
                    kick = Some((pid, tid, signal));
                }
                None => {
                    if !p.has_debugged_processes() {
                        return Err(PlatformError::Other(format!("Process {} not found", pid)));
                    }
                }
            }
        }
        loop {
            let queued_stop = match kick.take() {
                Some((kick_pid, kick_tid, signal)) => {
                    let replay_deferred = {
                        let p = platform.read().unwrap();
                        p.process(kick_pid).map(|pr| pr.book.steps.exclusive_stepper().is_none()).unwrap_or(true)
                    };
                    tracer.kick(kick_pid, kick_tid, signal, replay_deferred)?
                }
                None => None,
            };
            let stop = match queued_stop {
                Some(stop) => stop,
                None => {
                    // Another process may already have something to say (a
                    // child set up at its parent's fork) and nothing running.
                    if let Some(event) = platform.write().unwrap().next_queued_any() {
                        return Ok(Some(event));
                    }
                    tracer.wait_any()?
                }
            };
            match platform.write().unwrap().dispatch_stop(stop)? {
                Dispatch::Event(event) => return Ok(Some(event)),
                Dispatch::Kick(kick_pid, kick_tid, signal) => kick = Some((kick_pid, kick_tid, signal)),
                Dispatch::Wait => {}
            }
        }
    }

    fn has_debugged_processes(&self) -> bool {
        !self.vfork_children.is_empty() || self.processes.values().any(|p| !p.open_only)
    }

    /// One tracer stop, turned into an event or into what to resume.
    fn dispatch_stop(&mut self, stop: tracer::Stop) -> Result<Dispatch, PlatformError> {
        let pid = stop.pid;
        if self.vfork_children.contains_key(&pid) {
            return Ok(self.dispatch_pre_exec_child_stop(stop));
        }
        let reported = self.reported_signals.clone();
        let Some(process) = self.processes.get_mut(&pid).filter(|p| !p.open_only) else {
            // Nobody's process (a child we could not set up): let it go.
            warn!(pid, tid = stop.tid, kind = ?stop.kind, "stop from a process that is not debugged; detaching it");
            let _ = self.tracer.detach(pid);
            return Ok(Dispatch::Wait);
        };
        // Another thread's trap while one thread steps over a removed
        // breakpoint: hand it back, keep that thread stopped, carry on.
        if matches!(stop.kind, StopKind::Signal { signo: libc::SIGTRAP, .. }) && process.book.steps.is_stepping_over_other_thread(stop.tid) {
            trace!(pid, tid = stop.tid, "deferring a stop during another thread's step-over");
            let tid = stop.tid;
            process.os.tracer.defer(stop)?;
            return Ok(Dispatch::Kick(pid, tid, 0));
        }
        let tid = stop.tid;
        let mut handled = process.handle_stop(stop, &reported)?;
        // A SIGSEGV says where, not how: recover read/write/execute from
        // the faulting instruction so the record reads like Windows'.
        if let Some(DebugEvent::Exception { code, address, parameters, .. }) = &mut handled.event {
            if signals::is_memory_fault(*code) && parameters.len() == 2 {
                // The engine is thread-local behind a unit struct, so a fresh
                // handle costs nothing and sidesteps the platform borrow.
                if let (Ok(disasm), Ok(bytes)) = (CapstoneDisassembler::new(), process.os.read(pid, *address, 16)) {
                    parameters[0] = disasm.x86_fault_access_kind(process.book.arch, &bytes, *address, parameters[1]);
                    if let Some(pending) = process.last_fault.get_mut(&tid) {
                        pending.parameters = parameters.clone();
                    }
                }
            }
        }
        let exec_pending = std::mem::take(&mut process.exec_pending);
        let pending_fork = process.pending_fork.take();
        if exec_pending {
            if let Err(e) = self.reinit_after_exec(pid) {
                warn!(pid, error = %e, "re-reading the image after exec failed");
            }
        }
        if let Some((child, vfork)) = pending_fork {
            self.on_fork(pid, child, vfork);
        }
        Ok(match handled.event {
            Some(event) => Dispatch::Event(event),
            None => match self.next_queued(pid) {
                Some(event) => Dispatch::Event(event),
                None => Dispatch::Kick(pid, tid, handled.reinject.unwrap_or(0)),
            },
        })
    }

    /// `parent` forked `child` (already seized and stopped by the tracer).
    ///
    /// A fork child has a copy of the address space, breakpoint patches
    /// included: it gets the original bytes back, and is then either debugged
    /// as a process of its own or let go. A vfork child *shares* the address
    /// space until it execs or exits, so the patches come out for that window
    /// (`PTRACE_EVENT_VFORK_DONE` puts them back) and a debugged one becomes
    /// a process at its exec.
    fn on_fork(&mut self, parent: u32, child: u32, vfork: bool) {
        let Some(process) = self.processes.get_mut(&parent) else { return };
        let debug_child = process.debug_children;
        debug!(parent, child, vfork, debug_child, "fork");
        if vfork {
            process.lift_breakpoints_for_vfork(parent);
            if debug_child {
                self.vfork_children.insert(child, parent);
                if let Err(e) = self.tracer.kick(child, child, 0, false) {
                    warn!(child, error = %e, "resuming the vfork child failed");
                    self.vfork_children.remove(&child);
                }
            } else if let Err(e) = self.tracer.detach(child) {
                warn!(parent, child, error = %e, "detaching the vfork child failed");
            }
            return;
        }
        match ProcessMemory::open(child) {
            Ok(mem) => {
                for (addr, original) in process.book.bps.iter_originals() {
                    let _ = mem.write(addr, original);
                }
            }
            Err(e) => warn!(child, error = %e, "the forked child keeps the parent's breakpoint bytes"),
        }
        if debug_child {
            match self.adopt_forked_child(child) {
                Ok(()) => return,
                Err(e) => {
                    warn!(parent, child, error = %e, "setting the forked child up failed; it runs undebugged");
                    self.remove_process(child);
                }
            }
        }
        if let Err(e) = self.tracer.detach(child) {
            warn!(parent, child, error = %e, "detaching the forked child failed");
        }
    }

    /// Make a fork child a debugged process: the same image as its parent,
    /// announced the way an attach is (`ProcessCreated`, its modules, then
    /// an `InitialBreakpoint` where it stands, inside `fork`).
    fn adopt_forked_child(&mut self, child: u32) -> Result<(), PlatformError> {
        let created = self.init_process(child, false)?;
        let process = self.process_mut(child)?;
        process.debug_children = true;
        // `init_process` queued the interpreter and vdso; the creation goes first.
        process.os.queued.lock().unwrap().push_front(created);
        if let Err(e) = process.os.sync_modules() {
            warn!(child, error = %e, "link-map walk failed for the forked child");
        }
        let rip = process.os.image(child).map(|i| i.regs.rip).unwrap_or(0);
        process.os.queue(DebugEvent::InitialBreakpoint { pid: child, tid: child, address: rip });
        Ok(())
    }

    /// A stop of a debugged vfork child before its exec. It is not a process
    /// of ours yet (it runs in its parent's memory): only the exec is news.
    fn dispatch_pre_exec_child_stop(&mut self, stop: tracer::Stop) -> Dispatch {
        let child = stop.pid;
        match stop.kind {
            StopKind::Exec => {
                self.vfork_children.remove(&child);
                match self.init_process(child, true) {
                    Ok(event) => {
                        if let Some(process) = self.processes.get_mut(&child) {
                            process.debug_children = true;
                        }
                        Dispatch::Event(event)
                    }
                    Err(e) => {
                        warn!(child, error = %e, "setting the exec'd child up failed; it runs undebugged");
                        self.remove_process(child);
                        let _ = self.tracer.detach(child);
                        Dispatch::Wait
                    }
                }
            }
            StopKind::Exit { last_thread: true, .. } => {
                self.vfork_children.remove(&child);
                let _ = self.tracer.reap(child);
                Dispatch::Wait
            }
            StopKind::Gone { .. } => {
                self.vfork_children.remove(&child);
                let _ = self.tracer.forget(child);
                Dispatch::Wait
            }
            StopKind::Fork { child: grandchild, .. } => {
                let _ = self.tracer.detach(grandchild);
                Dispatch::Kick(child, stop.tid, 0)
            }
            StopKind::Signal { signo, code, .. } => {
                let pass = match signals::classify(signo, code) {
                    signals::SignalClass::Swallow => 0,
                    _ if signo == libc::SIGTRAP => 0,
                    _ => signo,
                };
                Dispatch::Kick(child, stop.tid, pass)
            }
            _ => Dispatch::Kick(child, stop.tid, 0),
        }
    }

    fn remove_process(&mut self, pid: u32) {
        self.processes.remove(&pid);
    }
}

/// Plant one of the backend's own breakpoints.
fn arm_internal(bps: &mut breakpoints::BreakpointTable, ops: &LinuxOps, pid: u32, address: u64, hook_id: u32) -> Result<(), PlatformError> {
    let bytes = breakpoints::breakpoint_bytes(Architecture::X64);
    let original = ops.read(pid, address, bytes.len())?;
    bps.insert_internal(address, original, hook_id);
    ops.write(pid, address, &bytes)
}

impl Stepper for LinuxPlatform {
    fn step(&mut self, pid: u32, tid: u32, kind: StepKind) -> Result<Option<DebugEvent>, PlatformError> {
        // Step-out only needs the caller's frame.
        let call_stack = if kind == StepKind::Out {
            let frames = self.unwind(pid, tid, 2).map_err(|e| PlatformError::Other(format!("Failed to get call stack for step-out: {}", e)))?;
            Some(frames.into_iter().map(|f| CallFrame { instruction_pointer: f.pc, stack_pointer: f.sp, frame_pointer: f.fp, symbol: None }).collect())
        } else {
            None
        };
        let disasm = self.disassembler.as_ref().ok_or_else(|| PlatformError::Other("Disassembler not initialized".to_string()))?;
        let process = self.processes.get_mut(&pid).ok_or_else(|| PlatformError::Other(format!("Process {} not found", pid)))?;
        // A step drops any fault that was waiting to be passed on.
        process.last_fault.remove(&tid);
        stepping::step(&mut process.book, &process.os, disasm, pid, tid, kind, call_stack)
    }
}

/// The vdso has no file: hand its bytes to the symbol loader so `[vdso]`
/// resolves like any other module (`__vdso_clock_gettime` etc.).
fn register_vdso_image(os: &LinuxOps, base: u64, size: u64) {
    match os.read(os.pid, base, size as usize) {
        Ok(bytes) if bytes.len() == size as usize => elf_symbols::register_in_memory_image("[vdso]", bytes),
        Ok(_) => warn!(pid = os.pid, "short read of the vdso; its symbols will be missing"),
        Err(e) => warn!(pid = os.pid, error = %e, "reading the vdso failed; its symbols will be missing"),
    }
}

impl LinuxPlatform {
    /// The process replaced its image (`execve`): every module is gone, every
    /// breakpoint with it, `/proc/pid/mem` is bound to the old address space
    /// and the kernel left only the leader thread. Report the unloads, then
    /// set the new image up the way a launch does — loader hook, entry hook
    /// (now an ordinary `Breakpoint`: the one `InitialBreakpoint` is spent)
    /// and the new executable, interpreter and vdso as loaded modules.
    fn reinit_after_exec(&mut self, pid: u32) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        let os = &process.os;
        let book = &mut process.book;

        for m in book.modules.list_modules() {
            os.queue(DebugEvent::DllUnloaded { pid, tid: pid, base_of_dll: m.base });
        }
        // Forget everything that referred to the old address space.
        book.modules.clear();
        let _ = book.bps.drain_all();
        book.bps.clear_step_over();
        book.bps.clear_step_out();
        book.steps = Default::default();
        book.hw = Default::default();
        book.coverage.forget();
        {
            let mut threads = os.threads.lock().unwrap();
            threads.clear();
            threads.insert(pid, 0, ());
        }
        *os.loader.lock().unwrap() = loader::LoaderState::default();
        *os.mem.write().unwrap() = ProcessMemory::open(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/mem after exec: {e}")))?;

        let probe = probe_image(pid)?;
        let ImageProbe { at_entry, load_bias, base, .. } = probe;
        *os.vdso.lock().unwrap() = probe.vdso;
        os.entry.store(at_entry, std::sync::atomic::Ordering::Relaxed);
        os.after_exec.store(true, std::sync::atomic::Ordering::Relaxed);

        let exe_str = probe.exe.display().to_string();
        let main_module = ModuleInfo { name: exe_str.clone(), base, size: Some(probe.layout.size) };
        os.note_known_module(load_bias, main_module.clone());
        os.queue(DebugEvent::DllLoaded { pid, tid: pid, dll_name: Some(exe_str), base_of_dll: base, size_of_dll: main_module.size });

        // The queued `DllLoaded`s put the modules in the table.
        arm_loader_hook(&mut book.bps, os, pid, &probe);
        if let Err(e) = arm_internal(&mut book.bps, os, pid, at_entry, loader::HOOK_ENTRY) {
            warn!(pid, error = %e, "arming the entry hook after exec failed");
        }
        process.exe = probe.exe;
        Ok(())
    }
}

impl LinuxProcess {
    /// A vfork child is about to run in this address space: take every
    /// breakpoint patch out so it cannot trip over one (it would die of the
    /// SIGTRAP, or report a stop that belongs to nobody).
    fn lift_breakpoints_for_vfork(&mut self, pid: u32) {
        for (addr, original) in self.book.bps.iter_originals() {
            if let Err(e) = self.os.write(pid, addr, original) {
                warn!(pid, address = %format!("{addr:#x}"), error = %e, "lifting a breakpoint for a vfork child failed");
            }
        }
        self.vfork_lifted = true;
    }

    /// The vfork child is out of the address space: put the patches back
    /// wherever the original instruction is still in place.
    pub(crate) fn rearm_breakpoints_after_vfork(&mut self, pid: u32) {
        if !std::mem::take(&mut self.vfork_lifted) {
            return;
        }
        let bytes = breakpoints::breakpoint_bytes(self.book.arch);
        for (addr, original) in self.book.bps.iter_originals() {
            if self.os.read(pid, addr, original.len()).is_ok_and(|current| current == *original) {
                if let Err(e) = self.os.write(pid, addr, &bytes) {
                    warn!(pid, address = %format!("{addr:#x}"), error = %e, "re-arming a breakpoint after a vfork failed");
                }
            }
        }
    }

    /// Resuming with a user breakpoint armed under `tid`'s PC (set while the
    /// thread sat there - the initial breakpoint is at the entry point, so a
    /// breakpoint on the entry point is the common case) would trap on that
    /// very instruction. Do what every debugger does: run the original
    /// instruction under a single step with the breakpoint lifted, re-arm it
    /// from the step (the same path a breakpoint hit takes), then continue.
    fn step_over_breakpoint_at_pc(&mut self, pid: u32, tid: u32) -> Result<(), PlatformError> {
        // A user step owns its own re-arm (`stepping::step` lifts the
        // breakpoint and re-arms on completion); a re-arm or step-over
        // already in flight means the breakpoint is lifted right now.
        if self.book.steps.has_active_single_step(tid)
            || self.book.steps.has_pending_rearm_for_tid(tid)
            || self.book.steps.exclusive_stepper().is_some()
        {
            return Ok(());
        }
        let pc = self.os.image(tid)?.regs.rip;
        if !self.book.bps.is_persistent(pc) {
            return Ok(());
        }
        trace!(pid, tid, pc = %format!("{pc:#x}"), "resuming on an armed breakpoint; stepping over it first");
        breakpoints::restore_persistent_original(&self.book.bps, &self.os, pid, pc)?;
        self.os.modify_context(pid, tid, &mut |context| {
            context.set_single_step(true);
            Ok(())
        })?;
        self.book.steps.schedule_rearm_after_single_step(tid, pc, false);
        stepping::begin_step_over(&mut self.book, &self.os, pid, tid, pc, "resume at breakpoint");
        Ok(())
    }
}

impl LinuxPlatform {
    /// Run one system call in the target: a stopped thread is pointed at a
    /// `syscall` instruction with the number and arguments in its registers,
    /// steps that one instruction, and gets its registers back. Returns the
    /// raw result (`-errno` on failure).
    fn inject_syscall(&self, pid: u32, number: u64, args: [u64; 6]) -> Result<u64, PlatformError> {
        let process = self.process(pid)?;
        if process.open_only {
            return Err(PlatformError::Other("the process is open, not debugged: nothing can be run in it".into()));
        }
        let os = &process.os;
        let tid = os
            .live_threads(pid)
            .into_iter()
            .find(|&t| os.image(t).is_ok())
            .ok_or_else(|| PlatformError::Other("no stopped thread to run the system call on: pause the target first".into()))?;
        let image = os.image(tid)?;
        os.tracer.set_regs(tid, self.syscall_setup(pid, &image, number, &args)?)?;
        let stepped = os.tracer.step_thread(tid);
        let result = os.image(tid).map(|after| after.regs.rax);
        // The thread's own state comes back whatever happened.
        os.tracer.set_regs(tid, regs::ContextWrite { regs: image.regs, fpregs: image.fpregs, debug: image.debug, trap_flag: image.trap_flag_pending })?;
        stepped?;
        result
    }

    /// `image` with the PC on a `syscall` instruction and the call's number
    /// and leading arguments in its registers.
    fn syscall_setup(&self, pid: u32, image: &regs::RegisterImage, number: u64, args: &[u64]) -> Result<regs::ContextWrite, PlatformError> {
        let mut regs = image.regs;
        regs.rip = self.find_syscall_gadget(pid, regs.rip)?;
        regs.rax = number;
        for (reg, &arg) in [&mut regs.rdi, &mut regs.rsi, &mut regs.rdx, &mut regs.r10, &mut regs.r8, &mut regs.r9].into_iter().zip(args) {
            *reg = arg;
        }
        // Not "inside a syscall": no restart bookkeeping on resume.
        regs.orig_rax = u64::MAX;
        Ok(regs::ContextWrite { regs, fpregs: image.fpregs, debug: image.debug, trap_flag: false })
    }

    /// Address of a `syscall` (0F 05) the target can be pointed at. A thread
    /// stopped inside a syscall has one right behind its PC; otherwise the
    /// first one in the vdso or libc's text is used.
    fn find_syscall_gadget(&self, pid: u32, rip: u64) -> Result<u64, PlatformError> {
        const SYSCALL: [u8; 2] = [0x0F, 0x05];
        let process = self.process(pid)?;
        if rip >= 2 {
            if let Ok(bytes) = process.os.read(pid, rip - 2, 2) {
                if bytes == SYSCALL {
                    return Ok(rip - 2);
                }
            }
        }
        // Only executable pages of the vdso / libc: the byte pair also occurs
        // in data (symbol tables, strings), and a `syscall` the thread cannot
        // execute from faults instead. Module order is a map walk, so without
        // this the gadget — and the outcome — would vary between runs.
        let regions = self.enumerate_memory_regions(pid)?;
        let modules = self.modules_for(pid);
        let candidates = modules.iter().filter(|m| m.name == "[vdso]" || m.name.contains("libc.so"));
        for module in candidates {
            let module_end = module.base + module.size.unwrap_or(0);
            for region in regions.iter().filter(|r| {
                r.base_address < module_end
                    && r.base_address + r.region_size > module.base
                    && r.protect & maps::PAGE_EXECUTABLE_MASK != 0
            }) {
                let start = region.base_address.max(module.base);
                let end = (region.base_address + region.region_size).min(module_end);
                let mut at = start;
                while at < end {
                    let len = ((end - at) as usize).min(0x10000);
                    let Ok(chunk) = process.os.read(pid, at, len) else { break };
                    if let Some(pos) = chunk.windows(2).position(|w| w == SYSCALL) {
                        return Ok(at + pos as u64);
                    }
                    at += len.max(1) as u64;
                }
            }
        }
        Err(PlatformError::Other("no executable syscall instruction found to run the thread through".into()))
    }
}

impl PlatformAPI for LinuxPlatform {
    fn launch(&mut self, command: &str, debug_children: bool, working_directory: Option<&str>, environment: Option<&[(String, String)]>) -> Result<Option<DebugEvent>, PlatformError> {
        let argv = launch::split_command(command)?;
        let cwd = working_directory
            .map(|d| CString::new(d).map_err(|_| PlatformError::Other("NUL in working directory".into())))
            .transpose()?;
        let envp = launch::build_envp(environment);
        info!(command, "launching");
        let launched = self.tracer.launch(argv, cwd, envp)?;
        match self.init_process(launched.pid, true) {
            Ok(event) => {
                self.process_mut(launched.pid)?.debug_children = debug_children;
                Ok(Some(event))
            }
            Err(e) => {
                let _ = self.tracer.detach(launched.pid);
                // SAFETY: plain syscall on a pid we created.
                unsafe { libc::kill(launched.pid as libc::pid_t, libc::SIGKILL) };
                Err(e)
            }
        }
    }

    fn attach(&mut self, pid: u32) -> Result<Option<DebugEvent>, PlatformError> {
        // An Open (non-invasive) session upgrading to a debug session: drop
        // the /proc-only view, the traced one is rebuilt from scratch.
        if self.processes.get(&pid).is_some_and(|p| p.open_only) {
            self.remove_process(pid);
        }
        let attached = self.tracer.attach(pid)?;
        let event = match self.init_process(pid, false) {
            Ok(e) => e,
            Err(e) => {
                let _ = self.tracer.detach(pid);
                return Err(e);
            }
        };
        let process = self.process_mut(pid)?;
        // Already-loaded libraries, the other threads, then the break-in.
        if let Err(e) = process.os.sync_modules() {
            warn!(pid, error = %e, "link-map walk failed on attach");
        }
        for &tid in &attached.tids {
            if tid == pid {
                continue;
            }
            let start_address = process.os.image(tid).map(|i| i.regs.rip).unwrap_or(0);
            process.os.threads.lock().unwrap().insert(tid, start_address, ());
            process.os.queue(DebugEvent::ThreadCreated { pid, tid, start_address });
        }
        let rip = process.os.image(pid).map(|i| i.regs.rip).unwrap_or(0);
        process.book.has_hit_initial_breakpoint = true;
        process.os.queue(DebugEvent::InitialBreakpoint { pid, tid: pid, address: rip });
        Ok(Some(event))
    }

    /// Non-invasive open: `/proc/pid/mem` for memory, `/proc/pid/maps` for
    /// modules and regions, `/proc/pid/task` for threads — and no ptrace, so
    /// the target never stops. Needs the same permission as attaching would
    /// (Yama: a descendant, `PR_SET_PTRACER`, or `CAP_SYS_PTRACE`).
    fn open_process(&mut self, pid: u32) -> Result<(), PlatformError> {
        if self.processes.contains_key(&pid) {
            return Ok(());
        }
        let exe = procfs::exe_path(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/exe: {e}")))?;
        // Opening /proc/pid/mem is gated by the same check as ptrace attach.
        let mem = ProcessMemory::open(pid).map_err(|e| tracer::attach_error(pid, e))?;
        let maps = maps::read_maps(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/maps: {e}")))?;
        let mut threads = ThreadTable::new();
        for tid in procfs::thread_ids(pid).unwrap_or_else(|_| vec![pid]) {
            threads.insert(tid, 0, ());
        }
        let vdso = maps::vdso_range(&maps);
        let os = LinuxOps::new(pid, self.tracer.clone(), mem, threads, vdso, 0);
        let mut book = DebugBook::new(Architecture::X64);
        book.has_hit_initial_breakpoint = true;
        // Every ELF mapped from a file at offset 0 is a module; its first
        // mapping is the image base (the lowest PT_LOAD is page-aligned).
        let mut seen = HashSet::new();
        for m in &maps {
            if m.offset != 0 || m.path.is_empty() || m.path.starts_with('[') || !seen.insert(m.path.clone()) {
                continue;
            }
            let path = procfs::clean_map_path(&m.path);
            // Data files are mapped at offset 0 too (locale archives, caches).
            if !elf::is_elf(path) {
                continue;
            }
            let Ok(layout) = elf::read_layout(path) else { continue };
            let name = path.display().to_string();
            let module = ModuleInfo { name, base: m.start, size: Some(layout.size) };
            book.modules.add_module(module.clone());
            if let Some(sm) = &self.symbol_manager {
                sm.start_loading_symbols(&module);
            }
        }
        if let Some((vbase, vsize)) = vdso {
            register_vdso_image(&os, vbase, vsize);
            let m = ModuleInfo { name: "[vdso]".to_string(), base: vbase, size: Some(vsize) };
            book.modules.add_module(m.clone());
            if let Some(sm) = &self.symbol_manager {
                sm.start_loading_symbols(&m);
            }
        }
        self.processes.insert(pid, LinuxProcess::new(os, book, exe, true));
        Ok(())
    }

    fn close_process(&mut self, pid: u32) -> Result<(), PlatformError> {
        if self.processes.get(&pid).is_some_and(|p| p.open_only) {
            self.remove_process(pid);
        }
        Ok(())
    }

    fn detach(&mut self, pid: u32) -> Result<(), PlatformError> {
        if let Ok(process) = self.process_mut(pid) {
            stepping::resume_all_step_over_suspensions(&mut process.book.steps, &process.os, pid);
            breakpoints::restore_all(&mut process.book.bps, &process.os, pid);
            process.book.coverage.forget();
            for tid in process.os.live_threads(pid) {
                let _ = process.os.tracer.set_debug_regs(tid, [0; 8]);
            }
        }
        self.tracer.detach(pid)?;
        self.remove_process(pid);
        Ok(())
    }

    fn continue_exec(&mut self, _pid: u32, _tid: u32) -> Result<Option<DebugEvent>, PlatformError> {
        // The server drives continues through `server_continue`, which needs
        // the shared lock to wait outside of; a bare `&mut self` cannot.
        Err(PlatformError::Other("continue_exec is served through server_continue on Linux".into()))
    }

    fn server_continue(platform: &Arc<RwLock<Self>>, pid: u32, tid: u32, pass_exception: bool) -> Result<Option<DebugEvent>, PlatformError> {
        Self::run_until_event(platform, pid, tid, pass_exception)
    }

    fn server_finalize_exited_process(platform: &Arc<RwLock<Self>>, pid: u32, _tid: u32) -> Result<(), PlatformError> {
        let (tracer, reaped) = {
            let p = platform.read().unwrap();
            match p.process(pid) {
                Ok(pr) => (pr.os.tracer.clone(), pr.reaped),
                Err(_) => return Ok(()),
            }
        };
        let result = if reaped { tracer.forget(pid) } else { tracer.reap(pid) };
        platform.write().unwrap().remove_process(pid);
        result
    }

    fn set_reported_signals(&mut self, signals: &[u32]) -> Result<(), PlatformError> {
        self.reported_signals = Arc::new(signals.iter().filter(|s| (1..=crate::posix_signals::SIGNAL_MAX).contains(*s)).map(|s| *s as i32).collect());
        Ok(())
    }

    fn write_minidump(&self, pid: u32, path: &str, kind: crate::protocol::MinidumpKind) -> Result<u64, PlatformError> {
        coredump::write_core(self, pid, Path::new(path), kind)
    }

    fn list_process_objects(&self, pid: u32) -> Result<crate::protocol::ProcessObjects, PlatformError> {
        self.process(pid)?;
        Ok(objects::list_process_objects(pid))
    }

    /// `close(fd)` in the target, by syscall injection on a stopped thread.
    fn close_remote_handle(&self, pid: u32, handle: u64) -> Result<(), PlatformError> {
        let result = self.inject_syscall(pid, libc::SYS_close as u64, [handle, 0, 0, 0, 0, 0])?;
        if (result as i64) < 0 {
            return Err(PlatformError::OsError(format!("close({handle}) in the target failed: {}", std::io::Error::from_raw_os_error(-(result as i64) as i32))));
        }
        Ok(())
    }

    fn set_breakpoint(&mut self, pid: u32, addr: u64, tid: Option<u32>) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        breakpoints::arm_persistent(&mut process.book.bps, &process.os, pid, addr, tid)
    }

    fn remove_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        breakpoints::remove_breakpoint(&mut process.book.bps, &process.os, pid, addr)
    }

    fn set_single_shot_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        breakpoints::arm_single_shot(&mut process.book.bps, &process.os, pid, addr)
    }

    fn set_hardware_breakpoint(&mut self, pid: u32, addr: u64, bp_type: crate::protocol::HardwareBreakpointType, size: crate::protocol::HardwareBreakpointSize) -> Result<u8, PlatformError> {
        let process = self.process_mut(pid)?;
        hw_breakpoints::set_hardware_breakpoint(&mut process.book, &process.os, pid, addr, bp_type, size)
    }

    fn remove_hardware_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        hw_breakpoints::remove_hardware_breakpoint(&mut process.book, &process.os, pid, addr)
    }

    fn enumerate_coverage_targets(&self, pid: u32, module_path: &str, sources: &[crate::protocol::CoverageTargetSource]) -> Result<Vec<crate::protocol::CoverageTarget>, PlatformError> {
        let arch = self.process(pid)?.book.arch;
        let symbol_manager = self.symbol_manager.as_ref().ok_or_else(|| PlatformError::Other("Symbol manager unavailable".to_string()))?;
        let disassembler = self.disassembler.as_ref().ok_or_else(|| PlatformError::Other("Disassembler unavailable".to_string()))?;
        crate::debugger_core::coverage_targets::enumerate_coverage_targets(self, symbol_manager, disassembler, arch, pid, module_path, sources)
    }

    fn start_code_coverage(&mut self, pid: u32, addrs: &[u64], limit: u64) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        coverage::start_code_coverage(&mut process.book, &process.os, pid, addrs, limit)
    }

    fn get_code_coverage(&self, pid: u32) -> Result<Vec<crate::protocol::CoverageHit>, PlatformError> {
        Ok(self.process(pid)?.book.coverage.snapshot())
    }

    fn stop_code_coverage(&mut self, pid: u32) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        coverage::clear_coverage(&mut process.book, &process.os, pid);
        Ok(())
    }

    fn start_watchpoint_trace(&mut self, pid: u32, addr: u64, bp_type: crate::protocol::HardwareBreakpointType, size: crate::protocol::HardwareBreakpointSize) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        watchpoints::start_trace(&mut process.book, &process.os, pid, addr, bp_type, size)
    }

    fn get_watchpoint_accesses(&self, pid: u32, addr: u64) -> Result<Vec<crate::protocol::WatchpointAccess>, PlatformError> {
        let mut accesses = self.process(pid)?.book.watch.snapshot(addr);
        for a in &mut accesses {
            a.accessor = watchpoints::attribute_accessor(self, pid, a.accessor_raw_rip);
        }
        Ok(accesses)
    }

    fn stop_watchpoint_trace(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError> {
        let process = self.process_mut(pid)?;
        watchpoints::stop_trace(&mut process.book, &process.os, pid, addr)
    }

    fn read_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError> {
        let process = self.process(pid)?;
        let mut data = process.os.read(pid, address, size)?;
        // The loader/entry hooks are the debugger's, not the user's.
        process.book.bps.hide_internal_bytes(address, &mut data);
        Ok(data)
    }

    fn write_memory(&self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        self.process(pid)?.os.write(pid, address, data)
    }

    /// `VirtualAllocEx` by syscall injection (see `inject_syscall`).
    fn allocate_memory(&self, pid: u32, size: usize, executable: bool) -> Result<u64, PlatformError> {
        let prot = (libc::PROT_READ | libc::PROT_WRITE | if executable { libc::PROT_EXEC } else { 0 }) as u64;
        let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        let address = self.inject_syscall(pid, libc::SYS_mmap as u64, [0, size.max(1) as u64, prot, flags, u64::MAX, 0])?;
        if (address as i64) < 0 && (address as i64) > -4096 {
            return Err(PlatformError::OsError(format!("mmap in the target failed: errno {}", -(address as i64))));
        }
        Ok(address)
    }

    fn read_wide_string(&self, pid: u32, address: u64, max_len: Option<usize>) -> Result<String, PlatformError> {
        strings::read_wide_string(|a, n| self.read_memory(pid, a, n), address, max_len)
    }

    fn get_thread_context(&self, pid: u32, tid: u32) -> Result<ThreadContext, PlatformError> {
        self.process(pid)?.os.get_context(pid, tid)
    }

    fn set_thread_context(&self, pid: u32, tid: u32, context: ThreadContext) -> Result<(), PlatformError> {
        self.process(pid)?.os.set_context(pid, tid, context)
    }

    fn get_function_arguments(&self, pid: u32, tid: u32, count: usize) -> Result<Vec<u64>, PlatformError> {
        let context = self.get_thread_context(pid, tid)?;
        function_args::function_arguments(function_args::CallingConvention::SysV64, &context, count, |a, n| self.read_memory(pid, a, n))
    }

    fn list_modules(&self, pid: u32) -> Result<Vec<ModuleInfo>, PlatformError> {
        Ok(self.process(pid)?.book.modules.list_modules())
    }

    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
        Ok(self.process(pid)?.os.threads.lock().unwrap().list_threads())
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        procfs::list_processes().map_err(|e| PlatformError::OsError(format!("/proc: {e}")))
    }

    fn find_symbol(&self, symbol_name: &str, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        self.symbols()?.find_symbol_across_all_modules(symbol_name, max_results)
    }

    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        self.symbols()?.list_symbols_raw(module_path)
    }

    fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<ModuleSymbol>, SymbolError> {
        self.symbols()?.resolve_rva_to_symbol_raw(module_path, rva)
    }

    fn resolve_address_to_symbol(&self, pid: u32, address: u64) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let modules = self.modules_for(pid);
        symbol_manager.resolve_address_to_symbol_raw(&modules, address)
    }

    fn try_resolve_addresses_to_symbols(&self, pid: u32, addresses: &[u64]) -> Result<Vec<Option<(String, ModuleSymbol, u64)>>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let mut modules = self.modules_for(pid);
        modules.sort_by_key(|m| m.base);
        Ok(symbol_manager.try_resolve_addresses_to_symbols_raw(&modules, addresses))
    }

    fn symbols_in_range(&self, pid: u32, start: u64, len: u64, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let mut modules = self.modules_for(pid);
        modules.sort_by_key(|m| m.base);
        Ok(symbol_manager.symbols_in_range(&modules, start, start.saturating_add(len), max_results))
    }

    fn get_symbol_status(&self, pid: u32) -> Result<Vec<crate::protocol::ModuleSymbolStatus>, SymbolError> {
        Ok(self.symbols()?.get_symbol_status(self.modules_for(pid)))
    }

    fn load_pdb_from_path(&self, pid: u32, module_base: u64, pdb_path: &str, force: bool) -> Result<crate::protocol::PdbLoadOutcome, SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.load_pdb_from_path(&module, Path::new(pdb_path), force)
    }

    fn retry_symbol_load(&self, pid: u32, module_base: u64) -> Result<(), SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.retry_loading_symbols(&module);
        Ok(())
    }

    fn unload_module_symbols(&self, pid: u32, module_base: u64) -> Result<(), SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.unload_module_symbols(&module.name);
        Ok(())
    }

    fn set_symbol_deny_list(&self, modules: Vec<String>) -> Result<(), SymbolError> {
        self.symbols()?.set_deny_list(modules);
        Ok(())
    }

    fn resolve_address_to_line(&self, pid: u32, address: u64) -> Result<Option<crate::protocol::AddressLineInfo>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let mut modules = self.modules_for(pid);
        modules.sort_by_key(|m| m.base);
        let Some(module) = SymbolManager::find_module_binary_search(&modules, address) else {
            return Ok(None);
        };
        let rva = (address - module.base) as u32;
        Ok(symbol_manager.resolve_rva_to_line(&module.name, rva)?.map(|(file, line_entry)| crate::protocol::AddressLineInfo {
            module_path: module.name.clone(),
            module_base: module.base,
            rva,
            file,
            line_entry,
        }))
    }

    fn get_source_file_line_map(&self, pid: u32, module_base: u64, file_path: &str, start_line: Option<u32>, end_line: Option<u32>) -> Result<(Option<crate::interfaces::SourceFileEntry>, Vec<crate::interfaces::LineEntry>), SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.file_line_map(&module.name, file_path, start_line, end_line)
    }

    fn list_source_files(&self, pid: u32, module_base: u64) -> Result<Vec<crate::interfaces::SourceFileEntry>, SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.list_source_files(&module.name)
    }

    fn list_types(&self, pid: u32, module_base: Option<u64>, filter: Option<&str>, max_results: usize) -> Result<Vec<crate::protocol::TypeSummary>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let modules = self.type_query_modules(pid, module_base);
        Ok(symbol_manager.list_types(&modules, filter, max_results))
    }

    fn get_type(&self, pid: u32, module_base: Option<u64>, name: &str) -> Result<Option<crate::protocol::TypeLayout>, SymbolError> {
        let symbol_manager = self.symbols()?;
        let modules = self.type_query_modules(pid, module_base);
        symbol_manager.get_type(&modules, name)
    }

    fn get_type_by_index(&self, pid: u32, module_base: u64, index: u32) -> Result<Option<crate::protocol::TypeLayout>, SymbolError> {
        let module = self.module_at(pid, module_base)?;
        self.symbols()?.get_type_by_index(&module, index)
    }

    fn disassemble_memory(&self, pid: u32, address: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        self.disassemble_memory_impl(pid, address, count * 16, count, arch)
    }

    fn disassemble_memory_bytes(&self, pid: u32, address: u64, byte_len: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        self.disassemble_memory_impl(pid, address, byte_len, byte_len, arch)
    }

    fn disassemble_backward(&self, pid: u32, target: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        let modules = self.modules_for(pid);
        let bounds = |probe: u64| self.find_function_bounds(pid, probe);
        disasm::disassemble_backward_anchored(self, pid, target, count, arch, self.symbol_manager.as_ref(), &modules, &bounds)
    }

    fn disassemble_function(&self, pid: u32, address: u64, max_instructions: usize, arch: Architecture) -> Result<(Vec<Instruction>, Option<u64>, Option<u64>, Option<String>), DisassemblerError> {
        let bounds = self.find_function_bounds(pid, address);
        disasm::disassemble_function(self, pid, address, max_instructions, arch, bounds)
    }

    fn get_call_stack(&self, pid: u32, tid: u32) -> Result<Vec<CallFrame>, PlatformError> {
        let frames = self.unwind(pid, tid, unwind::MAX_FRAMES)?;
        let modules = self.modules_for(pid);
        Ok(frames
            .into_iter()
            .map(|f| {
                let symbol = self
                    .symbol_manager
                    .as_ref()
                    .and_then(|sm| sm.resolve_address_to_symbol_raw(&modules, f.pc).ok().flatten())
                    .map(|(module_path, sym, offset)| crate::interfaces::SymbolInfo {
                        module_name: crate::formatting::module_stem(&module_path),
                        symbol_name: sym.name,
                        offset,
                    });
                CallFrame { instruction_pointer: f.pc, stack_pointer: f.sp, frame_pointer: f.fp, symbol }
            })
            .collect())
    }

    /// `SuspendThread` semantics on ptrace: a held thread is left stopped by
    /// every resume until released. Returns the previous count.
    fn suspend_thread(&self, pid: u32, tid: u32) -> Result<u32, PlatformError> {
        let process = self.process(pid)?;
        let previous = {
            let mut threads = process.os.threads.lock().unwrap();
            let info = threads.info_mut(tid).ok_or_else(|| PlatformError::Other(format!("thread {tid} not found")))?;
            let previous = info.suspend_count;
            info.suspend_count += 1;
            previous
        };
        process.os.tracer.hold(tid)?;
        Ok(previous)
    }

    fn resume_thread(&self, pid: u32, tid: u32) -> Result<u32, PlatformError> {
        let process = self.process(pid)?;
        let previous = {
            let mut threads = process.os.threads.lock().unwrap();
            let info = threads.info_mut(tid).ok_or_else(|| PlatformError::Other(format!("thread {tid} not found")))?;
            let previous = info.suspend_count;
            if previous == 0 {
                return Ok(0);
            }
            info.suspend_count -= 1;
            previous
        };
        process.os.tracer.release(tid)?;
        Ok(previous)
    }

    /// Linux cannot kill one thread from outside (a thread-directed SIGKILL
    /// takes the whole group), so the thread is pointed at a `syscall`
    /// instruction with `exit(code)` in its registers: it leaves through the
    /// kernel the next time it runs, and `ThreadExited` follows.
    fn terminate_thread(&self, pid: u32, tid: u32, exit_code: u32) -> Result<(), PlatformError> {
        let process = self.process(pid)?;
        let os = &process.os;
        os.tracer.hold(tid)?;
        let result = (|| {
            let image = os.image(tid)?;
            os.tracer.set_regs(tid, self.syscall_setup(pid, &image, libc::SYS_exit as u64, &[exit_code as u64])?)
        })();
        os.tracer.release(tid)?;
        result
    }

    fn terminate_process(&self, pid: u32) -> Result<(), PlatformError> {
        self.process(pid)?;
        // SAFETY: plain syscall.
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } != 0 {
            return Err(PlatformError::OsError(format!("kill({pid}, SIGKILL): {}", std::io::Error::last_os_error())));
        }
        Ok(())
    }

    fn break_into(&self, pid: u32) -> Result<(), PlatformError> {
        self.process(pid)?.os.tracer.interrupt(pid)
    }

    fn get_module_extra_info(&self, pid: u32, module_base: u64) -> Result<crate::pe_types::ModuleExtraInfo, PlatformError> {
        let module = self
            .modules_for(pid)
            .into_iter()
            .find(|m| m.base == module_base)
            .ok_or_else(|| PlatformError::Other(format!("no module at {module_base:#x}")))?;
        if module.name.starts_with('[') {
            return Err(PlatformError::Other(format!("{} has no file to read headers from", module.name)));
        }
        elf_info::module_extra_info(Path::new(&module.name))
    }

    fn query_memory_region(&self, pid: u32, address: u64) -> Result<MemoryRegionInfo, PlatformError> {
        // Only the mapping at `address` and its neighbours (for the extent of
        // a gap) need translating: the emulator asks once per page it touches.
        let maps = maps::read_maps(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/maps: {e}")))?;
        let idx = maps.partition_point(|m| m.start <= address);
        let around = &maps[idx.saturating_sub(1)..(idx + 1).min(maps.len())];
        Ok(maps::region_at(&self.regions_from_maps(pid, around), address))
    }

    fn enumerate_memory_regions(&self, pid: u32) -> Result<Vec<MemoryRegionInfo>, PlatformError> {
        let maps = maps::read_maps(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/maps: {e}")))?;
        Ok(self.regions_from_maps(pid, &maps))
    }

    fn dereference(&self, pid: u32, address: u64, count: usize, reference_base: Option<u64>, probe_start: bool) -> Result<Vec<crate::protocol::DereferenceEntry>, PlatformError> {
        let resolver = self.nonblocking_symbol_resolver(pid);
        dereference::dereference(&(self, pid), address, count, reference_base, probe_start, Architecture::X64, Some(resolver))
    }

    fn dereference_batch(&self, pid: u32, addresses: &[u64], count: usize, reference_base: Option<u64>, probe_start: bool) -> Result<Vec<Vec<crate::protocol::DereferenceEntry>>, PlatformError> {
        let resolver = self.nonblocking_symbol_resolver(pid);
        dereference::dereference_batch(&(self, pid), addresses, count, reference_base, probe_start, Architecture::X64, Some(resolver))
    }

    fn get_teb_address(&self, pid: u32, tid: u32) -> Result<u64, PlatformError> {
        Ok(self.process(pid)?.os.image(tid)?.regs.fs_base)
    }

    fn process_architecture(&self, _pid: u32) -> Result<Architecture, PlatformError> {
        Ok(Architecture::X64)
    }

    fn emulate_with_mode(
        &self,
        pid: u32,
        tid: u32,
        max_instructions: usize,
        mode: crate::protocol::EmulationMode,
        exit_condition: Option<crate::protocol::TraceExitCondition>,
        memory_reads: &[(u64, usize)],
    ) -> Result<crate::emulator::EmulationResult, PlatformError> {
        let target = crate::emulator::LiveTarget::new(self, pid, tid).map_err(|e| PlatformError::Other(e.to_string()))?;
        let mut emulator = crate::emulator::Emulator::from_context(&target, &target.context).map_err(|e| PlatformError::Other(e.to_string()))?;
        emulator
            .emulate_with_mode(&target, max_instructions, mode, exit_condition, memory_reads)
            .map_err(|e| PlatformError::Other(e.to_string()))
    }
}

impl LinuxPlatform {
    fn regions_from_maps(&self, pid: u32, maps: &[maps::Mapping]) -> Vec<MemoryRegionInfo> {
        let modules = self.modules_for(pid);
        maps::regions_from_maps(maps, |path| {
            let clean = procfs::clean_map_path(path);
            modules.iter().find(|m| Path::new(&m.name) == clean || m.name == path).map(|m| m.base)
        })
    }

    fn unwind(&self, pid: u32, tid: u32, max_frames: usize) -> Result<Vec<unwind::Frame>, PlatformError> {
        let process = self.process(pid)?;
        let image = process.os.image(tid)?;
        let modules = process.book.modules.list_modules();
        let mem = process.os.mem.read().unwrap();
        Ok(self.unwinder.lock().unwrap().unwind(&image.regs, &modules, &mem, max_frames))
    }

    /// Function bounds for an address: from the unwinder's FDE table when the
    /// module has one, else the symbol's extent is unknown.
    fn find_function_bounds(&self, pid: u32, address: u64) -> disasm::FunctionBounds {
        let modules = self.modules_for(pid);
        let module = modules.iter().find(|m| address >= m.base && address < m.base + m.size.unwrap_or(0))?;
        let (start, end) = self.unwinder.lock().unwrap().function_range(module, address)?;
        let name = self
            .symbol_manager
            .as_ref()
            .and_then(|sm| sm.resolve_address_to_symbol_raw(&modules, start).ok().flatten())
            .map(|(module_path, symbol, _)| format!("{}!{}", crate::formatting::module_stem(&module_path), symbol.name));
        Some((start, end, name))
    }

    fn disassemble_memory_impl(&self, pid: u32, address: u64, read_len: usize, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        let Some(disasm_engine) = self.disassembler.as_ref() else {
            return Err(DisassemblerError::CapstoneError("Disassembler not initialized".to_string()));
        };
        let process = self.process(pid).ok();
        let listing = disasm::Listing {
            reader: &(self, pid),
            bps: process.map(|p| &p.book.bps),
            disasm: disasm_engine,
            symbol_manager: self.symbol_manager.as_ref(),
            modules: self.modules_for(pid),
        };
        disasm::decode_listing(listing, address, read_len, count, arch, || {
            // Speculative pointer reads for indirect branch targets: one
            // syscall each, no probing, no logging.
            Some(Box::new(move |addr: u64| {
                memory::process_vm_read(pid, addr, 8)
                    .ok()
                    .filter(|b| b.len() == 8)
                    .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
            }) as Box<dyn Fn(u64) -> Option<u64>>)
        })
    }
}
