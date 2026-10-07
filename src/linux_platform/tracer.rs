//! The tracer thread: the one OS thread that owns every ptrace relationship.
//!
//! ptrace requests must come from the thread that seized the tracee, while
//! the server calls the platform from several connection threads. So one
//! thread does all of it and everyone else sends it a [`Cmd`] and waits for
//! the reply. Memory never comes through here (`memory.rs`, any thread).
//!
//! # All-stop
//!
//! Windows debug events freeze the whole process; ptrace stops one thread.
//! Whenever a stop is about to be reported, every other running thread of
//! the process is interrupted and waited for. Threads that answer with a real
//! event of their own (not our interrupt) keep that stop *queued*; it is
//! delivered on a later `Resume` without resuming anyone, exactly like
//! Windows re-queues an event with `DBG_REPLY_LATER`.
//!
//! # Deferral
//!
//! While one thread steps over a temporarily removed breakpoint (an
//! *exclusive* step-over, see `debugger_core::stepping`), another thread's
//! stop must wait: the platform hands it back with [`Cmd::Defer`] and the
//! tracer keeps it queued as *deferred* until a `Resume` says the step-over
//! is done (`replay_deferred`). Held threads (`freeze_thread`) are never
//! resumed; a `PTRACE_SINGLESTEP` is used for a thread whose trap flag the
//! shared stepper set (the backend emulates TF, see `regs.rs`).
//!
//! # Several processes
//!
//! A debugged child (`debug_children`) is one more traced process on the
//! same thread. Like `WaitForDebugEvent`, a wait reports the next stop of
//! *any* traced process: [`Cmd::Kick`] sets one process running (or hands
//! back a stop it already has queued) and [`Cmd::WaitAny`] waits. A stop
//! freezes only its own process; the others run on.
//!
//! # Liveness
//!
//! While a `Resume` is waiting for the next stop, the thread keeps serving
//! commands: it alternates a non-blocking wait with a short channel timeout,
//! so a hold/interrupt from another thread never has to wait for the target.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use tracing::{debug, trace, warn};

use super::ptrace;
use super::regs::{ContextWrite, RegisterImage};
use crate::interfaces::PlatformError;

/// A stop of one thread, as the wait loop classified it.
#[derive(Debug, Clone)]
pub struct Stop {
    pub pid: u32,
    pub tid: u32,
    pub kind: StopKind,
}

#[derive(Debug, Clone)]
pub enum StopKind {
    /// A signal-delivery stop.
    Signal { signo: i32, code: i32, addr: u64, rip: u64 },
    /// `PTRACE_EVENT_CLONE`: a new thread, already seized and stopped.
    Clone { new_tid: u32 },
    /// `PTRACE_EVENT_FORK`/`VFORK`: a child process, seized and stopped.
    Fork { child: u32, vfork: bool },
    /// `PTRACE_EVENT_VFORK_DONE`: the vfork child released the address space
    /// it shared with this process (it exec'd or exited).
    VforkDone,
    /// `PTRACE_EVENT_EXEC`: the process replaced its image.
    Exec,
    /// `PTRACE_EVENT_EXIT`: the thread is about to die; its address space is
    /// still intact. `last_thread` when no other thread of the process lives.
    Exit { status: i32, last_thread: bool },
    /// The thread was interrupted on request (`break_into`).
    Interrupted,
    /// The thread vanished without an exit stop (killed).
    Gone { status: i32 },
}

/// The outcome of a launch, from the exec stop.
#[derive(Debug)]
pub struct Launched {
    pub pid: u32,
}

#[derive(Debug)]
pub struct Attached {
    pub tids: Vec<u32>,
}

type Reply<T> = Sender<Result<T, PlatformError>>;

pub enum Cmd {
    Launch { argv: Vec<CString>, cwd: Option<CString>, envp: Vec<CString>, reply: Reply<Launched> },
    Attach { pid: u32, reply: Reply<Attached> },
    /// Restore nothing here (the platform already did); just let go.
    Detach { pid: u32, reply: Reply<()> },
    /// Set the process running (minus held/deferred threads). A stop it
    /// already has queued is handed back instead, resuming nobody.
    Kick { pid: u32, resume_tid: u32, signal: i32, replay_deferred: bool, reply: Reply<Option<Stop>> },
    /// Wait for the next stop of any traced process.
    WaitAny { reply: Reply<Stop> },
    /// Put a stop the platform will not process yet back in the queue.
    Defer { stop: Stop, reply: Reply<()> },
    Hold { tid: u32, reply: Reply<()> },
    Release { tid: u32, reply: Reply<()> },
    /// `break_into`: stop the leader; its stop is reported as `Interrupted`.
    Interrupt { pid: u32, reply: Reply<()> },
    /// Let a process whose exit was reported finish dying, and forget it.
    Reap { pid: u32, reply: Reply<()> },
    /// Forget a process we no longer trace (after detach or kill).
    Forget { pid: u32, reply: Reply<()> },
    GetRegs { tid: u32, reply: Reply<RegisterImage> },
    SetRegs { tid: u32, write: Box<ContextWrite>, reply: Reply<()> },
    GetDebugRegs { tid: u32, reply: Reply<[u64; 8]> },
    SetDebugRegs { tid: u32, regs: [u64; 8], reply: Reply<()> },
    /// Set or clear `tid`'s emulated trap flag: its next resume single-steps.
    SetWantStep { tid: u32, on: bool, reply: Reply<()> },
    /// Execute exactly one instruction on a stopped `tid`, nobody else
    /// running, and wait for it (syscall injection).
    StepThread { tid: u32, reply: Reply<()> },
}

/// A handle to the tracer thread; cloning shares the same thread.
#[derive(Clone)]
pub struct Tracer {
    tx: Sender<Cmd>,
}

impl std::fmt::Debug for Tracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tracer")
    }
}

impl Tracer {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("joybug-tracer".into())
            .spawn(move || Loop::new(rx).run())
            .expect("spawn tracer thread");
        Self { tx }
    }

    fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Cmd) -> Result<T, PlatformError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(make(reply_tx))
            .map_err(|_| PlatformError::Other("tracer thread is gone".into()))?;
        reply_rx
            .recv()
            .map_err(|_| PlatformError::Other("tracer thread dropped the request".into()))?
    }

    pub fn launch(&self, argv: Vec<CString>, cwd: Option<CString>, envp: Vec<CString>) -> Result<Launched, PlatformError> {
        self.call(|reply| Cmd::Launch { argv, cwd, envp, reply })
    }
    pub fn attach(&self, pid: u32) -> Result<Attached, PlatformError> {
        self.call(|reply| Cmd::Attach { pid, reply })
    }
    pub fn detach(&self, pid: u32) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::Detach { pid, reply })
    }
    pub fn kick(&self, pid: u32, resume_tid: u32, signal: i32, replay_deferred: bool) -> Result<Option<Stop>, PlatformError> {
        self.call(|reply| Cmd::Kick { pid, resume_tid, signal, replay_deferred, reply })
    }
    pub fn wait_any(&self) -> Result<Stop, PlatformError> {
        self.call(|reply| Cmd::WaitAny { reply })
    }
    pub fn defer(&self, stop: Stop) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::Defer { stop, reply })
    }
    pub fn hold(&self, tid: u32) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::Hold { tid, reply })
    }
    pub fn release(&self, tid: u32) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::Release { tid, reply })
    }
    pub fn interrupt(&self, pid: u32) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::Interrupt { pid, reply })
    }
    pub fn reap(&self, pid: u32) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::Reap { pid, reply })
    }
    pub fn forget(&self, pid: u32) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::Forget { pid, reply })
    }
    pub fn get_regs(&self, tid: u32) -> Result<RegisterImage, PlatformError> {
        self.call(|reply| Cmd::GetRegs { tid, reply })
    }
    pub fn step_thread(&self, tid: u32) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::StepThread { tid, reply })
    }
    pub fn set_regs(&self, tid: u32, write: ContextWrite) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::SetRegs { tid, write: Box::new(write), reply })
    }
    pub fn get_debug_regs(&self, tid: u32) -> Result<[u64; 8], PlatformError> {
        self.call(|reply| Cmd::GetDebugRegs { tid, reply })
    }
    pub fn set_debug_regs(&self, tid: u32, regs: [u64; 8]) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::SetDebugRegs { tid, regs, reply })
    }
    pub fn set_want_step(&self, tid: u32, on: bool) -> Result<(), PlatformError> {
        self.call(|reply| Cmd::SetWantStep { tid, on, reply })
    }
}

// ============================================================================
// The thread
// ============================================================================

#[derive(Debug, Default)]
struct ThreadState {
    stopped: bool,
    /// `freeze_thread` nesting; a held thread is never resumed.
    held: u32,
    /// Resume with `PTRACE_SINGLESTEP` (the emulated trap flag).
    want_step: bool,
    /// Reported its exit stop: no longer counts as live.
    exiting: bool,
    /// The last thread, parked in its exit stop (the address space stays
    /// readable); resumed only by `Reap`.
    parked_exit: bool,
    /// A stop already observed and not yet delivered.
    queued: Option<QueuedStop>,
}

#[derive(Debug)]
struct QueuedStop {
    stop: Stop,
    /// Seen by the platform once and handed back with `Defer`.
    deferred: bool,
}

#[derive(Debug, Default)]
struct ProcState {
    threads: HashMap<u32, ThreadState>,
    /// Threads we `PTRACE_INTERRUPT`ed for an all-stop; their `EVENT_STOP`
    /// is an acknowledgement to swallow, not an event.
    interrupt_pending: HashSet<u32>,
    /// `break_into` asked for the next interrupt stop to be reported.
    break_into_requested: bool,
    /// Set running by a `Kick` and not stopped since.
    running: bool,
}

impl ProcState {
    fn live_count(&self) -> usize {
        self.threads.values().filter(|t| !t.exiting).count()
    }
}

struct InFlight {
    reply: Reply<Stop>,
}

struct Loop {
    rx: Receiver<Cmd>,
    procs: HashMap<u32, ProcState>,
    /// tid -> pid for every thread we trace.
    owner: HashMap<u32, u32>,
    in_flight: Option<InFlight>,
    /// New processes (fork children, auto-seized) whose first stop was
    /// reaped by a wait before their parent's fork event named them.
    early_children: HashSet<u32>,
}

fn os_err(what: &str, e: std::io::Error) -> PlatformError {
    PlatformError::OsError(format!("{what}: {e}"))
}

impl Loop {
    fn new(rx: Receiver<Cmd>) -> Self {
        Self { rx, procs: HashMap::new(), owner: HashMap::new(), in_flight: None, early_children: HashSet::new() }
    }

    fn run(mut self) {
        loop {
            // With a resume in flight, poll the channel briefly between
            // non-blocking waits; otherwise block on the channel.
            let cmd = if self.in_flight.is_some() {
                match self.rx.recv_timeout(Duration::from_millis(1)) {
                    Ok(cmd) => Some(cmd),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            } else {
                match self.rx.recv() {
                    Ok(cmd) => Some(cmd),
                    Err(_) => return,
                }
            };
            if let Some(cmd) = cmd {
                self.handle(cmd);
            }
            if self.in_flight.is_some() {
                self.poll_wait();
            }
        }
    }

    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Launch { argv, cwd, envp, reply } => {
                let _ = reply.send(self.launch(argv, cwd, envp));
            }
            Cmd::Attach { pid, reply } => {
                let _ = reply.send(self.attach(pid));
            }
            Cmd::Detach { pid, reply } => {
                let _ = reply.send(self.detach(pid));
            }
            Cmd::Kick { pid, resume_tid, signal, replay_deferred, reply } => {
                let _ = reply.send(self.start_resume(pid, resume_tid, signal, replay_deferred));
            }
            Cmd::WaitAny { reply } => {
                if self.in_flight.is_some() {
                    let _ = reply.send(Err(PlatformError::Other("a wait is already in flight".into())));
                    return;
                }
                self.in_flight = Some(InFlight { reply });
            }
            Cmd::Defer { stop, reply } => {
                let _ = reply.send(self.defer(stop));
            }
            Cmd::Hold { tid, reply } => {
                let _ = reply.send(self.hold(tid));
            }
            Cmd::Release { tid, reply } => {
                let _ = reply.send(self.release(tid));
            }
            Cmd::Interrupt { pid, reply } => {
                let _ = reply.send(self.interrupt(pid));
            }
            Cmd::Reap { pid, reply } => {
                let _ = reply.send(self.reap(pid));
            }
            Cmd::Forget { pid, reply } => {
                self.forget_process(pid);
                let _ = reply.send(Ok(()));
            }
            Cmd::GetRegs { tid, reply } => {
                let _ = reply.send(self.get_regs(tid));
            }
            Cmd::SetRegs { tid, write, reply } => {
                let _ = reply.send(self.set_regs(tid, *write));
            }
            Cmd::GetDebugRegs { tid, reply } => {
                let _ = reply.send(self.stopped_thread(tid).and_then(|_| read_debug_regs(tid)));
            }
            Cmd::SetDebugRegs { tid, regs, reply } => {
                let _ = reply.send(self.stopped_thread(tid).and_then(|_| write_debug_regs(tid, &regs)));
            }
            Cmd::SetWantStep { tid, on, reply } => {
                let _ = reply.send(self.thread_mut(tid).map(|t| t.want_step = on));
            }
            Cmd::StepThread { tid, reply } => {
                let _ = reply.send(self.step_thread(tid));
            }
        }
    }

    // ---- bookkeeping -------------------------------------------------------

    fn thread_mut(&mut self, tid: u32) -> Result<&mut ThreadState, PlatformError> {
        let pid = *self.owner.get(&tid).ok_or_else(|| PlatformError::Other(format!("thread {tid} is not traced")))?;
        self.procs
            .get_mut(&pid)
            .and_then(|p| p.threads.get_mut(&tid))
            .ok_or_else(|| PlatformError::Other(format!("thread {tid} is not traced")))
    }

    fn stopped_thread(&mut self, tid: u32) -> Result<&mut ThreadState, PlatformError> {
        let t = self.thread_mut(tid)?;
        if !t.stopped {
            return Err(PlatformError::Other(format!("thread {tid} is running")));
        }
        Ok(t)
    }

    fn add_thread(&mut self, pid: u32, tid: u32, stopped: bool) {
        self.owner.insert(tid, pid);
        self.procs
            .entry(pid)
            .or_default()
            .threads
            .insert(tid, ThreadState { stopped, ..Default::default() });
    }

    fn remove_thread(&mut self, tid: u32) {
        if let Some(pid) = self.owner.remove(&tid) {
            if let Some(p) = self.procs.get_mut(&pid) {
                p.threads.remove(&tid);
                p.interrupt_pending.remove(&tid);
            }
        }
    }

    fn forget_process(&mut self, pid: u32) {
        if let Some(p) = self.procs.remove(&pid) {
            for tid in p.threads.keys() {
                self.owner.remove(tid);
            }
        }
    }

    // ---- launch / attach / detach -----------------------------------------

    fn launch(&mut self, argv: Vec<CString>, cwd: Option<CString>, envp: Vec<CString>) -> Result<Launched, PlatformError> {
        let child = super::launch::fork_stopped(&argv, cwd.as_deref(), &envp)?;
        let pid = child as u32;
        // The child sits in its SIGSTOP; seizing a stopped task makes it
        // report PTRACE_EVENT_STOP, which is where our control begins.
        ptrace::seize(child, ptrace::standard_options()).map_err(|e| os_err("PTRACE_SEIZE", e))?;
        self.add_thread(pid, pid, true);
        let status = wait_tid(child).map_err(|e| os_err("waitpid after seize", e))?;
        if !is_event_stop(status) {
            self.forget_process(pid);
            return Err(PlatformError::Other(format!("unexpected status after seize: {status:#x}")));
        }
        // Run to the exec. The only things between here and there are the
        // child's chdir and execvpe.
        ptrace::cont(child, 0).map_err(|e| os_err("PTRACE_CONT to exec", e))?;
        loop {
            let status = wait_tid(child).map_err(|e| os_err("waitpid for exec", e))?;
            if libc::WIFSTOPPED(status) {
                if status >> 16 == libc::PTRACE_EVENT_EXEC {
                    return Ok(Launched { pid });
                }
                // Anything else (a stray signal) is passed on; exec is coming.
                let sig = libc::WSTOPSIG(status);
                let pass = if status >> 16 != 0 || sig == libc::SIGTRAP { 0 } else { sig };
                ptrace::cont(child, pass).map_err(|e| os_err("PTRACE_CONT to exec", e))?;
            } else {
                self.forget_process(pid);
                let detail = super::launch::take_exec_error(child);
                return Err(PlatformError::OsError(match detail {
                    Some(msg) => format!("launch failed: {msg}"),
                    None => format!("the child exited before exec (status {status:#x})"),
                }));
            }
        }
    }

    fn attach(&mut self, pid: u32) -> Result<Attached, PlatformError> {
        let mut seized: Vec<u32> = Vec::new();
        // Threads can appear while we attach; rescan until the set is stable.
        loop {
            let tids = super::procfs::thread_ids(pid).map_err(|e| os_err("list threads", e))?;
            let new: Vec<u32> = tids.into_iter().filter(|t| !seized.contains(t)).collect();
            if new.is_empty() {
                break;
            }
            for tid in new {
                if let Err(e) = ptrace::seize(tid as libc::pid_t, ptrace::standard_options()) {
                    for t in &seized {
                        let _ = ptrace::detach(*t as libc::pid_t);
                    }
                    self.forget_process(pid);
                    return Err(attach_error(pid, e));
                }
                self.add_thread(pid, tid, false);
                seized.push(tid);
            }
        }
        // Stop every thread. A thread that was already in some other stop
        // keeps that stop queued.
        for &tid in &seized {
            ptrace::interrupt(tid as libc::pid_t).map_err(|e| os_err("PTRACE_INTERRUPT", e))?;
            self.procs.get_mut(&pid).unwrap().interrupt_pending.insert(tid);
        }
        for &tid in &seized {
            self.collect_one(pid, tid)?;
        }
        Ok(Attached { tids: seized })
    }

    fn detach(&mut self, pid: u32) -> Result<(), PlatformError> {
        let Some(p) = self.procs.get(&pid) else { return Ok(()) };
        let tids: Vec<u32> = p.threads.keys().copied().collect();
        // Every thread must be stopped to be detached; interrupt the runners.
        for &tid in &tids {
            let st = &self.procs[&pid].threads[&tid];
            if !st.stopped {
                let _ = ptrace::interrupt(tid as libc::pid_t);
                let _ = wait_tid(tid as libc::pid_t);
            }
            if let Err(e) = ptrace::detach(tid as libc::pid_t) {
                warn!(pid, tid, error = %e, "PTRACE_DETACH failed");
            }
        }
        self.forget_process(pid);
        Ok(())
    }

    // ---- resume / wait -----------------------------------------------------

    /// Deliver a queued stop, or resume the process and report `None` (its
    /// next stop will come from `poll_wait`).
    fn start_resume(&mut self, pid: u32, resume_tid: u32, signal: i32, replay_deferred: bool) -> Result<Option<Stop>, PlatformError> {
        let proc_state = self.procs.get_mut(&pid).ok_or_else(|| PlatformError::Other(format!("process {pid} is not traced")))?;
        // Fresh stops first (never seen by the platform), then deferred ones
        // once the deferring step-over is done.
        if let Some(stop) = take_queued(proc_state, false) {
            return Ok(Some(stop));
        }
        if replay_deferred {
            if let Some(stop) = take_queued(proc_state, true) {
                return Ok(Some(stop));
            }
        }
        let mut resumed = 0;
        for (&tid, st) in proc_state.threads.iter_mut() {
            match try_resume(tid, st, if tid == resume_tid { signal } else { 0 }) {
                None => trace!(pid, tid, stopped = st.stopped, held = st.held, parked = st.parked_exit, queued = st.queued.is_some(), "not resuming"),
                Some(Ok(())) => resumed += 1,
                Some(Err(e)) => warn!(pid, tid, error = %e, "resume failed (thread may have exited)"),
            }
        }
        proc_state.running = true;
        trace!(pid, resumed, "resumed");
        Ok(None)
    }

    /// One non-blocking wait while a resume is in flight.
    fn poll_wait(&mut self) {
        let mut status = 0;
        // SAFETY: plain syscall.
        let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG) };
        if tid == 0 {
            return;
        }
        if tid < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ECHILD) {
                // Nothing left to wait for: the process died under us.
                if let Some(f) = self.in_flight.take() {
                    let _ = f.reply.send(Err(PlatformError::Other("no traced thread left to wait for".into())));
                }
            }
            return;
        }
        let tid = tid as u32;
        trace!(tid, status = %format!("{status:#x}"), "wait status");
        match self.classify(tid, status) {
            Some(stop) => {
                trace!(pid = stop.pid, tid = stop.tid, kind = ?stop.kind, "stop");
                if let Err(e) = self.all_stop(stop.pid, stop.tid) {
                    warn!(error = %e, "all-stop collection failed");
                }
                if let Some(p) = self.procs.get_mut(&stop.pid) {
                    p.running = false;
                }
                if let Some(f) = self.in_flight.take() {
                    let _ = f.reply.send(Ok(stop));
                }
            }
            None => {
                // Nobody's event (a stale interrupt acknowledgement): the thread
                // is stopped again while its process is supposed to run, so
                // put it back on its way.
                if let Some(&pid) = self.owner.get(&tid) {
                    if self.procs.get(&pid).is_some_and(|p| p.running) {
                        self.resume_one_if_eligible(pid, tid);
                    }
                }
            }
        }
    }

    fn resume_one_if_eligible(&mut self, pid: u32, tid: u32) {
        let Some(st) = self.procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) else { return };
        match try_resume(tid, st, 0) {
            None => {}
            Some(Ok(())) => trace!(pid, tid, "re-resumed after a stale interrupt"),
            Some(Err(e)) => warn!(pid, tid, error = %e, "re-resume failed"),
        }
    }

    /// Interpret one wait status. `None` for stops that are nobody's event
    /// (our own interrupt acknowledgements, non-leader thread reaping).
    fn classify(&mut self, tid: u32, status: i32) -> Option<Stop> {
        let pid = match self.owner.get(&tid) {
            Some(&pid) => pid,
            None => {
                // A thread we have not registered yet: a clone whose parent's
                // event is still queued, or a brand-new tracee. Its tgid tells.
                if !libc::WIFSTOPPED(status) {
                    return None;
                }
                let Some(pid) = super::procfs::tgid_of(tid).filter(|p| self.procs.contains_key(p)) else {
                    // A forked child's first stop, ahead of the parent's fork
                    // event: remember it, that event will not wait for it again.
                    trace!(tid, "first stop of a process not announced yet");
                    self.early_children.insert(tid);
                    return None;
                };
                self.add_thread(pid, tid, true);
                pid
            }
        };

        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            let last = self.procs.get(&pid).map(|p| p.live_count() <= 1).unwrap_or(true);
            let was_parked = self.procs.get(&pid).and_then(|p| p.threads.get(&tid)).map(|t| t.parked_exit).unwrap_or(false);
            self.remove_thread(tid);
            // A thread whose exit stop we already reported just finished
            // dying; nothing new to say. A thread killed outright is news.
            if was_parked || !last {
                return None;
            }
            return Some(Stop { pid, tid, kind: StopKind::Gone { status } });
        }
        if !libc::WIFSTOPPED(status) {
            return None;
        }
        let proc_state = self.procs.get_mut(&pid)?;
        if let Some(t) = proc_state.threads.get_mut(&tid) {
            t.stopped = true;
        }
        let sig = libc::WSTOPSIG(status);
        let event = status >> 16;
        match event {
            0 => {
                let info = ptrace::getsiginfo(tid as libc::pid_t).ok();
                let (code, addr) = info
                    .map(|i| (i.si_code, unsafe { i.si_addr() } as u64))
                    .unwrap_or((0, 0));
                let rip = ptrace::getregs(tid as libc::pid_t).map(|r| r.rip).unwrap_or(0);
                Some(Stop { pid, tid, kind: StopKind::Signal { signo: sig, code, addr, rip } })
            }
            e if e == libc::PTRACE_EVENT_STOP => {
                if proc_state.interrupt_pending.remove(&tid) {
                    if proc_state.break_into_requested {
                        proc_state.break_into_requested = false;
                        return Some(Stop { pid, tid, kind: StopKind::Interrupted });
                    }
                    return None;
                }
                if sig == libc::SIGTRAP {
                    // An interrupt we did not ask for on this thread (a new
                    // thread's initial stop arrives this way too).
                    return None;
                }
                // Group-stop (SIGSTOP/SIGTSTP/...): treat like the signal.
                Some(Stop { pid, tid, kind: StopKind::Signal { signo: sig, code: 0, addr: 0, rip: 0 } })
            }
            e if e == libc::PTRACE_EVENT_CLONE => {
                let new_tid = ptrace::geteventmsg(tid as libc::pid_t).unwrap_or(0) as u32;
                // A clone() without CLONE_THREAD is a new process, whatever its
                // exit signal: same as a fork.
                if new_tid != 0 && !self.owner.contains_key(&new_tid) && super::procfs::tgid_of(new_tid).is_some_and(|tgid| tgid != pid) {
                    self.adopt_child(new_tid);
                    return Some(Stop { pid, tid, kind: StopKind::Fork { child: new_tid, vfork: false } });
                }
                if new_tid != 0 {
                    // The new thread starts stopped (its initial EVENT_STOP);
                    // consume that so it is not mistaken for an event later.
                    if !self.owner.contains_key(&new_tid) {
                        self.add_thread(pid, new_tid, false);
                        match wait_tid(new_tid as libc::pid_t) {
                            Ok(_) => {
                                if let Some(t) = self.procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&new_tid)) {
                                    t.stopped = true;
                                }
                            }
                            Err(e) => warn!(new_tid, error = %e, "waiting for the new thread's first stop failed"),
                        }
                    }
                }
                Some(Stop { pid, tid, kind: StopKind::Clone { new_tid } })
            }
            e if e == libc::PTRACE_EVENT_FORK || e == libc::PTRACE_EVENT_VFORK => {
                let child = ptrace::geteventmsg(tid as libc::pid_t).unwrap_or(0) as u32;
                if child != 0 {
                    self.adopt_child(child);
                }
                Some(Stop { pid, tid, kind: StopKind::Fork { child, vfork: e == libc::PTRACE_EVENT_VFORK } })
            }
            e if e == libc::PTRACE_EVENT_VFORK_DONE => Some(Stop { pid, tid, kind: StopKind::VforkDone }),
            e if e == libc::PTRACE_EVENT_EXEC => Some(Stop { pid, tid, kind: StopKind::Exec }),
            e if e == libc::PTRACE_EVENT_EXIT => {
                let exit_status = ptrace::geteventmsg(tid as libc::pid_t).unwrap_or(0) as i32;
                let last = proc_state.live_count() <= 1;
                if let Some(t) = proc_state.threads.get_mut(&tid) {
                    t.exiting = true;
                    // Only the last thread is held in its exit stop; the others
                    // must run on to finish dying (a join waits for that).
                    t.parked_exit = last;
                }
                Some(Stop { pid, tid, kind: StopKind::Exit { status: exit_status, last_thread: last } })
            }
            _ => {
                debug!(tid, event, "unhandled ptrace event; treating as a signal stop");
                Some(Stop { pid, tid, kind: StopKind::Signal { signo: sig, code: 0, addr: 0, rip: 0 } })
            }
        }
    }

    /// Register a new process the kernel seized for us (a fork child) and
    /// consume its first stop, so it sits stopped until someone kicks it.
    fn adopt_child(&mut self, child: u32) {
        let seen = self.early_children.remove(&child);
        self.add_thread(child, child, seen);
        if !seen {
            match wait_tid(child as libc::pid_t) {
                Ok(_) => {
                    if let Some(t) = self.procs.get_mut(&child).and_then(|p| p.threads.get_mut(&child)) {
                        t.stopped = true;
                    }
                }
                Err(e) => warn!(child, error = %e, "waiting for the new process's first stop failed"),
            }
        }
    }

    /// Stop every other running thread of `pid`, queueing any real event.
    fn all_stop(&mut self, pid: u32, except: u32) -> Result<(), PlatformError> {
        let running: Vec<u32> = self
            .procs
            .get(&pid)
            .map(|p| p.threads.iter().filter(|(t, s)| **t != except && !s.stopped).map(|(t, _)| *t).collect())
            .unwrap_or_default();
        for &tid in &running {
            if let Err(e) = ptrace::interrupt(tid as libc::pid_t) {
                warn!(pid, tid, error = %e, "PTRACE_INTERRUPT failed (thread may have exited)");
                continue;
            }
            self.procs.get_mut(&pid).unwrap().interrupt_pending.insert(tid);
        }
        for &tid in &running {
            if self.procs.get(&pid).map(|p| p.interrupt_pending.contains(&tid)).unwrap_or(false) {
                self.collect_one(pid, tid)?;
            }
        }
        Ok(())
    }

    /// Wait for one interrupted thread; a real event of its own is queued.
    fn collect_one(&mut self, pid: u32, tid: u32) -> Result<(), PlatformError> {
        let status = match wait_tid(tid as libc::pid_t) {
            Ok(s) => s,
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                self.remove_thread(tid);
                return Ok(());
            }
            Err(e) => return Err(os_err("waitpid during all-stop", e)),
        };
        if let Some(stop) = self.classify(tid, status) {
            if let Some(t) = self.procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
                t.queued = Some(QueuedStop { stop, deferred: false });
            }
        }
        Ok(())
    }

    fn defer(&mut self, stop: Stop) -> Result<(), PlatformError> {
        let t = self.thread_mut(stop.tid)?;
        t.queued = Some(QueuedStop { stop, deferred: true });
        Ok(())
    }

    fn hold(&mut self, tid: u32) -> Result<(), PlatformError> {
        let pid = *self.owner.get(&tid).ok_or_else(|| PlatformError::Other(format!("thread {tid} is not traced")))?;
        let t = self.thread_mut(tid)?;
        t.held += 1;
        if !t.stopped {
            ptrace::interrupt(tid as libc::pid_t).map_err(|e| os_err("PTRACE_INTERRUPT", e))?;
            self.procs.get_mut(&pid).unwrap().interrupt_pending.insert(tid);
            self.collect_one(pid, tid)?;
        }
        Ok(())
    }

    fn release(&mut self, tid: u32) -> Result<(), PlatformError> {
        let pid = *self.owner.get(&tid).ok_or_else(|| PlatformError::Other(format!("thread {tid} is not traced")))?;
        let t = self.thread_mut(tid)?;
        t.held = t.held.saturating_sub(1);
        // While the process is running, a thread released from its last hold
        // goes straight back to running; a paused process keeps it stopped
        // until the next resume, like every other thread.
        if t.held == 0 && self.procs.get(&pid).is_some_and(|p| p.running) {
            self.resume_one_if_eligible(pid, tid);
        }
        Ok(())
    }

    /// One instruction on `tid` alone, synchronously. The thread must be
    /// stopped and no resume may be in flight; it is stopped again on return.
    fn step_thread(&mut self, tid: u32) -> Result<(), PlatformError> {
        if self.in_flight.is_some() {
            return Err(PlatformError::Other("a resume is in flight".into()));
        }
        self.stopped_thread(tid)?;
        ptrace::singlestep(tid as libc::pid_t, 0).map_err(|e| os_err("PTRACE_SINGLESTEP", e))?;
        let mut status = 0;
        // SAFETY: plain syscall on a thread we trace.
        let waited = unsafe { libc::waitpid(tid as libc::pid_t, &mut status, libc::__WALL) };
        if waited != tid as libc::pid_t {
            return Err(PlatformError::OsError(format!("waitpid({tid}) after a single step: {}", std::io::Error::last_os_error())));
        }
        if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP {
            return Ok(());
        }
        // Anything else (a fault on the injected instruction, an exit) is
        // handed to the regular classification on the next poll.
        Err(PlatformError::Other(format!("thread {tid} did not single-step cleanly (status {status:#x})")))
    }

    fn interrupt(&mut self, pid: u32) -> Result<(), PlatformError> {
        let p = self.procs.get_mut(&pid).ok_or_else(|| PlatformError::Other(format!("process {pid} is not traced")))?;
        // Report the break-in on the main thread when it is running: the thread
        // the user then steps or inspects should be the predictable one, not
        // whichever the map iterates first (often one parked in a syscall).
        let running = |(_, s): &(&u32, &ThreadState)| !s.stopped;
        let Some(tid) = p
            .threads
            .iter()
            .find(|e| *e.0 == pid && running(e))
            .or_else(|| p.threads.iter().find(running))
            .map(|(t, _)| *t)
        else {
            return Ok(()); // already stopped
        };
        p.break_into_requested = true;
        p.interrupt_pending.insert(tid);
        ptrace::interrupt(tid as libc::pid_t).map_err(|e| os_err("PTRACE_INTERRUPT", e))
    }

    fn reap(&mut self, pid: u32) -> Result<(), PlatformError> {
        let Some(p) = self.procs.get(&pid) else { return Ok(()) };
        let tids: Vec<u32> = p.threads.keys().copied().collect();
        for &tid in &tids {
            let _ = ptrace::cont(tid as libc::pid_t, 0);
        }
        // The leader's final status arrives once every thread is gone.
        for &tid in &tids {
            match wait_tid(tid as libc::pid_t) {
                Ok(status) if libc::WIFSTOPPED(status) => {
                    // Still had something to say (another exit stop); push through.
                    let _ = ptrace::cont(tid as libc::pid_t, 0);
                    let _ = wait_tid(tid as libc::pid_t);
                }
                _ => {}
            }
        }
        self.forget_process(pid);
        Ok(())
    }

    // ---- registers ---------------------------------------------------------

    fn get_regs(&mut self, tid: u32) -> Result<RegisterImage, PlatformError> {
        let trap_flag_pending = self.stopped_thread(tid)?.want_step;
        let t = tid as libc::pid_t;
        let regs = ptrace::getregs(t).map_err(|e| os_err("PTRACE_GETREGS", e))?;
        let fpregs = ptrace::getfpregs(t).map_err(|e| os_err("PTRACE_GETFPREGS", e))?;
        let debug = read_debug_regs(tid)?;
        Ok(RegisterImage { regs, fpregs, debug, trap_flag_pending })
    }

    fn set_regs(&mut self, tid: u32, write: ContextWrite) -> Result<(), PlatformError> {
        let t = tid as libc::pid_t;
        let state = self.stopped_thread(tid)?;
        state.want_step = write.trap_flag;
        ptrace::setregs(t, &write.regs).map_err(|e| os_err("PTRACE_SETREGS", e))?;
        ptrace::setfpregs(t, &write.fpregs).map_err(|e| os_err("PTRACE_SETFPREGS", e))?;
        write_debug_regs(tid, &write.debug)
    }
}

/// Set a stopped thread running again (one instruction when its trap flag is
/// emulated), delivering `signal`. `None` when it has to stay where it is:
/// held, parked at its exit, or with a stop still to report.
fn try_resume(tid: u32, st: &mut ThreadState, signal: i32) -> Option<std::io::Result<()>> {
    if !st.stopped || st.held > 0 || st.parked_exit || st.queued.is_some() {
        return None;
    }
    let r = if st.want_step { ptrace::singlestep(tid as libc::pid_t, signal) } else { ptrace::cont(tid as libc::pid_t, signal) };
    if r.is_ok() {
        st.stopped = false;
    }
    Some(r)
}

fn take_queued(p: &mut ProcState, deferred: bool) -> Option<Stop> {
    let tid = p
        .threads
        .iter()
        .find(|(_, s)| s.queued.as_ref().is_some_and(|q| q.deferred == deferred))
        .map(|(t, _)| *t)?;
    p.threads.get_mut(&tid)?.queued.take().map(|q| q.stop)
}

fn wait_tid(tid: libc::pid_t) -> std::io::Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: plain syscall.
        let r = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
        if r == tid {
            return Ok(status);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn is_event_stop(status: i32) -> bool {
    libc::WIFSTOPPED(status) && status >> 16 == libc::PTRACE_EVENT_STOP
}

fn read_debug_regs(tid: u32) -> Result<[u64; 8], PlatformError> {
    let mut out = [0u64; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        if i == 4 || i == 5 {
            continue;
        }
        *slot = ptrace::peekuser(tid as libc::pid_t, ptrace::debugreg_offset(i)).map_err(|e| os_err("PTRACE_PEEKUSER(dr)", e))?;
    }
    Ok(out)
}

/// Addresses before DR7 (the kernel validates DR7 against them), DR6 last.
fn write_debug_regs(tid: u32, regs: &[u64; 8]) -> Result<(), PlatformError> {
    let current = read_debug_regs(tid)?;
    let t = tid as libc::pid_t;
    for i in 0..4 {
        if regs[i] != current[i] {
            ptrace::pokeuser(t, ptrace::debugreg_offset(i), regs[i]).map_err(|e| os_err("PTRACE_POKEUSER(dr0-3)", e))?;
        }
    }
    if regs[7] != current[7] {
        ptrace::pokeuser(t, ptrace::debugreg_offset(7), regs[7]).map_err(|e| os_err("PTRACE_POKEUSER(dr7)", e))?;
    }
    if regs[6] != current[6] {
        ptrace::pokeuser(t, ptrace::debugreg_offset(6), regs[6]).map_err(|e| os_err("PTRACE_POKEUSER(dr6)", e))?;
    }
    Ok(())
}

pub(super) fn attach_error(pid: u32, e: std::io::Error) -> PlatformError {
    if e.raw_os_error() == Some(libc::EPERM) {
        let scope = super::procfs::yama_ptrace_scope();
        return PlatformError::OsError(match scope {
            Some(n) if n > 0 => format!(
                "ptrace attach to {pid} denied (kernel.yama.ptrace_scope={n}): run with CAP_SYS_PTRACE, \
                 have the target call prctl(PR_SET_PTRACER), or set the sysctl to 0"
            ),
            _ => format!("ptrace attach to {pid} denied: {e}"),
        });
    }
    PlatformError::OsError(format!("ptrace attach to {pid} failed: {e}"))
}
