//! A tracer [`Stop`] becomes a `DebugEvent` (or nothing): the Linux twin of
//! the Windows `handle_debug_event`. Breakpoint and single-step traps go to
//! the shared ladder; signals are classified; lifecycle stops update the
//! thread table and the loader state.

use std::collections::HashSet;

use tracing::{debug, trace, warn};

use super::signals::{self, SignalClass};
use super::tracer::{Stop, StopKind};
use super::{LinuxProcess, PendingSignal};
use crate::posix_signals::signal_exception_code;
use crate::debugger_core::events::{on_breakpoint, on_single_step, TrapInfo};
use crate::debugger_core::stepping;
use crate::interfaces::PlatformError;
use crate::protocol::DebugEvent;

/// What the platform does after a stop: report the event (if any) and,
/// on the next resume of that thread, deliver `reinject`.
pub struct Handled {
    pub event: Option<DebugEvent>,
    pub reinject: Option<i32>,
}

impl LinuxProcess {
    /// A signal stop the client gets to see: remembered so the continue can
    /// deliver it (`pass_exception`) or drop it.
    fn report_signal(&mut self, pid: u32, tid: u32, signo: i32, code: u32, address: u64, parameters: Vec<u64>) -> DebugEvent {
        self.last_fault.insert(tid, PendingSignal { signo, code, address, parameters: parameters.clone(), second_chance_reported: false });
        DebugEvent::Exception { pid, tid, code, address, first_chance: true, parameters }
    }

    /// `reported`: the signals the client asked to see (`SetReportedSignals`).
    pub(super) fn handle_stop(&mut self, stop: Stop, reported: &HashSet<i32>) -> Result<Handled, PlatformError> {
        let pid = stop.pid;
        let tid = stop.tid;
        let none = |reinject: Option<i32>| Ok(Handled { event: None, reinject });
        match stop.kind {
            StopKind::Signal { signo, code, rip, .. } if signo == libc::SIGTRAP => {
                let trap = |code: u32| TrapInfo { code, first_chance: true };
                match code {
                    libc::SI_KERNEL | libc::TRAP_BRKPT => {
                        // The kernel leaves RIP past the int3; the ladder rewinds
                        // the ones we own.
                        let address = rip.wrapping_sub(1);
                        let event = on_breakpoint(&mut self.book, &self.os, pid, tid, address, trap(signals::STATUS_BREAKPOINT))?;
                        Ok(Handled { event, reinject: None })
                    }
                    libc::TRAP_TRACE | libc::TRAP_HWBKPT => {
                        let event = on_single_step(&mut self.book, &self.os, pid, tid, rip, trap(signals::STATUS_SINGLE_STEP))?;
                        Ok(Handled { event, reinject: None })
                    }
                    _ => {
                        debug!(pid, tid, code, "SIGTRAP from elsewhere (kill/tkill); reporting as a breakpoint exception");
                        Ok(Handled {
                            event: Some(DebugEvent::Exception { pid, tid, code: signals::STATUS_BREAKPOINT, address: rip, first_chance: true, parameters: vec![] }),
                            reinject: None,
                        })
                    }
                }
            }
            StopKind::Signal { signo, code, addr, rip } => match signals::classify(signo, code) {
                SignalClass::Fault(status) => {
                    let parameters = if signo == libc::SIGSEGV || signo == libc::SIGBUS { vec![0, addr] } else { vec![] };
                    trace!(pid, tid, signo, address = %format!("{rip:#x}"), "fault");
                    Ok(Handled { event: Some(self.report_signal(pid, tid, signo, status, rip, parameters)), reinject: None })
                }
                // The client asked to see this one: it stops like an exception
                // and is delivered only when the continue passes it on. A
                // group-stop (no PC: the tracer's mark for one) is a stop signal
                // taking effect after it was passed, not a second arrival.
                SignalClass::Reinject | SignalClass::Swallow if reported.contains(&signo) && rip != 0 => {
                    // A signal somebody sent (kill, tgkill, sigqueue) names its
                    // sender where a fault has its address.
                    let sender = if code <= 0 { addr & 0xFFFF_FFFF } else { 0 };
                    trace!(pid, tid, signo, "signal reported");
                    let parameters = vec![signo as u64, code as i64 as u64, sender];
                    Ok(Handled {
                        event: Some(self.report_signal(pid, tid, signo, signal_exception_code(signo as u32), rip, parameters)),
                        reinject: None,
                    })
                }
                SignalClass::Reinject => {
                    trace!(pid, tid, signo, "signal passed through");
                    none(Some(signo))
                }
                SignalClass::Swallow => {
                    trace!(pid, tid, signo, "job-control signal swallowed");
                    none(None)
                }
            },
            StopKind::Interrupted => {
                let address = self.os.image(tid).map(|i| i.regs.rip).unwrap_or(0);
                let event = if self.book.has_hit_initial_breakpoint {
                    DebugEvent::Breakpoint { pid, tid, address }
                } else {
                    self.book.has_hit_initial_breakpoint = true;
                    DebugEvent::InitialBreakpoint { pid, tid, address }
                };
                Ok(Handled { event: Some(event), reinject: None })
            }
            StopKind::Clone { new_tid } => {
                let start_address = self.os.image(new_tid).map(|i| i.regs.rip).unwrap_or(0);
                self.os.threads.lock().unwrap().insert(new_tid, start_address, ());
                // Debug registers are not inherited on Linux.
                let active = self.book.hw.active();
                if !active.is_empty() {
                    if let Err(e) = crate::debugger_core::ops::ProcessOps::apply_all_hw_bps(&self.os, pid, new_tid, &active) {
                        warn!(pid, new_tid, error = %e, "applying hardware breakpoints to the new thread failed");
                    }
                }
                Ok(Handled { event: Some(DebugEvent::ThreadCreated { pid, tid: new_tid, start_address }), reinject: None })
            }
            StopKind::Fork { child, vfork } => {
                // The platform decides what becomes of the child (it owns the
                // process table): see `LinuxPlatform::on_fork`.
                self.pending_fork = Some((child, vfork));
                none(None)
            }
            StopKind::VforkDone => {
                self.rearm_breakpoints_after_vfork(pid);
                none(None)
            }
            StopKind::Exec => {
                debug!(pid, "exec: the image was replaced");
                self.exec_pending = true;
                none(None)
            }
            StopKind::Exit { status, last_thread } => {
                let exit_code = signals::exit_code_from_status(status);
                if last_thread {
                    stepping::resume_all_step_over_suspensions(&mut self.book.steps, &self.os, pid);
                    self.book.bps.clear_step_over();
                    self.book.bps.clear_step_out();
                    self.exited = Some(exit_code);
                    Ok(Handled { event: Some(DebugEvent::ProcessExited { pid, tid, exit_code }), reinject: None })
                } else {
                    stepping::forget_thread_step_over(&mut self.book.steps, &self.os, pid, tid);
                    self.book.bps.retain_step_over_excluding_tid(tid);
                    self.book.bps.retain_step_out_excluding_tid(tid);
                    self.os.threads.lock().unwrap().remove_thread(tid);
                    Ok(Handled { event: Some(DebugEvent::ThreadExited { pid, tid, exit_code }), reinject: None })
                }
            }
            StopKind::Gone { status, .. } => {
                let exit_code = signals::exit_code_from_status(status);
                self.exited = Some(exit_code);
                self.reaped = true;
                Ok(Handled { event: Some(DebugEvent::ProcessExited { pid, tid, exit_code }), reinject: None })
            }
        }
    }
}
