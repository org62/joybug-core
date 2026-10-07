//! Linux signals in the protocol's vocabulary: which ones are the debuggee's
//! business (re-injected silently), which are faults (reported as
//! `Exception` with the NTSTATUS code the client already understands).

use libc::c_int;

// `si_code` values for SIGFPE/SIGILL (asm-generic/siginfo.h); libc lacks them.
const FPE_INTDIV: c_int = 1;
const FPE_INTOVF: c_int = 2;
const FPE_FLTDIV: c_int = 3;
const FPE_FLTOVF: c_int = 4;
const FPE_FLTUND: c_int = 5;
const FPE_FLTRES: c_int = 6;
const FPE_FLTINV: c_int = 7;
const FPE_FLTSUB: c_int = 8;
const ILL_PRVOPC: c_int = 5;

pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
pub const STATUS_FLOAT_DENORMAL_OPERAND: u32 = 0xC000_008D;
pub const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC000_008E;
pub const STATUS_FLOAT_INEXACT_RESULT: u32 = 0xC000_008F;
pub const STATUS_FLOAT_INVALID_OPERATION: u32 = 0xC000_0090;
pub const STATUS_FLOAT_OVERFLOW: u32 = 0xC000_0091;
pub const STATUS_FLOAT_UNDERFLOW: u32 = 0xC000_0093;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
pub const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;
pub const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC000_0409;

/// What to do with a signal-delivery stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalClass {
    /// Report as `Exception { code }`; `pass_exception` re-injects it.
    Fault(u32),
    /// The debuggee's own business: deliver it and keep running.
    Reinject,
    /// Job control (SIGSTOP and friends): the debugger owns stopping now.
    Swallow,
}

pub fn classify(signo: c_int, si_code: c_int) -> SignalClass {
    use SignalClass::*;
    match signo {
        libc::SIGSEGV => Fault(STATUS_ACCESS_VIOLATION),
        libc::SIGBUS => Fault(if si_code == libc::BUS_ADRALN { STATUS_DATATYPE_MISALIGNMENT } else { STATUS_ACCESS_VIOLATION }),
        libc::SIGFPE => Fault(match si_code {
            FPE_INTDIV => STATUS_INTEGER_DIVIDE_BY_ZERO,
            FPE_INTOVF => STATUS_INTEGER_OVERFLOW,
            FPE_FLTDIV => STATUS_FLOAT_DIVIDE_BY_ZERO,
            FPE_FLTOVF => STATUS_FLOAT_OVERFLOW,
            FPE_FLTUND => STATUS_FLOAT_UNDERFLOW,
            FPE_FLTRES => STATUS_FLOAT_INEXACT_RESULT,
            FPE_FLTINV => STATUS_FLOAT_INVALID_OPERATION,
            FPE_FLTSUB => STATUS_FLOAT_DENORMAL_OPERAND,
            _ => STATUS_INTEGER_DIVIDE_BY_ZERO,
        }),
        libc::SIGILL => Fault(if si_code == ILL_PRVOPC { STATUS_PRIVILEGED_INSTRUCTION } else { STATUS_ILLEGAL_INSTRUCTION }),
        libc::SIGABRT => Fault(STATUS_STACK_BUFFER_OVERRUN),
        libc::SIGSYS => Fault(STATUS_INVALID_SYSTEM_SERVICE),
        libc::SIGTRAP => Fault(STATUS_BREAKPOINT),
        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => Swallow,
        // Everything else - SIGCHLD, SIGALRM, SIGWINCH, SIGUSR1/2, SIGPIPE, SIGIO,
        // SIGURG, SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGXCPU, SIGXFSZ,
        // SIGPWR, and all realtime signals (32/33 are glibc-internal: swallowing
        // them breaks pthread_cancel/setuid) - is delivered as if we were not here.
        _ => Reinject,
    }
}

/// Whether an exception code is a memory fault whose parameters are
/// `[access kind, referenced address]`.
pub fn is_memory_fault(code: u32) -> bool {
    code == STATUS_ACCESS_VIOLATION || code == STATUS_DATATYPE_MISALIGNMENT
}

/// Whether delivering `signo` to `pid` ends the process: nobody handles it
/// and its default action is to terminate. This is what makes a passed
/// signal "unhandled", the condition for a second-chance stop.
pub fn kills_if_delivered(pid: u32, signo: c_int) -> bool {
    let Some((ignored, caught)) = super::procfs::signal_dispositions(pid) else { return false };
    kills_with_dispositions(signo, ignored, caught)
}

fn kills_with_dispositions(signo: c_int, ignored: u64, caught: u64) -> bool {
    if !(1..=64).contains(&signo) {
        return false;
    }
    let bit = 1u64 << (signo - 1);
    if (ignored | caught) & bit != 0 {
        return false;
    }
    // Default action "ignore" or "stop"; everything else terminates.
    !matches!(
        signo,
        libc::SIGCHLD | libc::SIGURG | libc::SIGWINCH | libc::SIGCONT | libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
    )
}

/// A wait status as the client's exit code: the exit status, or 128 + the
/// killing signal.
pub fn exit_code_from_status(status: i32) -> u32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status) as u32
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status) as u32
    } else {
        status as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faults_and_housekeeping() {
        assert_eq!(classify(libc::SIGSEGV, 0), SignalClass::Fault(STATUS_ACCESS_VIOLATION));
        assert_eq!(classify(libc::SIGFPE, FPE_INTDIV), SignalClass::Fault(STATUS_INTEGER_DIVIDE_BY_ZERO));
        assert_eq!(classify(libc::SIGCHLD, 0), SignalClass::Reinject);
        assert_eq!(classify(34, 0), SignalClass::Reinject, "realtime signals pass through");
        assert_eq!(classify(libc::SIGSTOP, 0), SignalClass::Swallow);
        assert_eq!(exit_code_from_status(42 << 8), 42);
        assert_eq!(exit_code_from_status(libc::SIGSEGV), 139);
    }

    #[test]
    fn unhandled_means_default_action_terminates() {
        let bit = |s: c_int| 1u64 << (s - 1);
        assert!(kills_with_dispositions(libc::SIGSEGV, 0, 0));
        assert!(kills_with_dispositions(libc::SIGUSR1, 0, 0));
        assert!(!kills_with_dispositions(libc::SIGUSR1, 0, bit(libc::SIGUSR1)), "a handler takes it");
        assert!(!kills_with_dispositions(libc::SIGUSR1, bit(libc::SIGUSR1), 0), "ignored");
        assert!(!kills_with_dispositions(libc::SIGCHLD, 0, 0), "default action is to ignore");
        assert!(kills_with_dispositions(40, 0, 0), "realtime signals terminate by default");
    }
}
