//! POSIX signals in the protocol's exception vocabulary, on every OS (a
//! Windows client talks to a Linux server).
//!
//! The Linux backend reports the fault signals as the NTSTATUS a Windows
//! target would raise (`linux_platform/signals.rs`). Every other signal has
//! no such twin, so it travels as `SIGNAL_EXCEPTION_BASE | signo`: one code
//! per signal, which is all an exception rule needs to tell them apart.
//! Numbers are the x86-64 / AArch64 Linux ones.

/// `'L' 'S'` in the high word; clear of every NTSTATUS facility in use.
pub const SIGNAL_EXCEPTION_BASE: u32 = 0x4C53_0000;

/// Highest signal number (`SIGRTMAX`).
pub const SIGNAL_MAX: u32 = 64;

const NAMES: [&str; 32] = [
    "", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV",
    "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU",
    "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
];

/// The exception code a reported `signo` travels as.
pub fn signal_exception_code(signo: u32) -> u32 {
    SIGNAL_EXCEPTION_BASE | (signo & 0xFFFF)
}

/// The signal behind an exception code, when the code is one of ours.
pub fn exception_code_signal(code: u32) -> Option<u32> {
    let signo = code & 0xFFFF;
    (code & 0xFFFF_0000 == SIGNAL_EXCEPTION_BASE && (1..=SIGNAL_MAX).contains(&signo)).then_some(signo)
}

/// `SIGUSR1`, `SIGRTMIN+3`, ... for a signal number.
pub fn signal_name(signo: u32) -> Option<String> {
    match signo {
        1..=31 => Some(NAMES[signo as usize].to_string()),
        // 32 and 33 belong to glibc (thread cancellation, setxid).
        32..=33 => Some(format!("SIG{signo}")),
        34 => Some("SIGRTMIN".to_string()),
        35..=SIGNAL_MAX => Some(format!("SIGRTMIN+{}", signo - 34)),
        _ => None,
    }
}

/// The number of a signal by name (`SIGUSR1`, `usr1`, `SIGRTMIN+2`).
pub fn signal_by_name(name: &str) -> Option<u32> {
    let upper = name.trim().to_ascii_uppercase();
    let full = if upper.starts_with("SIG") { upper } else { format!("SIG{upper}") };
    (1..=SIGNAL_MAX).find(|&n| signal_name(n).as_deref() == Some(full.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        assert_eq!(signal_exception_code(10), 0x4C53_000A);
        assert_eq!(exception_code_signal(0x4C53_000A), Some(10));
        assert_eq!(exception_code_signal(0xC000_0005), None);
        assert_eq!(exception_code_signal(SIGNAL_EXCEPTION_BASE), None);
        assert_eq!(signal_name(10).as_deref(), Some("SIGUSR1"));
        assert_eq!(signal_name(36).as_deref(), Some("SIGRTMIN+2"));
        assert_eq!(signal_by_name("usr2"), Some(12));
        assert_eq!(signal_by_name("SIGRTMIN+2"), Some(36));
        assert_eq!(signal_by_name("nope"), None);
    }
}
