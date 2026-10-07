//! Starting a debuggee: fork, stop the child before exec so the tracer can
//! seize it, then exec. `std::process::Command` cannot be used: its exec-
//! status pipe makes `spawn` wait for the exec, which can't happen before
//! the seize.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::sync::Mutex;

use crate::interfaces::PlatformError;

/// Split a command line into argv the way a POSIX shell would.
pub fn split_command(command: &str) -> Result<Vec<CString>, PlatformError> {
    let parts = shlex::split(command).ok_or_else(|| PlatformError::Other("unbalanced quotes in the launch command".into()))?;
    if parts.is_empty() {
        return Err(PlatformError::Other("empty launch command".into()));
    }
    parts
        .into_iter()
        .map(|p| CString::new(p).map_err(|_| PlatformError::Other("NUL byte in the launch command".into())))
        .collect()
}

/// The child's environment: ours, with `extra` overlaid (case-sensitive).
pub fn build_envp(extra: Option<&[(String, String)]>) -> Vec<CString> {
    let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    if let Some(extra) = extra {
        for (k, v) in extra {
            env.insert(k.clone().into(), v.clone().into());
        }
    }
    env.into_iter()
        .filter_map(|(k, v)| {
            let mut bytes = k.into_vec();
            bytes.push(b'=');
            bytes.extend(v.into_vec());
            CString::new(bytes).ok()
        })
        .collect()
}

/// Exec failures the child reported, by pid, for the tracer to pick up.
static EXEC_ERRORS: Mutex<Option<HashMap<libc::pid_t, (i32, libc::pid_t)>>> = Mutex::new(None);

/// Fork; the child stops itself with SIGSTOP and, once resumed, execs.
/// Returns the child's pid. An exec failure is reported through a pipe and
/// readable with [`take_exec_error`] once the child has exited.
pub fn fork_stopped(argv: &[CString], cwd: Option<&CStr>, envp: &[CString]) -> Result<libc::pid_t, PlatformError> {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let mut pipe = [0; 2];
    // SAFETY: plain syscalls; the child only calls async-signal-safe functions.
    unsafe {
        if libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            return Err(PlatformError::OsError(format!("pipe2: {}", std::io::Error::last_os_error())));
        }
        let pid = libc::fork();
        if pid < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            return Err(PlatformError::OsError(format!("fork: {e}")));
        }
        if pid == 0 {
            // ---- child ----
            libc::close(pipe[0]);
            if let Some(dir) = cwd {
                if libc::chdir(dir.as_ptr()) != 0 {
                    report_and_exit(pipe[1], b'c');
                }
            }
            libc::raise(libc::SIGSTOP);
            libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            report_and_exit(pipe[1], b'e');
        }
        // ---- parent ----
        libc::close(pipe[1]);
        EXEC_ERRORS.lock().unwrap().get_or_insert_with(HashMap::new).insert(pid, (pipe[0], pid));
        // Wait for the SIGSTOP; the child is now stopped and seizable.
        let mut status = 0;
        loop {
            let r = libc::waitpid(pid, &mut status, libc::WUNTRACED);
            if r == pid {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(PlatformError::OsError(format!("waitpid for the stopped child: {e}")));
            }
        }
        if !libc::WIFSTOPPED(status) {
            let msg = take_exec_error(pid).unwrap_or_else(|| format!("the child exited before stopping (status {status:#x})"));
            return Err(PlatformError::OsError(format!("launch failed: {msg}")));
        }
        Ok(pid)
    }
}

/// Child side: write `(what, errno)` to the pipe and exit. Async-signal-safe.
unsafe fn report_and_exit(fd: libc::c_int, what: u8) -> ! {
    unsafe {
        let errno = *libc::__errno_location();
        let mut buf = [0u8; 5];
        buf[0] = what;
        buf[1..].copy_from_slice(&errno.to_ne_bytes());
        libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
        libc::_exit(127);
    }
}

/// The message of a failed exec/chdir, if the child reported one.
pub fn take_exec_error(pid: libc::pid_t) -> Option<String> {
    let (fd, _) = EXEC_ERRORS.lock().unwrap().as_mut()?.remove(&pid)?;
    let mut buf = [0u8; 5];
    // SAFETY: fd is our read end; reading 5 bytes into a 5-byte buffer.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(fd) };
    if n != 5 {
        return None;
    }
    let errno = i32::from_ne_bytes(buf[1..].try_into().unwrap());
    let e = std::io::Error::from_raw_os_error(errno);
    Some(match buf[0] {
        b'c' => format!("chdir failed: {e}"),
        _ => format!("exec failed: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_a_shell() {
        let argv = split_command("/bin/sh -c 'echo \"hi there\"'").unwrap();
        let s: Vec<&str> = argv.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(s, ["/bin/sh", "-c", "echo \"hi there\""]);
        assert!(split_command("'unterminated").is_err());
        assert!(split_command("   ").is_err());
    }

    #[test]
    fn env_overlay_wins() {
        let envp = build_envp(Some(&[("JOYBUG_TEST_X".into(), "1".into())]));
        assert!(envp.iter().any(|e| e.to_bytes() == b"JOYBUG_TEST_X=1"));
    }
}
