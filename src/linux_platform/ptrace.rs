//! Thin, typed wrappers over the raw `ptrace(2)` requests the backend uses.
//! Every call must come from the tracer thread (`tracer.rs`); nothing here
//! enforces that, the tracer's ownership of the requests does.

use std::io;
use std::mem::{self, MaybeUninit};

use libc::{c_long, c_uint, c_void, pid_t};

fn check(ret: c_long) -> io::Result<c_long> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// A PEEK request: `errno` is the only way to tell a -1 return value from
/// an error, so it is cleared first.
fn request(req: c_uint, tid: pid_t, addr: *mut c_void, data: *mut c_void) -> io::Result<c_long> {
    unsafe {
        *libc::__errno_location() = 0;
        let ret = libc::ptrace(req, tid, addr, data);
        if ret == -1 && *libc::__errno_location() != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret)
    }
}

/// `PTRACE_SEIZE` with the given `PTRACE_O_*` options.
pub fn seize(tid: pid_t, options: i32) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_SEIZE, tid, 0 as *mut c_void, options as usize as *mut c_void)) }.map(|_| ())
}

pub fn interrupt(tid: pid_t) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_INTERRUPT, tid, 0 as *mut c_void, 0 as *mut c_void)) }.map(|_| ())
}

/// Resume `tid`, delivering `signal` (0 for none).
pub fn cont(tid: pid_t, signal: i32) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_CONT, tid, 0 as *mut c_void, signal as usize as *mut c_void)) }.map(|_| ())
}

/// Execute one instruction, delivering `signal` (0 for none).
pub fn singlestep(tid: pid_t, signal: i32) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_SINGLESTEP, tid, 0 as *mut c_void, signal as usize as *mut c_void)) }.map(|_| ())
}

pub fn detach(tid: pid_t) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_DETACH, tid, 0 as *mut c_void, 0 as *mut c_void)) }.map(|_| ())
}

pub fn getregs(tid: pid_t) -> io::Result<libc::user_regs_struct> {
    let mut regs = MaybeUninit::<libc::user_regs_struct>::uninit();
    unsafe {
        check(libc::ptrace(libc::PTRACE_GETREGS, tid, 0 as *mut c_void, regs.as_mut_ptr() as *mut c_void))?;
        Ok(regs.assume_init())
    }
}

pub fn setregs(tid: pid_t, regs: &libc::user_regs_struct) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_SETREGS, tid, 0 as *mut c_void, regs as *const _ as *mut c_void)) }.map(|_| ())
}

pub fn getfpregs(tid: pid_t) -> io::Result<libc::user_fpregs_struct> {
    let mut regs = MaybeUninit::<libc::user_fpregs_struct>::uninit();
    unsafe {
        check(libc::ptrace(libc::PTRACE_GETFPREGS, tid, 0 as *mut c_void, regs.as_mut_ptr() as *mut c_void))?;
        Ok(regs.assume_init())
    }
}

pub fn setfpregs(tid: pid_t, regs: &libc::user_fpregs_struct) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_SETFPREGS, tid, 0 as *mut c_void, regs as *const _ as *mut c_void)) }.map(|_| ())
}

/// Byte offset of debug register `index` in `struct user`, for PEEKUSER/POKEUSER.
pub fn debugreg_offset(index: usize) -> usize {
    mem::offset_of!(libc::user, u_debugreg) + index * mem::size_of::<libc::c_ulonglong>()
}

pub fn peekuser(tid: pid_t, offset: usize) -> io::Result<u64> {
    request(libc::PTRACE_PEEKUSER, tid, offset as *mut c_void, 0 as *mut c_void).map(|v| v as u64)
}

pub fn pokeuser(tid: pid_t, offset: usize, value: u64) -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_POKEUSER, tid, offset as *mut c_void, value as usize as *mut c_void)) }.map(|_| ())
}

/// The message of the last `PTRACE_EVENT_*` stop (new pid/tid, exit status).
pub fn geteventmsg(tid: pid_t) -> io::Result<u64> {
    let mut msg: libc::c_ulong = 0;
    unsafe { check(libc::ptrace(libc::PTRACE_GETEVENTMSG, tid, 0 as *mut c_void, &mut msg as *mut _ as *mut c_void))? };
    Ok(msg as u64)
}

pub fn getsiginfo(tid: pid_t) -> io::Result<libc::siginfo_t> {
    let mut info = MaybeUninit::<libc::siginfo_t>::uninit();
    unsafe {
        check(libc::ptrace(libc::PTRACE_GETSIGINFO, tid, 0 as *mut c_void, info.as_mut_ptr() as *mut c_void))?;
        Ok(info.assume_init())
    }
}

/// The `PTRACE_O_*` options every tracee gets.
pub fn standard_options() -> i32 {
    libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT
        | libc::PTRACE_O_EXITKILL
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACEVFORKDONE
}
