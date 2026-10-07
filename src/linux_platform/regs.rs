//! ptrace register images <-> the protocol's `CONTEXT` (the windows-sys x64
//! register struct every consumer already reads). The FXSAVE area ptrace
//! hands out (`user_fpregs_struct`) is byte-identical to `CONTEXT.FltSave`,
//! so the floating-point/SSE state is a single 512-byte copy.

use crate::protocol::{ThreadContext, CONTEXT};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;

/// Everything ptrace knows about a thread's registers.
#[derive(Clone, Copy)]
pub struct RegisterImage {
    pub regs: libc::user_regs_struct,
    pub fpregs: libc::user_fpregs_struct,
    /// DR0-DR7 as read with `PEEKUSER` (DR4/DR5 unused).
    pub debug: [u64; 8],
    /// The emulated trap flag: the next resume single-steps this thread.
    pub trap_flag_pending: bool,
}

impl std::fmt::Debug for RegisterImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RegisterImage {{ rip: {:#x}, rsp: {:#x} }}", self.regs.rip, self.regs.rsp)
    }
}

/// x86 trap flag.
pub const TRAP_FLAG: u64 = 0x100;

const _: () = assert!(std::mem::size_of::<libc::user_fpregs_struct>() == 512);
const _: () = assert!(std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::XSAVE_FORMAT>() == 512);

/// Build the protocol context. `trap_flag_pending` is ORed into EFlags: the
/// backend emulates the flag with `PTRACE_SINGLESTEP`, and the shared stepper
/// expects to read back what it set.
pub fn to_context(image: &RegisterImage, trap_flag_pending: bool) -> ThreadContext {
    let r = &image.regs;
    // SAFETY: CONTEXT is plain old data; an all-zero image is a valid value.
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_ALL_AMD64;
    ctx.Rax = r.rax;
    ctx.Rbx = r.rbx;
    ctx.Rcx = r.rcx;
    ctx.Rdx = r.rdx;
    ctx.Rsi = r.rsi;
    ctx.Rdi = r.rdi;
    ctx.Rbp = r.rbp;
    ctx.Rsp = r.rsp;
    ctx.R8 = r.r8;
    ctx.R9 = r.r9;
    ctx.R10 = r.r10;
    ctx.R11 = r.r11;
    ctx.R12 = r.r12;
    ctx.R13 = r.r13;
    ctx.R14 = r.r14;
    ctx.R15 = r.r15;
    ctx.Rip = r.rip;
    let mut eflags = r.eflags;
    if trap_flag_pending {
        eflags |= TRAP_FLAG;
    }
    ctx.EFlags = eflags as u32;
    ctx.SegCs = r.cs as u16;
    ctx.SegSs = r.ss as u16;
    ctx.SegDs = r.ds as u16;
    ctx.SegEs = r.es as u16;
    ctx.SegFs = r.fs as u16;
    ctx.SegGs = r.gs as u16;
    ctx.Dr0 = image.debug[0];
    ctx.Dr1 = image.debug[1];
    ctx.Dr2 = image.debug[2];
    ctx.Dr3 = image.debug[3];
    ctx.Dr6 = image.debug[6];
    ctx.Dr7 = image.debug[7];
    ctx.MxCsr = image.fpregs.mxcsr;
    // SAFETY: both are 512-byte FXSAVE images (asserted above), plain old data.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &image.fpregs as *const libc::user_fpregs_struct as *const u8,
            &mut ctx.Anonymous.FltSave as *mut _ as *mut u8,
            512,
        );
    }
    ThreadContext::Win32RawContext(ctx)
}

/// What a `set_thread_context` asks the backend to write, split by the
/// ptrace request that carries it. `trap_flag` is the TF the caller wants;
/// the backend strips it from the register write and emulates it.
pub struct ContextWrite {
    pub regs: libc::user_regs_struct,
    pub fpregs: libc::user_fpregs_struct,
    pub debug: [u64; 8],
    pub trap_flag: bool,
}

/// Overlay a protocol context onto the thread's current image (which
/// supplies `orig_rax`, `fs_base`, `gs_base` - fields `CONTEXT` has no slot for).
pub fn from_context(ctx: &CONTEXT, current: &RegisterImage) -> ContextWrite {
    let mut regs = current.regs;
    regs.rax = ctx.Rax;
    regs.rbx = ctx.Rbx;
    regs.rcx = ctx.Rcx;
    regs.rdx = ctx.Rdx;
    regs.rsi = ctx.Rsi;
    regs.rdi = ctx.Rdi;
    regs.rbp = ctx.Rbp;
    regs.rsp = ctx.Rsp;
    regs.r8 = ctx.R8;
    regs.r9 = ctx.R9;
    regs.r10 = ctx.R10;
    regs.r11 = ctx.R11;
    regs.r12 = ctx.R12;
    regs.r13 = ctx.R13;
    regs.r14 = ctx.R14;
    regs.r15 = ctx.R15;
    regs.rip = ctx.Rip;
    let trap_flag = ctx.EFlags as u64 & TRAP_FLAG != 0;
    regs.eflags = (ctx.EFlags as u64) & !TRAP_FLAG;
    regs.cs = ctx.SegCs as u64;
    regs.ss = ctx.SegSs as u64;
    regs.ds = ctx.SegDs as u64;
    regs.es = ctx.SegEs as u64;
    regs.fs = ctx.SegFs as u64;
    regs.gs = ctx.SegGs as u64;
    let mut fpregs = current.fpregs;
    // SAFETY: both are 512-byte FXSAVE images, plain old data.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &ctx.Anonymous.FltSave as *const _ as *const u8,
            &mut fpregs as *mut libc::user_fpregs_struct as *mut u8,
            512,
        );
    }
    fpregs.mxcsr = ctx.MxCsr;
    let mut debug = current.debug;
    debug[0] = ctx.Dr0;
    debug[1] = ctx.Dr1;
    debug[2] = ctx.Dr2;
    debug[3] = ctx.Dr3;
    debug[6] = ctx.Dr6;
    debug[7] = ctx.Dr7;
    ContextWrite { regs, fpregs, debug, trap_flag }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> RegisterImage {
        // SAFETY: plain old data.
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.rip = 0x401000;
        regs.rsp = 0x7ffe0000;
        regs.rax = 42;
        regs.eflags = 0x246;
        regs.cs = 0x33;
        regs.fs_base = 0x7f00_0000_0000;
        regs.orig_rax = u64::MAX;
        let mut fpregs: libc::user_fpregs_struct = unsafe { std::mem::zeroed() };
        fpregs.mxcsr = 0x1f80;
        fpregs.xmm_space[0] = 0xdead_beef;
        RegisterImage { regs, fpregs, debug: [0, 0, 0, 0, 0, 0, 0, 0x400], trap_flag_pending: false }
    }

    #[test]
    fn round_trips_and_keeps_what_context_cannot_carry() {
        let img = image();
        let ThreadContext::Win32RawContext(ctx) = to_context(&img, true) else { panic!() };
        assert_eq!(ctx.Rip, 0x401000);
        assert_eq!(ctx.Rax, 42);
        assert_eq!(ctx.EFlags, 0x346, "TF ORed in while a step is pending");
        assert_eq!(ctx.SegCs, 0x33);
        assert_eq!(ctx.Dr7, 0x400);
        assert_eq!(ctx.MxCsr, 0x1f80);
        assert_eq!(unsafe { ctx.Anonymous.Anonymous.Xmm0.Low }, 0xdead_beef);

        let mut edited = ctx;
        edited.Rax = 7;
        let w = from_context(&edited, &img);
        assert_eq!(w.regs.rax, 7);
        assert!(w.trap_flag, "TF is reported to the caller, not written");
        assert_eq!(w.regs.eflags, 0x246, "TF stripped from the register write");
        assert_eq!(w.regs.fs_base, 0x7f00_0000_0000, "fs_base preserved");
        assert_eq!(w.regs.orig_rax, u64::MAX, "orig_rax preserved");
        assert_eq!(w.fpregs.xmm_space[0], 0xdead_beef);
    }
}
