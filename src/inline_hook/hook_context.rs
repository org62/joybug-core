/// CPU register context saved/restored by the detour stub.
///
/// The field order matches the push sequence in the shellcode (lowest address first):
/// pushfq, push r15..r8, push rdi..rax
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HookContext {
    pub rflags: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}

/// AArch64 register context saved/restored by the detour stub.
///
/// Field order matches the store layout in the stub (lowest address first):
/// x0 at [sp+0x00] … x30 at [sp+0xF0]. NZCV is not preserved (it is
/// caller-saved/volatile across an AAPCS64 call).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HookContext {
    pub x: [u64; 31], // x0..x30
}
