/// CPU register context saved/restored by the detour stub.
///
/// The field order matches the push sequence in the shellcode (lowest address first):
/// pushfq, push r15..r8, push rdi..rax
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
