/// Generates x64 detour stub shellcode that:
/// 1. Saves all GPRs + RFLAGS
/// 2. Calls a dispatch function with (context_ptr, hook_id)
/// 3. Restores all GPRs + RFLAGS
/// 4. Jumps to the trampoline (original function)

/// Size of the generated detour stub in bytes.
pub const DETOUR_STUB_SIZE: usize = 128;

// Byte offsets of the 8-byte immediate values within the generated shellcode.
const HOOK_ID_OFFSET: usize = 35;
const CALLBACK_ADDR_OFFSET: usize = 45;
const TRAMPOLINE_ADDR_OFFSET: usize = 89;

/// Build a detour stub with the given hook_id and callback address.
/// The trampoline address is left zeroed — call `patch_trampoline_addr` after
/// obtaining the trampoline pointer from `HookEngine::create`.
pub fn build_detour_stub(hook_id: u64, callback_addr: u64) -> Vec<u8> {
    #[rustfmt::skip]
    let mut code: Vec<u8> = vec![
        // === Save all registers (24 bytes, offset 0..24) ===
        0x50,                               // push rax
        0x51,                               // push rcx
        0x52,                               // push rdx
        0x53,                               // push rbx
        0x55,                               // push rbp
        0x56,                               // push rsi
        0x57,                               // push rdi
        0x41, 0x50,                         // push r8
        0x41, 0x51,                         // push r9
        0x41, 0x52,                         // push r10
        0x41, 0x53,                         // push r11
        0x41, 0x54,                         // push r12
        0x41, 0x55,                         // push r13
        0x41, 0x56,                         // push r14
        0x41, 0x57,                         // push r15
        0x9C,                               // pushfq

        // === Align stack + shadow space (4 bytes, offset 24..28) ===
        // Entry RSP is 8-aligned (caller's CALL pushed return addr).
        // 16 pushes = 128 bytes → still 8-aligned. sub 0x28 → 16-aligned.
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28

        // === Set up args + call (offset 28..55) ===
        0x48, 0x8D, 0x4C, 0x24, 0x28,       // lea rcx, [rsp+0x28]  ; arg1 = &HookContext
        0x48, 0xBA,                          // mov rdx, imm64       ; arg2 = hook_id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [offset 35..43] hook_id
        0x48, 0xB8,                          // mov rax, imm64       ; callback fn
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [offset 45..53] callback_addr
        0xFF, 0xD0,                          // call rax

        // === Restore all registers (28 bytes, offset 55..83) ===
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
        0x9D,                               // popfq
        0x41, 0x5F,                         // pop r15
        0x41, 0x5E,                         // pop r14
        0x41, 0x5D,                         // pop r13
        0x41, 0x5C,                         // pop r12
        0x41, 0x5B,                         // pop r11
        0x41, 0x5A,                         // pop r10
        0x41, 0x59,                         // pop r9
        0x41, 0x58,                         // pop r8
        0x5F,                               // pop rdi
        0x5E,                               // pop rsi
        0x5D,                               // pop rbp
        0x5B,                               // pop rbx
        0x5A,                               // pop rdx
        0x59,                               // pop rcx
        0x58,                               // pop rax

        // === Jump to trampoline (14 bytes, offset 83..97) ===
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [offset 89..97] trampoline_addr
    ];

    code[HOOK_ID_OFFSET..HOOK_ID_OFFSET + 8].copy_from_slice(&hook_id.to_le_bytes());
    code[CALLBACK_ADDR_OFFSET..CALLBACK_ADDR_OFFSET + 8].copy_from_slice(&callback_addr.to_le_bytes());

    // Pad to DETOUR_STUB_SIZE with INT3 (0xCC)
    code.resize(DETOUR_STUB_SIZE, 0xCC);
    code
}

/// Patch the trampoline address into an already-built detour stub.
pub fn patch_trampoline_addr(stub: &mut [u8], trampoline_addr: u64) {
    stub[TRAMPOLINE_ADDR_OFFSET..TRAMPOLINE_ADDR_OFFSET + 8]
        .copy_from_slice(&trampoline_addr.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_size() {
        let stub = build_detour_stub(0x42, 0xDEADBEEF);
        assert_eq!(stub.len(), DETOUR_STUB_SIZE);
    }

    #[test]
    fn test_hook_id_embedded() {
        let stub = build_detour_stub(0x1234_5678_9ABC_DEF0, 0);
        let val = u64::from_le_bytes(stub[HOOK_ID_OFFSET..HOOK_ID_OFFSET + 8].try_into().unwrap());
        assert_eq!(val, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_callback_addr_embedded() {
        let stub = build_detour_stub(0, 0xCAFE_BABE_DEAD_BEEF);
        let val = u64::from_le_bytes(stub[CALLBACK_ADDR_OFFSET..CALLBACK_ADDR_OFFSET + 8].try_into().unwrap());
        assert_eq!(val, 0xCAFE_BABE_DEAD_BEEF);
    }

    #[test]
    fn test_trampoline_addr_patch() {
        let mut stub = build_detour_stub(0, 0);
        patch_trampoline_addr(&mut stub, 0x1111_2222_3333_4444);
        let val = u64::from_le_bytes(stub[TRAMPOLINE_ADDR_OFFSET..TRAMPOLINE_ADDR_OFFSET + 8].try_into().unwrap());
        assert_eq!(val, 0x1111_2222_3333_4444);
    }
}
