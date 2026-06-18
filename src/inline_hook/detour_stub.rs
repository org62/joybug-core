/// Generates detour stub shellcode that:
/// 1. Saves all GPRs (+ RFLAGS on x86)
/// 2. Calls a dispatch function with (context_ptr, hook_id)
/// 3. Restores all GPRs (+ RFLAGS on x86)
/// 4. Jumps to the trampoline (original function)

/// Size of the generated detour stub in bytes.
#[cfg(target_arch = "x86_64")]
pub const DETOUR_STUB_SIZE: usize = 128;
#[cfg(target_arch = "aarch64")]
pub const DETOUR_STUB_SIZE: usize = 256;

// Byte offsets of the 8-byte immediate values within the generated shellcode.
#[cfg(target_arch = "x86_64")]
const HOOK_ID_OFFSET: usize = 35;
#[cfg(target_arch = "x86_64")]
const CALLBACK_ADDR_OFFSET: usize = 45;
#[cfg(target_arch = "x86_64")]
const TRAMPOLINE_ADDR_OFFSET: usize = 89;

/// Build a detour stub with the given hook_id and callback address.
/// The trampoline address is left zeroed — call `patch_trampoline_addr` after
/// obtaining the trampoline pointer from `HookEngine::create`.
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
pub fn patch_trampoline_addr(stub: &mut [u8], trampoline_addr: u64) {
    stub[TRAMPOLINE_ADDR_OFFSET..TRAMPOLINE_ADDR_OFFSET + 8]
        .copy_from_slice(&trampoline_addr.to_le_bytes());
}

// ===================== AArch64 detour stub =====================

/// Byte offset of the trampoline-address MOVZ/MOVK block in the AArch64 stub.
/// The stub prefix is a fixed 44 instructions (176 bytes); the trampoline load
/// (4 instructions = 16 bytes) and final `BR X16` (4 bytes) follow.
#[cfg(target_arch = "aarch64")]
const ARM64_TRAMPOLINE_MOV_OFFSET: usize = 176;

/// Encode a 64-bit immediate into Xd using MOVZ + 3×MOVK (16 bytes).
#[cfg(target_arch = "aarch64")]
fn mov_imm64(reg: u32, value: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    for hw in 0..4u32 {
        let imm16 = ((value >> (hw * 16)) & 0xFFFF) as u32;
        // hw==0 → MOVZ (0xD2800000), hw>0 → MOVK (0xF2800000)
        let base = if hw == 0 { 0xD280_0000 } else { 0xF280_0000 };
        let insn = base | (hw << 21) | (imm16 << 5) | reg;
        out[(hw as usize) * 4..(hw as usize) * 4 + 4].copy_from_slice(&insn.to_le_bytes());
    }
    out
}

// --- Minimal AArch64 instruction encoders (sp-relative forms used by the stub) ---
// Hand-encoded rather than assembled at runtime: the stub is a fixed instruction
// sequence, and avoiding Keystone here sidesteps its process-global state (which
// is unsafe to mix across x86/ARM64 engine creation even when calls are serialized).
#[cfg(target_arch = "aarch64")]
mod enc {
    /// STP Xt, Xt2, [SP, #off]  (signed offset, 64-bit)
    pub fn stp_sp(rt: u32, rt2: u32, off: u32) -> u32 {
        0xA900_0000 | (((off / 8) & 0x7F) << 15) | (rt2 << 10) | (31 << 5) | rt
    }
    /// LDP Xt, Xt2, [SP, #off]
    pub fn ldp_sp(rt: u32, rt2: u32, off: u32) -> u32 {
        0xA940_0000 | (((off / 8) & 0x7F) << 15) | (rt2 << 10) | (31 << 5) | rt
    }
    /// STR Xt, [SP, #off]  (unsigned offset, 64-bit)
    pub fn str_sp(rt: u32, off: u32) -> u32 {
        0xF900_0000 | (((off / 8) & 0xFFF) << 10) | (31 << 5) | rt
    }
    /// LDR Xt, [SP, #off]
    pub fn ldr_sp(rt: u32, off: u32) -> u32 {
        0xF940_0000 | (((off / 8) & 0xFFF) << 10) | (31 << 5) | rt
    }
    /// SUB SP, SP, #imm  (imm < 4096)
    pub fn sub_sp(imm: u32) -> u32 {
        0xD100_0000 | ((imm & 0xFFF) << 10) | (31 << 5) | 31
    }
    /// ADD SP, SP, #imm
    pub fn add_sp(imm: u32) -> u32 {
        0x9100_0000 | ((imm & 0xFFF) << 10) | (31 << 5) | 31
    }
    /// MOV Xd, SP  (alias of ADD Xd, SP, #0)
    pub fn mov_from_sp(rd: u32) -> u32 {
        0x9100_0000 | (31 << 5) | rd
    }
    /// BLR Xn
    pub fn blr(rn: u32) -> u32 {
        0xD63F_0000 | (rn << 5)
    }
    /// BR Xn
    pub fn br(rn: u32) -> u32 {
        0xD61F_0000 | (rn << 5)
    }
}

/// Build the AArch64 detour stub.
///
/// Saves x0-x30 to a stack-allocated `HookContext`, calls
/// `dispatch(ctx_ptr, hook_id)`, restores x0-x30 (so the Lua handler's register
/// edits take effect), then branches to the trampoline via x16 (an
/// intra-procedure scratch register per AAPCS64). AArch64 condition flags (NZCV)
/// are caller-saved/volatile across a call, so we don't preserve them.
///
/// The trampoline address is left as a placeholder — patch it with
/// `patch_trampoline_addr` once the trampoline pointer is known.
#[cfg(target_arch = "aarch64")]
pub fn build_detour_stub(hook_id: u64, callback_addr: u64) -> Vec<u8> {
    // x0..x29 saved as pairs at [sp+0x00 .. sp+0xE8], x30 at [sp+0xF0].
    let pairs: [(u32, u32, u32); 15] = [
        (0, 1, 0x00), (2, 3, 0x10), (4, 5, 0x20), (6, 7, 0x30),
        (8, 9, 0x40), (10, 11, 0x50), (12, 13, 0x60), (14, 15, 0x70),
        (16, 17, 0x80), (18, 19, 0x90), (20, 21, 0xa0), (22, 23, 0xb0),
        (24, 25, 0xc0), (26, 27, 0xd0), (28, 29, 0xe0),
    ];

    let mut insns: Vec<u32> = Vec::new();
    // Reserve 0x100 (256, 16-aligned) for the 31-register HookContext (248 bytes).
    insns.push(enc::sub_sp(0x100));
    for (a, b, off) in pairs {
        insns.push(enc::stp_sp(a, b, off));
    }
    insns.push(enc::str_sp(30, 0xf0));
    // dispatch(ctx_ptr = sp, hook_id) via x2 = callback.
    insns.push(enc::mov_from_sp(0)); // mov x0, sp

    let mut code: Vec<u8> = Vec::new();
    for insn in &insns {
        code.extend_from_slice(&insn.to_le_bytes());
    }
    code.extend_from_slice(&mov_imm64(1, hook_id)); // x1 = hook_id
    code.extend_from_slice(&mov_imm64(2, callback_addr)); // x2 = callback

    let mut tail: Vec<u32> = Vec::new();
    tail.push(enc::blr(2));
    tail.push(enc::ldr_sp(30, 0xf0));
    for (a, b, off) in pairs.iter().rev() {
        tail.push(enc::ldp_sp(*a, *b, *off));
    }
    tail.push(enc::add_sp(0x100));
    for insn in &tail {
        code.extend_from_slice(&insn.to_le_bytes());
    }

    debug_assert_eq!(
        code.len(),
        ARM64_TRAMPOLINE_MOV_OFFSET,
        "AArch64 detour stub prefix size changed; update ARM64_TRAMPOLINE_MOV_OFFSET"
    );

    // Trampoline load (placeholder 0) + BR X16.
    code.extend_from_slice(&mov_imm64(16, 0));
    code.extend_from_slice(&enc::br(16).to_le_bytes());
    code.resize(DETOUR_STUB_SIZE, 0x00);
    code
}

/// Patch the trampoline address into an already-built detour stub.
#[cfg(target_arch = "aarch64")]
pub fn patch_trampoline_addr(stub: &mut [u8], trampoline_addr: u64) {
    let mov = mov_imm64(16, trampoline_addr);
    stub[ARM64_TRAMPOLINE_MOV_OFFSET..ARM64_TRAMPOLINE_MOV_OFFSET + 16].copy_from_slice(&mov);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_size() {
        let stub = build_detour_stub(0x42, 0xDEADBEEF);
        assert_eq!(stub.len(), DETOUR_STUB_SIZE);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_hook_id_embedded() {
        let stub = build_detour_stub(0x1234_5678_9ABC_DEF0, 0);
        let val = u64::from_le_bytes(stub[HOOK_ID_OFFSET..HOOK_ID_OFFSET + 8].try_into().unwrap());
        assert_eq!(val, 0x1234_5678_9ABC_DEF0);
    }

    #[cfg(target_arch = "x86_64")]
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
        #[cfg(target_arch = "x86_64")]
        {
            let val = u64::from_le_bytes(stub[TRAMPOLINE_ADDR_OFFSET..TRAMPOLINE_ADDR_OFFSET + 8].try_into().unwrap());
            assert_eq!(val, 0x1111_2222_3333_4444);
        }
        #[cfg(target_arch = "aarch64")]
        {
            // Verify the MOVZ/MOVK block decodes back to the patched address.
            let mut v: u64 = 0;
            for hw in 0..4u32 {
                let insn = u32::from_le_bytes(
                    stub[ARM64_TRAMPOLINE_MOV_OFFSET + (hw as usize) * 4
                        ..ARM64_TRAMPOLINE_MOV_OFFSET + (hw as usize) * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
                let imm16 = ((insn >> 5) & 0xFFFF) as u64;
                v |= imm16 << (hw * 16);
            }
            assert_eq!(v, 0x1111_2222_3333_4444);
        }
    }
}
