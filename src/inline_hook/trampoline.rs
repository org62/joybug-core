use super::error::InlineHookError;
use capstone::prelude::*;
#[cfg(target_arch = "x86_64")]
use capstone::arch::x86::X86OperandType;
#[cfg(target_arch = "x86_64")]
use capstone::arch::ArchDetail;
#[cfg(target_arch = "x86_64")]
use capstone::RegId;
use std::cell::RefCell;

/// X86 RIP register ID in Capstone.
#[cfg(target_arch = "x86_64")]
const X86_REG_RIP: u16 = 41;

/// Minimum bytes we must overwrite at the target for the patch jump.
/// x86: 5-byte E9 JMP rel32. ARM64: one 4-byte `B` instruction.
#[cfg(target_arch = "x86_64")]
pub const MIN_HOOK_SIZE: usize = 5;
#[cfg(target_arch = "aarch64")]
pub const MIN_HOOK_SIZE: usize = 4;

/// Size of the relay stub (absolute jump to the detour).
/// x86: FF 25 00 00 00 00 + 8-byte address = 14. ARM64: LDR X17,#8 + BR X17 +
/// 8-byte address = 16.
#[cfg(target_arch = "x86_64")]
pub const RELAY_SIZE: usize = 14;
#[cfg(target_arch = "aarch64")]
pub const RELAY_SIZE: usize = 16;


thread_local! {
    static CS_ENGINE: RefCell<Option<Capstone>> = const { RefCell::new(None) };
}

#[cfg(target_arch = "x86_64")]
fn with_capstone<F, R>(f: F) -> Result<R, InlineHookError>
where
    F: FnOnce(&Capstone) -> Result<R, InlineHookError>,
{
    CS_ENGINE.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            let engine = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| InlineHookError::DisassemblyFailed(e.to_string()))?;
            *opt = Some(engine);
        }
        f(opt.as_ref().unwrap())
    })
}

#[cfg(target_arch = "aarch64")]
fn with_capstone<F, R>(f: F) -> Result<R, InlineHookError>
where
    F: FnOnce(&Capstone) -> Result<R, InlineHookError>,
{
    CS_ENGINE.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            let engine = Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| InlineHookError::DisassemblyFailed(e.to_string()))?;
            *opt = Some(engine);
        }
        f(opt.as_ref().unwrap())
    })
}

/// Information about the analyzed prologue.
pub struct PrologueInfo {
    /// Original bytes from the target function that we'll overwrite.
    pub original_bytes: Vec<u8>,
    /// Number of bytes we need to overwrite (>= MIN_HOOK_SIZE).
    pub patch_size: usize,
    /// Instruction boundaries in the original code (offsets from start).
    pub boundaries: Vec<(usize, usize)>, // (offset, length) pairs
}

/// Result of building a trampoline.
pub struct TrampolineLayout {
    /// Offset within the slot where the relay stub starts.
    pub relay_offset: usize,
    /// Offset within the slot where the trampoline code starts.
    pub trampoline_offset: usize,
    /// Total bytes written to the slot.
    pub total_size: usize,
}

/// Analyze the prologue at `target` to determine how many bytes to copy.
pub fn analyze_prologue(target: *const u8, max_read: usize) -> Result<PrologueInfo, InlineHookError> {
    let code = unsafe { std::slice::from_raw_parts(target, max_read) };
    let address = target as u64;

    with_capstone(|cs| {
        let insns = cs
            .disasm_all(code, address)
            .map_err(|e| InlineHookError::DisassemblyFailed(e.to_string()))?;

        let mut total_bytes = 0usize;
        let mut boundaries = Vec::new();

        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let mn_lower = mnemonic.to_lowercase();

            // Stop at RET — can't copy past a return.
            if mn_lower == "ret" || mn_lower == "retf" || mn_lower == "retn" {
                if total_bytes < MIN_HOOK_SIZE {
                    return Err(InlineHookError::PrologueTooShort {
                        needed: MIN_HOOK_SIZE,
                        available: total_bytes,
                    });
                }
                break;
            }

            // Stop at INT3 padding.
            if mn_lower == "int3" {
                if total_bytes < MIN_HOOK_SIZE {
                    return Err(InlineHookError::PrologueTooShort {
                        needed: MIN_HOOK_SIZE,
                        available: total_bytes,
                    });
                }
                break;
            }

            boundaries.push((total_bytes, insn.len()));
            total_bytes += insn.len();

            if total_bytes >= MIN_HOOK_SIZE {
                break;
            }
        }

        if total_bytes < MIN_HOOK_SIZE {
            return Err(InlineHookError::PrologueTooShort {
                needed: MIN_HOOK_SIZE,
                available: total_bytes,
            });
        }

        let original_bytes = code[..total_bytes].to_vec();

        Ok(PrologueInfo {
            original_bytes,
            patch_size: total_bytes,
            boundaries,
        })
    })
}

/// Build relay stub + trampoline into `slot`.
///
/// Layout within slot:
///   [0..14)         relay stub  → jumps to detour
///   [14..14+N+14)   trampoline  → relocated prologue + jump back to target+patch_size
///
/// Returns the layout offsets.
pub fn build_trampoline(
    slot: *mut u8,
    slot_size: usize,
    target: *const u8,
    detour: *const u8,
    prologue: &PrologueInfo,
) -> Result<TrampolineLayout, InlineHookError> {
    let relay_offset = 0usize;
    let trampoline_offset = RELAY_SIZE;

    // Build relay: FF 25 00 00 00 00 + 8-byte detour address
    let relay = build_abs_jmp(detour as u64);
    if relay_offset + RELAY_SIZE > slot_size {
        return Err(InlineHookError::AllocationFailed("slot too small for relay".into()));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(relay.as_ptr(), slot.add(relay_offset), RELAY_SIZE);
    }

    // Build trampoline: relocated instructions + abs jump back
    let trampoline_addr = unsafe { slot.add(trampoline_offset) } as u64;
    let return_addr = (target as u64) + (prologue.patch_size as u64);

    let relocated = relocate_prologue(
        &prologue.original_bytes,
        target as u64,
        trampoline_addr,
        &prologue.boundaries,
    )?;

    let jmp_back = build_abs_jmp(return_addr);
    let trampoline_total = relocated.len() + jmp_back.len();

    if trampoline_offset + trampoline_total > slot_size {
        return Err(InlineHookError::AllocationFailed("slot too small for trampoline".into()));
    }

    unsafe {
        let dst = slot.add(trampoline_offset);
        std::ptr::copy_nonoverlapping(relocated.as_ptr(), dst, relocated.len());
        std::ptr::copy_nonoverlapping(jmp_back.as_ptr(), dst.add(relocated.len()), jmp_back.len());
    }

    Ok(TrampolineLayout {
        relay_offset,
        trampoline_offset,
        total_size: trampoline_offset + trampoline_total,
    })
}

/// Build the patch jump (overwrites the target prologue) from `from` to `to`.
/// x86: 5-byte E9 JMP rel32. ARM64: one 4-byte `B` (±128MB range).
#[cfg(target_arch = "x86_64")]
pub fn build_rel_jmp(from: u64, to: u64) -> Result<Vec<u8>, InlineHookError> {
    let next_ip = from + 5;
    let offset = (to as i64) - (next_ip as i64);
    if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
        return Err(InlineHookError::RelocationFailed(format!(
            "relative jump from 0x{from:X} to 0x{to:X} out of range"
        )));
    }
    let rel32 = offset as i32;
    let mut buf = vec![0u8; 5];
    buf[0] = 0xE9;
    buf[1..5].copy_from_slice(&rel32.to_le_bytes());
    Ok(buf)
}

#[cfg(target_arch = "aarch64")]
pub fn build_rel_jmp(from: u64, to: u64) -> Result<Vec<u8>, InlineHookError> {
    Ok(encode_b(from, to)?.to_vec())
}

/// Encode an AArch64 unconditional `B` from `from` to `to`.
/// `B` uses a signed 26-bit immediate (instruction count) → ±128MB range.
#[cfg(target_arch = "aarch64")]
fn encode_b(from: u64, to: u64) -> Result<[u8; 4], InlineHookError> {
    let offset = (to as i64) - (from as i64);
    if offset & 0x3 != 0 {
        return Err(InlineHookError::RelocationFailed(format!(
            "B target 0x{to:X} from 0x{from:X} is not 4-byte aligned"
        )));
    }
    let imm = offset >> 2;
    if !(-(1 << 25)..(1 << 25)).contains(&imm) {
        return Err(InlineHookError::RelocationFailed(format!(
            "B from 0x{from:X} to 0x{to:X} out of ±128MB range"
        )));
    }
    // B: 0b000101 | imm26
    let insn: u32 = 0x1400_0000 | ((imm as u32) & 0x03FF_FFFF);
    Ok(insn.to_le_bytes())
}

/// Build an absolute jump to `target`.
/// x86: 14 bytes FF 25 00 00 00 00 + 8-byte address.
/// ARM64: 16 bytes `LDR X17, #8` + `BR X17` + 8-byte address.
#[cfg(target_arch = "x86_64")]
fn build_abs_jmp(target: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 14];
    buf[0] = 0xFF;
    buf[1] = 0x25;
    // buf[2..6] = 0x00000000 (RIP+0 displacement — already zeroed)
    buf[6..14].copy_from_slice(&target.to_le_bytes());
    buf
}

#[cfg(target_arch = "aarch64")]
fn build_abs_jmp(target: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 16];
    // LDR X17, #8  → load the 8-byte literal at PC+8 into X17 (imm19 = 8/4 = 2)
    buf[0..4].copy_from_slice(&0x5800_0051u32.to_le_bytes());
    // BR X17
    buf[4..8].copy_from_slice(&0xD61F_0220u32.to_le_bytes());
    // 8-byte absolute target
    buf[8..16].copy_from_slice(&target.to_le_bytes());
    buf
}

/// Relocate prologue instructions from `old_addr` to `new_addr`.
fn relocate_prologue(
    original: &[u8],
    old_addr: u64,
    new_addr: u64,
    boundaries: &[(usize, usize)],
) -> Result<Vec<u8>, InlineHookError> {
    with_capstone(|cs| {
        let insns = cs
            .disasm_all(original, old_addr)
            .map_err(|e| InlineHookError::DisassemblyFailed(e.to_string()))?;

        let mut output = Vec::new();
        let mut new_offset = 0u64; // offset within the output buffer

        for (i, insn) in insns.iter().enumerate() {
            if i >= boundaries.len() {
                break;
            }

            let old_ip = insn.address();
            let new_ip = new_addr + new_offset;

            let relocated = relocate_instruction(cs, &insn, old_ip, new_ip)?;
            output.extend_from_slice(&relocated);
            new_offset = output.len() as u64;
        }

        Ok(output)
    })
}

/// Relocate a single instruction.
#[cfg(target_arch = "x86_64")]
fn relocate_instruction(
    cs: &Capstone,
    insn: &capstone::Insn,
    old_ip: u64,
    new_ip: u64,
) -> Result<Vec<u8>, InlineHookError> {
    let bytes = insn.bytes();
    let insn_len = bytes.len();

    // Check for RIP-relative addressing via Capstone detail.
    if has_rip_relative(cs, insn) {
        return relocate_rip_relative(bytes, old_ip, new_ip, insn_len);
    }

    // Relative CALL (E8 + rel32).
    if insn_len == 5 && bytes[0] == 0xE8 {
        let old_rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let target = (old_ip as i64 + 5 + old_rel as i64) as u64;
        let new_rel = (target as i64 - (new_ip as i64 + 5)) as i32;
        let mut out = vec![0xE8];
        out.extend_from_slice(&new_rel.to_le_bytes());
        return Ok(out);
    }

    // JMP rel32 (E9 + rel32).
    if insn_len == 5 && bytes[0] == 0xE9 {
        let old_rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let target = (old_ip as i64 + 5 + old_rel as i64) as u64;
        let new_rel = (target as i64 - (new_ip as i64 + 5)) as i32;
        let mut out = vec![0xE9];
        out.extend_from_slice(&new_rel.to_le_bytes());
        return Ok(out);
    }

    // JMP rel8 (EB + rel8) → expand to E9 rel32.
    if insn_len == 2 && bytes[0] == 0xEB {
        let old_rel = bytes[1] as i8;
        let target = (old_ip as i64 + 2 + old_rel as i64) as u64;
        let new_rel = (target as i64 - (new_ip as i64 + 5)) as i32;
        let mut out = vec![0xE9];
        out.extend_from_slice(&new_rel.to_le_bytes());
        return Ok(out);
    }

    // Jcc rel8 (70-7F + rel8) → expand to 0F 80-8F + rel32.
    if insn_len == 2 && bytes[0] >= 0x70 && bytes[0] <= 0x7F {
        let cc = bytes[0] - 0x70;
        let old_rel = bytes[1] as i8;
        let target = (old_ip as i64 + 2 + old_rel as i64) as u64;
        let new_insn_len = 6i64; // 0F 8x + 4 bytes
        let new_rel = (target as i64 - (new_ip as i64 + new_insn_len)) as i32;
        let mut out = vec![0x0F, 0x80 + cc];
        out.extend_from_slice(&new_rel.to_le_bytes());
        return Ok(out);
    }

    // Jcc rel32 (0F 80-8F + rel32).
    if insn_len == 6 && bytes[0] == 0x0F && bytes[1] >= 0x80 && bytes[1] <= 0x8F {
        let old_rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let target = (old_ip as i64 + 6 + old_rel as i64) as u64;
        let new_rel = (target as i64 - (new_ip as i64 + 6)) as i32;
        let mut out = vec![bytes[0], bytes[1]];
        out.extend_from_slice(&new_rel.to_le_bytes());
        return Ok(out);
    }

    // LOOP/LOOPE/LOOPNE/JCXZ/JECXZ/JRCXZ (rel8 — can't easily expand,
    // but these are rare in function prologues). For now, error.
    if insn_len == 2 && (bytes[0] == 0xE0 || bytes[0] == 0xE1 || bytes[0] == 0xE2 || bytes[0] == 0xE3) {
        return Err(InlineHookError::RelocationFailed(format!(
            "unsupported loop/jcxz instruction at 0x{old_ip:X}"
        )));
    }

    // No relocation needed — copy as-is.
    Ok(bytes.to_vec())
}

/// Relocate a single AArch64 instruction moved from `old_ip` to `new_ip`.
///
/// Re-encodes PC-relative direct branches (`B`/`BL`). Instructions with other
/// forms of PC-relative addressing (ADR/ADRP, conditional/compare/test branches,
/// LDR-literal) cannot be trivially relocated in place and are rejected — these
/// are rare as the first instruction of a function prologue. All other
/// instructions are position-independent and copied verbatim.
#[cfg(target_arch = "aarch64")]
fn relocate_instruction(
    _cs: &Capstone,
    insn: &capstone::Insn,
    old_ip: u64,
    new_ip: u64,
) -> Result<Vec<u8>, InlineHookError> {
    let bytes = insn.bytes();
    if bytes.len() != 4 {
        return Err(InlineHookError::RelocationFailed(format!(
            "unexpected AArch64 instruction length {} at 0x{old_ip:X}",
            bytes.len()
        )));
    }
    let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    // B (0x14000000) / BL (0x94000000): imm26, target = ip + SignExtend(imm26:00).
    if (raw & 0xFC00_0000) == 0x1400_0000 || (raw & 0xFC00_0000) == 0x9400_0000 {
        let imm26 = raw & 0x03FF_FFFF;
        // sign-extend the 26-bit immediate, then *4
        let off = ((imm26 as i32) << 6 >> 6) as i64 * 4;
        let target = (old_ip as i64 + off) as u64;
        let new_off = target as i64 - new_ip as i64;
        if new_off & 0x3 != 0 || !(-(1 << 27)..(1 << 27)).contains(&new_off) {
            return Err(InlineHookError::RelocationFailed(format!(
                "B/BL relocation out of range at 0x{old_ip:X}"
            )));
        }
        let new_imm = ((new_off >> 2) as u32) & 0x03FF_FFFF;
        let new_raw = (raw & 0xFC00_0000) | new_imm;
        return Ok(new_raw.to_le_bytes().to_vec());
    }

    // PC-relative forms we cannot relocate in place.
    let pc_relative = (raw & 0x1F00_0000) == 0x1000_0000      // ADR / ADRP
        || (raw & 0xFF00_0010) == 0x5400_0000                 // B.cond
        || (raw & 0x7E00_0000) == 0x3400_0000                 // CBZ / CBNZ
        || (raw & 0x7E00_0000) == 0x3600_0000                 // TBZ / TBNZ
        || (raw & 0x3B00_0000) == 0x1800_0000;                // LDR (literal)
    if pc_relative {
        return Err(InlineHookError::RelocationFailed(format!(
            "cannot relocate PC-relative instruction 0x{raw:08X} at 0x{old_ip:X}"
        )));
    }

    // Position-independent — copy verbatim.
    Ok(bytes.to_vec())
}

/// Check if an instruction uses RIP-relative addressing.
#[cfg(target_arch = "x86_64")]
fn has_rip_relative(cs: &Capstone, insn: &capstone::Insn) -> bool {
    let detail = match cs.insn_detail(insn) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if let ArchDetail::X86Detail(x86) = detail.arch_detail() {
        for op in x86.operands() {
            if let X86OperandType::Mem(ref mem) = op.op_type {
                if mem.base() == RegId(X86_REG_RIP) {
                    return true;
                }
            }
        }
    }
    false
}

/// Relocate an instruction with RIP-relative addressing.
///
/// The displacement field is a 32-bit signed offset from the end of the instruction
/// to the target address. We recompute it for the new location.
#[cfg(target_arch = "x86_64")]
fn relocate_rip_relative(
    bytes: &[u8],
    old_ip: u64,
    new_ip: u64,
    insn_len: usize,
) -> Result<Vec<u8>, InlineHookError> {
    // Find the displacement field. It's always a 4-byte signed value at the end
    // of the instruction (before any immediate), located via the ModR/M byte.
    // For RIP-relative, ModR/M mod=00, rm=101.
    //
    // Strategy: the displacement is always 4 bytes. We need to find where it is
    // in the instruction bytes. We know the old target:
    //   target = old_ip + insn_len + old_disp
    // And we need:
    //   new_disp = target - (new_ip + insn_len)
    //
    // We scan for the displacement field by trying each possible 4-byte offset.
    // The correct one will produce a displacement that, combined with old_ip + insn_len,
    // gives a plausible address.

    let mut output = bytes.to_vec();
    let old_next_ip = old_ip + insn_len as u64;
    let new_next_ip = new_ip + insn_len as u64;

    // Find the 4-byte displacement. We look for the position where the disp32
    // field is by checking the ModR/M encoding. For simplicity, we use a
    // known-good approach: the IP delta is constant for all bytes, so we just
    // need to find and patch the disp32.
    //
    // The displacement difference between old and new location:
    let ip_delta = old_next_ip as i64 - new_next_ip as i64;

    // Find the displacement field position. We scan the instruction for a 4-byte
    // value that, when interpreted as i32, gives a RIP-relative target. We look
    // for it by finding the ModR/M byte with mod=00, rm=101 (RIP-relative).
    if let Some(disp_offset) = find_rip_disp_offset(bytes) {
        let old_disp = i32::from_le_bytes([
            bytes[disp_offset],
            bytes[disp_offset + 1],
            bytes[disp_offset + 2],
            bytes[disp_offset + 3],
        ]);
        let new_disp = old_disp as i64 + ip_delta;
        if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
            return Err(InlineHookError::RelocationFailed(format!(
                "RIP-relative displacement overflow at 0x{old_ip:X}"
            )));
        }
        let new_disp = new_disp as i32;
        output[disp_offset..disp_offset + 4].copy_from_slice(&new_disp.to_le_bytes());
        return Ok(output);
    }

    Err(InlineHookError::RelocationFailed(format!(
        "could not locate RIP-relative displacement at 0x{old_ip:X}"
    )))
}

/// Find the byte offset of the RIP-relative disp32 field in an x64 instruction.
///
/// RIP-relative is encoded as ModR/M with mod=00, rm=101. The ModR/M byte
/// follows opcode bytes and optional prefixes. After ModR/M (and optional SIB),
/// the 4-byte displacement appears.
#[cfg(target_arch = "x86_64")]
fn find_rip_disp_offset(bytes: &[u8]) -> Option<usize> {
    let len = bytes.len();
    if len < 5 {
        return None; // Minimum: 1 opcode + 1 modrm + 4 disp
    }

    let mut pos = 0;

    // Skip legacy prefixes (groups 1-4).
    while pos < len {
        match bytes[pos] {
            // Group 1: lock, rep, repne
            0xF0 | 0xF2 | 0xF3 |
            // Group 2: segment overrides
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 |
            // Group 3: operand size override
            0x66 |
            // Group 4: address size override
            0x67 => pos += 1,
            _ => break,
        }
    }

    // Skip REX prefix (0x40-0x4F).
    if pos < len && (bytes[pos] & 0xF0) == 0x40 {
        pos += 1;
    }

    // Now at opcode. Determine opcode length and find ModR/M.
    if pos >= len {
        return None;
    }

    // Two-byte opcode (0F xx)?
    let two_byte = bytes[pos] == 0x0F;
    if two_byte {
        pos += 1;
        if pos >= len {
            return None;
        }
        // Three-byte opcode (0F 38 xx or 0F 3A xx)?
        if bytes[pos] == 0x38 || bytes[pos] == 0x3A {
            pos += 1;
            if pos >= len {
                return None;
            }
        }
    }

    // Skip the opcode byte itself.
    pos += 1;

    // pos should now be at ModR/M, if present.
    if pos >= len {
        return None;
    }

    let modrm = bytes[pos];
    let mod_field = (modrm >> 6) & 0x03;
    let rm_field = modrm & 0x07;

    // RIP-relative: mod=00, rm=101
    if mod_field == 0b00 && rm_field == 0b101 {
        // No SIB for RIP-relative.
        let disp_pos = pos + 1; // right after ModR/M
        if disp_pos + 4 <= len {
            return Some(disp_pos);
        }
    }

    None
}
