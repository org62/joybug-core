use super::error::InlineHookError;
use capstone::prelude::*;
use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchDetail;
use capstone::RegId;
use std::cell::RefCell;

/// X86 RIP register ID in Capstone.
const X86_REG_RIP: u16 = 41;

/// Minimum bytes we must overwrite at the target for a 5-byte E9 JMP rel32.
pub const MIN_HOOK_SIZE: usize = 5;

/// Size of the relay stub: FF 25 00 00 00 00 + 8-byte address.
pub const RELAY_SIZE: usize = 14;


thread_local! {
    static CS_ENGINE: RefCell<Option<Capstone>> = const { RefCell::new(None) };
}

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

/// Build a 5-byte E9 relative JMP from `from` to `to`.
/// Returns the 5 bytes to write at `from`.
pub fn build_rel_jmp(from: u64, to: u64) -> Result<[u8; 5], InlineHookError> {
    let next_ip = from + 5;
    let offset = (to as i64) - (next_ip as i64);
    if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
        return Err(InlineHookError::RelocationFailed(format!(
            "relative jump from 0x{from:X} to 0x{to:X} out of range"
        )));
    }
    let rel32 = offset as i32;
    let mut buf = [0u8; 5];
    buf[0] = 0xE9;
    buf[1..5].copy_from_slice(&rel32.to_le_bytes());
    Ok(buf)
}

/// Build a 14-byte absolute JMP: FF 25 00 00 00 00 + 8-byte address.
fn build_abs_jmp(target: u64) -> [u8; 14] {
    let mut buf = [0u8; 14];
    buf[0] = 0xFF;
    buf[1] = 0x25;
    // buf[2..6] = 0x00000000 (RIP+0 displacement — already zeroed)
    buf[6..14].copy_from_slice(&target.to_le_bytes());
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

/// Check if an instruction uses RIP-relative addressing.
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
