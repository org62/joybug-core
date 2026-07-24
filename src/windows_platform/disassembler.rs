use crate::interfaces::{Architecture, DisassemblerError, DisassemblerProvider, Instruction};
use capstone::prelude::*;
use capstone::arch::ArchDetail;
use capstone::arch::x86::X86OperandType;
use capstone::RegId;
use std::cell::RefCell;

// Thread-local cache for Capstone engines (one per architecture per thread)
// This avoids expensive engine recreation for repeated disassembly calls
thread_local! {
    static X64_ENGINE: RefCell<Option<Capstone>> = const { RefCell::new(None) };
    static ARM64_ENGINE: RefCell<Option<Capstone>> = const { RefCell::new(None) };
}

pub struct CapstoneDisassembler {
}

impl CapstoneDisassembler {
    pub fn new() -> Result<Self, DisassemblerError> {
        Ok(Self {})
    }

    fn with_engine<F, R>(arch: Architecture, f: F) -> Result<R, DisassemblerError>
    where
        F: FnOnce(&Capstone) -> Result<R, DisassemblerError>,
    {
        let tls = match arch {
            Architecture::X64 => &X64_ENGINE,
            Architecture::Arm64 => &ARM64_ENGINE,
        };

        tls.with(|cell| {
            let mut engine_opt = cell.borrow_mut();
            if engine_opt.is_none() {
                let engine = match arch {
                    Architecture::X64 => {
                        Capstone::new()
                            .x86()
                            .mode(arch::x86::ArchMode::Mode64)
                            .syntax(arch::x86::ArchSyntax::Intel)
                            .detail(true)
                            .build()
                            .map_err(|e| DisassemblerError::CapstoneError(e.to_string()))?
                    }
                    Architecture::Arm64 => {
                        Capstone::new()
                            .arm64()
                            .mode(arch::arm64::ArchMode::Arm)
                            .detail(true)
                            .build()
                            .map_err(|e| DisassemblerError::CapstoneError(e.to_string()))?
                    }
                };
                *engine_opt = Some(engine);
            }
            f(engine_opt.as_ref().unwrap())
        })
    }
}

/// Detect if mnemonic is a jump instruction (x64 or arm64)
fn is_jump_mnemonic(mnemonic: &str, arch: Architecture) -> bool {
    let mnemonic_lower = mnemonic.to_lowercase();
    match arch {
        Architecture::X64 => {
            // x64 jumps: jmp, jcc (ja, jae, jb, jbe, jc, je, jg, jge, jl, jle, jna, jnae, jnb, jnbe, jnc, jne, jng, jnge, jnl, jnle, jno, jnp, jns, jnz, jo, jp, jpe, jpo, js, jz)
            // Also: loop, loope, loopne, jcxz, jecxz, jrcxz
            mnemonic_lower.starts_with('j')
                || mnemonic_lower.starts_with("loop")
        }
        Architecture::Arm64 => {
            // ARM64 branches: b, b.cond (b.eq, b.ne, etc.), cbz, cbnz, tbz, tbnz
            mnemonic_lower == "b"
                || mnemonic_lower.starts_with("b.")
                || mnemonic_lower == "cbz"
                || mnemonic_lower == "cbnz"
                || mnemonic_lower == "tbz"
                || mnemonic_lower == "tbnz"
        }
    }
}

/// Detect if mnemonic is a call instruction
fn is_call_mnemonic(mnemonic: &str, arch: Architecture) -> bool {
    let mnemonic_lower = mnemonic.to_lowercase();
    match arch {
        Architecture::X64 => mnemonic_lower == "call",
        Architecture::Arm64 => mnemonic_lower == "bl" || mnemonic_lower == "blr",
    }
}

/// Detect if mnemonic is a return instruction
fn is_ret_mnemonic(mnemonic: &str, arch: Architecture) -> bool {
    let mnemonic_lower = mnemonic.to_lowercase();
    match arch {
        Architecture::X64 => mnemonic_lower == "ret" || mnemonic_lower == "retf" || mnemonic_lower == "retn",
        Architecture::Arm64 => mnemonic_lower == "ret",
    }
}

/// X86 RIP register ID in Capstone
const X86_REG_RIP: u16 = 41;

/// Whether it is safe *and* useful to ask Capstone for this ARM64 instruction's
/// operands.
///
/// capstone-rs builds `Arm64OperandType` by transmuting Capstone's raw
/// system-register, PSTATE, prefetch and barrier encodings into closed Rust
/// enums. Those enums name only a small fraction of the encodings Capstone can
/// emit — for system registers, ~700 of 32768 — so reading the operands of a
/// system instruction transmutes an invalid discriminant. That is a
/// non-unwinding panic: it aborts the process and cannot be caught.
///
/// Every ARM64 form that can carry a code address is a branch, a PC-relative
/// address, or a literal load, and none of those is a system instruction. So we
/// allowlist the forms we want rather than denylist the hazardous ones — a
/// denylist would abort the debugger the first time it missed an encoding.
fn arm64_may_have_address_operand(mnemonic: &str) -> bool {
    is_jump_mnemonic(mnemonic, Architecture::Arm64)
        || is_call_mnemonic(mnemonic, Architecture::Arm64)
        // PC-relative address materialization
        || mnemonic.eq_ignore_ascii_case("adr")
        || mnemonic.eq_ignore_ascii_case("adrp")
        // Literal (PC-relative) loads
        || mnemonic.eq_ignore_ascii_case("ldr")
        || mnemonic.eq_ignore_ascii_case("ldrsw")
}

/// The single sanctioned reader of ARM64 operand details: returns the
/// address-sized immediates of `insn`, or nothing when the instruction isn't an
/// address-bearing form. Owns the `arm64_may_have_address_operand` gate so the
/// transmute-hazardous `Arm64OperandType` access happens in exactly one place —
/// a new caller cannot forget the gate and reintroduce the process abort.
fn arm64_address_imms(engine: &Capstone, insn: &capstone::Insn) -> Vec<u64> {
    let mut addresses = Vec::new();
    if !arm64_may_have_address_operand(insn.mnemonic().unwrap_or("")) {
        return addresses;
    }
    let Ok(detail) = engine.insn_detail(insn) else {
        return addresses;
    };
    if let ArchDetail::Arm64Detail(arm64) = detail.arch_detail() {
        for op in arm64.operands() {
            if let capstone::arch::arm64::Arm64OperandType::Imm(value) = op.op_type {
                let addr = value as u64;
                if addr > 0x10000 {
                    addresses.push(addr);
                }
            }
        }
    }
    addresses
}

/// Extract all addresses that should be symbolized from instruction operands
/// Uses Capstone's structured operand data instead of text parsing
fn extract_addresses_from_operands(
    engine: &Capstone,
    insn: &capstone::Insn,
    arch: Architecture,
) -> Vec<u64> {
    let mut addresses = Vec::new();

    match arch {
        Architecture::X64 => {
            let detail = match engine.insn_detail(insn) {
                Ok(d) => d,
                Err(_) => return addresses,
            };
            if let ArchDetail::X86Detail(x86) = detail.arch_detail() {
                for op in x86.operands() {
                    match op.op_type {
                        X86OperandType::Imm(value) => {
                            // Immediate value - potential jump/call target or address constant
                            let addr = value as u64;
                            if addr > 0x10000 {
                                addresses.push(addr);
                            }
                        }
                        X86OperandType::Mem(ref mem) => {
                            // Check for RIP-relative addressing
                            if mem.base() == RegId(X86_REG_RIP) {
                                // RIP-relative: target = instruction_end + displacement
                                let target = insn.address()
                                    .wrapping_add(insn.len() as u64)
                                    .wrapping_add_signed(mem.disp());
                                if target > 0x10000 {
                                    addresses.push(target);
                                }
                            } else {
                                // Check displacement for absolute addresses (e.g., mov eax, [0x12345678])
                                let disp = mem.disp();
                                if disp > 0x10000 {
                                    addresses.push(disp as u64);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Architecture::Arm64 => {
            addresses = arm64_address_imms(engine, insn);
        }
    }

    addresses
}

/// Extract jump/call target from structured operand data
fn extract_jump_target_from_operands(
    engine: &Capstone,
    insn: &capstone::Insn,
    arch: Architecture,
) -> Option<u64> {
    match arch {
        Architecture::X64 => {
            let detail = engine.insn_detail(insn).ok()?;
            if let ArchDetail::X86Detail(x86) = detail.arch_detail() {
                for op in x86.operands() {
                    match op.op_type {
                        X86OperandType::Imm(value) => {
                            // Direct jump/call target
                            let addr = value as u64;
                            if addr > 0x10000 {
                                return Some(addr);
                            }
                        }
                        X86OperandType::Mem(ref mem) => {
                            // RIP-relative call/jump (e.g., call qword ptr [rip+0x1234])
                            if mem.base() == RegId(X86_REG_RIP) {
                                let target = insn.address()
                                    .wrapping_add(insn.len() as u64)
                                    .wrapping_add_signed(mem.disp());
                                return Some(target);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Architecture::Arm64 => {
            return arm64_address_imms(engine, insn).into_iter().next();
        }
    }

    None
}

impl DisassemblerProvider for CapstoneDisassembler {
    fn disassemble(
        &self,
        arch: Architecture,
        data: &[u8],
        address: u64,
        count: usize,
    ) -> Result<Vec<Instruction>, DisassemblerError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Longest possible instruction encoding per architecture. Used as the
        // buffer-tail guard below: a decode stall with fewer than this many
        // bytes left is buffer truncation, not a genuine bad byte.
        let max_ilen = arch.max_instruction_len();

        Self::with_engine(arch, |engine| {
            let mut result: Vec<Instruction> = Vec::new();
            let mut offset: usize = 0;

            // Resync loop: Capstone's `disasm_count` silently stops at the first
            // undecodable byte and returns only what it decoded. Rather than
            // truncate the whole listing there, we emit a 1-byte `db 0xXX`
            // placeholder for the bad byte and resume decoding after it —
            // x64dbg/TitanEngine style — so valid code below a bad byte stays
            // visible and the UI can keep scrolling past it.
            while result.len() < count && offset < data.len() {
                let remaining = count - result.len();
                let instructions = engine
                    .disasm_count(&data[offset..], address + offset as u64, remaining)
                    .map_err(|e| DisassemblerError::CapstoneError(e.to_string()))?;

                if instructions.is_empty() {
                    // Stalled at `offset`. If too few bytes remain for a full
                    // instruction this is a buffer-end truncation (reads are
                    // sized `count * 16`, so a real bad byte always leaves
                    // >= max_ilen bytes) — stop instead of emitting a spurious
                    // trailing `db`.
                    if data.len() - offset < max_ilen {
                        break;
                    }
                    let bad = data[offset];
                    result.push(Instruction {
                        address: address + offset as u64,
                        bytes: vec![bad],
                        mnemonic: "db".to_string(),
                        op_str: format!("0x{:02X}", bad),
                        size: 1,
                        is_invalid: true,
                        ..Default::default()
                    });
                    offset += 1;
                    continue;
                }

                let mut consumed: usize = 0;
                for insn in instructions.iter() {
                    let mnemonic = insn.mnemonic().unwrap_or("");
                    let op_str = insn.op_str().unwrap_or("");

                    let is_jump = is_jump_mnemonic(mnemonic, arch);
                    let is_call = is_call_mnemonic(mnemonic, arch);
                    let is_ret = is_ret_mnemonic(mnemonic, arch);

                    // Extract jump target for jumps and calls using structured operand data
                    let jump_target = if is_jump || is_call {
                        extract_jump_target_from_operands(engine, &insn, arch)
                    } else {
                        None
                    };

                    // Extract all addresses that should be symbolized from operands
                    let addresses_to_symbolize = extract_addresses_from_operands(engine, &insn, arch);

                    result.push(Instruction {
                        address: insn.address(),
                        bytes: insn.bytes().to_vec(),
                        mnemonic: mnemonic.to_string(),
                        op_str: op_str.to_string(),
                        size: insn.len(),
                        is_jump,
                        is_call,
                        is_ret,
                        jump_target,
                        addresses_to_symbolize,
                        ..Default::default()
                    });
                    consumed += insn.len();
                }
                // Every decoded instruction has size >= 1, so `offset` always
                // advances — the loop cannot spin.
                offset += consumed;
            }

            Ok(result)
        })
    }
}

impl Clone for CapstoneDisassembler {
    fn clone(&self) -> Self {
        Self {}
    }
} 
#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::{Architecture, DisassemblerProvider, SymbolInfo};

    // Operand extraction ignores addresses <= 0x10000, so use realistic VAs:
    // call 0x140002000 encoded at 0x140001000: E8 FB 0F 00 00 (rel32 = 0xFFB)
    const CALL_BYTES: &[u8] = &[0xE8, 0xFB, 0x0F, 0x00, 0x00];
    const CALL_SITE: u64 = 0x140001000;
    const CALL_TARGET: u64 = 0x140002000;

    fn resolver_with_offset(offset: u64) -> impl Fn(u64) -> Option<SymbolInfo> {
        move |addr| {
            (addr == CALL_TARGET).then(|| SymbolInfo {
                module_name: "mod".to_string(),
                symbol_name: "sym".to_string(),
                offset,
            })
        }
    }

    #[test]
    fn operand_symbolized_at_exact_symbol() {
        let disasm = CapstoneDisassembler::new().unwrap();
        let instrs = disasm
            .disassemble_with_symbols(Architecture::X64, CALL_BYTES, CALL_SITE, 1, resolver_with_offset(0))
            .unwrap();
        assert_eq!(instrs[0].symbolized_op_str.as_deref(), Some("mod!sym"));
    }

    #[test]
    fn operand_stays_raw_at_nonzero_offset() {
        let disasm = CapstoneDisassembler::new().unwrap();
        let instrs = disasm
            .disassemble_with_symbols(Architecture::X64, CALL_BYTES, CALL_SITE, 1, resolver_with_offset(5))
            .unwrap();
        assert_eq!(instrs[0].symbolized_op_str, None);
        assert!(instrs[0].op_str.contains("0x140002000"));
    }

    // A decode that hits an undecodable byte must emit a 1-byte `db` placeholder
    // and continue past it, not truncate the listing at the bad byte.
    #[test]
    fn resilient_decode_emits_db_and_continues() {
        // 0x06 (PUSH ES) is invalid in x64 long mode. Sandwich it between a NOP
        // and a run of NOPs long enough that the buffer-tail guard (>= 15 bytes
        // remaining at the stall) still classifies 0x06 as a real bad byte.
        let mut bytes = vec![0x90u8, 0x06];
        bytes.extend(std::iter::repeat(0x90u8).take(20));
        let base = 0x140001000u64;

        let disasm = CapstoneDisassembler::new().unwrap();
        let instrs = disasm.disassemble(Architecture::X64, &bytes, base, 64).unwrap();

        // First row: the leading NOP, decoded normally.
        assert_eq!(instrs[0].mnemonic, "nop");
        assert!(!instrs[0].is_invalid);

        // Second row: the synthetic invalid byte.
        assert!(instrs[1].is_invalid);
        assert_eq!(instrs[1].mnemonic, "db");
        assert_eq!(instrs[1].size, 1);
        assert_eq!(instrs[1].bytes, vec![0x06]);
        assert_eq!(instrs[1].address, base + 1);
        assert!(instrs[1].op_str.contains("06"));

        // Third row: decoding resumed AFTER the bad byte (not truncated at it).
        assert_eq!(instrs[2].mnemonic, "nop");
        assert!(!instrs[2].is_invalid);
        assert_eq!(instrs[2].address, base + 2);

        // All 22 bytes accounted for: NOP + db + 20 NOPs.
        assert_eq!(instrs.len(), 22);
    }

    // capstone-rs builds `Arm64OperandType` by transmuting capstone's raw
    // system-register encoding into the `arm64_sysreg` enum. That enum only
    // names ~700 of the 32768 well-formed encodings, so every MRS/MSR on an
    // unnamed sysreg transmutes to an invalid discriminant — a non-unwinding
    // panic that aborts the process, uncatchable. Same hazard for the SYS /
    // PSTATE / PREFETCH / BARRIER operand kinds. We must therefore never ask
    // capstone for ARM64 operands on a system instruction.
    //
    // If this regresses, the test binary aborts rather than failing cleanly.
    #[test]
    fn arm64_unnamed_sysreg_does_not_abort() {
        // mrs x0, S3_0_C0_C0_1 — well-formed, absent from capstone's enum.
        let bytes = [0x20u8, 0x00, 0x38, 0xD5];
        let base = 0x140001000u64;

        let disasm = CapstoneDisassembler::new().unwrap();
        let instrs = disasm.disassemble(Architecture::Arm64, &bytes, base, 1).unwrap();

        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].mnemonic, "mrs");
        // A system register is never a code address worth symbolizing.
        assert!(instrs[0].addresses_to_symbolize.is_empty());
        assert_eq!(instrs[0].jump_target, None);
    }

    // The address-bearing ARM64 forms must still yield their targets.
    #[test]
    fn arm64_branch_and_pcrel_targets_still_extracted() {
        let base = 0x140001000u64;
        let disasm = CapstoneDisassembler::new().unwrap();

        // bl #0x1000 -> 0x140002000
        let bl = disasm
            .disassemble(Architecture::Arm64, &[0x00u8, 0x04, 0x00, 0x94], base, 1)
            .unwrap();
        assert_eq!(bl[0].mnemonic, "bl");
        assert!(bl[0].is_call);
        assert_eq!(bl[0].jump_target, Some(0x140002000));
        assert!(bl[0].addresses_to_symbolize.contains(&0x140002000));

        // adrp x0, #0x141001000 — pc-relative page address
        let adrp = disasm
            .disassemble(Architecture::Arm64, &[0x00u8, 0x80, 0x00, 0xB0], base, 1)
            .unwrap();
        assert_eq!(adrp[0].mnemonic, "adrp");
        assert!(
            adrp[0].addresses_to_symbolize.iter().any(|a| *a > 0x10000),
            "adrp should surface its page address, got {:?}",
            adrp[0].addresses_to_symbolize
        );
    }
}
