use crate::interfaces::{Architecture, DisassemblerError, DisassemblerProvider, Instruction};
use capstone::prelude::*;
use capstone::arch::ArchDetail;
use capstone::arch::x86::X86OperandType;
use capstone::RegId;
use std::cell::RefCell;

// Thread-local cache for Capstone engines (one per architecture per thread)
// This avoids expensive engine recreation for repeated disassembly calls
thread_local! {
    static X86_ENGINE: RefCell<Option<Capstone>> = const { RefCell::new(None) };
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
            Architecture::X86 => &X86_ENGINE,
            Architecture::X64 => &X64_ENGINE,
            Architecture::Arm64 => &ARM64_ENGINE,
        };

        tls.with(|cell| {
            let mut engine_opt = cell.borrow_mut();
            if engine_opt.is_none() {
                let engine = match arch {
                    Architecture::X86 => {
                        Capstone::new()
                            .x86()
                            .mode(arch::x86::ArchMode::Mode32)
                            .syntax(arch::x86::ArchSyntax::Intel)
                            .detail(true)
                            .build()
                            .map_err(|e| DisassemblerError::CapstoneError(e.to_string()))?
                    }
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

/// Detect if mnemonic is a jump instruction (x86/x64 or arm64)
fn is_jump_mnemonic(mnemonic: &str, arch: Architecture) -> bool {
    // Capstone emits lowercase mnemonics; compared allocation-free because
    // this runs per decoded instruction (the xref sweep decodes whole images).
    let m = mnemonic.as_bytes();
    match arch {
        Architecture::X86 | Architecture::X64 => {
            // x64 jumps: jmp, jcc (ja, jae, jb, jbe, jc, je, jg, jge, jl, jle, jna, jnae, jnb, jnbe, jnc, jne, jng, jnge, jnl, jnle, jno, jnp, jns, jnz, jo, jp, jpe, jpo, js, jz)
            // Also: loop, loope, loopne, jcxz, jecxz, jrcxz
            m.first().is_some_and(|c| c.eq_ignore_ascii_case(&b'j'))
                || m.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"loop"))
        }
        Architecture::Arm64 => {
            // ARM64 branches: b, b.cond (b.eq, b.ne, etc.), cbz, cbnz, tbz, tbnz
            mnemonic.eq_ignore_ascii_case("b")
                || m.get(..2).is_some_and(|p| p.eq_ignore_ascii_case(b"b."))
                || mnemonic.eq_ignore_ascii_case("cbz")
                || mnemonic.eq_ignore_ascii_case("cbnz")
                || mnemonic.eq_ignore_ascii_case("tbz")
                || mnemonic.eq_ignore_ascii_case("tbnz")
        }
    }
}

/// Detect if mnemonic is a call instruction
fn is_call_mnemonic(mnemonic: &str, arch: Architecture) -> bool {
    match arch {
        Architecture::X86 | Architecture::X64 => mnemonic.eq_ignore_ascii_case("call"),
        Architecture::Arm64 => mnemonic.eq_ignore_ascii_case("bl") || mnemonic.eq_ignore_ascii_case("blr"),
    }
}

/// Detect if mnemonic is a return instruction
fn is_ret_mnemonic(mnemonic: &str, arch: Architecture) -> bool {
    match arch {
        Architecture::X86 | Architecture::X64 => ["ret", "retf", "retn"].iter().any(|r| mnemonic.eq_ignore_ascii_case(r)),
        Architecture::Arm64 => mnemonic.eq_ignore_ascii_case("ret"),
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

/// Linear address referenced by a RIP-relative memory operand. RIP-relative
/// displacements are relative to the *end* of the instruction, so the target
/// is next-instruction address + displacement.
fn rip_relative_target(insn: &capstone::Insn, mem: &capstone::arch::x86::X86OpMem) -> u64 {
    insn.address()
        .wrapping_add(insn.len() as u64)
        .wrapping_add_signed(mem.disp())
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
        // 32-bit code has no RIP-relative operands, so the RIP branch below is
        // simply never taken; absolute displacements are the common case there.
        Architecture::X86 | Architecture::X64 => {
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
                                let target = rip_relative_target(insn, mem);
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

/// Extract the absolute address of a memory operand when it is statically
/// resolvable: RIP-relative (`[rip ± disp]`) or absolute displacement
/// (`[0x12345678]`). Register-based operands (`[rax + rcx*8]`) have no static
/// address and yield `None`. First memory operand wins — x86 has at most one
/// memory operand per instruction outside of exotic string ops.
///
/// ARM64 memory operands are register-based (PC-relative literals surface as
/// immediates, already covered by `arm64_address_imms`), so this is x86/x64-only.
fn extract_mem_ref_from_operands(
    engine: &Capstone,
    insn: &capstone::Insn,
    arch: Architecture,
) -> Option<u64> {
    if !arch.is_x86_family() {
        return None;
    }
    let detail = engine.insn_detail(insn).ok()?;
    if let ArchDetail::X86Detail(x86) = detail.arch_detail() {
        for op in x86.operands() {
            if let X86OperandType::Mem(ref mem) = op.op_type {
                // A segment-override displacement (`fs:[0x...]`) is relative
                // to the segment base, not a linear address — never a mem_ref.
                if mem.segment() != RegId(0) {
                    continue;
                }
                if mem.base() == RegId(X86_REG_RIP) {
                    let target = rip_relative_target(insn, mem);
                    if target > 0x10000 {
                        return Some(target);
                    }
                } else if mem.base() == RegId(0) && mem.index() == RegId(0) && mem.disp() > 0x10000 {
                    // No base/index register: the displacement IS the address.
                    return Some(mem.disp() as u64);
                }
            }
        }
    }
    None
}

/// Extract jump/call target from structured operand data
fn extract_jump_target_from_operands(
    engine: &Capstone,
    insn: &capstone::Insn,
    arch: Architecture,
) -> Option<u64> {
    match arch {
        Architecture::X86 | Architecture::X64 => {
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
                                return Some(rip_relative_target(insn, mem));
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
        // How far a stall skips: one byte on x86, one whole word on ARM64.
        // Skipping a single byte of a fixed-width stream would leave every
        // later decode misaligned, turning real code into plausible garbage
        // (the ILT padding at the start of an ARM64 `.text` used to desync
        // the whole xref sweep this way).
        let skip = arch.instruction_alignment();

        Self::with_engine(arch, |engine| {
            let mut result: Vec<Instruction> = Vec::new();
            let mut offset: usize = 0;

            // Resync loop: Capstone's `disasm_count` silently stops at the first
            // undecodable byte and returns only what it decoded. Rather than
            // truncate the whole listing there, we emit a `db` placeholder for
            // the bad byte (word on ARM64) and resume decoding after it —
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
                    let bad = &data[offset..offset + skip];
                    result.push(Instruction {
                        address: address + offset as u64,
                        bytes: bad.to_vec(),
                        mnemonic: "db".to_string(),
                        op_str: bad.iter().map(|b| format!("0x{:02X}", b)).collect::<Vec<_>>().join(", "),
                        size: skip,
                        is_invalid: true,
                        ..Default::default()
                    });
                    offset += skip;
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

                    let mem_ref = extract_mem_ref_from_operands(engine, &insn, arch);

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
                        mem_ref,
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

    // 32-bit mode: a PE32 image or a WOW64 thread. The decoder must be the
    // Mode32 engine (a Mode64 decode of these bytes reads `mov edi, edi` the
    // same but turns `55` into `push rbp`), and absolute `[disp32]` operands —
    // the way 32-bit code reaches its IAT — must surface as `mem_ref`.
    #[test]
    fn x86_decodes_32bit_prologue() {
        let disasm = CapstoneDisassembler::new().unwrap();
        // kernel32!BaseThreadInitThunk-style hot-patchable prologue.
        let instrs = disasm
            .disassemble(Architecture::X86, &[0x8B, 0xFF, 0x55, 0x8B, 0xEC], 0x10015970, 3)
            .unwrap();
        let text: Vec<String> = instrs.iter().map(|i| format!("{} {}", i.mnemonic, i.op_str)).collect();
        assert_eq!(text, ["mov edi, edi", "push ebp", "mov ebp, esp"]);
        assert_eq!(instrs[1].address, 0x10015972);
    }

    #[test]
    fn x86_absolute_memory_operand_is_mem_ref() {
        let disasm = CapstoneDisassembler::new().unwrap();
        // call dword ptr [0x10080DD0] — FF 15 D0 0D 08 10 (IAT thunk call)
        let instrs = disasm
            .disassemble(Architecture::X86, &[0xFF, 0x15, 0xD0, 0x0D, 0x08, 0x10], 0x10001000, 1)
            .unwrap();
        assert!(instrs[0].is_call);
        assert_eq!(instrs[0].mem_ref, Some(0x10080DD0));
        // In 32-bit mode a rel32 call target is a 32-bit VA and gets symbolized.
        let call = disasm
            .disassemble_with_symbols(
                Architecture::X86,
                &[0xE8, 0xFB, 0x0F, 0x00, 0x00],
                0x10001000,
                1,
                |addr| (addr == 0x10002000).then(|| SymbolInfo {
                    module_name: "k32".into(),
                    symbol_name: "fn".into(),
                    offset: 0,
                }),
            )
            .unwrap();
        assert_eq!(call[0].jump_target, Some(0x10002000));
        assert_eq!(call[0].symbolized_op_str.as_deref(), Some("k32!fn"));
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

    // mem_ref: RIP-relative and absolute memory operands resolve to a static
    // data address; immediates and register-based operands must not.
    #[test]
    fn mem_ref_extracted_for_static_memory_operands() {
        let base = 0x140001000u64;
        let disasm = CapstoneDisassembler::new().unwrap();

        // mov rax, qword ptr [rip + 0xffb] — 48 8B 05 FB 0F 00 00 (7 bytes)
        // target = base + 7 + 0xffb
        let rip_rel = disasm
            .disassemble(Architecture::X64, &[0x48, 0x8B, 0x05, 0xFB, 0x0F, 0x00, 0x00], base, 1)
            .unwrap();
        assert_eq!(rip_rel[0].mem_ref, Some(base + 7 + 0xFFB));

        // mov rax, qword ptr [0x40002000] — absolute displacement (SIB, no
        // base/index): the displacement is the address.
        let abs = disasm
            .disassemble(
                Architecture::X64,
                &[0x48, 0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x40],
                base,
                1,
            )
            .unwrap();
        assert_eq!(abs[0].mem_ref, Some(0x40002000));

        // mov rax, qword ptr fs:[0x1122334455667788] — segment-relative
        // displacement (moffs with fs override), not a linear address.
        let seg = disasm
            .disassemble(
                Architecture::X64,
                &[0x64, 0x48, 0xA1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
                base,
                1,
            )
            .unwrap();
        assert_eq!(seg[0].mem_ref, None);

        // movabs rax, 0x140002000 — an immediate, not a memory reference.
        let imm = disasm
            .disassemble(
                Architecture::X64,
                &[0x48, 0xB8, 0x00, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00],
                base,
                1,
            )
            .unwrap();
        assert_eq!(imm[0].mem_ref, None);

        // mov rax, qword ptr [rcx + rdx*8 + 0x10] — register-based, no static address.
        let reg_mem = disasm
            .disassemble(Architecture::X64, &[0x48, 0x8B, 0x44, 0xD1, 0x10], base, 1)
            .unwrap();
        assert_eq!(reg_mem[0].mem_ref, None);
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

    // On fixed-width ARM64 a stall must skip a whole word. Skipping one byte
    // would decode the rest of the buffer at a misaligned offset, so the `bl`
    // after the bad word would never be seen at its real address (this is how
    // the zero-padded ILT at the start of an ARM64 `.text` used to hide every
    // call in the image from the xref sweep).
    #[test]
    fn arm64_stall_skips_a_whole_word() {
        let base = 0x140001000u64;
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&[0x1F, 0x20, 0x03, 0xD5]); // nop
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // undecodable
        bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x94]); // bl #0x1000
        for _ in 0..4 {
            bytes.extend_from_slice(&[0x1F, 0x20, 0x03, 0xD5]); // nop
        }

        let disasm = CapstoneDisassembler::new().unwrap();
        let instrs = disasm.disassemble(Architecture::Arm64, &bytes, base, 64).unwrap();

        assert_eq!(instrs[0].mnemonic, "nop");
        assert!(instrs[1].is_invalid);
        assert_eq!(instrs[1].mnemonic, "db");
        assert_eq!(instrs[1].address, base + 4);
        assert_eq!(instrs[1].size, 4);
        assert_eq!(instrs[1].bytes, vec![0, 0, 0, 0]);

        // Decoding resumed on the next word boundary: the call is intact.
        assert_eq!(instrs[2].mnemonic, "bl");
        assert_eq!(instrs[2].address, base + 8);
        assert!(instrs[2].is_call);
        assert_eq!(instrs[2].jump_target, Some(base + 8 + 0x1000));
        assert_eq!(instrs.len(), 7);
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
