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

/// Extract all addresses that should be symbolized from instruction operands
/// Uses Capstone's structured operand data instead of text parsing
fn extract_addresses_from_operands(
    engine: &Capstone,
    insn: &capstone::Insn,
    arch: Architecture,
) -> Vec<u64> {
    let mut addresses = Vec::new();

    let detail = match engine.insn_detail(insn) {
        Ok(d) => d,
        Err(_) => return addresses,
    };

    match arch {
        Architecture::X64 => {
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
            // ARM64 handling - immediates in branch instructions
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
    let detail = engine.insn_detail(insn).ok()?;

    match arch {
        Architecture::X64 => {
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
            if let ArchDetail::Arm64Detail(arm64) = detail.arch_detail() {
                for op in arm64.operands() {
                    if let capstone::arch::arm64::Arm64OperandType::Imm(value) = op.op_type {
                        let addr = value as u64;
                        if addr > 0x10000 {
                            return Some(addr);
                        }
                    }
                }
            }
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

        Self::with_engine(arch, |engine| {
            let instructions = engine
                .disasm_count(data, address, count)
                .map_err(|e| DisassemblerError::CapstoneError(e.to_string()))?;

            let mut result = Vec::new();
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

                result.push(crate::interfaces::Instruction {
                    address: insn.address(),
                    bytes: insn.bytes().to_vec(),
                    mnemonic: mnemonic.to_string(),
                    op_str: op_str.to_string(),
                    size: insn.len(),
                    symbol_info: None,
                    symbolized_op_str: None,
                    is_jump,
                    is_call,
                    is_ret,
                    jump_target,
                    addresses_to_symbolize,
                });
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