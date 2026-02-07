//! Memory operand analysis for instruction tracing
//!
//! Provides Capstone-based memory operand extraction to determine which memory
//! addresses an instruction will read from or write to.

use capstone::prelude::*;
use capstone::arch::ArchDetail;
use capstone::arch::x86::{X86OperandType, X86Reg};
use std::cell::RefCell;

use crate::interfaces::Architecture;
use crate::protocol::{MemoryAccess, MemoryAccessType, RegisterSnapshot, X64RegisterSnapshot};

// Thread-local Capstone engines for memory operand analysis
thread_local! {
    static X64_ENGINE: RefCell<Option<Capstone>> = const { RefCell::new(None) };
}

/// Information about a memory operand before execution
#[derive(Debug, Clone)]
pub struct MemoryOperandInfo {
    /// Whether this operand is read
    pub is_read: bool,
    /// Whether this operand is written
    pub is_write: bool,
    /// Computed effective address
    pub address: u64,
    /// Size of the memory access in bytes
    pub size: usize,
}

/// Get the value of a register from an X64RegisterSnapshot using Capstone's X86Reg constants
fn get_x64_register_value(regs: &X64RegisterSnapshot, reg_id: u16) -> u64 {
    // Use Capstone's x86_reg constants (from capstone::arch::x86::X86Reg)
    // Cast to u16 for comparison with RegId.0
    match reg_id as u32 {
        // 64-bit general purpose registers
        X86Reg::X86_REG_RAX => regs.rax,
        X86Reg::X86_REG_RBX => regs.rbx,
        X86Reg::X86_REG_RCX => regs.rcx,
        X86Reg::X86_REG_RDX => regs.rdx,
        X86Reg::X86_REG_RSI => regs.rsi,
        X86Reg::X86_REG_RDI => regs.rdi,
        X86Reg::X86_REG_RBP => regs.rbp,
        X86Reg::X86_REG_RSP => regs.rsp,
        X86Reg::X86_REG_R8 => regs.r8,
        X86Reg::X86_REG_R9 => regs.r9,
        X86Reg::X86_REG_R10 => regs.r10,
        X86Reg::X86_REG_R11 => regs.r11,
        X86Reg::X86_REG_R12 => regs.r12,
        X86Reg::X86_REG_R13 => regs.r13,
        X86Reg::X86_REG_R14 => regs.r14,
        X86Reg::X86_REG_R15 => regs.r15,
        X86Reg::X86_REG_RIP => regs.rip,

        // 32-bit registers (lower 32 bits of 64-bit counterparts)
        X86Reg::X86_REG_EAX => regs.rax & 0xFFFFFFFF,
        X86Reg::X86_REG_EBX => regs.rbx & 0xFFFFFFFF,
        X86Reg::X86_REG_ECX => regs.rcx & 0xFFFFFFFF,
        X86Reg::X86_REG_EDX => regs.rdx & 0xFFFFFFFF,
        X86Reg::X86_REG_ESI => regs.rsi & 0xFFFFFFFF,
        X86Reg::X86_REG_EDI => regs.rdi & 0xFFFFFFFF,
        X86Reg::X86_REG_EBP => regs.rbp & 0xFFFFFFFF,
        X86Reg::X86_REG_ESP => regs.rsp & 0xFFFFFFFF,
        X86Reg::X86_REG_R8D => regs.r8 & 0xFFFFFFFF,
        X86Reg::X86_REG_R9D => regs.r9 & 0xFFFFFFFF,
        X86Reg::X86_REG_R10D => regs.r10 & 0xFFFFFFFF,
        X86Reg::X86_REG_R11D => regs.r11 & 0xFFFFFFFF,
        X86Reg::X86_REG_R12D => regs.r12 & 0xFFFFFFFF,
        X86Reg::X86_REG_R13D => regs.r13 & 0xFFFFFFFF,
        X86Reg::X86_REG_R14D => regs.r14 & 0xFFFFFFFF,
        X86Reg::X86_REG_R15D => regs.r15 & 0xFFFFFFFF,

        _ => 0,
    }
}

/// Get the value of a register from a RegisterSnapshot using Capstone's X86Reg constants
/// Returns 0 if the snapshot is not x64 or register is unknown
fn get_register_value(regs: &RegisterSnapshot, reg_id: u16) -> u64 {
    match regs {
        RegisterSnapshot::X64(x64_regs) => get_x64_register_value(x64_regs, reg_id),
        RegisterSnapshot::Arm64(_) => 0, // ARM64 not supported in x64 memory operand analysis
    }
}

/// Determine if an x86 instruction reads from or writes to a memory operand
/// based on the mnemonic and operand position.
fn classify_x86_memory_access(mnemonic: &str, operand_index: usize, total_operands: usize) -> (bool, bool) {
    let mnemonic_lower = mnemonic.to_lowercase();

    // Instructions that only read memory (second operand or single operand)
    let read_only = [
        "cmp", "test", "bt", "bts", "btr", "btc",
        "push", "fld", "fild", "movsx", "movzx", "movsxd",
        "cvtsi2ss", "cvtsi2sd", "cvtss2sd", "cvtsd2ss",
        "vbroadcast", "vpbroadcast", "vgather", "vpgather",
    ];

    // Instructions that only write memory (first operand)
    let write_only = [
        "pop", "fst", "fstp", "fistp", "fisttp",
        "movnti", "movntdq", "movntps", "movntpd", "movnt",
        "lea", // LEA doesn't actually access memory, but operand 1 is dest
        "stos", "stosb", "stosd", "stosq",
    ];

    // Instructions that read-modify-write (typically first operand)
    let read_write = [
        "inc", "dec", "neg", "not",
        "add", "sub", "adc", "sbb", "and", "or", "xor",
        "rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar",
        "lock", // prefix for atomic operations
        "xadd", "xchg", "cmpxchg",
    ];

    // Check for read-modify-write instructions
    for rw_insn in read_write.iter() {
        if mnemonic_lower.starts_with(rw_insn) {
            if operand_index == 0 {
                return (true, true); // First operand: read and write
            }
            return (true, false); // Other operands: read only
        }
    }

    // Check for read-only instructions
    for r_insn in read_only.iter() {
        if mnemonic_lower.starts_with(r_insn) {
            return (true, false);
        }
    }

    // Check for write-only instructions
    for w_insn in write_only.iter() {
        if mnemonic_lower.starts_with(w_insn) {
            if operand_index == 0 {
                return (false, true);
            }
            return (true, false);
        }
    }

    // mov-like instructions: first operand is destination, rest are sources
    if mnemonic_lower.starts_with("mov") || mnemonic_lower.starts_with("vmov") {
        if operand_index == 0 {
            return (false, true); // Destination
        }
        return (true, false); // Source
    }

    // Default: assume read for non-first operand, write for first operand
    // This is a common convention for two-operand x86 instructions
    if total_operands >= 2 {
        if operand_index == 0 {
            return (false, true); // First operand typically destination
        }
        return (true, false); // Other operands typically sources
    }

    // Single operand: assume read (safer default)
    (true, false)
}

/// Analyze an instruction to extract its memory operands.
///
/// # Arguments
/// * `instruction_bytes` - The raw bytes of the instruction
/// * `instruction_address` - The virtual address of the instruction
/// * `registers` - The register state before instruction execution
/// * `arch` - The CPU architecture
///
/// # Returns
/// A vector of MemoryOperandInfo describing each memory operand
pub fn analyze_memory_operands(
    instruction_bytes: &[u8],
    instruction_address: u64,
    registers: &RegisterSnapshot,
    arch: Architecture,
) -> Vec<MemoryOperandInfo> {
    match arch {
        Architecture::X64 => analyze_x64_memory_operands(instruction_bytes, instruction_address, registers),
        Architecture::Arm64 => Vec::new(), // TODO: Implement ARM64 support
    }
}

fn analyze_x64_memory_operands(
    instruction_bytes: &[u8],
    instruction_address: u64,
    registers: &RegisterSnapshot,
) -> Vec<MemoryOperandInfo> {
    X64_ENGINE.with(|cell| {
        let mut engine_opt = cell.borrow_mut();
        if engine_opt.is_none() {
            let engine = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build();
            if let Ok(e) = engine {
                *engine_opt = Some(e);
            } else {
                return Vec::new();
            }
        }

        let engine = engine_opt.as_ref().unwrap();
        let instructions = match engine.disasm_count(instruction_bytes, instruction_address, 1) {
            Ok(insns) => insns,
            Err(_) => return Vec::new(),
        };

        let insn = match instructions.iter().next() {
            Some(i) => i,
            None => return Vec::new(),
        };

        let mnemonic = insn.mnemonic().unwrap_or("");

        // Skip LEA - it computes address but doesn't access memory
        if mnemonic.eq_ignore_ascii_case("lea") {
            return Vec::new();
        }

        let detail = match engine.insn_detail(&insn) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        let mut result = Vec::new();

        if let ArchDetail::X86Detail(x86) = detail.arch_detail() {
            let operands: Vec<_> = x86.operands().collect();
            let total_operands = operands.len();

            for (op_index, op) in operands.iter().enumerate() {
                if let X86OperandType::Mem(ref mem) = op.op_type {
                    // Compute effective address: base + index*scale + disp
                    let mut addr: u64 = 0;

                    // Handle base register
                    let base_id = mem.base().0;
                    if base_id != 0 {
                        if base_id as u32 == X86Reg::X86_REG_RIP {
                            // RIP-relative addressing: RIP points to next instruction
                            addr = instruction_address.wrapping_add(insn.len() as u64);
                        } else {
                            addr = get_register_value(registers, base_id);
                        }
                    }

                    // Handle index register with scale
                    let index_id = mem.index().0;
                    if index_id != 0 {
                        let index_val = get_register_value(registers, index_id);
                        addr = addr.wrapping_add(index_val.wrapping_mul(mem.scale() as u64));
                    }

                    // Add displacement
                    addr = addr.wrapping_add_signed(mem.disp());

                    // Skip addresses in the null page guard region (< 0x10000 on Windows)
                    // These are invalid addresses that would cause read errors
                    if addr < 0x10000 {
                        continue;
                    }

                    // Determine access type
                    let (is_read, is_write) = classify_x86_memory_access(mnemonic, op_index, total_operands);

                    // Get operand size (default to 8 bytes for x64)
                    let size = if op.size > 0 { op.size as usize } else { 8 };

                    result.push(MemoryOperandInfo {
                        is_read,
                        is_write,
                        address: addr,
                        size,
                    });
                }
            }
        }

        result
    })
}

/// Convert memory operand infos and data into MemoryAccess records
pub fn create_memory_accesses(
    operands: &[MemoryOperandInfo],
    read_memory: impl Fn(u64, usize) -> Option<Vec<u8>>,
) -> Vec<MemoryAccess> {
    let mut accesses = Vec::new();

    for op in operands {
        let access_type = match (op.is_read, op.is_write) {
            (true, true) => MemoryAccessType::ReadWrite,
            (true, false) => MemoryAccessType::Read,
            (false, true) => MemoryAccessType::Write,
            (false, false) => continue, // No access
        };

        // Read memory data
        if let Some(data) = read_memory(op.address, op.size) {
            accesses.push(MemoryAccess {
                access_type,
                address: op.address,
                data,
            });
        }
    }

    accesses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regs() -> RegisterSnapshot {
        // Use addresses above 0x10000 (null page guard region)
        RegisterSnapshot::X64(X64RegisterSnapshot {
            rax: 0x100000,
            rbx: 0x200000,
            rcx: 0x300000,
            rdx: 0x400000,
            rsi: 0x500000,
            rdi: 0x600000,
            rbp: 0x700000,
            rsp: 0x800000,
            r8: 0x900000,
            r9: 0xA00000,
            r10: 0xB00000,
            r11: 0xC00000,
            r12: 0xD00000,
            r13: 0xE00000,
            r14: 0xF00000,
            r15: 0x1000000,
            rip: 0x140001000,
            rflags: 0x246,
        })
    }

    #[test]
    fn test_mov_reg_mem() {
        // mov rax, [rbx] - read from memory
        let bytes = [0x48, 0x8B, 0x03]; // mov rax, [rbx]
        let regs = make_regs();
        let ops = analyze_memory_operands(&bytes, 0x140001000, &regs, Architecture::X64);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].address, 0x200000); // rbx value
        assert!(ops[0].is_read);
        assert!(!ops[0].is_write);
    }

    #[test]
    fn test_mov_mem_reg() {
        // mov [rbx], rax - write to memory
        let bytes = [0x48, 0x89, 0x03]; // mov [rbx], rax
        let regs = make_regs();
        let ops = analyze_memory_operands(&bytes, 0x140001000, &regs, Architecture::X64);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].address, 0x200000); // rbx value
        assert!(!ops[0].is_read);
        assert!(ops[0].is_write);
    }

    #[test]
    fn test_add_mem_reg() {
        // add [rbx], rax - read-modify-write
        let bytes = [0x48, 0x01, 0x03]; // add [rbx], rax
        let regs = make_regs();
        let ops = analyze_memory_operands(&bytes, 0x140001000, &regs, Architecture::X64);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].address, 0x200000); // rbx value
        assert!(ops[0].is_read);
        assert!(ops[0].is_write);
    }

    #[test]
    fn test_base_index_scale_disp() {
        // mov rax, [rbx + rcx*4 + 0x100]
        let bytes = [0x48, 0x8B, 0x84, 0x8B, 0x00, 0x01, 0x00, 0x00];
        let regs = make_regs();
        let ops = analyze_memory_operands(&bytes, 0x140001000, &regs, Architecture::X64);
        assert_eq!(ops.len(), 1);
        // Address = rbx (0x200000) + rcx*4 (0x300000*4=0xC00000) + 0x100 = 0xE00100
        assert_eq!(ops[0].address, 0xE00100);
    }

    #[test]
    fn test_lea_no_memory_access() {
        // lea rax, [rbx + 0x100] - no actual memory access
        let bytes = [0x48, 0x8D, 0x83, 0x00, 0x01, 0x00, 0x00];
        let regs = make_regs();
        let ops = analyze_memory_operands(&bytes, 0x140001000, &regs, Architecture::X64);
        assert_eq!(ops.len(), 0); // LEA doesn't access memory
    }
}
