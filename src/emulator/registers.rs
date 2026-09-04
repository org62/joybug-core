//! Register mapping between Windows CONTEXT and Unicorn registers

use unicorn_engine::{RegisterARM64, RegisterX86, Unicorn};
use crate::protocol::ThreadContext;
use super::error::EmulatorError;

/// Load a WOW64 (32-bit x86) thread's registers into a Mode32 Unicorn.
pub fn write_x86_registers<D>(
    emu: &mut Unicorn<'_, D>,
    context: &ThreadContext,
) -> Result<(), EmulatorError> {
    let ThreadContext::Wow64RawContext(ctx) = context else {
        return Err(EmulatorError::RegisterError("x86 emulation needs a WOW64 context".into()));
    };
    let regs: [(RegisterX86, u32, &str); 9] = [
        (RegisterX86::EAX, ctx.Eax, "EAX"), (RegisterX86::EBX, ctx.Ebx, "EBX"),
        (RegisterX86::ECX, ctx.Ecx, "ECX"), (RegisterX86::EDX, ctx.Edx, "EDX"),
        (RegisterX86::ESI, ctx.Esi, "ESI"), (RegisterX86::EDI, ctx.Edi, "EDI"),
        (RegisterX86::EBP, ctx.Ebp, "EBP"), (RegisterX86::ESP, ctx.Esp, "ESP"),
        (RegisterX86::EIP, ctx.Eip, "EIP"),
    ];
    for (reg, value, name) in regs {
        emu.reg_write(reg, value as u64)
            .map_err(|e| EmulatorError::RegisterError(format!("{}: {:?}", name, e)))?;
    }
    // Clear TF (bit 8) so the emulation itself never single-steps.
    let eflags_no_tf = (ctx.EFlags as u64) & !0x100;
    emu.reg_write(RegisterX86::EFLAGS, eflags_no_tf)
        .map_err(|e| EmulatorError::RegisterError(format!("EFLAGS: {:?}", e)))?;
    Ok(())
}

/// Write x64 registers from Windows CONTEXT to Unicorn
#[cfg(target_arch = "x86_64")]
pub fn write_x64_registers<D>(
    emu: &mut Unicorn<'_, D>,
    context: &ThreadContext,
) -> Result<(), EmulatorError> {
    match context {
        ThreadContext::Wow64RawContext(_) => {
            return Err(EmulatorError::RegisterError("emulation of 32-bit (WOW64) contexts is not supported yet".into()));
        }
        ThreadContext::Win32RawContext(ctx) => {
            // General purpose registers
            emu.reg_write(RegisterX86::RAX, ctx.Rax)
                .map_err(|e| EmulatorError::RegisterError(format!("RAX: {:?}", e)))?;
            emu.reg_write(RegisterX86::RBX, ctx.Rbx)
                .map_err(|e| EmulatorError::RegisterError(format!("RBX: {:?}", e)))?;
            emu.reg_write(RegisterX86::RCX, ctx.Rcx)
                .map_err(|e| EmulatorError::RegisterError(format!("RCX: {:?}", e)))?;
            emu.reg_write(RegisterX86::RDX, ctx.Rdx)
                .map_err(|e| EmulatorError::RegisterError(format!("RDX: {:?}", e)))?;
            emu.reg_write(RegisterX86::RSI, ctx.Rsi)
                .map_err(|e| EmulatorError::RegisterError(format!("RSI: {:?}", e)))?;
            emu.reg_write(RegisterX86::RDI, ctx.Rdi)
                .map_err(|e| EmulatorError::RegisterError(format!("RDI: {:?}", e)))?;
            emu.reg_write(RegisterX86::RBP, ctx.Rbp)
                .map_err(|e| EmulatorError::RegisterError(format!("RBP: {:?}", e)))?;
            emu.reg_write(RegisterX86::RSP, ctx.Rsp)
                .map_err(|e| EmulatorError::RegisterError(format!("RSP: {:?}", e)))?;
            emu.reg_write(RegisterX86::R8, ctx.R8)
                .map_err(|e| EmulatorError::RegisterError(format!("R8: {:?}", e)))?;
            emu.reg_write(RegisterX86::R9, ctx.R9)
                .map_err(|e| EmulatorError::RegisterError(format!("R9: {:?}", e)))?;
            emu.reg_write(RegisterX86::R10, ctx.R10)
                .map_err(|e| EmulatorError::RegisterError(format!("R10: {:?}", e)))?;
            emu.reg_write(RegisterX86::R11, ctx.R11)
                .map_err(|e| EmulatorError::RegisterError(format!("R11: {:?}", e)))?;
            emu.reg_write(RegisterX86::R12, ctx.R12)
                .map_err(|e| EmulatorError::RegisterError(format!("R12: {:?}", e)))?;
            emu.reg_write(RegisterX86::R13, ctx.R13)
                .map_err(|e| EmulatorError::RegisterError(format!("R13: {:?}", e)))?;
            emu.reg_write(RegisterX86::R14, ctx.R14)
                .map_err(|e| EmulatorError::RegisterError(format!("R14: {:?}", e)))?;
            emu.reg_write(RegisterX86::R15, ctx.R15)
                .map_err(|e| EmulatorError::RegisterError(format!("R15: {:?}", e)))?;

            // Instruction pointer
            emu.reg_write(RegisterX86::RIP, ctx.Rip)
                .map_err(|e| EmulatorError::RegisterError(format!("RIP: {:?}", e)))?;

            // Flags - clear TF (Trap Flag, bit 8) to avoid single-step exceptions during emulation
            let eflags_no_tf = (ctx.EFlags as u64) & !0x100;
            emu.reg_write(RegisterX86::EFLAGS, eflags_no_tf)
                .map_err(|e| EmulatorError::RegisterError(format!("EFLAGS: {:?}", e)))?;

            // Segment registers - skip FS/GS as they require MSR handling on x64
            // In 64-bit mode, FS/GS bases are set via MSRs not segment descriptors.
            // The CONTEXT only has selector values which aren't directly usable.
            // CS, DS, ES, SS can also cause issues in Unicorn on 64-bit mode.
            // For general code emulation these aren't needed - skip all segment writes.
            // Code that accesses TEB/PEB via fs:[0] or gs:[0] will fail, which is expected.

            Ok(())
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn write_x64_registers<D>(
    _emu: &mut Unicorn<'_, D>,
    _context: &ThreadContext,
) -> Result<(), EmulatorError> {
    Err(EmulatorError::RegisterError("x64 not supported on this platform".to_string()))
}

/// Write ARM64 registers from Windows CONTEXT to Unicorn
#[cfg(target_arch = "aarch64")]
pub fn write_arm64_registers<D>(
    emu: &mut Unicorn<'_, D>,
    context: &ThreadContext,
) -> Result<(), EmulatorError> {
    match context {
        ThreadContext::Wow64RawContext(_) => {
            return Err(EmulatorError::RegisterError("emulation of 32-bit (WOW64) contexts is not supported yet".into()));
        }
        ThreadContext::Win32RawContext(ctx) => {
            // General purpose registers X0-X28
            let x_regs = unsafe { ctx.Anonymous.X };
            for i in 0..29 {
                let reg = match i {
                    0 => RegisterARM64::X0,
                    1 => RegisterARM64::X1,
                    2 => RegisterARM64::X2,
                    3 => RegisterARM64::X3,
                    4 => RegisterARM64::X4,
                    5 => RegisterARM64::X5,
                    6 => RegisterARM64::X6,
                    7 => RegisterARM64::X7,
                    8 => RegisterARM64::X8,
                    9 => RegisterARM64::X9,
                    10 => RegisterARM64::X10,
                    11 => RegisterARM64::X11,
                    12 => RegisterARM64::X12,
                    13 => RegisterARM64::X13,
                    14 => RegisterARM64::X14,
                    15 => RegisterARM64::X15,
                    16 => RegisterARM64::X16,
                    17 => RegisterARM64::X17,
                    18 => RegisterARM64::X18,
                    19 => RegisterARM64::X19,
                    20 => RegisterARM64::X20,
                    21 => RegisterARM64::X21,
                    22 => RegisterARM64::X22,
                    23 => RegisterARM64::X23,
                    24 => RegisterARM64::X24,
                    25 => RegisterARM64::X25,
                    26 => RegisterARM64::X26,
                    27 => RegisterARM64::X27,
                    28 => RegisterARM64::X28,
                    _ => continue,
                };
                emu.reg_write(reg, x_regs[i])
                    .map_err(|e| EmulatorError::RegisterError(format!("X{}: {:?}", i, e)))?;
            }

            // Frame pointer (X29), Link register (X30)
            // ARM64 CONTEXT has nested anonymous union for Fp/Lr
            emu.reg_write(RegisterARM64::X29, unsafe { ctx.Anonymous.Anonymous.Fp })
                .map_err(|e| EmulatorError::RegisterError(format!("FP: {:?}", e)))?;
            emu.reg_write(RegisterARM64::X30, unsafe { ctx.Anonymous.Anonymous.Lr })
                .map_err(|e| EmulatorError::RegisterError(format!("LR: {:?}", e)))?;

            // Stack pointer and Program counter
            emu.reg_write(RegisterARM64::SP, ctx.Sp)
                .map_err(|e| EmulatorError::RegisterError(format!("SP: {:?}", e)))?;
            emu.reg_write(RegisterARM64::PC, ctx.Pc)
                .map_err(|e| EmulatorError::RegisterError(format!("PC: {:?}", e)))?;

            // PSTATE/CPSR (condition flags)
            emu.reg_write(RegisterARM64::NZCV, ctx.Cpsr as u64)
                .map_err(|e| EmulatorError::RegisterError(format!("NZCV: {:?}", e)))?;

            Ok(())
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub fn write_arm64_registers<D>(
    _emu: &mut Unicorn<'_, D>,
    _context: &ThreadContext,
) -> Result<(), EmulatorError> {
    Err(EmulatorError::RegisterError("ARM64 not supported on this platform".to_string()))
}

/// Read x64 (or, by its 32-bit names, x86) register by name
pub fn read_x64_registers<D>(emu: &Unicorn<'_, D>, name: &str) -> Result<u64, EmulatorError> {
    let reg = match name.to_uppercase().as_str() {
        "RAX" => RegisterX86::RAX,
        "RBX" => RegisterX86::RBX,
        "RCX" => RegisterX86::RCX,
        "RDX" => RegisterX86::RDX,
        "RSI" => RegisterX86::RSI,
        "RDI" => RegisterX86::RDI,
        "RBP" => RegisterX86::RBP,
        "RSP" => RegisterX86::RSP,
        "R8" => RegisterX86::R8,
        "R9" => RegisterX86::R9,
        "R10" => RegisterX86::R10,
        "R11" => RegisterX86::R11,
        "R12" => RegisterX86::R12,
        "R13" => RegisterX86::R13,
        "R14" => RegisterX86::R14,
        "R15" => RegisterX86::R15,
        "RIP" => RegisterX86::RIP,
        "EFLAGS" | "RFLAGS" => RegisterX86::EFLAGS,
        "EAX" => RegisterX86::EAX,
        "EBX" => RegisterX86::EBX,
        "ECX" => RegisterX86::ECX,
        "EDX" => RegisterX86::EDX,
        "ESI" => RegisterX86::ESI,
        "EDI" => RegisterX86::EDI,
        "EBP" => RegisterX86::EBP,
        "ESP" => RegisterX86::ESP,
        "EIP" => RegisterX86::EIP,
        _ => return Err(EmulatorError::RegisterError(format!("Unknown register: {}", name))),
    };

    emu.reg_read(reg)
        .map_err(|e| EmulatorError::RegisterError(format!("{}: {:?}", name, e)))
}

/// Read ARM64 register by name
pub fn read_arm64_registers<D>(emu: &Unicorn<'_, D>, name: &str) -> Result<u64, EmulatorError> {
    let reg = match name.to_uppercase().as_str() {
        "X0" => RegisterARM64::X0,
        "X1" => RegisterARM64::X1,
        "X2" => RegisterARM64::X2,
        "X3" => RegisterARM64::X3,
        "X4" => RegisterARM64::X4,
        "X5" => RegisterARM64::X5,
        "X6" => RegisterARM64::X6,
        "X7" => RegisterARM64::X7,
        "X8" => RegisterARM64::X8,
        "X9" => RegisterARM64::X9,
        "X10" => RegisterARM64::X10,
        "X11" => RegisterARM64::X11,
        "X12" => RegisterARM64::X12,
        "X13" => RegisterARM64::X13,
        "X14" => RegisterARM64::X14,
        "X15" => RegisterARM64::X15,
        "X16" => RegisterARM64::X16,
        "X17" => RegisterARM64::X17,
        "X18" => RegisterARM64::X18,
        "X19" => RegisterARM64::X19,
        "X20" => RegisterARM64::X20,
        "X21" => RegisterARM64::X21,
        "X22" => RegisterARM64::X22,
        "X23" => RegisterARM64::X23,
        "X24" => RegisterARM64::X24,
        "X25" => RegisterARM64::X25,
        "X26" => RegisterARM64::X26,
        "X27" => RegisterARM64::X27,
        "X28" => RegisterARM64::X28,
        "X29" | "FP" => RegisterARM64::X29,
        "X30" | "LR" => RegisterARM64::X30,
        "SP" => RegisterARM64::SP,
        "PC" => RegisterARM64::PC,
        "NZCV" | "CPSR" => RegisterARM64::NZCV,
        _ => return Err(EmulatorError::RegisterError(format!("Unknown register: {}", name))),
    };

    emu.reg_read(reg)
        .map_err(|e| EmulatorError::RegisterError(format!("{}: {:?}", name, e)))
}

