use crate::interfaces::{Architecture, DisassemblerError, DisassemblerProvider, Instruction};
use capstone::prelude::*;

pub struct CapstoneDisassembler {
}

impl CapstoneDisassembler {
    pub fn new() -> Result<Self, DisassemblerError> {
        Ok(Self {
        })
    }

    fn create_engine(&self, arch: Architecture) -> Result<Capstone, DisassemblerError> {
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

        Ok(engine)
    }
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

        let engine = self.create_engine(arch)?;
        
        let instructions = engine
            .disasm_count(data, address, count)
            .map_err(|e| DisassemblerError::CapstoneError(e.to_string()))?;

        let mut result = Vec::new();
        for insn in instructions.iter() {
            result.push(crate::interfaces::Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                op_str: insn.op_str().unwrap_or("").to_string(),
                size: insn.len(),
                symbol_info: None,
                symbolized_op_str: None,
            });
        }

        Ok(result)
    }
}

impl Clone for CapstoneDisassembler {
    fn clone(&self) -> Self {
        Self {}
    }
} 