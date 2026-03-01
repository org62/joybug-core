//! Hook installation helpers for Unicorn emulator
//!
//! Provides deduplicated hook installation for syscall, instruction trace,
//! and basic block modes.

use std::sync::{Arc, RwLock};

use unicorn_engine::{Unicorn, RegisterX86, RegisterARM64, UcHookId};

#[cfg(target_arch = "x86_64")]
use unicorn_engine::unicorn_const::X86Insn;

use crate::interfaces::Architecture;
use crate::protocol::{MemoryAccess, MemoryAccessType};

use super::Emulator;
use super::types::{EmulatorSharedState, snapshot_from_unicorn};
use super::error::EmulatorError;

impl<'a> Emulator<'a> {
    /// Install a syscall hook that stops emulation on syscall/SVC.
    ///
    /// Used by all emulation modes to halt at system calls.
    pub(super) fn install_syscall_hook(&mut self) -> Result<UcHookId, EmulatorError> {
        let shared = self.shared_state.clone();
        match self.architecture {
            Architecture::X64 => {
                #[cfg(target_arch = "x86_64")]
                {
                    self.emu.add_insn_sys_hook(
                        X86Insn::SYSCALL,
                        0, u64::MAX,
                        move |emu| {
                            let rip = emu.reg_read(RegisterX86::RIP).unwrap_or(0);
                            let mut state = shared.write().unwrap();
                            state.syscall_address = Some(rip);
                            state.stop_requested = true;
                            drop(state);
                            emu.emu_stop().ok();
                        }
                    ).map_err(|e| EmulatorError::UnicornError(format!("syscall hook failed: {:?}", e)))
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    Err(EmulatorError::UnicornError("x64 syscall hook not supported on this platform".into()))
                }
            }
            Architecture::Arm64 => {
                const EXCP_SWI: u32 = 2;
                self.emu.add_intr_hook(
                    move |emu, intno| {
                        let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
                        let mut state = shared.write().unwrap();
                        if intno == EXCP_SWI {
                            state.syscall_address = Some(pc);
                        } else {
                            tracing::warn!("Unhandled ARM64 interrupt: intno={} at PC=0x{:X}", intno, pc);
                            state.exception_intno = Some(intno);
                        }
                        state.stop_requested = true;
                        drop(state);
                        emu.emu_stop().ok();
                    }
                ).map_err(|e| EmulatorError::UnicornError(format!("intr hook failed: {:?}", e)))
            }
        }
    }

    /// Install a CODE hook for InstructionTrace mode.
    ///
    /// Fires on every instruction to record address, registers, and memory accesses.
    pub(super) fn install_code_hook(&mut self) -> Result<UcHookId, EmulatorError> {
        let shared = self.shared_state.clone();
        let arch = self.architecture;
        self.emu.add_code_hook(0, u64::MAX, move |emu, addr, size| {
            Self::code_hook_handler(emu, &shared, arch, addr, size);
        }).map_err(|e| EmulatorError::UnicornError(format!("code hook failed: {:?}", e)))
    }

    /// CODE hook handler logic — captures instruction trace, register snapshots,
    /// and memory operand data.
    fn code_hook_handler(
        emu: &mut Unicorn<'_, Arc<RwLock<EmulatorSharedState>>>,
        shared: &Arc<RwLock<EmulatorSharedState>>,
        arch: Architecture,
        addr: u64,
        size: u32,
    ) {
        use crate::memory_operand::analyze_memory_operands;

        let mut state = shared.write().unwrap();

        // If a stop was requested (e.g., syscall hit), don't record further instructions
        if state.stop_requested {
            emu.emu_stop().ok();
            return;
        }

        // If we're retrying after a memory fault, pop the stale trace entry
        // that was recorded before the fault caused emulation to stop.
        if state.retrying_after_fault {
            state.retrying_after_fault = false;
            if let Some(&(last_addr, _)) = state.instruction_trace.last() {
                if last_addr == addr {
                    state.instruction_trace.pop();
                    state.register_trace.pop();
                    state.memory_trace.pop();
                    state.pending_write_ops.clear();
                    // Revert last_instruction tracking to prevent spurious basic block entry
                    if let Some(&(prev_addr, prev_size)) = state.instruction_trace.last() {
                        state.last_instruction_addr = Some(prev_addr);
                        state.last_instruction_size = Some(prev_size as u32);
                    } else {
                        state.last_instruction_addr = None;
                        state.last_instruction_size = None;
                    }
                }
            }
        }

        // Step 1: Capture pending write data from previous instruction
        // (previous instruction has now completed execution)
        if !state.pending_write_ops.is_empty() && !state.memory_trace.is_empty() {
            let pending: Vec<_> = state.pending_write_ops.drain(..).collect();
            let last_mem = state.memory_trace.last_mut().unwrap();
            for (write_addr, write_size) in pending {
                if let Ok(data) = emu.mem_read_as_vec(write_addr, write_size) {
                    last_mem.push(MemoryAccess {
                        access_type: MemoryAccessType::Write,
                        address: write_addr,
                        data,
                    });
                }
            }
        } else {
            state.pending_write_ops.clear();
        }

        // Record instruction trace
        state.instruction_trace.push((addr, size as usize));
        let step = state.instruction_trace.len();

        // Capture full register snapshot
        let snapshot = snapshot_from_unicorn(emu, addr);
        state.register_trace.push(snapshot.clone());

        tracing::trace!("step {} RIP=0x{:X} RFLAGS=0x{:X} size={}", step, addr,
            emu.reg_read(RegisterX86::RFLAGS).unwrap_or(0), size);

        // Step 2: Analyze current instruction for memory operands
        let mut current_mem_accesses: Vec<MemoryAccess> = Vec::new();

        if let Ok(insn_bytes) = emu.mem_read_as_vec(addr, size as usize) {
            let operands = analyze_memory_operands(&insn_bytes, addr, &snapshot, arch);

            for op in operands {
                if op.is_read {
                    if let Ok(data) = emu.mem_read_as_vec(op.address, op.size) {
                        let access_type = if op.is_write {
                            MemoryAccessType::ReadWrite
                        } else {
                            MemoryAccessType::Read
                        };
                        current_mem_accesses.push(MemoryAccess {
                            access_type,
                            address: op.address,
                            data,
                        });
                    }
                }
                if op.is_write && !op.is_read {
                    state.pending_write_ops.push((op.address, op.size));
                } else if op.is_write && op.is_read {
                    state.pending_write_ops.push((op.address, op.size));
                }
            }
        }

        state.memory_trace.push(current_mem_accesses);

        // Check for exit address
        if let Some(exit_addr) = state.exit_address {
            if addr == exit_addr {
                state.stop_requested = true;
                emu.emu_stop().ok();
                return;
            }
        }

        // Track basic blocks via non-sequential jumps
        if let (Some(last_addr), Some(last_size)) = (state.last_instruction_addr, state.last_instruction_size) {
            if addr != last_addr + last_size as u64 {
                state.basic_blocks.push(addr);
            }
        }
        state.last_instruction_addr = Some(addr);
        state.last_instruction_size = Some(size);
    }

    /// Install a BLOCK hook for BasicBlock mode.
    ///
    /// Fires at translation block boundaries (more efficient than per-instruction).
    pub(super) fn install_block_hook(&mut self) -> Result<UcHookId, EmulatorError> {
        let shared = self.shared_state.clone();
        self.emu.add_block_hook(0, u64::MAX, move |_emu, addr, _size| {
            let mut state = shared.write().unwrap();
            state.basic_blocks.push(addr);
        }).map_err(|e| EmulatorError::UnicornError(format!("block hook failed: {:?}", e)))
    }
}
