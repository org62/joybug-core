//! CPU Emulator module using Unicorn engine
//!
//! Provides forward emulation from debugger state for:
//! - Basic block prediction
//! - Module transition detection
//! - Condition-based search
//!
//! The emulator is agnostic about where its memory comes from: an
//! [`EmuTarget`] supplies pages, modules and the TEB on demand. A paused
//! debuggee thread ([`LiveTarget`]) and a PE file on disk
//! (`static_pe::StaticTarget`) are both targets.

use std::sync::{Arc, RwLock};

use unicorn_engine::{
    unicorn_const::{Arch, Mode, HookType},
    Unicorn, RegisterX86, RegisterARM64,
};

use crate::interfaces::{Architecture, MAX_USER_ADDRESS};
use crate::protocol::ThreadContext;

mod error;
mod registers;
mod types;
mod memory;
mod hooks;
mod execution;
pub mod target;

pub use error::EmulatorError;
pub use types::{EmulationResult, StopReason, ModuleBoundary};
pub(crate) use types::format_symbol_with_offset;
pub use target::{EmuRegion, EmuTarget, FetchIntercept, LiveTarget};
pub use registers::write_register_by_name;
use types::{EmulatorSharedState, snapshot_from_unicorn};
use registers::{write_x64_registers, write_x86_registers, write_arm64_registers, read_x64_registers, read_arm64_registers};

/// What to do when emulated code calls through an import stub (only a
/// process-less target has those; a live target resolves imports for real).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportPolicy {
    /// Stop with `StopReason::ImportCall` naming the import.
    #[default]
    Stop,
    /// Return to the caller immediately with `value` in the return register.
    /// Exact on x64/ARM64 (caller cleans the stack); on x86 stdcall the callee
    /// would have popped its arguments, which cannot be known statically, so
    /// `esp` ends up low by the argument bytes.
    Skip { value: u64 },
}

/// CPU Emulator that initializes from debugger state
pub struct Emulator<'a> {
    emu: Unicorn<'a, Arc<RwLock<EmulatorSharedState>>>,
    architecture: Architecture,
    shared_state: Arc<RwLock<EmulatorSharedState>>,
    import_policy: ImportPolicy,
}

impl<'a> Emulator<'a> {
    /// An emulator over `target` whose registers come from `context`.
    pub fn from_context<T: EmuTarget>(target: &T, context: &ThreadContext) -> Result<Self, EmulatorError> {
        let mut this = Self::new(target)?;
        match this.architecture {
            Architecture::X86 => write_x86_registers(&mut this.emu, context)?,
            Architecture::X64 => write_x64_registers(&mut this.emu, context)?,
            Architecture::Arm64 => write_arm64_registers(&mut this.emu, context)?,
        }
        this.set_current_module(context.get_pc());
        Ok(this)
    }

    /// An emulator over `target` with registers given by name (`"rcx"`,
    /// `"esp"`, `"x0"`, ...); unspecified registers are zero. `pc` is where
    /// execution starts.
    pub fn with_registers<T: EmuTarget>(
        target: &T,
        pc: u64,
        registers: &[(String, u64)],
    ) -> Result<Self, EmulatorError> {
        let mut this = Self::new(target)?;
        for (name, value) in registers {
            write_register_by_name(&mut this.emu, this.architecture, name, *value)?;
        }
        this.set_pc(pc)?;
        this.set_current_module(pc);
        Ok(this)
    }

    /// Bare emulator: Unicorn for the target's architecture, the fault hook,
    /// the module map and the segment base. No registers written yet.
    fn new<T: EmuTarget>(target: &T) -> Result<Self, EmulatorError> {
        let architecture = target.arch();
        let shared_state = Arc::new(RwLock::new(EmulatorSharedState::new(target.modules())));

        let (arch, mode) = match architecture {
            Architecture::X86 => (Arch::X86, Mode::MODE_32),
            Architecture::X64 => (Arch::X86, Mode::MODE_64),
            Architecture::Arm64 => (Arch::ARM64, Mode::LITTLE_ENDIAN),
        };

        let mut emu = Unicorn::new_with_data(arch, mode, shared_state.clone())
            .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))?;

        // Add memory fault hook to capture the actual fault address
        let hook_state = shared_state.clone();
        emu.add_mem_hook(
            HookType::MEM_READ_UNMAPPED | HookType::MEM_WRITE_UNMAPPED | HookType::MEM_FETCH_UNMAPPED,
            0,
            u64::MAX,
            move |_emu, mem_type, address, size, _value| {
                let mut state = hook_state.write().unwrap();
                tracing::trace!(
                    "Memory fault hook: type={:?} address=0x{:X} size={}",
                    mem_type, address, size
                );
                state.pending_memory_fault = Some(address);
                false
            }
        ).map_err(|e| EmulatorError::UnicornError(format!("mem hook failed: {:?}", e)))?;

        let mut this = Self {
            emu,
            architecture,
            shared_state,
            import_policy: ImportPolicy::Stop,
        };
        this.setup_segments(target)?;
        Ok(this)
    }

    /// How import-stub calls are handled (process-less targets only).
    pub fn set_import_policy(&mut self, policy: ImportPolicy) {
        self.import_policy = policy;
    }

    fn set_current_module(&self, pc: u64) {
        let mut state = self.shared_state.write().unwrap();
        state.current_module = state.modules.iter()
            .find(|m| pc >= m.base && pc < m.end)
            .map(|m| m.name.clone());
    }

    /// Point the thread-local segment at the TEB and pre-load it: `fs` for a
    /// 32-bit thread (the WOW64 TEB32), `gs` for x64. ARM64 reaches its TEB
    /// through x18, which the context carries.
    fn setup_segments<T: EmuTarget>(&mut self, target: &T) -> Result<(), EmulatorError> {
        let seg = match self.architecture {
            Architecture::X86 => RegisterX86::FS_BASE,
            Architecture::X64 => RegisterX86::GS_BASE,
            Architecture::Arm64 => return Ok(()),
        };
        let Some(teb) = target.teb_address() else { return Ok(()) };
        tracing::debug!("Setting {:?} to TEB address: 0x{:X}", seg, teb);
        self.emu.reg_write(seg, teb)
            .map_err(|e| EmulatorError::UnicornError(format!("{:?} write failed: {:?}", seg, e)))?;
        if let Some(region) = target.region(teb) {
            let size = Self::align_size(region.size);
            if self.emu.mem_map(region.base, size, region.prot).is_ok() {
                tracing::trace!(
                    "Unicorn mem_map (TEB): base=0x{:X} size=0x{:X} prot={}",
                    region.base, size, Self::prot_to_str(region.prot)
                );
                if region.committed {
                    if let Some(data) = target.read(region.base, region.size as usize) {
                        let _ = self.emu.mem_write(region.base, &data);
                    }
                }
                let mut state = self.shared_state.write().unwrap();
                state.note_mapped(region.base, size);
            }
        }
        Ok(())
    }

    /// Get current instruction pointer
    pub fn get_pc(&self) -> Result<u64, EmulatorError> {
        match self.architecture {
            Architecture::X86 => {
                self.emu.reg_read(RegisterX86::EIP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::X64 => {
                self.emu.reg_read(RegisterX86::RIP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::Arm64 => {
                self.emu.reg_read(RegisterARM64::PC)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
        }
    }

    /// Set the instruction pointer
    pub(super) fn set_pc(&mut self, value: u64) -> Result<(), EmulatorError> {
        match self.architecture {
            Architecture::X86 => {
                self.emu.reg_write(RegisterX86::EIP, value)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::X64 => {
                self.emu.reg_write(RegisterX86::RIP, value)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::Arm64 => {
                self.emu.reg_write(RegisterARM64::PC, value)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
        }
    }

    /// Recover from a fetch fault on a PAC-signed pointer.
    ///
    /// Windows ARM64 signs return addresses (`pacibsp`) with per-process keys
    /// the emulator cannot know, so `autibsp` cannot authenticate them (it is
    /// a hint-space no-op under Unicorn) and the following `ret` lands on the
    /// still-signed address. When an unmapped fetch targets such an address,
    /// strip the PAC bits (`MAX_USER_ADDRESS`); if the resulting address is
    /// loadable, redirect PC there and report success so the caller can
    /// continue emulating.
    ///
    /// `is_fetch` distinguishes the faulting access: only an instruction fetch
    /// can be repaired this way, since the repair moves PC.
    pub(super) fn try_pac_fetch_recovery<T: EmuTarget>(
        &mut self,
        target: &T,
        fault_addr: u64,
        is_fetch: bool,
    ) -> bool {
        let stripped = fault_addr & MAX_USER_ADDRESS;
        if !is_fetch || self.architecture != Architecture::Arm64 || stripped == fault_addr {
            return false;
        }
        if self.load_memory_region(target, stripped).is_err() || self.set_pc(stripped).is_err() {
            return false;
        }
        tracing::debug!("PAC fetch recovery: 0x{:X} -> 0x{:X}", fault_addr, stripped);
        true
    }

    /// Get stack pointer
    pub fn get_sp(&self) -> Result<u64, EmulatorError> {
        match self.architecture {
            Architecture::X86 => {
                self.emu.reg_read(RegisterX86::ESP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::X64 => {
                self.emu.reg_read(RegisterX86::RSP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
            Architecture::Arm64 => {
                self.emu.reg_read(RegisterARM64::SP)
                    .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
            }
        }
    }

    fn set_sp(&mut self, value: u64) -> Result<(), EmulatorError> {
        let res = match self.architecture {
            Architecture::X86 => self.emu.reg_write(RegisterX86::ESP, value),
            Architecture::X64 => self.emu.reg_write(RegisterX86::RSP, value),
            Architecture::Arm64 => self.emu.reg_write(RegisterARM64::SP, value),
        };
        res.map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))
    }

    /// The address the current callee would return to: `[sp]` on x86/x64,
    /// `lr` on ARM64.
    pub(super) fn return_address(&self) -> Result<u64, EmulatorError> {
        match self.architecture {
            Architecture::X86 | Architecture::X64 => {
                let sp = self.get_sp()?;
                let ptr = self.architecture.pointer_size();
                let bytes = self.emu.mem_read_as_vec(sp, ptr)
                    .map_err(|e| EmulatorError::UnicornError(format!("read return address at 0x{:X}: {:?}", sp, e)))?;
                let mut buf = [0u8; 8];
                buf[..ptr].copy_from_slice(&bytes);
                Ok(u64::from_le_bytes(buf))
            }
            Architecture::Arm64 => self.read_register("LR"),
        }
    }

    /// Perform the return the callee would have done, with `value` as the
    /// return value: the "skip this call" move. On x86/x64 this pops the
    /// return address; on ARM64 it comes from `lr`.
    pub(super) fn return_to_caller(&mut self, value: u64) -> Result<(), EmulatorError> {
        let ret_addr = self.return_address()?;
        let (ret_reg, pop) = match self.architecture {
            Architecture::X86 => (RegisterX86::EAX as i32, true),
            Architecture::X64 => (RegisterX86::RAX as i32, true),
            Architecture::Arm64 => (RegisterARM64::X0 as i32, false),
        };
        if pop {
            let sp = self.get_sp()?;
            self.set_sp(sp + self.architecture.pointer_size() as u64)?;
        }
        self.emu.reg_write(ret_reg, value)
            .map_err(|e| EmulatorError::UnicornError(format!("{:?}", e)))?;
        self.set_pc(ret_addr)
    }

    /// Read a register by name (for condition checking)
    pub fn read_register(&self, name: &str) -> Result<u64, EmulatorError> {
        match self.architecture {
            Architecture::X86 | Architecture::X64 => read_x64_registers(&self.emu, name),
            Architecture::Arm64 => read_arm64_registers(&self.emu, name),
        }
    }

    /// Read memory from the emulator's address space (Unicorn).
    pub fn read_emulated_memory(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        self.emu.mem_read_as_vec(address, size).ok()
    }

    /// Build EmulationResult from current state
    fn build_result(
        &self,
        instructions_executed: usize,
        stop_reason: StopReason,
        emulation_time_us: u64,
        pages_before: usize,
        stats_text: String,
        memory_reads: &[(u64, usize)],
    ) -> Result<EmulationResult, EmulatorError> {
        let final_pc = self.get_pc()?;
        let final_registers = snapshot_from_unicorn(&self.emu, self.architecture, final_pc);
        let state = self.shared_state.read().unwrap();
        let pages_loaded = state.mapped_regions.len().saturating_sub(pages_before);

        let memory_snapshots: Vec<(u64, Vec<u8>)> = memory_reads.iter()
            .filter_map(|&(addr, size)| {
                self.emu.mem_read_as_vec(addr, size).ok().map(|data| (addr, data))
            })
            .collect();

        Ok(EmulationResult {
            final_pc,
            instructions_executed,
            stop_reason,
            emulation_time_us,
            pages_loaded,
            basic_blocks: state.basic_blocks.clone(),
            instruction_trace: state.instruction_trace.clone(),
            register_trace: state.register_trace.clone(),
            memory_trace: state.memory_trace.clone(),
            stats_text,
            memory_snapshots,
            final_registers,
        })
    }
}

#[cfg(test)]
mod tests;
