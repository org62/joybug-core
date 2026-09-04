//! CPU Emulator module using Unicorn engine
//!
//! Provides forward emulation from debugger state for:
//! - Basic block prediction
//! - Module transition detection
//! - Condition-based search

use std::sync::{Arc, RwLock};

use unicorn_engine::{
    unicorn_const::{Arch, Mode, HookType},
    Unicorn, RegisterX86, RegisterARM64,
};

use crate::interfaces::{Architecture, PlatformAPI, MAX_USER_ADDRESS};
use crate::protocol::ThreadContext;

mod error;
mod registers;
mod types;
mod memory;
mod hooks;
mod execution;

pub use error::EmulatorError;
pub use types::{EmulationResult, StopReason};
use types::{ModuleBoundary, EmulatorSharedState};
use registers::{write_x64_registers, write_x86_registers, write_arm64_registers, read_x64_registers, read_arm64_registers};

/// CPU Emulator that initializes from debugger state
pub struct Emulator<'a> {
    emu: Unicorn<'a, Arc<RwLock<EmulatorSharedState>>>,
    architecture: Architecture,
    pid: u32,
    shared_state: Arc<RwLock<EmulatorSharedState>>,
}

impl<'a> Emulator<'a> {
    /// Create a new emulator from debugger state
    pub fn from_debugger_state<P: PlatformAPI>(
        platform: &P,
        pid: u32,
        tid: u32,
    ) -> Result<Self, EmulatorError> {
        let context = platform.get_thread_context(pid, tid)
            .map_err(|e| EmulatorError::PlatformError(e.to_string()))?;

        let architecture = Self::detect_architecture(&context);

        let modules_info = platform.list_modules(pid)
            .map_err(|e| EmulatorError::PlatformError(e.to_string()))?;

        let modules: Vec<ModuleBoundary> = modules_info
            .iter()
            .map(|m| ModuleBoundary {
                name: m.name.clone(),
                base: m.base,
                end: m.base + m.size.unwrap_or(0x1000),
            })
            .collect();

        let shared_state = Arc::new(RwLock::new(EmulatorSharedState::new(modules)));

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

        // For x64, set up GS segment base for TEB access
        #[cfg(target_arch = "x86_64")]
        if matches!(architecture, Architecture::X64) {
            Self::setup_x64_segments(&mut emu, platform, pid, tid)?;
        }

        // For a WOW64 thread, `fs:` addresses the 32-bit TEB.
        if matches!(architecture, Architecture::X86) {
            Self::setup_x86_segments(&mut emu, platform, pid, tid)?;
        }

        // Write registers from context
        match architecture {
            Architecture::X86 => write_x86_registers(&mut emu, &context)?,
            Architecture::X64 => write_x64_registers(&mut emu, &context)?,
            Architecture::Arm64 => write_arm64_registers(&mut emu, &context)?,
        }

        // Set current module based on PC
        let pc = context.get_pc();
        {
            let mut state = shared_state.write().unwrap();
            state.current_module = state.modules.iter()
                .find(|m| pc >= m.base && pc < m.end)
                .map(|m| m.name.clone());
        }

        Ok(Self {
            emu,
            architecture,
            pid,
            shared_state,
        })
    }

    fn detect_architecture(context: &ThreadContext) -> Architecture {
        context.architecture()
    }

    /// Set up the 32-bit FS base: the WOW64 thread's 32-bit TEB
    /// (`get_teb_address` reports that one for an x86 target).
    fn setup_x86_segments<D, P: PlatformAPI>(
        emu: &mut Unicorn<'_, D>,
        platform: &P,
        pid: u32,
        tid: u32,
    ) -> Result<(), EmulatorError> {
        use windows_sys::Win32::System::Memory::MEM_COMMIT;

        match platform.get_teb_address(pid, tid) {
            Ok(teb32) => {
                tracing::debug!("Setting FS_BASE to TEB32 address: 0x{:08X}", teb32);
                emu.reg_write(RegisterX86::FS_BASE, teb32)
                    .map_err(|e| EmulatorError::UnicornError(format!("FS_BASE write failed: {:?}", e)))?;
                if let Ok(region) = platform.query_memory_region(pid, teb32) {
                    let size = Self::align_size(region.region_size);
                    let prot = Self::windows_protect_to_unicorn(region.protect);
                    if emu.mem_map(region.base_address, size, prot).is_ok() && region.state == MEM_COMMIT {
                        if let Ok(data) = platform.read_memory(pid, region.base_address, region.region_size as usize) {
                            let _ = emu.mem_write(region.base_address, &data);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Could not get TEB32 address: {}. FS segment access will fail.", e);
            }
        }
        Ok(())
    }

    /// Set up x64 segment bases (GS for TEB)
    #[cfg(target_arch = "x86_64")]
    fn setup_x64_segments<D, P: PlatformAPI>(
        emu: &mut Unicorn<'_, D>,
        platform: &P,
        pid: u32,
        tid: u32,
    ) -> Result<(), EmulatorError> {
        use windows_sys::Win32::System::Memory::MEM_COMMIT;

        match platform.get_teb_address(pid, tid) {
            Ok(teb_address) => {
                tracing::debug!("Setting GS_BASE to TEB address: 0x{:016X}", teb_address);
                emu.reg_write(RegisterX86::GS_BASE, teb_address)
                    .map_err(|e| EmulatorError::UnicornError(format!("GS_BASE write failed: {:?}", e)))?;

                if let Ok(region) = platform.query_memory_region(pid, teb_address) {
                    let size = Self::align_size(region.region_size);
                    let prot = Self::windows_protect_to_unicorn(region.protect);

                    if emu.mem_map(region.base_address, size, prot).is_ok() {
                        tracing::trace!(
                            "Unicorn mem_map (TEB): base=0x{:X} size=0x{:X} prot={}",
                            region.base_address, size, Self::prot_to_str(prot)
                        );
                        if region.state == MEM_COMMIT {
                            if let Ok(data) = platform.read_memory(pid, region.base_address, region.region_size as usize) {
                                let _ = emu.mem_write(region.base_address, &data);
                                tracing::debug!("Pre-loaded TEB region: 0x{:016X} - 0x{:016X} ({} bytes)",
                                    region.base_address, region.base_address + region.region_size, region.region_size);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Could not get TEB address: {}. GS segment access will fail.", e);
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
    pub(super) fn try_pac_fetch_recovery<P: PlatformAPI>(
        &mut self,
        platform: &P,
        fault_addr: u64,
        is_fetch: bool,
    ) -> bool {
        let stripped = fault_addr & MAX_USER_ADDRESS;
        if !is_fetch || self.architecture != Architecture::Arm64 || stripped == fault_addr {
            return false;
        }
        if self.load_memory_region(platform, stripped).is_err() || self.set_pc(stripped).is_err() {
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
        let state = self.shared_state.read().unwrap();
        let pages_loaded = state.mapped_regions.len() - pages_before;

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
        })
    }
}

#[cfg(test)]
mod tests;
