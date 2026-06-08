//! Memory loading and protection helpers

use unicorn_engine::unicorn_const::Prot;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

use crate::interfaces::PlatformAPI;

use super::Emulator;
use super::types::MappedRegion;
use super::error::EmulatorError;

impl<'a> Emulator<'a> {
    /// Load a single 4KB page from debugger on demand
    ///
    /// Maps only the page containing the faulting address with 0x1000 granularity.
    pub fn load_memory_region<P: PlatformAPI>(
        &mut self,
        platform: &P,
        address: u64,
    ) -> Result<(), EmulatorError> {
        const PAGE_SIZE: u64 = 0x1000;

        // Align address down to page boundary
        let page_base = address & !(PAGE_SIZE - 1);

        // Check if page is already mapped
        {
            let state = self.shared_state.read().unwrap();
            if state.mapped_regions.contains_key(&page_base) {
                return Ok(());
            }
        }

        // Query the region to get permissions and state
        let region = platform.query_memory_region(self.pid, address)
            .map_err(|e| {
                tracing::warn!("query_memory_region failed for 0x{:X}: {}", address, e);
                EmulatorError::PlatformError(e.to_string())
            })?;

        // Can't map free memory
        if region.state == MEM_FREE {
            return Err(EmulatorError::PlatformError("cannot map free memory".into()));
        }

        let prot = Self::windows_protect_to_unicorn(region.protect);

        // Map the single page
        self.emu.mem_map(page_base, PAGE_SIZE, prot)
            .map_err(|e| {
                tracing::warn!("mem_map failed for page 0x{:X}: {:?}", page_base, e);
                EmulatorError::UnicornError(format!("mem_map failed: {:?}", e))
            })?;

        tracing::trace!(
            "Unicorn mem_map: base=0x{:X} size=0x{:X} prot={} state={}",
            page_base, PAGE_SIZE, Self::prot_to_str(prot), Self::state_to_str(region.state)
        );

        // Read and write page content if committed
        if region.state == MEM_COMMIT {
            match platform.read_memory(self.pid, page_base, PAGE_SIZE as usize) {
                Ok(data) => {
                    if let Err(e) = self.emu.mem_write(page_base, &data) {
                        tracing::warn!("mem_write failed for page 0x{:X}: {:?}", page_base, e);
                    }
                }
                Err(_) => {
                    tracing::warn!("Failed to read memory for page 0x{:X}, leaving as zeros", page_base);
                }
            }
        } else {
            tracing::warn!(
                "Page 0x{:X} not committed (state={}), leaving as zeros",
                page_base,
                Self::state_to_str(region.state)
            );
        }

        // Track the mapped page
        {
            let mut state = self.shared_state.write().unwrap();
            state.mapped_regions.insert(page_base, MappedRegion {
                base: page_base,
                size: PAGE_SIZE,
            });
        }

        Ok(())
    }

    pub(super) fn windows_protect_to_unicorn(protect: u32) -> Prot {
        let mut prot = Prot::NONE;

        if protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
            prot |= Prot::EXEC;
        }

        if protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
            prot |= Prot::READ;
        }

        if protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
            prot |= Prot::WRITE;
        }

        if prot == Prot::NONE {
            prot = Prot::READ;
        }

        prot
    }

    pub(super) fn prot_to_str(prot: Prot) -> &'static str {
        let r = (prot & Prot::READ) != Prot::NONE;
        let w = (prot & Prot::WRITE) != Prot::NONE;
        let x = (prot & Prot::EXEC) != Prot::NONE;
        match (r, w, x) {
            (true, true, true) => "RWX",
            (true, true, false) => "RW",
            (true, false, true) => "RX",
            (true, false, false) => "R",
            (false, true, true) => "WX",
            (false, true, false) => "W",
            (false, false, true) => "X",
            (false, false, false) => "NONE",
        }
    }

    pub(super) fn state_to_str(state: u32) -> &'static str {
        match state {
            MEM_COMMIT => "MEM_COMMIT",
            MEM_FREE => "MEM_FREE",
            MEM_RESERVE => "MEM_RESERVE",
            _ => "UNKNOWN",
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn align_size(size: u64) -> u64 {
        const PAGE_SIZE: u64 = 0x1000;
        (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }
}
