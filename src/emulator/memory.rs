//! Memory loading and protection helpers

use unicorn_engine::unicorn_const::Prot;

use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

use super::Emulator;
use super::target::EmuTarget;
use super::error::EmulatorError;

impl<'a> Emulator<'a> {
    /// Load a single 4KB page from the target on demand
    ///
    /// Maps only the page containing the faulting address with 0x1000 granularity.
    pub fn load_memory_region<T: EmuTarget>(
        &mut self,
        target: &T,
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

        // Query the region to get permissions and state; nothing there = free memory.
        let region = target.region(address)
            .ok_or_else(|| EmulatorError::PlatformError(format!("cannot map free memory at 0x{:X}", address)))?;

        // Map the single page
        self.emu.mem_map(page_base, PAGE_SIZE, region.prot)
            .map_err(|e| {
                tracing::warn!("mem_map failed for page 0x{:X}: {:?}", page_base, e);
                EmulatorError::UnicornError(format!("mem_map failed: {:?}", e))
            })?;

        tracing::trace!(
            "Unicorn mem_map: base=0x{:X} size=0x{:X} prot={} committed={}",
            page_base, PAGE_SIZE, Self::prot_to_str(region.prot), region.committed
        );

        // Read and write page content if committed
        if region.committed {
            match target.read(page_base, PAGE_SIZE as usize) {
                Some(data) => {
                    if let Err(e) = self.emu.mem_write(page_base, &data) {
                        tracing::warn!("mem_write failed for page 0x{:X}: {:?}", page_base, e);
                    }
                }
                None => {
                    tracing::warn!("Failed to read memory for page 0x{:X}, leaving as zeros", page_base);
                }
            }
        } else {
            tracing::warn!("Page 0x{:X} not committed, leaving as zeros", page_base);
        }

        // Track the mapped page
        self.shared_state.write().unwrap().note_mapped(page_base, PAGE_SIZE);

        Ok(())
    }

    pub(crate) fn windows_protect_to_unicorn(protect: u32) -> Prot {
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

    pub(crate) fn align_size(size: u64) -> u64 {
        const PAGE_SIZE: u64 = 0x1000;
        (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }
}
