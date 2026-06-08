use super::error::InlineHookError;

/// Trait for allocating executable memory near a target address.
pub trait CodeAllocator {
    /// Allocate at least `size` bytes of RWX memory within ±2GB of `near_addr`.
    fn alloc_near(&mut self, near_addr: usize, size: usize) -> Result<*mut u8, InlineHookError>;
    /// Free a previously allocated block.
    fn free(&mut self, ptr: *mut u8);
}

// --- Windows implementation ---

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        VirtualAlloc, VirtualFree, VirtualQuery, MEMORY_BASIC_INFORMATION,
    };

    const PAGE_SIZE: usize = 4096;
    const DEFAULT_SLOT_SIZE: usize = 64;
    /// Maximum distance for a 32-bit relative jump (slightly under 2GB to be safe).
    const MAX_RANGE: usize = 0x7FFF_0000;

    struct PageInfo {
        base: *mut u8,
        slots: Vec<bool>, // true = occupied
    }

    pub struct WindowsCodeAllocator {
        pages: Vec<PageInfo>,
        slot_size: usize,
    }

    // SAFETY: The raw pointers in PageInfo point to VirtualAlloc'd memory that is
    // process-global and not tied to any specific thread.
    unsafe impl Send for WindowsCodeAllocator {}

    impl WindowsCodeAllocator {
        pub fn new() -> Self {
            Self { pages: Vec::new(), slot_size: DEFAULT_SLOT_SIZE }
        }

        /// Create an allocator with a custom slot size.
        pub fn with_slot_size(slot_size: usize) -> Self {
            assert!(slot_size > 0 && slot_size <= PAGE_SIZE);
            Self { pages: Vec::new(), slot_size }
        }

        fn slots_per_page(&self) -> usize {
            PAGE_SIZE / self.slot_size
        }

        /// Find or allocate a page within ±2GB of `near_addr`, return a free slot.
        fn find_or_alloc_slot(&mut self, near_addr: usize) -> Result<*mut u8, InlineHookError> {
            let lo = near_addr.saturating_sub(MAX_RANGE);
            let hi = near_addr.saturating_add(MAX_RANGE);

            // Try existing pages first.
            for page in &mut self.pages {
                let base = page.base as usize;
                if base >= lo && base <= hi {
                    if let Some(idx) = page.slots.iter().position(|&occupied| !occupied) {
                        page.slots[idx] = true;
                        return Ok(unsafe { page.base.add(idx * self.slot_size) });
                    }
                }
            }

            // Allocate a new page near the target.
            let base = self.alloc_page_near(near_addr, lo, hi)?;
            let mut slots = vec![false; self.slots_per_page()];
            slots[0] = true;
            self.pages.push(PageInfo { base, slots });
            Ok(base)
        }

        fn alloc_page_near(
            &self,
            near_addr: usize,
            lo: usize,
            hi: usize,
        ) -> Result<*mut u8, InlineHookError> {
            // Search outward from near_addr in both directions using VirtualQuery
            // to find a MEM_FREE region, then VirtualAlloc at that address.
            let granularity: usize = 0x10000; // 64KB allocation granularity

            // Align starting point down to granularity.
            let start = near_addr & !(granularity - 1);

            let mut offset: usize = 0;
            loop {
                // Try below
                if let Some(addr) = start.checked_sub(offset) {
                    if addr >= lo {
                        if let Some(base) = self.try_alloc_at(addr)? {
                            return Ok(base);
                        }
                    }
                }

                // Try above
                if let Some(addr) = start.checked_add(offset) {
                    if addr <= hi {
                        if let Some(base) = self.try_alloc_at(addr)? {
                            return Ok(base);
                        }
                    }
                }

                offset += granularity;

                // Both directions out of range.
                let below_out = start.checked_sub(offset).is_none_or(|a| a < lo);
                let above_out = start.checked_add(offset).is_none_or(|a| a > hi);
                if below_out && above_out {
                    break;
                }
            }

            Err(InlineHookError::AllocationFailed(format!(
                "no free memory within ±2GB of 0x{near_addr:X}"
            )))
        }

        /// Try to VirtualAlloc a page at `addr`. Returns Ok(Some(ptr)) on success,
        /// Ok(None) if the region is not free, Err on unexpected failure.
        fn try_alloc_at(&self, addr: usize) -> Result<Option<*mut u8>, InlineHookError> {
            unsafe {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let ret = VirtualQuery(
                    addr as *const _,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if ret == 0 {
                    return Ok(None); // Can't query — skip this address.
                }
                if mbi.State != MEM_FREE {
                    return Ok(None);
                }
                // Region is free; try to allocate.
                let ptr = VirtualAlloc(
                    addr as *const _,
                    PAGE_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if ptr.is_null() {
                    return Ok(None); // Allocation failed (race or alignment) — try next.
                }
                Ok(Some(ptr as *mut u8))
            }
        }

        fn free_slot(&mut self, ptr: *mut u8) {
            let addr = ptr as usize;
            for page in &mut self.pages {
                let base = page.base as usize;
                if addr >= base && addr < base + PAGE_SIZE {
                    let idx = (addr - base) / self.slot_size;
                    if idx < page.slots.len() {
                        page.slots[idx] = false;
                    }
                    // If all slots free, release the page.
                    if page.slots.iter().all(|&occ| !occ) {
                        unsafe {
                            VirtualFree(page.base as *mut _, 0, MEM_RELEASE);
                        }
                        page.base = std::ptr::null_mut();
                    }
                    return;
                }
            }
        }
    }

    impl Drop for WindowsCodeAllocator {
        fn drop(&mut self) {
            for page in &self.pages {
                if !page.base.is_null() {
                    unsafe {
                        VirtualFree(page.base as *mut _, 0, MEM_RELEASE);
                    }
                }
            }
        }
    }

    impl CodeAllocator for WindowsCodeAllocator {
        fn alloc_near(&mut self, near_addr: usize, _size: usize) -> Result<*mut u8, InlineHookError> {
            self.find_or_alloc_slot(near_addr)
        }

        fn free(&mut self, ptr: *mut u8) {
            self.free_slot(ptr);
        }
    }
}

#[cfg(windows)]
pub use windows_impl::WindowsCodeAllocator;
