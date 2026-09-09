//! What the emulator runs against.
//!
//! The emulator never talks to a process directly: everything it needs — the
//! instruction set, the module map, page contents and protections, the TEB, a
//! symbol for a stop-reason label — comes through [`EmuTarget`]. Two targets
//! exist: [`LiveTarget`], a paused thread of a debuggee reached through
//! `PlatformAPI` (the original behaviour), and `static_pe::StaticTarget`, a PE
//! file laid out at its load base with no process at all.

use unicorn_engine::unicorn_const::Prot;

use crate::interfaces::{Architecture, Instruction, PlatformAPI};
use crate::protocol::ThreadContext;

use super::types::ModuleBoundary;

/// One mappable span of the target's address space.
#[derive(Debug, Clone)]
pub struct EmuRegion {
    pub base: u64,
    pub size: u64,
    pub prot: Prot,
    /// Whether the span has contents to copy in. A reserved-but-uncommitted
    /// range maps as zeros.
    pub committed: bool,
}

/// What an unmapped instruction fetch at an address means to the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchIntercept {
    /// The address is a stand-in for an import (`"kernel32!WriteFile"`): the
    /// emulated code just called through its IAT.
    Import(String),
    /// The address is the sentinel return address the target planted under
    /// the initial stack pointer: the emulated routine returned to its caller.
    ReturnSentinel,
}

/// Memory, modules and metadata the emulator pulls on demand.
pub trait EmuTarget {
    fn arch(&self) -> Architecture;

    /// Loaded modules, for module-transition detection.
    fn modules(&self) -> Vec<ModuleBoundary>;

    /// The region containing `addr`, or `None` when nothing is mapped there.
    fn region(&self, addr: u64) -> Option<EmuRegion>;

    /// `len` bytes at `addr`, or `None` when they cannot be read.
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>>;

    /// The thread's TEB, which becomes the `fs`/`gs` segment base.
    fn teb_address(&self) -> Option<u64>;

    /// `symbol` or `symbol+0xNN` for `addr`, used in stop-reason labels.
    fn symbolize(&self, addr: u64) -> Option<String>;

    /// The instruction at `addr`, for exception diagnostics only.
    fn disassemble_one(&self, addr: u64) -> Option<Instruction>;

    /// Whether an unmapped fetch at `addr` is one of the target's synthetic
    /// addresses rather than a genuine fault.
    fn intercept_fetch(&self, _addr: u64) -> Option<FetchIntercept> {
        None
    }
}

/// A paused thread of a live debuggee. Captures the thread context once at
/// construction so the architecture and initial registers are consistent.
pub struct LiveTarget<'p, P: PlatformAPI + ?Sized> {
    platform: &'p P,
    pid: u32,
    tid: u32,
    /// The initial register file, for `Emulator::from_context`.
    pub context: ThreadContext,
}

impl<'p, P: PlatformAPI + ?Sized> LiveTarget<'p, P> {
    pub fn new(platform: &'p P, pid: u32, tid: u32) -> Result<Self, super::EmulatorError> {
        let context = platform
            .get_thread_context(pid, tid)
            .map_err(|e| super::EmulatorError::PlatformError(e.to_string()))?;
        Ok(Self { platform, pid, tid, context })
    }
}

impl<P: PlatformAPI + ?Sized> EmuTarget for LiveTarget<'_, P> {
    fn arch(&self) -> Architecture {
        self.context.architecture()
    }

    fn modules(&self) -> Vec<ModuleBoundary> {
        self.platform
            .list_modules(self.pid)
            .map(|mods| {
                mods.iter()
                    .map(|m| ModuleBoundary {
                        name: m.name.clone(),
                        base: m.base,
                        end: m.base + m.size.unwrap_or(0x1000),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn region(&self, addr: u64) -> Option<EmuRegion> {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_FREE};
        let r = self
            .platform
            .query_memory_region(self.pid, addr)
            .map_err(|e| tracing::warn!("query_memory_region failed for 0x{:X}: {}", addr, e))
            .ok()?;
        if r.state == MEM_FREE {
            return None;
        }
        Some(EmuRegion {
            base: r.base_address,
            size: r.region_size,
            prot: super::Emulator::windows_protect_to_unicorn(r.protect),
            committed: r.state == MEM_COMMIT,
        })
    }

    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        self.platform.read_memory(self.pid, addr, len).ok()
    }

    fn teb_address(&self) -> Option<u64> {
        match self.platform.get_teb_address(self.pid, self.tid) {
            Ok(teb) => Some(teb),
            Err(e) => {
                tracing::warn!("Could not get TEB address: {}. Segment access will fail.", e);
                None
            }
        }
    }

    fn symbolize(&self, addr: u64) -> Option<String> {
        self.platform
            .resolve_address_to_symbol(self.pid, addr)
            .ok()
            .flatten()
            .map(|(_, sym, offset)| super::types::format_symbol_with_offset(&sym.name, offset))
    }

    fn disassemble_one(&self, addr: u64) -> Option<Instruction> {
        self.platform
            .disassemble_memory(self.pid, addr, 1, self.arch())
            .ok()?
            .into_iter()
            .next()
    }
}
