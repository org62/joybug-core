//! Process-less emulation: run code from a PE file laid out at its load base,
//! with a synthetic stack, a zero TEB page and every IAT slot pointed at a
//! stub the emulator recognises as "a call to this import".

use std::collections::HashMap;

use unicorn_engine::unicorn_const::Prot;

use crate::emulator::{EmuRegion, EmuTarget, Emulator, EmulatorError, EmulationResult, FetchIntercept, ImportPolicy, ModuleBoundary};
use crate::interfaces::{Architecture, Instruction};
use crate::protocol::{EmulationMode, TraceExitCondition};

use super::mapped::PAGE_SIZE;
use super::PeImage;

/// The synthetic address space a run gets, so a script can place its inputs
/// (`mem_writes` into the stack, registers pointing at them) before the run.
/// All of it sits high in user space, well away from any sane image base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct EmuLayout {
    pub stack_base: u64,
    pub stack_top: u64,
    /// Default initial stack pointer (the return sentinel sits at `[sp]`).
    pub sp: u64,
    pub teb: u64,
    pub sentinel: u64,
    pub stub_base: u64,
}

/// The layout for `arch` with a `stack_size`-byte stack.
pub fn emu_layout(arch: Architecture, stack_size: u64) -> EmuLayout {
    let (stack_top, teb, sentinel, stub_base) = match arch {
        Architecture::X86 => (0x7E00_0000, 0x7EF0_0000, 0x7EFF_F000, 0x7F00_0000),
        Architecture::X64 | Architecture::Arm64 => (0x7FFF_E000_0000, 0x7FFF_D000_0000, 0x7FFF_EFFF_F000, 0x7FFF_F000_0000),
    };
    let stack_size = Emulator::align_size(stack_size.max(PAGE_SIZE));
    EmuLayout {
        stack_base: stack_top - stack_size,
        stack_top,
        // 256 bytes below the top: room for a home area / red zone.
        sp: (stack_top - 0x100) & !0xF,
        teb,
        sentinel,
        stub_base,
    }
}

/// Bytes between consecutive import stubs.
const STUB_STRIDE: u64 = 16;
/// Address space reserved for import stubs (65536 imports).
const STUB_AREA: u64 = 0x100_0000;
pub const DEFAULT_STACK_SIZE: u64 = 1024 * 1024;
pub const DEFAULT_MAX_INSTRUCTIONS: usize = 10_000;

/// Everything that parametrises one process-less run.
#[derive(Debug, Clone)]
pub struct EmulateSpec {
    /// Where execution starts.
    pub va: u64,
    pub max_instructions: usize,
    pub mode: EmulationMode,
    /// Stop when this address is about to execute.
    pub exit: Option<u64>,
    /// Initial registers by name; the stack pointer defaults to the top of the
    /// synthetic stack (and `lr` to the return sentinel on ARM64), everything
    /// else to zero.
    pub registers: Vec<(String, u64)>,
    pub stack_size: u64,
    pub import_policy: ImportPolicy,
    /// `(address, size)` ranges to read back from emulator memory afterwards.
    pub memory_reads: Vec<(u64, usize)>,
    /// Bytes to plant before the run (in the image or the synthetic stack).
    pub memory_writes: Vec<(u64, Vec<u8>)>,
}

impl EmulateSpec {
    pub fn at(va: u64) -> Self {
        Self {
            va,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            mode: EmulationMode::Basic,
            exit: None,
            registers: Vec::new(),
            stack_size: DEFAULT_STACK_SIZE,
            import_policy: ImportPolicy::Stop,
            memory_reads: Vec::new(),
            memory_writes: Vec::new(),
        }
    }
}

/// A PE file as an emulation target.
///
/// The mapped image is shared, not copied: pages the run modifies before it
/// starts (IAT slots redirected to stubs, user `memory_writes`) live in a
/// copy-on-write overlay keyed by page address, and the synthetic stack is an
/// all-zero region that only materialises pages the same way. The emulator
/// pulls one page at a time, so a run touches a handful of pages of a
/// multi-megabyte image and never duplicates the rest.
pub struct StaticTarget<'a> {
    image: &'a PeImage,
    layout: EmuLayout,
    /// Page address -> the page's contents, for image/stack pages written
    /// before the run.
    overlay: HashMap<u64, Box<[u8]>>,
    /// `stubs[i]` is the import behind `stub_base + i * STUB_STRIDE`.
    stubs: Vec<String>,
}

impl<'a> StaticTarget<'a> {
    /// Build the target for `spec` with the run's initial stack pointer `sp`
    /// (the return sentinel is planted at `[sp]` on x86/x64).
    fn new(image: &'a PeImage, spec: &EmulateSpec, sp: u64) -> Result<Self, EmulatorError> {
        let arch = image.arch();
        let mapped = image.mapped();
        let layout = emu_layout(arch, spec.stack_size);

        let overlaps = |lo: u64, hi: u64| mapped.base < hi && lo < mapped.end();
        if overlaps(layout.stack_base, layout.stack_top)
            || overlaps(layout.teb, layout.teb + PAGE_SIZE)
            || overlaps(layout.stub_base, layout.stub_base + STUB_AREA)
        {
            return Err(EmulatorError::PlatformError(format!(
                "image at 0x{:X}-0x{:X} overlaps the synthetic stack/TEB/import area; open it at a different base",
                mapped.base, mapped.end()
            )));
        }

        let mut this = Self { image, layout, overlay: HashMap::new(), stubs: Vec::new() };

        let ptr = arch.pointer_size();
        for imp in image.imports() {
            let stub = layout.stub_base + this.stubs.len() as u64 * STUB_STRIDE;
            if this.write(imp.iat_va, &stub.to_le_bytes()[..ptr]).is_ok() {
                this.stubs.push(imp.qualified_name());
            }
        }

        if arch.is_x86_family() {
            let sentinel = layout.sentinel.to_le_bytes();
            if this.write(sp, &sentinel[..ptr]).is_err() {
                tracing::debug!("initial sp 0x{:X} is outside the synthetic stack; no return sentinel planted", sp);
            }
        }

        for (addr, data) in &spec.memory_writes {
            this.write(*addr, data).map_err(|_| EmulatorError::PlatformError(format!(
                "memory write at 0x{:X} ({} bytes) is outside the image and the synthetic stack", addr, data.len()
            )))?;
        }
        Ok(this)
    }

    fn in_image(&self, addr: u64) -> bool {
        self.image.mapped().contains(addr)
    }

    fn in_stack(&self, addr: u64) -> bool {
        addr >= self.layout.stack_base && addr < self.layout.stack_top
    }

    /// The pristine contents of the page at `page` (image bytes, or zeros for
    /// the stack), or `None` when the target has nothing there.
    fn base_page(&self, page: u64) -> Option<Box<[u8]>> {
        if self.in_image(page) {
            let mapped = self.image.mapped();
            let off = (page - mapped.base) as usize;
            let end = (off + PAGE_SIZE as usize).min(mapped.bytes.len());
            let mut out = vec![0u8; PAGE_SIZE as usize];
            out[..end - off].copy_from_slice(&mapped.bytes[off..end]);
            Some(out.into_boxed_slice())
        } else if self.in_stack(page) {
            Some(vec![0u8; PAGE_SIZE as usize].into_boxed_slice())
        } else {
            None
        }
    }

    /// Plant bytes into the image or the stack before the run: each touched
    /// page is copied into the overlay once, then patched.
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), ()> {
        let end = addr.checked_add(data.len() as u64).ok_or(())?;
        let mut cur = addr;
        while cur < end {
            let page = cur & !(PAGE_SIZE - 1);
            if !self.overlay.contains_key(&page) {
                let fresh = self.base_page(page).ok_or(())?;
                self.overlay.insert(page, fresh);
            }
            let off = (cur - page) as usize;
            let n = ((page + PAGE_SIZE) - cur).min(end - cur) as usize;
            let src = (cur - addr) as usize;
            self.overlay.get_mut(&page).unwrap()[off..off + n].copy_from_slice(&data[src..src + n]);
            cur += n as u64;
        }
        Ok(())
    }

    fn page_region(&self, addr: u64, prot: Prot, committed: bool) -> EmuRegion {
        EmuRegion { base: addr & !(PAGE_SIZE - 1), size: PAGE_SIZE, prot, committed }
    }
}

impl EmuTarget for StaticTarget<'_> {
    fn arch(&self) -> Architecture {
        self.image.arch()
    }

    fn modules(&self) -> Vec<ModuleBoundary> {
        let mapped = self.image.mapped();
        vec![ModuleBoundary { name: self.image.module_name().to_string(), base: mapped.base, end: mapped.end() }]
    }

    fn region(&self, addr: u64) -> Option<EmuRegion> {
        if let Some(region) = self.image.mapped().region_at(addr) {
            return Some(self.page_region(addr, region.prot, true));
        }
        if self.in_stack(addr) {
            return Some(self.page_region(addr, Prot::READ | Prot::WRITE, true));
        }
        if addr >= self.layout.teb && addr < self.layout.teb + PAGE_SIZE {
            return Some(self.page_region(addr, Prot::READ | Prot::WRITE, false));
        }
        None
    }

    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let end = addr.checked_add(len as u64)?;
        let mut out = Vec::with_capacity(len);
        let mut cur = addr;
        while cur < end {
            let page = cur & !(PAGE_SIZE - 1);
            let off = (cur - page) as usize;
            let n = ((page + PAGE_SIZE) - cur).min(end - cur) as usize;
            match self.overlay.get(&page) {
                Some(p) => out.extend_from_slice(&p[off..off + n]),
                None => out.extend_from_slice(&self.base_page(page)?[off..off + n]),
            }
            cur += n as u64;
        }
        Some(out)
    }

    fn teb_address(&self) -> Option<u64> {
        Some(self.layout.teb)
    }

    fn symbolize(&self, addr: u64) -> Option<String> {
        self.image.resolve_va(addr).map(|s| crate::emulator::format_symbol_with_offset(&s.symbol_name, s.offset))
    }

    fn disassemble_one(&self, addr: u64) -> Option<Instruction> {
        self.image.disassemble(addr, 1).ok()?.into_iter().next()
    }

    fn intercept_fetch(&self, addr: u64) -> Option<FetchIntercept> {
        if addr == self.layout.sentinel {
            return Some(FetchIntercept::ReturnSentinel);
        }
        let idx = addr.checked_sub(self.layout.stub_base)? / STUB_STRIDE;
        self.stubs.get(idx as usize).map(|name| FetchIntercept::Import(name.clone()))
    }
}

/// Run `spec` against `image` with no process behind it.
pub fn emulate(image: &PeImage, spec: &EmulateSpec) -> Result<EmulationResult, EmulatorError> {
    let mapped = image.mapped();
    if mapped.region_at(spec.va).is_none() {
        return Err(EmulatorError::PlatformError(format!(
            "start address 0x{:X} is outside the image (0x{:X}-0x{:X})",
            spec.va, mapped.base, mapped.end()
        )));
    }
    let arch = image.arch();
    let layout = emu_layout(arch, spec.stack_size);

    // The caller's registers win; the stack pointer (and `lr` on ARM64, so a
    // routine emulated from its entry returns to the sentinel) get defaults.
    let mut regs = spec.registers.clone();
    let given = |regs: &[(String, u64)], names: &[&str]| {
        regs.iter().find(|(n, _)| names.iter().any(|w| n.eq_ignore_ascii_case(w))).map(|(_, v)| *v)
    };
    let sp = match given(&regs, &["esp", "rsp", "sp"]) {
        Some(sp) => sp,
        None => {
            let sp_name = match arch { Architecture::X86 => "esp", Architecture::X64 => "rsp", Architecture::Arm64 => "sp" };
            regs.push((sp_name.to_string(), layout.sp));
            layout.sp
        }
    };
    if arch == Architecture::Arm64 && given(&regs, &["lr", "x30"]).is_none() {
        regs.push(("lr".to_string(), layout.sentinel));
    }

    let target = StaticTarget::new(image, spec, sp)?;
    let mut emu = Emulator::with_registers(&target, spec.va, &regs)?;
    emu.set_import_policy(spec.import_policy);
    emu.emulate_with_mode(
        &target,
        spec.max_instructions,
        spec.mode,
        spec.exit.map(TraceExitCondition::ReachAddress),
        &spec.memory_reads,
    )
}
