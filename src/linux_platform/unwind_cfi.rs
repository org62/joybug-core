//! `.eh_frame` interpretation with gimli, and the frame-pointer fallback.

use std::borrow::Cow;

use gimli::{BaseAddresses, CfaRule, EhFrame, EhFrameHdr, EndianSlice, LittleEndian, RegisterRule, UnwindContext, UnwindSection, X86_64};
use object::{Object, ObjectSection};

use crate::protocol::ModuleInfo;

/// The registers CFI needs: the callee-saved set plus pc/sp.
#[derive(Debug, Clone, Copy)]
pub struct Registers {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl Registers {
    pub fn from_regs(r: &libc::user_regs_struct) -> Self {
        Self { pc: r.rip, sp: r.rsp, fp: r.rbp, rbx: r.rbx, r12: r.r12, r13: r.r13, r14: r.r14, r15: r.r15 }
    }

    fn get(&self, reg: gimli::Register) -> Option<u64> {
        Some(match reg {
            X86_64::RA => self.pc,
            X86_64::RSP => self.sp,
            X86_64::RBP => self.fp,
            X86_64::RBX => self.rbx,
            X86_64::R12 => self.r12,
            X86_64::R13 => self.r13,
            X86_64::R14 => self.r14,
            X86_64::R15 => self.r15,
            _ => return None,
        })
    }

    fn set(&mut self, reg: gimli::Register, value: u64) {
        match reg {
            X86_64::RA => self.pc = value,
            X86_64::RSP => self.sp = value,
            X86_64::RBP => self.fp = value,
            X86_64::RBX => self.rbx = value,
            X86_64::R12 => self.r12 = value,
            X86_64::R13 => self.r13 = value,
            X86_64::R14 => self.r14 = value,
            X86_64::R15 => self.r15 = value,
            _ => {}
        }
    }
}

/// The classic `[rbp] -> saved rbp, [rbp+8] -> return address` walk.
pub fn step_frame_pointer(state: &Registers, read: &dyn Fn(u64) -> Option<u64>) -> Option<Registers> {
    if state.fp == 0 || state.fp < state.sp {
        return None;
    }
    let saved_fp = read(state.fp)?;
    let ra = read(state.fp + 8)?;
    if ra == 0 {
        return None;
    }
    let mut next = *state;
    next.pc = ra;
    next.sp = state.fp + 16;
    next.fp = saved_fp;
    Some(next)
}

/// One module's `.eh_frame` (and header), owning the section bytes.
pub struct ModuleUnwind {
    eh_frame: Vec<u8>,
    eh_frame_hdr: Option<Vec<u8>>,
    bases: BaseAddresses,
}

impl ModuleUnwind {
    /// Read the unwind sections of the module's file; `None` when it has
    /// none (or cannot be read).
    pub fn load(module: &ModuleInfo) -> Option<Self> {
        if module.name.starts_with('[') {
            return None;
        }
        let data = std::fs::read(&module.name).ok()?;
        let layout = crate::elf::layout::layout_from_bytes(&data).ok()?;
        let file = object::File::parse(&*data).ok()?;
        let load_bias = module.base.wrapping_sub(layout.min_vaddr);
        let eh = file.section_by_name(".eh_frame")?;
        let eh_frame: Vec<u8> = match eh.uncompressed_data().ok()? {
            Cow::Borrowed(b) => b.to_vec(),
            Cow::Owned(v) => v,
        };
        let mut bases = BaseAddresses::default().set_eh_frame(eh.address().wrapping_add(load_bias));
        if let Some(text) = file.section_by_name(".text") {
            bases = bases.set_text(text.address().wrapping_add(load_bias));
        }
        let eh_frame_hdr = file.section_by_name(".eh_frame_hdr").and_then(|s| {
            bases = bases.clone().set_eh_frame_hdr(s.address().wrapping_add(load_bias));
            s.uncompressed_data().ok().map(|c| c.into_owned())
        });
        Some(Self { eh_frame, eh_frame_hdr, bases })
    }

    fn section(&self) -> EhFrame<EndianSlice<'_, LittleEndian>> {
        EhFrame::new(&self.eh_frame, LittleEndian)
    }

    /// The FDE covering the (runtime) `address`.
    fn fde(&self, address: u64) -> Option<gimli::FrameDescriptionEntry<EndianSlice<'_, LittleEndian>>> {
        let eh = self.section();
        if let Some(hdr) = &self.eh_frame_hdr {
            let hdr = EhFrameHdr::new(hdr, LittleEndian).parse(&self.bases, 8).ok()?;
            if let Some(table) = hdr.table() {
                return table.fde_for_address(&eh, &self.bases, address, |s, b, o| s.cie_from_offset(b, o)).ok();
            }
        }
        eh.fde_for_address(&self.bases, address, |s, b, o| s.cie_from_offset(b, o)).ok()
    }

    pub fn function_range(&self, address: u64) -> Option<(u64, u64)> {
        let fde = self.fde(address)?;
        Some((fde.initial_address(), fde.initial_address() + fde.len()))
    }

    /// One frame up, per the CFI at `lookup`.
    pub fn step(
        &self,
        state: &Registers,
        lookup: u64,
        ctx: &mut UnwindContext<usize>,
        read: &dyn Fn(u64) -> Option<u64>,
    ) -> Option<Registers> {
        let eh = self.section();
        let fde = self.fde(lookup)?;
        let row = fde.unwind_info_for_address(&eh, &self.bases, ctx, lookup).ok()?;
        let cfa = match row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => state.get(*register)?.wrapping_add(*offset as u64),
            CfaRule::Expression(_) => return None,
        };
        let mut next = *state;
        let mut ra_rule_seen = false;
        for (reg, rule) in row.registers() {
            let value = match rule {
                RegisterRule::Undefined => {
                    if *reg == X86_64::RA {
                        return None; // outermost frame
                    }
                    continue;
                }
                RegisterRule::SameValue => continue,
                RegisterRule::Offset(off) => read(cfa.wrapping_add(*off as u64))?,
                RegisterRule::ValOffset(off) => cfa.wrapping_add(*off as u64),
                RegisterRule::Register(r) => state.get(*r)?,
                _ => continue,
            };
            if *reg == X86_64::RA {
                ra_rule_seen = true;
            }
            next.set(*reg, value);
        }
        if !ra_rule_seen {
            // The default x86-64 rule: the return address is at CFA-8.
            next.pc = read(cfa.wrapping_sub(8))?;
        }
        next.sp = cfa;
        if next.pc == 0 {
            return None;
        }
        Some(next)
    }
}
