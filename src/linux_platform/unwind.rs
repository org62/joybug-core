//! Call stacks: DWARF CFI (`.eh_frame`) with a frame-pointer fallback.

use std::collections::HashMap;

use crate::protocol::ModuleInfo;

use super::memory::ProcessMemory;

#[derive(Debug, Clone, Copy)]
pub struct Frame {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
}

pub const MAX_FRAMES: usize = 100;

/// Per-module unwind tables, cached by path.
#[derive(Default)]
pub struct Unwinder {
    tables: HashMap<String, Option<super::unwind_cfi::ModuleUnwind>>,
}

impl Unwinder {
    fn table(&mut self, module: &ModuleInfo) -> Option<&super::unwind_cfi::ModuleUnwind> {
        if !self.tables.contains_key(&module.name) {
            let t = super::unwind_cfi::ModuleUnwind::load(module);
            self.tables.insert(module.name.clone(), t);
        }
        self.tables.get(&module.name).and_then(|t| t.as_ref())
    }

    /// `[start, end)` of the function containing `address`, from the FDEs.
    pub fn function_range(&mut self, module: &ModuleInfo, address: u64) -> Option<(u64, u64)> {
        self.table(module)?.function_range(address)
    }

    /// At most `max_frames` frames, innermost first.
    pub fn unwind(&mut self, regs: &libc::user_regs_struct, modules: &[ModuleInfo], mem: &ProcessMemory, max_frames: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut state = super::unwind_cfi::Registers::from_regs(regs);
        let read = |addr: u64| mem.try_read_pointer(addr);
        let mut ctx = gimli::UnwindContext::new();
        for depth in 0..max_frames.min(MAX_FRAMES) {
            let pc = state.pc;
            if pc == 0 {
                break;
            }
            frames.push(Frame { pc, sp: state.sp, fp: state.fp });
            // Frames above the innermost are return addresses: look up the
            // call site, one byte before.
            let lookup = if depth == 0 { pc } else { pc.wrapping_sub(1) };
            let module = modules.iter().find(|m| lookup >= m.base && lookup < m.base + m.size.unwrap_or(0));
            let next = module
                .and_then(|m| self.table(m).and_then(|t| t.step(&state, lookup, &mut ctx, &read)))
                .or_else(|| super::unwind_cfi::step_frame_pointer(&state, &read));
            match next {
                Some(next) if next.sp > state.sp || (next.sp == state.sp && next.pc != state.pc) => state = next,
                _ => break,
            }
        }
        frames
    }
}
