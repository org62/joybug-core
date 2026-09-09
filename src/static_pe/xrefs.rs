//! Cross-references and function-start recovery over a mapped image.
//!
//! Built from one linear sweep of the executable regions. Linear sweep is
//! exact for fixed-width ARM64 (an undecodable word is skipped whole, so the
//! sweep stays word-aligned) and a good approximation for x86/x64, where data
//! embedded in code sections can desynchronise the decoder for a few bytes
//! (`db` placeholders resynchronise it).

use std::collections::{BTreeSet, HashMap};

use crate::interfaces::{Architecture, DisassemblerProvider, ModuleSymbol};
use crate::pe_types::{ExportKind, ModuleExtraInfo};
use crate::windows_platform::disassembler::CapstoneDisassembler;

use super::mapped::MappedImage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// `call target` or `call [slot]` — `to` is the target or the slot.
    Call,
    /// `jmp`/`jcc target` or `jmp [slot]`.
    Jump,
    /// A memory operand with a static address (`mov eax, [0x4b08f4]`,
    /// `lea rcx, [rip+x]`).
    DataRef,
    /// An immediate that falls inside the image (`push offset str`).
    Immediate,
}

impl XrefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::DataRef => "data",
            XrefKind::Immediate => "imm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

/// All references found in the image, indexed both ways: `refs` sorted by
/// `(to, from)` answers "who references X"; `by_from` (indices into `refs`,
/// sorted by `(from, to)`) answers "what does the instruction at X reference".
/// Two sorted vectors instead of two hash maps of vectors: an image with
/// hundreds of thousands of references costs no per-key allocations.
#[derive(Debug, Default)]
pub struct XrefIndex {
    refs: Vec<Xref>,
    by_from: Vec<u32>,
    /// Direct call targets inside the image — function-start evidence.
    call_targets: BTreeSet<u64>,
}

/// Instructions per decode call during the sweep.
const SWEEP_CHUNK: usize = 4096;

/// A reference resolved from an ARM64 instruction pair (see [`Arm64Pairs`]).
struct PairRef {
    to: u64,
    kind: XrefKind,
    /// A `blr` through a materialised address (not a loaded slot): the
    /// target is a function start.
    direct_call: bool,
}

/// ARM64 has no absolute operands: an address is materialised as `adrp Xd,
/// page` followed by `add Xd, Xd, #lo` (the address itself) or `ldr Xt, [Xd,
/// #lo]` (a load through it, typically an IAT slot), then optionally used by
/// `br`/`blr`. No single instruction carries the final target, so the sweep
/// remembers the previous instruction's contribution and resolves the pair.
/// Only *adjacent* instructions pair up: that is the only shape MSVC and LLVM
/// emit for ILT thunks, import calls and global accesses, and it keeps false
/// positives out without tracking register liveness.
#[derive(Default)]
struct Arm64Pairs {
    /// `adrp` just seen: (destination register, page base).
    page: Option<(String, u64)>,
    /// Register holding a materialised address (`add`) or the contents of a
    /// slot (`ldr`): (register, address, loaded-through-slot).
    value: Option<(String, u64, bool)>,
}

impl Arm64Pairs {
    fn step(&mut self, insn: &crate::interfaces::Instruction) -> Option<PairRef> {
        // Any instruction that doesn't consume the pending state ends it.
        let page = self.page.take();
        let value = self.value.take();
        let m = insn.mnemonic.to_ascii_lowercase();
        let ops = insn.op_str.as_str();
        match m.as_str() {
            "adrp" => {
                let reg = ops.split(',').next()?.trim();
                let base = insn.addresses_to_symbolize.first().copied()
                    .or_else(|| parse_imm(ops.rsplit(',').next()?.trim()))?;
                self.page = Some((reg.to_string(), base));
                None
            }
            "add" => {
                let (reg, base) = page?;
                let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
                if parts.len() != 3 || parts[1] != reg {
                    return None;
                }
                let to = base.wrapping_add(parse_imm(parts[2])?);
                self.value = Some((parts[0].to_string(), to, false));
                Some(PairRef { to, kind: XrefKind::Immediate, direct_call: false })
            }
            "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "str" | "strb" | "strh" => {
                let (reg, base) = page?;
                let (rt, inner) = parse_mem(ops)?;
                let mut it = inner.split(',').map(str::trim);
                if it.next()? != reg {
                    return None;
                }
                let lo = match it.next() { Some(s) => parse_imm(s)?, None => 0 };
                if it.next().is_some() {
                    return None;
                }
                let to = base.wrapping_add(lo);
                if m == "ldr" && rt.starts_with('x') {
                    self.value = Some((rt.to_string(), to, true));
                }
                Some(PairRef { to, kind: XrefKind::DataRef, direct_call: false })
            }
            "br" | "blr" => {
                let (reg, to, via_slot) = value?;
                if ops.trim() != reg {
                    return None;
                }
                let call = m == "blr";
                Some(PairRef {
                    to,
                    kind: if call { XrefKind::Call } else { XrefKind::Jump },
                    direct_call: call && !via_slot,
                })
            }
            _ => None,
        }
    }
}

/// `#0x1f0`, `#496`, `#-8` → value (negatives wrap, for `wrapping_add`).
fn parse_imm(s: &str) -> Option<u64> {
    let s = s.strip_prefix('#')?;
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let v = match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok()?,
        None => s.parse::<u64>().ok()?,
    };
    Some(if neg { v.wrapping_neg() } else { v })
}

/// `x16, [x16, #0x9f0]` → (`x16`, `x16, #0x9f0`). Rejects pre/post-indexed
/// forms (`[x0], #8`, `[x0, #8]!`), whose base register is modified.
fn parse_mem(ops: &str) -> Option<(&str, &str)> {
    let (rt, rest) = ops.split_once(',')?;
    let rest = rest.trim();
    let inner = rest.strip_prefix('[')?.strip_suffix(']')?;
    Some((rt.trim(), inner))
}

impl XrefIndex {
    pub fn build(image: &MappedImage, arch: Architecture) -> XrefIndex {
        let disasm = match CapstoneDisassembler::new() {
            Ok(d) => d,
            Err(_) => return XrefIndex::default(),
        };
        let mut refs: Vec<Xref> = Vec::new();
        let mut call_targets = BTreeSet::new();
        let in_image = |a: u64| image.contains(a);
        let is_arm64 = arch == Architecture::Arm64;

        for (region_va, bytes) in image.code_regions() {
            let mut offset = 0usize;
            let mut pairs = Arm64Pairs::default();
            while offset < bytes.len() {
                let Ok(insns) = disasm.disassemble(arch, &bytes[offset..], region_va + offset as u64, SWEEP_CHUNK) else { break };
                if insns.is_empty() {
                    break;
                }
                let mut consumed = 0usize;
                for insn in &insns {
                    consumed += insn.size;
                    if insn.is_invalid {
                        continue;
                    }
                    let from = insn.address;
                    let mut seen: Vec<u64> = Vec::with_capacity(3);

                    if insn.is_call || insn.is_jump {
                        let kind = if insn.is_call { XrefKind::Call } else { XrefKind::Jump };
                        // Direct target, or the slot of an indirect `call [mem]`.
                        let to = insn.jump_target.or(insn.mem_ref);
                        if let Some(to) = to.filter(|a| in_image(*a)) {
                            refs.push(Xref { from, to, kind });
                            seen.push(to);
                            if insn.is_call && insn.jump_target == Some(to) {
                                call_targets.insert(to);
                            }
                        }
                    } else if let Some(to) = insn.mem_ref.filter(|a| in_image(*a)) {
                        refs.push(Xref { from, to, kind: XrefKind::DataRef });
                        seen.push(to);
                    }

                    if is_arm64 {
                        if let Some(p) = pairs.step(insn) {
                            if in_image(p.to) && !seen.contains(&p.to) {
                                refs.push(Xref { from, to: p.to, kind: p.kind });
                                seen.push(p.to);
                                if p.direct_call {
                                    call_targets.insert(p.to);
                                }
                            }
                        }
                        // An `adrp` immediate is a 4 KiB page base, not a
                        // reference to whatever happens to start there; the
                        // precise address comes from the pair above.
                        if insn.mnemonic.eq_ignore_ascii_case("adrp") {
                            continue;
                        }
                    }

                    for &imm in &insn.addresses_to_symbolize {
                        if in_image(imm) && !seen.contains(&imm) {
                            refs.push(Xref { from, to: imm, kind: XrefKind::Immediate });
                            seen.push(imm);
                        }
                    }
                }
                if consumed == 0 {
                    break;
                }
                offset += consumed;
            }
        }

        refs.sort_by_key(|x| (x.to, x.from));
        let mut by_from: Vec<u32> = (0..refs.len() as u32).collect();
        by_from.sort_by_key(|&i| (refs[i as usize].from, refs[i as usize].to));
        XrefIndex { refs, by_from, call_targets }
    }

    /// References whose target is `va`, sorted by source address.
    pub fn xrefs_to(&self, va: u64) -> Vec<Xref> {
        let lo = self.refs.partition_point(|x| x.to < va);
        let hi = self.refs.partition_point(|x| x.to <= va);
        self.refs[lo..hi].to_vec()
    }

    /// References made by the instruction at `va`, sorted by target.
    pub fn xrefs_from(&self, va: u64) -> Vec<Xref> {
        let from_of = |i: &u32| self.refs[*i as usize].from;
        let lo = self.by_from.partition_point(|i| from_of(i) < va);
        let hi = self.by_from.partition_point(|i| from_of(i) <= va);
        self.by_from[lo..hi].iter().map(|&i| self.refs[i as usize].clone()).collect()
    }

    pub fn call_targets(&self) -> impl Iterator<Item = u64> + '_ {
        self.call_targets.iter().copied()
    }
}

/// A recovered function start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntry {
    pub start: u64,
    /// Known only from `.pdata` (or the next known start).
    pub end: Option<u64>,
    pub name: Option<String>,
    /// Where the evidence came from: `entry`, `tls`, `export`, `pdata`,
    /// `symbol`, `call`, `prologue`.
    pub source: &'static str,
}

/// Prologue byte patterns whose hit — when preceded by padding or a return —
/// marks a function start. Kept deliberately short: each entry is a common
/// compiler idiom, and every hit is filtered by what precedes it.
const X86_PROLOGUES: &[&[u8]] = &[
    &[0x55, 0x8B, 0xEC],              // push ebp; mov ebp, esp
    &[0x8B, 0xFF, 0x55, 0x8B, 0xEC],  // mov edi, edi; push ebp; mov ebp, esp
    &[0x56, 0x53, 0x55, 0x57],        // push esi; push ebx; push ebp; push edi (twinBASIC)
];
const X64_PROLOGUES: &[&[u8]] = &[
    &[0x48, 0x89, 0x5C, 0x24],        // mov [rsp+x], rbx
    &[0x48, 0x83, 0xEC],              // sub rsp, imm8
    &[0x40, 0x53],                    // push rbx
    &[0x40, 0x55],                    // push rbp
    &[0x48, 0x8B, 0xC4],              // mov rax, rsp
    &[0x55, 0x48, 0x8B, 0xEC],        // push rbp; mov rbp, rsp
];

/// Whether the byte before a prologue hit is what precedes a function:
/// alignment padding (`int3`, `nop`, zero) or the previous function's `ret`.
fn preceded_by_boundary(bytes: &[u8], off: usize) -> bool {
    off == 0 || matches!(bytes[off - 1], 0xCC | 0x90 | 0x00 | 0xC3 | 0xC2)
}

/// Union every source of function-start evidence into one sorted list.
/// `symbols` must be sorted by RVA.
pub fn collect_functions(
    image: &MappedImage,
    info: &ModuleExtraInfo,
    symbols: Option<&[ModuleSymbol]>,
    xrefs: &XrefIndex,
    arch: Architecture,
) -> Vec<FunctionEntry> {
    let base = image.base;
    // First source wins for the `source` tag: ordered from most to least authoritative.
    let mut starts: HashMap<u64, (&'static str, Option<u64>)> = HashMap::new();
    let mut add = |va: u64, source: &'static str, end: Option<u64>| {
        if image.contains(va) {
            starts.entry(va).or_insert((source, end));
        }
    };

    if let Some(funcs) = &info.runtime_functions {
        for rf in funcs {
            if rf.EndAddress > rf.BeginAddress {
                add(base + rf.BeginAddress as u64, "pdata", Some(base + rf.EndAddress as u64));
            }
        }
    }
    let ep = info.nt_headers.OptionalHeader.AddressOfEntryPoint;
    if ep != 0 {
        add(base + ep as u64, "entry", None);
    }
    for &rva in &info.tls_callbacks {
        add(base + rva as u64, "tls", None);
    }
    if let Some(exports) = &info.exports {
        for e in &exports.entries {
            if let ExportKind::Symbol { rva } = e.kind {
                if image.region_at(base + rva as u64).is_some_and(|r| r.executable) {
                    add(base + rva as u64, "export", None);
                }
            }
        }
    }
    if let Some(syms) = symbols {
        for s in syms.iter().filter(|s| s.is_function) {
            add(base + s.rva as u64, "symbol", None);
        }
    }
    for t in xrefs.call_targets() {
        if image.region_at(t).is_some_and(|r| r.executable) {
            add(t, "call", None);
        }
    }
    let prologues: &[&[u8]] = match arch {
        Architecture::X86 => X86_PROLOGUES,
        Architecture::X64 => X64_PROLOGUES,
        Architecture::Arm64 => &[],
    };
    if !prologues.is_empty() {
        for (region_va, bytes) in image.code_regions() {
            for pat in prologues {
                let mut off = 0;
                while let Some(pos) = memchr::memmem::find(&bytes[off..], pat) {
                    let hit = off + pos;
                    if preceded_by_boundary(bytes, hit) {
                        add(region_va + hit as u64, "prologue", None);
                    }
                    off = hit + 1;
                    if off >= bytes.len() { break; }
                }
            }
        }
    }

    let name_of = |va: u64| symbols.and_then(|syms| crate::windows_platform::symbol_name_at(syms, (va - base) as u32));

    let mut out: Vec<FunctionEntry> = starts
        .into_iter()
        .map(|(start, (source, end))| FunctionEntry { start, end, name: name_of(start), source })
        .collect();
    out.sort_by_key(|f| f.start);
    // Without `.pdata`, a function ends where the next known one starts (a
    // ceiling, not a bound).
    for i in 0..out.len() {
        if out[i].end.is_none() {
            let next = out.get(i + 1).map(|f| f.start);
            let region_end = image.region_at(out[i].start).map(|r| base + r.rva as u64 + r.size as u64);
            out[i].end = match (next, region_end) {
                (Some(n), Some(re)) => Some(n.min(re)),
                (Some(n), None) => Some(n),
                (None, re) => re,
            };
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::Instruction;

    fn insn(mnemonic: &str, op_str: &str, page: Option<u64>) -> Instruction {
        Instruction {
            mnemonic: mnemonic.into(),
            op_str: op_str.into(),
            addresses_to_symbolize: page.into_iter().collect(),
            ..Default::default()
        }
    }

    // MSVC's incremental-link thunk: `adrp x16, page; add x16, x16, #lo; br x16`.
    #[test]
    fn arm64_adrp_add_br_is_an_immediate_then_a_jump() {
        let mut p = Arm64Pairs::default();
        assert!(p.step(&insn("adrp", "x16, #0x140003000", Some(0x140003000))).is_none());
        let add = p.step(&insn("add", "x16, x16, #0xad0", None)).unwrap();
        assert_eq!((add.to, add.kind), (0x140003ad0, XrefKind::Immediate));
        let br = p.step(&insn("br", "x16", None)).unwrap();
        assert_eq!((br.to, br.kind, br.direct_call), (0x140003ad0, XrefKind::Jump, false));
        // The state is consumed: a second `br` resolves nothing.
        assert!(p.step(&insn("br", "x16", None)).is_none());
    }

    // An import call: `adrp x16, page; ldr x16, [x16, #slot]; blr x16` —
    // the data reference and the call both name the IAT slot, and a call
    // through a slot is not function-start evidence.
    #[test]
    fn arm64_adrp_ldr_blr_references_the_slot() {
        let mut p = Arm64Pairs::default();
        p.step(&insn("adrp", "x16, #0x140005000", Some(0x140005000)));
        let ldr = p.step(&insn("ldr", "x16, [x16, #0x9f0]", None)).unwrap();
        assert_eq!((ldr.to, ldr.kind), (0x1400059f0, XrefKind::DataRef));
        let blr = p.step(&insn("blr", "x16", None)).unwrap();
        assert_eq!((blr.to, blr.kind, blr.direct_call), (0x1400059f0, XrefKind::Call, false));
    }

    #[test]
    fn arm64_blr_through_materialised_address_is_a_direct_call() {
        let mut p = Arm64Pairs::default();
        p.step(&insn("adrp", "x8, #0x140001000", Some(0x140001000)));
        p.step(&insn("add", "x8, x8, #0x120", None));
        let blr = p.step(&insn("blr", "x8", None)).unwrap();
        assert!(blr.direct_call);
        assert_eq!(blr.to, 0x140001120);
    }

    #[test]
    fn arm64_pairs_require_adjacency_and_matching_registers() {
        let mut p = Arm64Pairs::default();
        p.step(&insn("adrp", "x8, #0x140012000", Some(0x140012000)));
        // A different base register is not the pair.
        assert!(p.step(&insn("add", "x0, x9, #0x18", None)).is_none());
        // ...and the `adrp` is forgotten after the intervening instruction.
        assert!(p.step(&insn("add", "x0, x8, #0x18", None)).is_none());

        p.step(&insn("adrp", "x8, #0x140012000", Some(0x140012000)));
        p.step(&insn("add", "x0, x8, #0x18", None));
        assert!(p.step(&insn("mov", "x1, x0", None)).is_none());
        assert!(p.step(&insn("br", "x0", None)).is_none());

        // Global data through a page: `adrp x8, page; ldr w8, [x8, #off]`.
        p.step(&insn("adrp", "x8, #0x140012000", Some(0x140012000)));
        let ldr = p.step(&insn("ldr", "w8, [x8, #0x30]", None)).unwrap();
        assert_eq!((ldr.to, ldr.kind), (0x140012030, XrefKind::DataRef));
        // A `w` load is not a pointer: nothing to branch through.
        assert!(p.step(&insn("br", "x8", None)).is_none());
    }

    #[test]
    fn arm64_operand_parsing() {
        assert_eq!(parse_imm("#0x1f0"), Some(0x1f0));
        assert_eq!(parse_imm("#496"), Some(496));
        assert_eq!(parse_imm("#-8"), Some(8u64.wrapping_neg()));
        assert_eq!(parse_imm("x0"), None);
        assert_eq!(parse_mem("x16, [x16, #0x9f0]"), Some(("x16", "x16, #0x9f0")));
        assert_eq!(parse_mem("w8, [x8]"), Some(("w8", "x8")));
        assert_eq!(parse_mem("x0, [x1], #8"), None);
        assert_eq!(parse_mem("x0, [x1, #8]!"), None);
    }
}
