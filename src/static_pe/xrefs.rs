//! Cross-references and function-start recovery over a mapped image.
//!
//! Built from one linear sweep of the executable regions. Linear sweep is
//! exact for fixed-width ARM64 and a good approximation for x86/x64, where
//! data embedded in code sections can desynchronise the decoder for a few
//! bytes (`db` placeholders resynchronise it).

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

impl XrefIndex {
    pub fn build(image: &MappedImage, arch: Architecture) -> XrefIndex {
        let disasm = match CapstoneDisassembler::new() {
            Ok(d) => d,
            Err(_) => return XrefIndex::default(),
        };
        let mut refs: Vec<Xref> = Vec::new();
        let mut call_targets = BTreeSet::new();
        let in_image = |a: u64| image.contains(a);

        for (region_va, bytes) in image.code_regions() {
            let mut offset = 0usize;
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
