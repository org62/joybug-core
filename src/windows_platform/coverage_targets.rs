//! Which addresses in a module are worth arming a coverage breakpoint on.
//!
//! Two sources are unioned:
//!
//! * **`.pdata` RUNTIME_FUNCTION starts** — the exception directory is the
//!   authoritative function table and is parsed from the module *file*, so it
//!   works on stripped and obfuscated binaries with no usable PDB.
//! * **Symbols** — a PDB names far more than `.pdata` covers, and on x86-32
//!   there is no exception directory at all.
//!
//! Symbols the PDB marks as functions are trusted. Everything else (labels,
//! and publics from PDBs that never set `CV_PUBSYMFLAGS_Function` — control-flow
//! obfuscators emit tens of thousands of these) has to pass
//! [`classify_code_start`] first, because a coverage breakpoint *writes* an
//! `int3` into the target: one landing in a variable is silent memory
//! corruption, not just a useless table row.

use crate::interfaces::{
    Architecture, DisassemblerProvider, Instruction, ModuleSymbol, PlatformAPI, PlatformError,
    SymbolError, MAX_USER_ADDRESS,
};
use crate::protocol::{CoverageTarget, CoverageTargetSource, MemoryRegionInfo};
use tracing::{info, trace, warn};

use super::disassembler::CapstoneDisassembler;

const MEM_COMMIT: u32 = 0x1000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;
/// PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
const PAGE_EXECUTABLE_MASK: u32 = 0x10 | 0x20 | 0x40 | 0x80;

/// How far the sanity sweep decodes before giving a candidate the benefit of the
/// doubt. Long enough that data usually trips one of the checks, short enough
/// that ~100k candidates stay sub-second.
const SWEEP_MAX_INSNS: usize = 16;

/// Byte window that lets `SWEEP_MAX_INSNS` instructions decode even if every one
/// is maximum length, so the instruction count is the *only* binding limit. A
/// fixed byte cap silently truncates the sweep on dense code — a flat 64 bytes
/// stopped one byte short of an undecodable byte in obfuscated x64, accepting
/// data the decode-error check would have caught. The extra instruction of slack
/// keeps a genuine bad byte at the very end from being written off as buffer
/// truncation (see `CapstoneDisassembler::disassemble`).
fn sweep_window(arch: Architecture) -> usize {
    arch.max_instruction_len() * (SWEEP_MAX_INSNS + 1)
}

/// A run this short is not evidence on its own. Random bytes reach a `jmp`/`ret`
/// opcode almost immediately (`0xEB`, `0xE9`, `0xC3` are common byte values), so
/// the sweep can stop before it sees anything wrong.
///
/// Shorter runs are not rejected outright — control-flow obfuscators chop real
/// code into exactly this shape, two instructions chained by a jump, and that is
/// the case this feature exists to instrument. They have to be corroborated
/// instead; see `jumps_to_known_code`.
const MIN_EVIDENCE_INSNS: usize = 4;

/// Largest plausible displacement in a register-relative memory operand. Stack
/// frames and struct offsets are orders of magnitude smaller than this, and
/// globals are reached RIP-relative; data decoded as code produces things like
/// `mov ebx, dword ptr [rsp - 0x6ef498d8]` — a 1.8 GB stack offset.
const MAX_PLAUSIBLE_DISPLACEMENT: u64 = 0x10_0000;

/// Refuse to snapshot more than this much of one module. A real module's
/// executable sections are a few MB; anything past this is a runaway.
const MAX_IMAGE_SNAPSHOT: usize = 64 * 1024 * 1024;

/// A snapshot of a module's committed, executable memory, so the sweep decodes
/// from a local buffer instead of issuing a cross-process read per candidate.
struct ExecImage {
    /// `(start, bytes)` chunks, ascending and non-overlapping.
    chunks: Vec<(u64, Vec<u8>)>,
}

impl ExecImage {
    /// The bytes from `addr` to the end of its chunk, or `None` when `addr` is
    /// not in committed executable memory. Doubles as the executable-memory
    /// gate: everything this returns `None` for is refused outright.
    fn from(&self, addr: u64) -> Option<&[u8]> {
        let idx = self.chunks.partition_point(|(start, _)| *start <= addr);
        let (start, bytes) = self.chunks.get(idx.checked_sub(1)?)?;
        let offset = (addr - start) as usize;
        // An address exactly at the chunk end belongs to no chunk.
        if offset >= bytes.len() {
            return None;
        }
        Some(&bytes[offset..])
    }
}

/// Find the region containing `address` in an ascending region list.
fn find_region(regions: &[MemoryRegionInfo], address: u64) -> Option<&MemoryRegionInfo> {
    let idx = regions.partition_point(|r| r.base_address <= address);
    let region = regions.get(idx.checked_sub(1)?)?;
    (address < region.base_address + region.region_size).then_some(region)
}

fn is_accessible(region: &MemoryRegionInfo) -> bool {
    region.state == MEM_COMMIT
        && region.protect != 0
        && region.protect != PAGE_NOACCESS
        && (region.protect & PAGE_GUARD) == 0
}

/// Why a candidate was refused. Tallied and logged so the filter's behaviour on
/// a real target is measurable instead of guessed at — the thresholds here were
/// tuned against these counts, and re-tuning needs the same visibility.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Reject {
    /// Not in committed executable memory. The safety gate.
    NotExecutable,
    Padding,
    Misaligned,
    DecodeError,
    RedFlag,
    WildBranch,
    WildMemRef,
    BigDisplacement,
    ZeroChain,
    /// Terminated too early to be evidence, and the jump it ended on didn't lead
    /// to anything that looked like code either.
    UnconvincingRun,
}

/// Keyed by the enum itself so a reordered or newly-inserted `Reject` variant
/// can never silently mislabel the trace line (the summary is the stated tuning
/// instrument for this filter). `Ord` follows declaration order, so the summary
/// stays in variant order.
#[derive(Default)]
struct RejectTally(std::collections::BTreeMap<Reject, usize>);

impl RejectTally {
    fn record(&mut self, reason: Reject) {
        *self.0.entry(reason).or_default() += 1;
    }

    fn total(&self) -> usize {
        self.0.values().sum()
    }

    /// `reason=count` pairs for the non-zero reasons, for the trace line.
    fn summary(&self) -> String {
        self.0
            .iter()
            .map(|(reason, count)| format!("{:?}={}", reason, count))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The destination operand — everything before the first comma. A bare register
/// name here means a real write to that register; `dword ptr [esp+8]` does not
/// match, which is what makes the stack-pointer checks below precise.
fn destination(op_str: &str) -> &str {
    op_str.split(',').next().unwrap_or("").trim()
}

/// Whether `op_str` mentions `name` as a whole register token rather than as
/// part of a longer one — so `sp` does not match inside `rsp`, and `ah` does not
/// match inside a symbol name.
fn mentions_register(op_str: &str, name: &str) -> bool {
    let bytes = op_str.as_bytes();
    op_str.match_indices(name).any(|(index, _)| {
        let before_ok = index == 0 || !bytes[index - 1].is_ascii_alphanumeric();
        let after = index + name.len();
        let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
        before_ok && after_ok
    })
}

/// Whether an operand names an MMX register (`mm0`-`mm7`) rather than an SSE/AVX
/// one. MMX is dead in 64-bit compiler output, but Capstone spells the MMX and
/// SSE forms of `pandn`/`psllw`/... identically, so the registers are the only
/// way to tell them apart.
fn uses_mmx(op_str: &str) -> bool {
    let bytes = op_str.as_bytes();
    bytes.windows(3).enumerate().any(|(i, w)| {
        &w[..2] == b"mm"
            && w[2].is_ascii_digit()
            && !matches!(bytes.get(i.wrapping_sub(1)), Some(b'x' | b'y' | b'z'))
    })
}

/// Instructions that no compiler emits into user-mode code. One of these inside
/// the run a candidate starts means the decoder is chewing through data.
///
/// The x64 list is derived from measurement, not intuition: across 23,771
/// instructions decoded from 1,572 known-good function starts (ntdll plus an
/// obfuscated binary's `.pdata`), *none* of these appeared, while an
/// obfuscated binary's encrypted-blob symbols produced them constantly. Two of
/// the structural rules below had an exact zero-versus-hundreds split.
///
/// Deliberately a blocklist and not a whitelist. Coverage targets include
/// obfuscated basic-block labels, which are arbitrary mid-function code rather
/// than prologues, so a whitelist trained on function entries would reject
/// exactly the case this feature exists to serve.
///
/// Split by architecture rather than merged: `str` is a privileged x86 "store
/// task register" but the ordinary ARM64 store, so a shared list would reject
/// most ARM64 functions.
fn is_red_flag(ins: &Instruction, arch: Architecture) -> bool {
    if arch == Architecture::X64 {
        // Any mention of `esp`/`sp` at all. 64-bit code addresses the stack
        // through `rsp`; writing the 32-bit alias zeroes the top half and
        // instantly destroys the stack, and reading it is equally meaningless.
        // Measured: 0 occurrences in known-good code.
        if mentions_register(&ins.op_str, "esp") || mentions_register(&ins.op_str, "sp") {
            return true;
        }
        // Segment register as the destination. Note this is not the same as a
        // `gs:`/`fs:` memory prefix, which is ordinary TEB/PEB access and must
        // keep working.
        if matches!(destination(&ins.op_str), "es" | "ds" | "ss" | "cs" | "fs" | "gs") {
            return true;
        }
        // Register-to-register `xchg` — the single-byte 0x90+r accumulator
        // encoding. Compilers never emit it; the only real `xchg` is the
        // `lock`-prefixed memory form used for atomics.
        if ins.mnemonic == "xchg" && !ins.op_str.contains('[') {
            return true;
        }
        // High-byte registers. REX prefixes make `ah`/`bh`/`ch`/`dh`
        // inaccessible, so 64-bit compilers use `spl`/`bpl`/`sil`/`dil`
        // instead and never emit these. Measured: 0 in known-good code, the
        // most frequent single tell in decoded data.
        if ["ah", "bh", "ch", "dh"]
            .iter()
            .any(|reg| mentions_register(&ins.op_str, reg))
        {
            return true;
        }
        // `rsp` written by anything other than the handful of ways a compiler
        // adjusts the stack pointer (frame setup, teardown, alignment).
        if destination(&ins.op_str) == "rsp"
            && !matches!(ins.mnemonic.as_str(), "mov" | "add" | "sub" | "lea" | "and")
        {
            return true;
        }
        // `ret imm16` — a stdcall-era callee-cleanup return with no place in the
        // x64 calling convention. Measured: 0 in known-good code, 78 in blobs.
        if ins.mnemonic == "ret" && !ins.op_str.is_empty() {
            return true;
        }
        if uses_mmx(&ins.op_str) {
            return true;
        }
    }
    // `movabs` with a *memory* operand is the moffs (A0-A3) encoding: a 64-bit
    // absolute load/store that no 64-bit compiler emits — they address globals
    // RIP-relative. Checked here rather than in the mnemonic list because
    // `movabs reg, imm64` is ordinary code and shares the mnemonic; only the
    // memory-operand form is the tell. Data misread as code produces these
    // constantly, and their absolute addresses are usually non-canonical, which
    // `mem_ref_sane` cannot always see (a negative displacement is not extracted
    // as a mem_ref at all).
    if arch == Architecture::X64 && ins.mnemonic == "movabs" && ins.op_str.contains('[') {
        return true;
    }
    let mnemonic = ins.mnemonic.as_str();
    match arch {
        Architecture::X64 => {
            // The x87 FPU. 64-bit compilers do everything in SSE; an `f`-prefixed
            // stack op is the single most common thing random bytes decode into
            // (~40 distinct kinds appeared in the blobs, none in real code).
            if matches!(mnemonic.as_bytes().first(), Some(b'f'))
                && matches!(
                    mnemonic,
                    "fadd" | "faddp" | "fbld" | "fbstp" | "fchs" | "fclex" | "fcom" | "fcomi"
                    | "fcomip" | "fcompi" | "fcomp" | "fcompp" | "fcmovb" | "fcmovbe"
                    | "fcmove" | "fcmovnb" | "fcmovnbe" | "fcmovne" | "fcmovnu" | "fcmovu"
                    | "fcos" | "fdecstp" | "fdisi8087_nop" | "fdiv" | "fdivp" | "fdivr"
                    | "fdivrp" | "feni8087_nop" | "ffree" | "ffreep" | "fiadd" | "ficom"
                    | "ficomp" | "fidiv" | "fidivr" | "fild" | "fimul" | "fincstp"
                    | "finit" | "fist" | "fistp" | "fisttp" | "fisub" | "fisubr" | "fld"
                    | "fld1" | "fldcw" | "fldenv" | "fldl2e" | "fldl2t" | "fldlg2"
                    | "fldln2" | "fldpi" | "fldz" | "fmul" | "fmulp" | "fnclex" | "fninit"
                    | "fnop" | "fnsave" | "fnstcw" | "fnstenv" | "fnstsw" | "fpatan"
                    | "fprem" | "fprem1" | "fptan" | "frndint" | "frstor" | "fsave"
                    | "fscale" | "fsetpm" | "fsin" | "fsincos" | "fsqrt" | "fst" | "fstp"
                    | "fstpnce" | "fstcw" | "fstenv" | "fstsw" | "fsub" | "fsubp"
                    | "fsubr" | "fsubrp" | "ftst" | "fucom" | "fucomi" | "fucomip"
                    | "fucomp" | "fucompp" | "fxam" | "fxch" | "fxtract" | "fyl2x"
                    | "fyl2xp1" | "fwait"
                )
            {
                return true;
            }
            matches!(
                mnemonic,
                // Privileged / IO — ring 0 only.
                "hlt" | "in" | "out" | "insb" | "insw" | "insd" | "outsb" | "outsw" | "outsd"
                | "cli" | "sti" | "clts" | "invd" | "wbinvd" | "invlpg" | "invpcid"
                | "lgdt" | "lidt" | "lldt" | "ltr" | "sgdt" | "sidt" | "sldt" | "str"
                | "lmsw" | "smsw" | "rsm" | "sysret" | "sysretq" | "sysexit" | "wrmsr" | "rdmsr"
                // Invalid in 64-bit mode, or legacy forms no 64-bit compiler emits.
                | "aaa" | "aad" | "aam" | "aas" | "daa" | "das" | "arpl" | "bound" | "into"
                | "salc" | "pusha" | "pushad" | "popa" | "popad" | "les" | "lds"
                | "retf" | "retfq" | "iret" | "iretd" | "iretq" | "ud0" | "ud1"
                // Debug/trap forms. `int3` is excluded on purpose: it is real
                // padding and a legitimate terminator.
                | "int" | "int1" | "icebp" | "wait"
                // Legacy loop and indexed-jump control flow. Compilers lower
                // loops to cmp/jcc; none of these survive in generated code.
                | "loop" | "loope" | "loopne" | "loopnz" | "loopz" | "jrcxz" | "jecxz"
                | "enter" | "xlatb" | "xlat"
                // Overflow branches: C has no overflow-conditional control flow,
                // so a compiler never emits these (unlike jp/jnp, which do appear
                // in floating-point NaN handling and are therefore allowed).
                | "jo" | "jno"
                // Flag-register games. Compilers set flags as a side effect of
                // arithmetic and never poke them directly.
                | "clc" | "stc" | "cmc" | "cld" | "std" | "lahf" | "sahf"
                // Rotate-through-carry and the `sal` alias: never generated.
                | "rcl" | "rcr" | "sal"
                // Implicit-operand string instructions. `rep movs`/`rep stos` are
                // real (inlined memcpy/memset) and carry the prefix in the
                // mnemonic, so only the bare and nonsensical forms land here.
                | "lodsb" | "lodsw" | "lodsd" | "lodsq" | "rep lodsb" | "rep lodsd"
                | "repne lodsb" | "repne lodsd" | "scasb" | "scasw" | "scasd" | "scasq"
                | "movsb" | "stosb" | "cmpsb" | "cmpsd" | "cmpsw" | "cmpsq"
                | "rep insb" | "rep insd" | "rep outsb" | "rep outsd"
            )
        }
        Architecture::Arm64 => matches!(
            mnemonic,
            "eret" | "eretaa" | "eretab" | "hvc" | "smc" | "dcps1" | "dcps2" | "dcps3"
        ),
    }
}

/// Whether a register-relative memory operand carries an implausibly large
/// displacement. RIP-relative operands are exempt: their displacement is a
/// module-sized distance by nature, and `mem_ref_sane` already validates where
/// they actually land.
///
/// Scale factors (`rax*8`) are written without a `0x` prefix, so requiring one
/// keeps them from being mistaken for a displacement.
fn displacement_implausible(op_str: &str) -> bool {
    let mut rest = op_str;
    while let Some(open) = rest.find('[') {
        let Some(close) = rest[open..].find(']') else { break };
        let operand = &rest[open + 1..open + close];
        rest = &rest[open + close..];
        if operand.contains("rip") {
            continue;
        }
        // Only register-relative operands: a bare absolute address is an
        // ordinary (if rare) encoding, and `mem_ref_sane` judges it properly.
        if !operand.contains('r') && !operand.contains('e') {
            continue;
        }
        for (index, _) in operand.match_indices("0x") {
            // Fold the hex digits straight into a value — this runs on every
            // instruction of every candidate's sweep, so the old per-literal
            // `String` was millions of short-lived allocations. Saturating stops
            // an over-long literal from wrapping past the threshold.
            let mut value: u64 = 0;
            let mut any = false;
            for c in operand[index + 2..].chars() {
                let Some(digit) = c.to_digit(16) else { break };
                any = true;
                value = value.saturating_mul(16).saturating_add(digit as u64);
                if value >= MAX_PLAUSIBLE_DISPLACEMENT {
                    break;
                }
            }
            // Displacements are printed sign-magnitude (`[rsp - 0x98]`), so the
            // magnitude alone is what matters here.
            if any && value >= MAX_PLAUSIBLE_DISPLACEMENT {
                return true;
            }
        }
    }
    false
}

/// Whether a run ending immediately is the one legitimate short-function shape:
/// an import thunk, `jmp qword ptr [rip + N]`.
fn is_thunk(first: &Instruction) -> bool {
    first.mnemonic == "jmp" && first.op_str.contains('[') && first.op_str.contains("rip")
}

/// Corroborates a run too short to judge on its own: does it end by jumping to
/// somewhere independently known to be code?
///
/// `code_labels` holds every symbol address and `.pdata` function start in the
/// module, ascending. A control-flow obfuscator's blocks jump to each other, and
/// it labels those destinations, so a real short block lands exactly on a label. 
/// Data decoded as code jumps to an arbitrary offset, which at this module's label 
/// density coincides with one only ~1.5% of the time.
///
/// Preferred over recursively re-running the sweep on the destination: chained
/// short blocks would each fail to corroborate the next, rejecting whole chains
/// of genuine code.
fn jumps_to_known_code(ins: &Instruction, code_labels: &[u64]) -> bool {
    if ins.mnemonic != "jmp" || ins.op_str.contains('[') {
        return false;
    }
    ins.jump_target
        .is_some_and(|target| code_labels.binary_search(&target).is_ok())
}

/// A statically-resolvable memory operand must point at real user-mode memory.
/// Data decoded as code yields absolute operands like
/// `movabs al, byte ptr [0xa0509bf591ba1da3]` — non-canonical addresses no real
/// instruction would touch. Genuine x64 code reaches its globals RIP-relative,
/// and the resolved target is committed memory in the same module.
fn mem_ref_sane(ins: &Instruction, regions: &[MemoryRegionInfo]) -> bool {
    let Some(target) = ins.mem_ref else {
        return true; // register-relative, or below the operand extractor's floor
    };
    if target > MAX_USER_ADDRESS {
        return false;
    }
    find_region(regions, target).is_some_and(is_accessible)
}

/// Whether `ins` unconditionally ends the linear run — the point past which
/// bytes belong to whatever follows (padding, data, the next function) and say
/// nothing about the candidate that started the run.
///
/// Conditional branches and calls are deliberately *not* terminators: both have
/// a fallthrough path, so the bytes after them really are part of the run.
fn is_terminator(ins: &Instruction, arch: Architecture) -> bool {
    if ins.is_ret {
        return true;
    }
    match arch {
        Architecture::X64 => matches!(ins.mnemonic.as_str(), "jmp" | "int3" | "ud2"),
        Architecture::Arm64 => matches!(
            ins.mnemonic.as_str(),
            "b" | "br" | "braa" | "brab" | "braaz" | "brabz" | "brk" | "udf"
        ),
    }
}

/// A branch or call with a computable destination must point somewhere real.
/// Data misread as code produces rel32 displacements that fly out of any mapped
/// code, which on x86 — where nearly every byte sequence decodes to *something*
/// — is the single strongest signal available.
///
/// Memory-indirect forms (`jmp qword ptr [rip+N]`, the import-thunk shape) carry
/// the address of the pointer *slot*, not the destination, so those only have to
/// land in readable memory.
fn branch_target_sane(ins: &Instruction, regions: &[MemoryRegionInfo]) -> bool {
    if !(ins.is_jump || ins.is_call) {
        return true;
    }
    let Some(target) = ins.jump_target else {
        return true; // register-indirect, or below the operand extractor's floor
    };
    let Some(region) = find_region(regions, target) else {
        return false;
    };
    if !is_accessible(region) {
        return false;
    }
    ins.op_str.contains('[') || (region.protect & PAGE_EXECUTABLE_MASK) != 0
}

/// Whether `addr` plausibly begins an instruction stream: `None` accepts,
/// `Some(reason)` rejects (the reason is tallied by the caller for the trace
/// line).
///
/// The forward sweep stops at the first unconditional terminator, so a one
/// instruction thunk (`jmp qword ptr [rip+N]`) and a function whose bytes are
/// followed by data are both judged only on the run they actually own. A run
/// that reaches the instruction cap without terminating is accepted: long
/// straight-line code is real, and conditional branches don't end a run.
///
/// Disqualifying, in the order they tend to fire on obfuscated x64: an operand
/// pointing outside mapped user memory (branch target or absolute memory
/// reference), a `movabs` moffs form, a privileged or 64-bit-invalid opcode, an
/// undecodable byte, or a chain of zero bytes.
///
/// This is a filter, not a proof — x86 decodes almost any byte sequence into
/// *something* — which is why the executable-memory gate, the one that keeps an
/// `int3` out of a variable, is enforced independently of it.
fn classify_code_start(
    image: &ExecImage,
    regions: &[MemoryRegionInfo],
    disasm: &CapstoneDisassembler,
    arch: Architecture,
    addr: u64,
    code_labels: &[u64],
) -> Option<Reject> {
    // Gate 1: committed executable memory (safety). Live page protection, not
    // on-disk section flags — packers map non-executable sections as executable.
    let Some(slice) = image.from(addr) else {
        return Some(Reject::NotExecutable);
    };

    // Gate 2: ARM64 instructions are 4-byte aligned by definition.
    if arch == Architecture::Arm64 && addr % 4 != 0 {
        return Some(Reject::Misaligned);
    }

    // Gate 3: padding and uninitialised fill. Zero bytes decode happily as
    // `add [rax], al`, so the decoder can't be relied on to reject them.
    let head = &slice[..slice.len().min(8)];
    if head.iter().all(|&b| b == 0x00) || head.iter().all(|&b| b == 0xFF) {
        return Some(Reject::Padding);
    }
    if arch == Architecture::X64 && slice[0] == 0xCC {
        return Some(Reject::Padding); // int3 filler between functions
    }

    // Gate 4: bounded linear sweep.
    let window = &slice[..slice.len().min(sweep_window(arch))];
    let Some(instructions) = disasm
        .disassemble(arch, window, addr, SWEEP_MAX_INSNS)
        .ok()
        .filter(|decoded| !decoded.is_empty())
    else {
        return Some(Reject::DecodeError);
    };

    let mut zero_run = 0usize;
    let mut decoded = 0usize;
    for ins in &instructions {
        if ins.is_invalid {
            return Some(Reject::DecodeError);
        }
        if is_red_flag(ins, arch) {
            return Some(Reject::RedFlag);
        }
        if !branch_target_sane(ins, regions) {
            return Some(Reject::WildBranch);
        }
        if !mem_ref_sane(ins, regions) {
            return Some(Reject::WildMemRef);
        }
        if arch == Architecture::X64 && displacement_implausible(&ins.op_str) {
            return Some(Reject::BigDisplacement);
        }
        decoded += 1;
        // Consecutive instructions decoded purely from zero bytes: the signature
        // of a pointer table, whose high halves are zero on Windows x64.
        if ins.bytes.iter().all(|&b| b == 0x00) {
            zero_run += 1;
            if zero_run >= 2 {
                return Some(Reject::ZeroChain);
            }
        } else {
            zero_run = 0;
        }
        if is_terminator(ins, arch) {
            // A run this short shows almost nothing, and random bytes reach a
            // terminator opcode quickly — but obfuscated code has this exact
            // shape, so it has to be corroborated rather than refused.
            if decoded >= MIN_EVIDENCE_INSNS
                || is_thunk(&instructions[0])
                || jumps_to_known_code(ins, code_labels)
            {
                return None;
            }
            return Some(Reject::UnconvincingRun);
        }
    }
    // Reached the instruction cap without terminating: a long straight-line run,
    // which is ordinary code.
    None
}

/// The name of the symbol starting exactly at `rva`, if there is one.
/// `symbols` must be sorted by RVA.
///
/// Exact match only, deliberately. Every target is either a symbol address
/// (which matches exactly) or a `.pdata` function start, and labelling an
/// unnamed function start with the nearest symbol *below* it would attribute it
/// to the previous function — worse than admitting the address has no name and
/// letting the caller fall back to `sub_<addr>`.
fn name_for(symbols: &[ModuleSymbol], rva: u32) -> Option<String> {
    let idx = symbols.partition_point(|s| s.rva <= rva);
    let symbol = symbols.get(idx.checked_sub(1)?)?;
    (symbol.rva == rva).then(|| symbol.name.clone())
}

impl super::WindowsPlatform {
    /// See [`crate::interfaces::PlatformAPI::enumerate_coverage_targets`].
    pub(super) fn enumerate_coverage_targets_impl(
        &self,
        pid: u32,
        module_path: &str,
        sources: &[CoverageTargetSource],
    ) -> Result<Vec<CoverageTarget>, PlatformError> {
        // Empty means "everything"; otherwise only what was asked for. Symbols
        // are still read when no symbol tier is requested — they name the
        // `.pdata` targets — but the code-sanity sweep, which is the expensive
        // part on a module with a hundred thousand symbols, is skipped.
        let wants = |source: CoverageTargetSource| sources.is_empty() || sources.contains(&source);
        let wants_function_symbols = wants(CoverageTargetSource::FunctionSymbol);
        let wants_validated = wants(CoverageTargetSource::ValidatedSymbol);

        let modules = self.modules_for(pid);
        let module = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(module_path))
            .ok_or_else(|| PlatformError::Other(format!("Module not loaded: {}", module_path)))?;
        let base = module.base;
        let module_end = base + module.size.unwrap_or(0);
        let arch = self.get_process(pid)?.architecture();

        let symbol_manager = self
            .symbol_manager
            .as_ref()
            .ok_or_else(|| PlatformError::Other("Symbol manager unavailable".to_string()))?;

        // `.pdata` first: it needs no symbols at all.
        let ranges = symbol_manager.runtime_function_ranges(&module.name);

        // Symbols are optional — a module with no PDB still gets its `.pdata`
        // functions — but "still loading" must not be silently downgraded to
        // "no symbols", or a scan started during a PDB download would quietly
        // produce a nameless table. That one case is reported so the caller retries.
        let symbols: Vec<ModuleSymbol> = match symbol_manager.list_symbols_raw(&module.name) {
            Ok(symbols) => symbols,
            Err(SymbolError::SymbolsStillLoading(m)) => {
                return Err(PlatformError::Other(format!(
                    "Symbols for {} are still loading; retry once they settle",
                    m
                )));
            }
            Err(e) => {
                trace!(module = %module.name, error = %e, "No symbols for coverage targets; using .pdata only");
                Vec::new()
            }
        };

        let regions = self.enumerate_memory_regions(pid)?;
        let image = self.snapshot_executable_image(pid, &regions, base, module_end);
        let disassembler = self
            .disassembler
            .as_ref()
            .ok_or_else(|| PlatformError::Other("Disassembler unavailable".to_string()))?;

        // Address -> source. `.pdata` wins ties: it is the stronger claim, and
        // the UI shows where each row came from.
        let mut targets: std::collections::BTreeMap<u64, CoverageTargetSource> =
            std::collections::BTreeMap::new();
        if wants(CoverageTargetSource::Pdata) {
            for (begin_rva, _) in &ranges {
                let addr = base + *begin_rva as u64;
                if image.from(addr).is_some() {
                    targets.insert(addr, CoverageTargetSource::Pdata);
                }
            }
        }

        // Every address the module claims is *something* — a symbol or a
        // function start. A short run that jumps here is corroborated as code;
        // built once, ascending, for binary search. Only the validated tier
        // reads it, so a scan that didn't ask for that tier skips the O(n log n)
        // build entirely.
        let code_labels: Vec<u64> = if wants_validated {
            let mut labels: Vec<u64> = symbols
                .iter()
                .map(|s| base + s.rva as u64)
                .chain(ranges.iter().map(|(begin, _)| base + *begin as u64))
                .collect();
            labels.sort_unstable();
            labels.dedup();
            labels
        } else {
            Vec::new()
        };

        let mut tally = RejectTally::default();
        if wants_function_symbols || wants_validated {
            for symbol in &symbols {
                let addr = base + symbol.rva as u64;
                if targets.get(&addr) == Some(&CoverageTargetSource::Pdata) {
                    continue;
                }
                if symbol.is_function {
                    if !wants_function_symbols {
                        continue;
                    }
                    // Trusted by source, but still subject to the executable-memory
                    // gate: a function symbol pointing at data is broken metadata,
                    // and arming it would corrupt the target.
                    if image.from(addr).is_some() {
                        targets.insert(addr, CoverageTargetSource::FunctionSymbol);
                    }
                    continue;
                }
                if !wants_validated || targets.contains_key(&addr) {
                    continue;
                }
                match classify_code_start(&image, &regions, disassembler, arch, addr, &code_labels) {
                    None => {
                        targets.insert(addr, CoverageTargetSource::ValidatedSymbol);
                    }
                    Some(reason) => tally.record(reason),
                }
            }
        }

        let result: Vec<CoverageTarget> = targets
            .into_iter()
            .map(|(address, source)| {
                let rva = (address - base) as u32;
                CoverageTarget { address, rva, symbol: name_for(&symbols, rva), source }
            })
            .collect();

        info!(
            pid,
            module = %module.name,
            targets = result.len(),
            pdata = ranges.len(),
            symbols = symbols.len(),
            rejected = tally.total(),
            reasons = %tally.summary(),
            "Enumerated coverage targets"
        );
        Ok(result)
    }

    /// Read the module's committed executable memory into one local buffer per
    /// region, so the sanity sweep never crosses the process boundary.
    fn snapshot_executable_image(
        &self,
        pid: u32,
        regions: &[MemoryRegionInfo],
        base: u64,
        module_end: u64,
    ) -> ExecImage {
        let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut total = 0usize;
        for region in regions {
            let region_end = region.base_address + region.region_size;
            if region_end <= base || region.base_address >= module_end {
                continue;
            }
            if !is_accessible(region) || (region.protect & PAGE_EXECUTABLE_MASK) == 0 {
                continue;
            }
            let start = region.base_address.max(base);
            let end = region_end.min(module_end);
            let len = (end - start) as usize;
            if len == 0 || total.saturating_add(len) > MAX_IMAGE_SNAPSHOT {
                warn!(pid, start, len, "Skipping executable region: coverage snapshot budget exhausted");
                continue;
            }
            match self.read_memory(pid, start, len) {
                Ok(bytes) => {
                    total += bytes.len();
                    chunks.push((start, bytes));
                }
                Err(e) => {
                    warn!(pid, start, len, error = %e, "Failed to snapshot executable region for coverage");
                }
            }
        }
        chunks.sort_by_key(|(start, _)| *start);
        ExecImage { chunks }
    }
}
