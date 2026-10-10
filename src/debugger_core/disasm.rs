//! Instruction decoding over a tracee: read the bytes, hide our own
//! breakpoint bytes, hand them to Capstone.

use super::breakpoints::BreakpointTable;
use super::dereference::MemoryReader;
use super::disassembler::CapstoneDisassembler;
use super::ops::ProcessOps;
use crate::interfaces::{Architecture, DisassemblerError, DisassemblerProvider, Instruction, PlatformAPI, SymbolInfo};
use crate::protocol::{DisasmOptions, ModuleInfo};
use crate::symbols::symbol_manager::SymbolManager;

/// Decode the single instruction at `address`. Raw (non-symbolizing): callers
/// that only need size + mnemonic (the stepper) must not contend with the
/// symbol machinery while a large debug file is parsed.
pub fn decode_one<O: ProcessOps + ?Sized>(
    ops: &O,
    bps: &BreakpointTable,
    disasm: &CapstoneDisassembler,
    pid: u32,
    address: u64,
    arch: Architecture,
) -> Result<Option<Instruction>, DisassemblerError> {
    // 16 bytes covers the longest x86 instruction (15) with slack.
    let mut data = ops
        .read(pid, address, 16)
        .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;
    bps.patch_breakpoint_bytes(address, &mut data);
    Ok(disasm.disassemble(arch, &data, address, 1)?.into_iter().next())
}

/// Non-blocking symbol resolver over a snapshot of the process's module
/// list: returns `None` immediately for a module whose symbols are still
/// loading rather than waiting (up to seconds) for the debug-file parse -
/// callers stay instant even for large symbol files, and re-resolve once
/// symbols land.
pub fn nonblocking_symbol_resolver(
    symbol_manager: Option<&SymbolManager>,
    mut modules: Vec<ModuleInfo>,
) -> impl Fn(u64) -> Option<SymbolInfo> + '_ {
    // Sort by base address for binary search in symbol resolution
    modules.sort_by_key(|m| m.base);
    move |addr: u64| -> Option<SymbolInfo> {
        let sm = symbol_manager?;
        if let Ok(Some((module_path, symbol, offset))) = sm.try_resolve_address_to_symbol(&modules, addr) {
            let module_name = crate::formatting::module_stem(&module_path);
            return Some(SymbolInfo { module_name, symbol_name: symbol.name, offset });
        }
        None
    }
}

/// A platform's current [`DisasmOptions`], settable through `&self`.
#[derive(Debug, Default)]
pub struct DisasmOptionsCell(std::sync::Mutex<DisasmOptions>);

impl DisasmOptionsCell {
    pub fn set(&self, options: DisasmOptions) {
        *self.0.lock().unwrap() = options;
    }

    pub fn get(&self) -> DisasmOptions {
        *self.0.lock().unwrap()
    }
}

/// The function containing `start`, named `module!symbol` — when `with_name`.
/// Off, the lookup is skipped altogether: it waits for a module whose symbols
/// are still loading, which a listing that must not stall cannot afford. The
/// time spent is the span's `name_us`.
pub fn function_name(
    symbol_manager: Option<&SymbolManager>,
    modules: &[ModuleInfo],
    start: u64,
    with_name: bool,
    span: &mut crate::perf::Span,
) -> Option<String> {
    if !with_name {
        return None;
    }
    let t = std::time::Instant::now();
    let name = symbol_manager
        .and_then(|sm| sm.resolve_address_to_symbol_raw(modules, start).ok().flatten())
        .map(|(module_path, symbol, _offset)| format!("{}!{}", crate::formatting::module_stem(&module_path), symbol.name));
    span.attr_elapsed("name_us", t);
    name
}

/// What a symbolized listing decode needs from the process.
pub struct Listing<'a> {
    pub reader: &'a dyn MemoryReader,
    /// Our own breakpoint bytes are hidden before decoding.
    pub bps: Option<&'a BreakpointTable>,
    pub disasm: &'a CapstoneDisassembler,
    pub symbol_manager: Option<&'a SymbolManager>,
    /// The process's modules (any order).
    pub modules: Vec<ModuleInfo>,
    pub options: DisasmOptions,
}

/// Shared body of `disassemble_memory` / `disassemble_memory_bytes`: reads
/// `read_len` bytes and decodes up to `count` instructions, symbolized and
/// annotated with cached source lines. `pointer_reader` is built lazily, only
/// when the listing contains an indirect call/jump whose slot is worth
/// reading; it may return `None` to skip that resolution.
pub fn decode_listing<'a>(
    listing: Listing<'a>,
    address: u64,
    read_len: usize,
    count: usize,
    arch: Architecture,
    pointer_reader: impl FnOnce() -> Option<Box<dyn Fn(u64) -> Option<u64> + 'a>>,
) -> Result<Vec<Instruction>, DisassemblerError> {
    use std::cell::Cell;
    use std::time::Instant;

    let Listing { reader, bps, disasm, symbol_manager, mut modules, options } = listing;
    let symbol_manager = symbol_manager.filter(|_| options.symbolizes());
    let mut span = crate::perf::span("disasm.decode_listing");
    let timed = span.is_live();

    let t = Instant::now();
    let mut data = reader
        .read(address, read_len)
        .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;

    // Patch breakpoint bytes with originals so disassembly shows real instructions
    if let Some(bps) = bps {
        bps.patch_breakpoint_bytes(address, &mut data);
    }
    span.attr_elapsed("read_us", t);
    span.attr("read_bytes", data.len() as u64);

    if options.naive {
        let t = Instant::now();
        let instructions = disasm.disassemble(arch, &data, address, count)?;
        span.attr_elapsed("decode_us", t);
        span.attr("instructions", instructions.len() as u64);
        span.attr("naive", 1);
        return Ok(instructions);
    }

    // Sort modules by base address for binary search
    let t = Instant::now();
    modules.sort_by_key(|m| m.base);
    // The symbol resolver closure consumes `modules`; keep a copy for line annotation.
    let modules_for_lines = modules.clone();
    span.attr_elapsed("modules_us", t);
    span.attr("modules", modules.len() as u64);
    if timed {
        if let Some(module) = SymbolManager::find_module_binary_search(&modules, address) {
            span.attr("module_key", crate::perf::path_key(&module.name));
        }
    }

    let symbol_us = Cell::new(0u64);
    let symbol_calls = Cell::new(0u64);
    let symbol_resolver = |addr: u64| -> Option<SymbolInfo> {
        let symbol_manager = symbol_manager?;
        let t = timed.then(Instant::now);
        // Non-blocking: skip symbolization while symbols are still loading rather
        // than stalling the disassembly response behind symbol downloads.
        // The UI re-requests disassembly once symbols finish loading.
        let result = match symbol_manager.try_resolve_address_to_symbol(&modules, addr) {
            Ok(Some((module_path, symbol, offset))) => {
                let module_name = crate::formatting::module_stem(&module_path);
                Some(SymbolInfo { module_name, symbol_name: symbol.name, offset })
            }
            _ => None,
        };
        if let Some(t) = t {
            symbol_us.set(symbol_us.get() + t.elapsed().as_micros() as u64);
            symbol_calls.set(symbol_calls.get() + 1);
        }
        result
    };

    let t = Instant::now();
    let result = disasm.disassemble_with_symbols(arch, &data, address, count, symbol_resolver);
    // Includes the resolver time, reported separately below.
    span.attr_elapsed("decode_us", t);
    span.attr("symbolize_us", symbol_us.get());
    span.attr("resolver_calls", symbol_calls.get());

    // Resolve indirect jump/call targets (e.g., `call qword ptr [IAT_slot]`)
    // by reading the pointer value so clicking navigates to the actual
    // function. This is best-effort and speculative: for misdecoded data the
    // target is garbage/unmapped, so the backend supplies a fast pointer read
    // (no partial-read fallback, no error log). One reader is shared by every
    // read in the batch (IAT-heavy code has hundreds).
    let mut instructions = result?;
    span.attr("instructions", instructions.len() as u64);
    let t = Instant::now();
    let mut indirect_reads = 0u64;
    let is_indirect = |i: &Instruction| (i.is_call || i.is_jump) && i.jump_target.is_some() && i.op_str.contains('[');
    let ptr_reader = instructions.iter().any(is_indirect).then(pointer_reader).flatten();
    if let Some(read_ptr) = ptr_reader {
        for instr in &mut instructions {
            if is_indirect(instr) {
                let ptr_addr = instr.jump_target.unwrap();
                indirect_reads += 1;
                if let Some(actual_target) = read_ptr(ptr_addr) {
                    instr.jump_target = Some(actual_target);
                }
            }
        }
    }
    span.attr_elapsed("indirect_us", t);
    span.attr("indirect_reads", indirect_reads);

    // Annotate with source lines from already-parsed line tables only: a table
    // still parsing in the background is skipped, so bulk disassembly never
    // stalls behind one.
    if let Some(symbol_manager) = symbol_manager {
        let t = Instant::now();
        for instr in &mut instructions {
            instr.line_info = symbol_manager.try_resolve_address_to_line_cached(&modules_for_lines, instr.address);
            // At a symbol start, collect every name sharing this address (aliases
            // like NtClose/ZwClose) so the UI can show all labels, not just the
            // one `symbol_info` picked. Gated on offset == 0 to avoid a lookup for
            // the vast majority of instructions that sit mid-symbol.
            if instr.symbol_info.as_ref().is_some_and(|s| s.offset == 0) {
                let all = symbol_manager.resolve_all_at_exact_address(&modules_for_lines, instr.address);
                // Keep the trait-default seed (the single resolved symbol) if
                // the alias lookup unexpectedly comes back empty.
                if !all.is_empty() {
                    instr.symbols_at_address = all;
                }
            }
        }
        span.attr_elapsed("lines_us", t);
    }
    Ok(instructions)
}

/// `(function start, function end, name)` of the function containing an
/// address, from whatever table the backend has (`.pdata`, `.eh_frame`).
pub type FunctionBounds = Option<(u64, u64, Option<String>)>;

/// Backward disassembly anchored on a guaranteed instruction boundary: the
/// containing function's start or the nearest symbol start - so the forward
/// decode is exactly aligned all the way to `target` with no guessing. We
/// probe near `target - back` first (to preserve full backward reach); if that
/// byte sits in an uncovered gap we fall back to the boundary containing the
/// byte just before `target` (aligning at least the rows nearest `target`),
/// and finally to the plain self-resync window when no boundary is known
/// (leaf/JIT code, no symbols).
pub fn disassemble_backward_anchored<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    target: u64,
    count: usize,
    arch: Architecture,
    symbol_manager: Option<&SymbolManager>,
    modules: &[ModuleInfo],
    bounds: &dyn Fn(u64) -> FunctionBounds,
    options: DisasmOptions,
) -> Result<Vec<Instruction>, DisassemblerError> {
    if count == 0 || target == 0 {
        return Ok(Vec::new());
    }
    let mut span = crate::perf::span("disasm.backward");
    if options.naive {
        span.attr("naive", 1);
        return platform.disassemble_backward_resync(pid, target, count, arch);
    }
    let symbol_manager = symbol_manager.filter(|_| options.symbolizes());
    let back = crate::interfaces::backward_resync_window(arch, count);
    let fallback_start = target.saturating_sub(back);
    // Never anchor an anchored decode more than this far before `target`, so a
    // huge function can't turn each scroll-up tick into a massive re-decode.
    const MAX_ANCHOR_SPAN: u64 = 8192;
    let min_anchor = target.saturating_sub(MAX_ANCHOR_SPAN.max(back));

    // Largest guaranteed instruction boundary <= `probe`, within
    // [min_anchor, target): function start first, then nearest symbol.
    let boundary_before = |probe: u64| -> Option<u64> {
        let mut best: Option<u64> = None;
        if let Some((func_start, _, _)) = bounds(probe) {
            if func_start >= min_anchor && func_start < target {
                best = Some(func_start);
            }
        }
        if let Some(symbol_manager) = symbol_manager {
            if let Ok(Some((_, _, offset))) = symbol_manager.try_resolve_address_to_symbol(modules, probe) {
                let sym_start = probe.saturating_sub(offset);
                if sym_start >= min_anchor && sym_start < target {
                    best = Some(best.map_or(sym_start, |b| b.max(sym_start)));
                }
            }
        }
        best
    };

    // No known boundary (leaf/JIT code, no symbols) - plain self-resync
    // fallback, provided by the trait. An anchor needs no region clamp: it
    // is already inside a mapped module and `boundary_before` guarantees
    // min_anchor <= start < target.
    let t = std::time::Instant::now();
    let anchor = boundary_before(fallback_start).or_else(|| boundary_before(target - 1));
    span.attr_elapsed("anchor_us", t);
    let Some(start) = anchor else {
        span.attr("anchored", 0);
        return platform.disassemble_backward_resync(pid, target, count, arch);
    };
    let window = (target - start) as usize;
    span.attr("anchored", 1);
    span.attr("window_bytes", window as u64);
    let instructions = platform.disassemble_memory_bytes(pid, start, window, arch)?;
    Ok(crate::interfaces::align_backward_instructions(instructions, target, count))
}

/// Disassemble a function with bounds detection.
/// Returns (instructions, function_start, function_end, function_name).
pub fn disassemble_function<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    address: u64,
    max_instructions: usize,
    arch: Architecture,
    bounds: FunctionBounds,
) -> Result<(Vec<Instruction>, Option<u64>, Option<u64>, Option<String>), DisassemblerError> {
    let mut span = crate::perf::span("disasm.function");
    span.attr("has_bounds", bounds.is_some() as u64);
    let mut decodes = 0u64;
    let (func_start, func_end, func_name) = match &bounds {
        Some((start, end, name)) => (Some(*start), Some(*end), name.clone()),
        None => (None, None, None),
    };
    // Whole-function decode when it fits, else a bounded window at the
    // address - see `decode_function_listing` for why.
    let instructions = crate::interfaces::decode_function_listing(
        bounds.map(|(s, e, _)| (s, e)),
        address,
        max_instructions,
        |start, count| {
            decodes += 1;
            platform.disassemble_memory(pid, start, count, arch)
        },
    )?;
    // 2 = the whole-function decode had no row at `address` and ran again.
    span.attr("decodes", decodes);
    span.attr("instructions", instructions.len() as u64);
    Ok((instructions, func_start, func_end, func_name))
}
