//! Instruction decoding over a tracee: read the bytes, hide our own
//! breakpoint bytes, hand them to Capstone.

use super::breakpoints::BreakpointTable;
use super::dereference::MemoryReader;
use super::disassembler::CapstoneDisassembler;
use super::ops::ProcessOps;
use crate::interfaces::{Architecture, DisassemblerError, DisassemblerProvider, Instruction, PlatformAPI, SymbolInfo};
use crate::protocol::ModuleInfo;
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

/// What a symbolized listing decode needs from the process.
pub struct Listing<'a> {
    pub reader: &'a dyn MemoryReader,
    /// Our own breakpoint bytes are hidden before decoding.
    pub bps: Option<&'a BreakpointTable>,
    pub disasm: &'a CapstoneDisassembler,
    pub symbol_manager: Option<&'a SymbolManager>,
    /// The process's modules (any order).
    pub modules: Vec<ModuleInfo>,
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
    use std::time::Instant;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::cell::Cell;

    // Thread-local timing accumulators
    thread_local! {
        static MEMORY_READ_US: Cell<u64> = const { Cell::new(0) };
        static DISASM_US: Cell<u64> = const { Cell::new(0) };
        static SYMBOL_US: Cell<u64> = const { Cell::new(0) };
        static CALL_COUNT: Cell<u64> = const { Cell::new(0) };
        static SYMBOL_CALLS: Cell<u64> = const { Cell::new(0) };
    }

    let Listing { reader, bps, disasm, symbol_manager, mut modules } = listing;

    // Time memory read
    let t0 = Instant::now();
    let mut data = reader
        .read(address, read_len)
        .map_err(|e| DisassemblerError::InvalidData(format!("Failed to read memory: {}", e)))?;

    // Patch breakpoint bytes with originals so disassembly shows real instructions
    if let Some(bps) = bps {
        bps.patch_breakpoint_bytes(address, &mut data);
    }
    let memory_time = t0.elapsed();

    // Sort modules by base address for binary search
    modules.sort_by_key(|m| m.base);
    // The symbol resolver closure consumes `modules`; keep a copy for line annotation.
    let modules_for_lines = modules.clone();

    // Track symbol resolution time
    let symbol_time_us = std::sync::Arc::new(AtomicU64::new(0));
    let symbol_call_count = std::sync::Arc::new(AtomicU64::new(0));
    let symbol_time_clone = symbol_time_us.clone();
    let symbol_count_clone = symbol_call_count.clone();

    let symbol_resolver = move |addr: u64| -> Option<SymbolInfo> {
        let t = Instant::now();
        let result = if let Some(symbol_manager) = symbol_manager {
            // Non-blocking: skip symbolization while symbols are still loading rather
            // than stalling the disassembly response behind symbol downloads.
            // The UI re-requests disassembly once symbols finish loading.
            if let Ok(Some((module_path, symbol, offset))) = symbol_manager.try_resolve_address_to_symbol(&modules, addr) {
                let module_name = crate::formatting::module_stem(&module_path);
                Some(SymbolInfo { module_name, symbol_name: symbol.name, offset })
            } else { None }
        } else { None };
        symbol_time_clone.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        symbol_count_clone.fetch_add(1, Ordering::Relaxed);
        result
    };

    // Time disassembly
    let t2 = Instant::now();
    let result = disasm.disassemble_with_symbols(arch, &data, address, count, symbol_resolver);
    let disasm_time = t2.elapsed();

    // Accumulate timing stats
    MEMORY_READ_US.with(|c| c.set(c.get() + memory_time.as_micros() as u64));
    DISASM_US.with(|c| c.set(c.get() + disasm_time.as_micros() as u64));
    SYMBOL_US.with(|c| c.set(c.get() + symbol_time_us.load(Ordering::Relaxed)));
    SYMBOL_CALLS.with(|c| c.set(c.get() + symbol_call_count.load(Ordering::Relaxed)));
    let call_count = CALL_COUNT.with(|c| { c.set(c.get() + 1); c.get() });

    // Print stats every 1000 calls
    if call_count % 1000 == 0 {
        let mem_ms = MEMORY_READ_US.with(|c| c.get()) as f64 / 1000.0;
        let dis_ms = DISASM_US.with(|c| c.get()) as f64 / 1000.0;
        let sym_ms = SYMBOL_US.with(|c| c.get()) as f64 / 1000.0;
        let sym_calls = SYMBOL_CALLS.with(|c| c.get());
        println!("\n=== TIMING STATS after {} calls ===", call_count);
        println!("  Memory read:    {:8.2} ms", mem_ms);
        println!("  Disassembly:    {:8.2} ms (includes symbol resolution)", dis_ms);
        println!("  Symbol resolve: {:8.2} ms ({} calls, {:.3} ms/call avg)",
            sym_ms, sym_calls, if sym_calls > 0 { sym_ms / sym_calls as f64 } else { 0.0 });
        println!("=====================================\n");
    }

    // Resolve indirect jump/call targets (e.g., `call qword ptr [IAT_slot]`)
    // by reading the pointer value so clicking navigates to the actual
    // function. This is best-effort and speculative: for misdecoded data the
    // target is garbage/unmapped, so the backend supplies a fast pointer read
    // (no partial-read fallback, no error log). One reader is shared by every
    // read in the batch (IAT-heavy code has hundreds).
    let mut instructions = result?;
    let is_indirect = |i: &Instruction| (i.is_call || i.is_jump) && i.jump_target.is_some() && i.op_str.contains('[');
    let ptr_reader = instructions.iter().any(is_indirect).then(pointer_reader).flatten();
    if let Some(read_ptr) = ptr_reader {
        for instr in &mut instructions {
            if is_indirect(instr) {
                let ptr_addr = instr.jump_target.unwrap();
                if let Some(actual_target) = read_ptr(ptr_addr) {
                    instr.jump_target = Some(actual_target);
                }
            }
        }
    }

    // Annotate with source lines from already-cached line tables only.
    // The first source-view request triggers the parse; until then this is a no-op,
    // so bulk disassembly never stalls behind a line-table parse.
    if let Some(symbol_manager) = symbol_manager {
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
) -> Result<Vec<Instruction>, DisassemblerError> {
    if count == 0 || target == 0 {
        return Ok(Vec::new());
    }
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
    let Some(start) = boundary_before(fallback_start).or_else(|| boundary_before(target - 1)) else {
        return platform.disassemble_backward_resync(pid, target, count, arch);
    };
    let window = (target - start) as usize;
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
        |start, count| platform.disassemble_memory(pid, start, count, arch),
    )?;
    Ok((instructions, func_start, func_end, func_name))
}
