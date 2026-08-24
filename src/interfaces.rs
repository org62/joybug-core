use thiserror::Error;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::protocol::{MinidumpKind, ModuleInfo, ProcessInfo, ProcessObjects, ThreadInfo};

pub type Address = u64;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("OS error: {0}")]
    OsError(String),
    #[error("Not implemented")]
    NotImplemented,
    #[error("Other: {0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum SymbolError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("PE parsing failed: {0}")]
    PeParsingFailed(String),
    #[error("PDB parsing failed: {0}")]
    PdbParsingFailed(String),
    #[error("PDB not found: {0}")]
    PdbNotFound(String),
    #[error("Symbols not found: {0}")]
    SymbolsNotFound(String),
    /// The module's symbols are still being loaded in the background. Callers that
    /// enumerate symbols must retry (poll `GetSymbolStatus`) rather than treat the
    /// result as "this module has no symbols" — a large PDB can take minutes.
    #[error("Symbols are still loading for {0}")]
    SymbolsStillLoading(String),
    #[error("SymSrv error: {0}")]
    SymSrvError(String),
    #[error("Module not loaded: {0}")]
    ModuleNotLoaded(String),
}

/// Configuration for symbol resolution, plumbed from the embedding application.
#[derive(Debug, Clone, Default)]
pub struct SymbolConfig {
    /// Overrides the `_NT_SYMBOL_PATH` environment variable when set.
    pub symbol_path: Option<String>,
    /// When true, remote symbol-server URLs are stripped so nothing is downloaded;
    /// local caches and directories still resolve.
    pub offline: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleSymbol {
    pub name: String,
    pub rva: u32, // Relative Virtual Address
    pub is_function: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSymbol {
    pub name: String,
    pub module_name: String,
    pub rva: u32, // Relative Virtual Address
    pub va: u64,  // Virtual Address (module_base + rva)
    pub is_function: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Architecture {
    X64,
    Arm64,
}

impl Architecture {
    pub fn from_native() -> Self {
        if cfg!(target_arch = "x86_64") { Architecture::X64 } else { Architecture::Arm64 }
    }

    /// Longest possible instruction encoding, in bytes (ARM64 is fixed-width).
    pub fn max_instruction_len(self) -> usize {
        match self {
            Architecture::X64 => 15,
            Architecture::Arm64 => 4,
        }
    }
}

/// Byte window for a self-resync backward decode of `count` instructions:
/// one max-length instruction per row plus one extra instruction of lead-in,
/// which gives an x86 decode room to resynchronize before it reaches the
/// target (ARM64 is fixed-width, so any aligned start decodes exactly).
pub fn backward_resync_window(arch: Architecture, count: usize) -> u64 {
    let max_ilen = arch.max_instruction_len() as u64;
    max_ilen * count as u64 + max_ilen
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    pub size: usize,
    pub symbol_info: Option<SymbolInfo>,
    pub symbolized_op_str: Option<String>, // Operands with symbolized addresses
    pub is_jump: bool,           // jmp, jcc instructions (conditional/unconditional jumps)
    pub is_call: bool,           // call instruction
    pub is_ret: bool,            // ret instruction
    pub jump_target: Option<u64>, // Target address if resolvable (for jumps/calls)
    /// Absolute address of a memory operand when statically resolvable
    /// (RIP-relative or absolute displacement) — the data address the
    /// instruction reads/writes, e.g. `mov rdx, [rip + 0xNN]`. Unlike
    /// `addresses_to_symbolize` this never contains plain immediates, so a UI
    /// can offer "go to memory" only for real memory references.
    #[serde(default)]
    pub mem_ref: Option<u64>,
    pub addresses_to_symbolize: Vec<u64>, // Addresses extracted from operands for symbolization
    #[serde(default)]
    pub line_info: Option<SourceLineRef>, // Source file/line, if the module's line table is loaded
    /// Every symbol that starts exactly at this address (offset 0). More than one
    /// name can share an address — e.g. ntdll's `NtClose`/`ZwClose` aliases — so the
    /// UI can render all of them as label rows. `symbol_info` still carries the single
    /// nearest-below symbol (used for the `+offset` display and operand symbolization);
    /// this is populated only at exact symbol starts and is otherwise empty.
    #[serde(default)]
    pub symbols_at_address: Vec<SymbolInfo>,
    /// True for a synthetic 1-byte placeholder emitted where a byte could not be
    /// decoded (rendered as `db 0xXX`). Lets the decoder continue past bad bytes
    /// instead of truncating the whole listing (x64dbg-style).
    #[serde(default)]
    pub is_invalid: bool,
}

/// A source file referenced by a module's PDB line table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceFileEntry {
    /// File path as recorded in the PDB (compile-time path).
    pub path: String,
    /// Checksum algorithm: "md5" | "sha1" | "sha256" | "none".
    pub checksum_kind: String,
    /// Hex-encoded checksum of the file contents; empty when kind is "none".
    pub checksum: String,
}

/// One address-range → source-line mapping from a PDB line table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LineEntry {
    pub rva: u32,
    /// Byte length of the covered code; 0 if unknown.
    pub length: u32,
    /// Index into the module's deduplicated source file list.
    pub file_index: u32,
    pub line_start: u32,
    pub line_end: u32,
    pub col_start: Option<u32>,
    pub col_end: Option<u32>,
}

/// A resolved source location attached to an instruction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceLineRef {
    pub file_path: String,
    pub line: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolInfo {
    pub module_name: String,
    pub symbol_name: String,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallFrame {
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub symbol: Option<SymbolInfo>,
}

pub trait InstructionFormatter {
    fn format_disassembly(&self) -> String;
}

impl InstructionFormatter for Vec<Instruction> {
    fn format_disassembly(&self) -> String {
        if self.is_empty() {
            return "No instructions".to_string();
        }
        
        let mut result = String::new();
        result.push_str("Disassembly:\n");
        
        for instruction in self {
            result.push_str(&format!("{}\n", instruction));
        }
        
        result
    }
}

impl InstructionFormatter for &[Instruction] {
    fn format_disassembly(&self) -> String {
        self.to_vec().format_disassembly()
    }
}

#[derive(Debug, Error)]
pub enum DisassemblerError {
    #[error("Capstone error: {0}")]
    CapstoneError(String),
    #[error("Unsupported architecture: {0:?}")]
    UnsupportedArchitecture(Architecture),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub trait SymbolProvider: Send + Sync {
    fn load_symbols_for_module(
        &mut self,
        module_path: &str,
        module_base: Address,
        module_size: Option<usize>,
    ) -> Result<(), SymbolError>;

    fn find_symbol(
        &self,
        symbol_name: &str,
        max_results: usize,
    ) -> Result<Vec<ResolvedSymbol>, SymbolError>;

    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError>;

    fn resolve_rva_to_symbol(
        &self,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<ModuleSymbol>, SymbolError>;
}

pub trait DisassemblerProvider: Send + Sync {
    fn disassemble(
        &self,
        arch: Architecture,
        data: &[u8],
        address: u64,
        count: usize,
    ) -> Result<Vec<Instruction>, DisassemblerError>;

    fn disassemble_single(
        &self,
        arch: Architecture,
        data: &[u8],
        address: u64,
    ) -> Result<Option<Instruction>, DisassemblerError> {
        let instructions = self.disassemble(arch, data, address, 1)?;
        Ok(instructions.into_iter().next())
    }
    
    fn disassemble_with_symbols<F>(
        &self,
        arch: Architecture,
        data: &[u8],
        address: u64,
        count: usize,
        symbol_resolver: F,
    ) -> Result<Vec<Instruction>, DisassemblerError>
    where
        F: Fn(u64) -> Option<SymbolInfo>,
    {
        let mut instructions = self.disassemble(arch, data, address, count)?;
        for instruction in &mut instructions {
            instruction.symbol_info = symbol_resolver(instruction.address);
            // At an exact symbol start, seed `symbols_at_address` with the resolved
            // name so every decode path yields at least one label. Platforms with a
            // richer symbol source (WindowsPlatform) overwrite this with the full
            // alias set during enrichment.
            if let Some(s) = instruction.symbol_info.as_ref().filter(|s| s.offset == 0) {
                instruction.symbols_at_address = vec![s.clone()];
            }

            // Symbolize operand addresses using pre-extracted address list (no regex).
            // Only exact symbol hits (offset 0) are substituted — a mid-symbol
            // target keeps its raw address rather than a misleading `sym+0xNNN`.
            if !instruction.addresses_to_symbolize.is_empty() {
                let mut op_str = instruction.op_str.clone();
                for addr in &instruction.addresses_to_symbolize {
                    if let Some(symbol) = symbol_resolver(*addr).filter(|s| s.offset == 0) {
                        let symbol_str = symbol.format_symbol();
                        // Try direct hex replacement first (for absolute addresses)
                        let hex_lower = format!("0x{:x}", addr);
                        let hex_upper = format!("0x{:X}", addr);
                        let before = op_str.clone();
                        op_str = op_str.replace(&hex_lower, &symbol_str);
                        op_str = op_str.replace(&hex_upper, &symbol_str);

                        // Fallback: RIP-relative pattern replacement
                        // Capstone outputs [rip + 0xNNNN] but the resolved address isn't in the text
                        if op_str == before {
                            let disp = (*addr).wrapping_sub(instruction.address + instruction.size as u64) as i64;
                            let (pattern, replacement) = if disp >= 0 {
                                (format!("[rip + 0x{:x}]", disp), format!("[{}]", symbol_str))
                            } else {
                                (format!("[rip - 0x{:x}]", disp.unsigned_abs()), format!("[{}]", symbol_str))
                            };
                            op_str = op_str.replace(&pattern, &replacement);
                        }
                    }
                }
                if op_str != instruction.op_str {
                    instruction.symbolized_op_str = Some(op_str);
                }
            }
        }
        Ok(instructions)
    }
}

pub trait Stepper: Send + Sync {
    fn step(&mut self, pid: u32, tid: u32, kind: crate::protocol::StepKind) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
}

pub trait PlatformAPI: Send + Sync {
    fn attach(&mut self, pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn detach(&mut self, pid: u32) -> Result<(), PlatformError>;
    /// Open a process non-invasively (OpenProcess only, no debugger attach) so
    /// read-only capabilities work without a debug loop.
    fn open_process(&mut self, _pid: u32) -> Result<(), PlatformError> { Err(PlatformError::NotImplemented) }
    /// Release a non-invasively opened process.
    fn close_process(&mut self, _pid: u32) -> Result<(), PlatformError> { Err(PlatformError::NotImplemented) }
    fn continue_exec(&mut self, pid: u32, tid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn set_breakpoint(&mut self, pid: u32, addr: u64, tid: Option<u32>) -> Result<(), PlatformError>;
    fn remove_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError>;
    fn set_single_shot_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError>;
    fn set_hardware_breakpoint(&mut self, pid: u32, addr: u64, bp_type: crate::protocol::HardwareBreakpointType, size: crate::protocol::HardwareBreakpointSize) -> Result<u8, PlatformError>;
    fn remove_hardware_breakpoint(&mut self, pid: u32, addr: u64) -> Result<(), PlatformError>;

    // Code-coverage: silent, server-side-counted software breakpoints. Hits are
    // counted in the server and the debuggee auto-continues without notifying the
    // client (see `handle_exception_event`). `limit` is the hit count after which
    // each breakpoint is auto-removed (`0` = never, `1` = remove on first hit).
    fn start_code_coverage(&mut self, _pid: u32, _addrs: &[u64], _limit: u64) -> Result<(), PlatformError> { Err(PlatformError::NotImplemented) }
    /// Enumerate every address in `module_path` worth arming a coverage
    /// breakpoint on: `.pdata` RUNTIME_FUNCTION starts unioned with the module's
    /// symbols. Symbols the PDB marks as functions are taken as-is; the rest
    /// (labels, and publics from PDBs that never set the function flag) must
    /// pass a code-sanity check first, since a coverage breakpoint writes an
    /// `int3` and one landing in a variable corrupts the target. Every returned
    /// address is in committed executable memory.
    ///
    /// Independent of symbols by design: a stripped or obfuscated module still
    /// yields its exception-directory functions.
    /// `sources` restricts which tiers contribute; empty means all. Anything not
    /// requested is never computed, so asking for `[Pdata]` alone skips symbol
    /// enumeration and the code-sanity sweep outright.
    fn enumerate_coverage_targets(
        &self,
        _pid: u32,
        _module_path: &str,
        _sources: &[crate::protocol::CoverageTargetSource],
    ) -> Result<Vec<crate::protocol::CoverageTarget>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// Fetch a [`crate::protocol::CoverageHit`] (address, hit count, first-hit
    /// order, thread ids) for every coverage breakpoint hit at least once
    /// (never-hit addresses are omitted; the client knows the armed set).
    fn get_code_coverage(&self, _pid: u32) -> Result<Vec<crate::protocol::CoverageHit>, PlatformError> { Err(PlatformError::NotImplemented) }
    /// Remove all coverage breakpoints and clear coverage state.
    fn stop_code_coverage(&mut self, _pid: u32) -> Result<(), PlatformError> { Err(PlatformError::NotImplemented) }

    // Hardware access trace: a hardware watchpoint (Write / ReadWrite) run in
    // silent "find what accesses this address" mode. Each read/write is recorded
    // server-side (the accessing instruction pointer) and the target auto-continues
    // without notifying the client (see `handle_exception_event`).
    /// Arm a watchpoint at `addr` and start collecting accessors.
    fn start_watchpoint_trace(&mut self, _pid: u32, _addr: u64, _bp_type: crate::protocol::HardwareBreakpointType, _size: crate::protocol::HardwareBreakpointSize) -> Result<(), PlatformError> { Err(PlatformError::NotImplemented) }
    /// Fetch a [`crate::protocol::WatchpointAccess`] for every distinct instruction
    /// that has accessed the watched `addr` at least once.
    fn get_watchpoint_accesses(&self, _pid: u32, _addr: u64) -> Result<Vec<crate::protocol::WatchpointAccess>, PlatformError> { Err(PlatformError::NotImplemented) }
    /// Remove the watchpoint at `addr` and clear its collected accesses.
    fn stop_watchpoint_trace(&mut self, _pid: u32, _addr: u64) -> Result<(), PlatformError> { Err(PlatformError::NotImplemented) }
    fn launch(&mut self, command: &str, debug_children: bool, working_directory: Option<&str>, environment: Option<&[(String, String)]>) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>;
    fn read_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>, PlatformError>;
    fn write_memory(&self, pid: u32, address: u64, data: &[u8]) -> Result<(), PlatformError>;
    fn read_wide_string(&self, pid: u32, address: u64, max_len: Option<usize>) -> Result<String, PlatformError>;
    fn get_thread_context(&self, pid: u32, tid: u32) -> Result<crate::protocol::ThreadContext, PlatformError>;
    fn set_thread_context(&self, pid: u32, tid: u32, context: crate::protocol::ThreadContext) -> Result<(), PlatformError>;
    fn get_function_arguments(&self, pid: u32, tid: u32, count: usize) -> Result<Vec<u64>, PlatformError>;
    fn list_modules(&self, pid: u32) -> Result<Vec<ModuleInfo>, PlatformError>;
    fn list_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError>;
    // Thread control. Suspend/resume return the *previous* suspend count.
    fn suspend_thread(&self, _pid: u32, _tid: u32) -> Result<u32, PlatformError> { Err(PlatformError::NotImplemented) }
    fn resume_thread(&self, _pid: u32, _tid: u32) -> Result<u32, PlatformError> { Err(PlatformError::NotImplemented) }
    fn terminate_thread(&self, _pid: u32, _tid: u32, _exit_code: u32) -> Result<(), PlatformError> { Err(PlatformError::NotImplemented) }
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError>;
    
    // Symbol-related methods
    fn find_symbol(&self, symbol_name: &str, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError>;
    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError>;
    fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<ModuleSymbol>, SymbolError>;
    fn resolve_address_to_symbol(&self, pid: u32, address: u64) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError>; // Returns (module_path, symbol, offset_from_symbol)

    /// Resolve many addresses to symbols WITHOUT waiting on in-flight symbol
    /// loads: an address in a module whose symbols are still loading yields
    /// `None` immediately instead of stalling behind the parse (the blocking
    /// `resolve_address_to_symbol` waits up to the platform's timeout). One
    /// result per input address, in order; callers re-request once
    /// `get_symbol_status` reports the load settled. The default loops the
    /// blocking resolver — platforms with background symbol loading should
    /// override to guarantee the non-waiting behavior.
    fn try_resolve_addresses_to_symbols(&self, pid: u32, addresses: &[u64]) -> Result<Vec<Option<(String, ModuleSymbol, u64)>>, SymbolError> {
        Ok(addresses
            .iter()
            .map(|&address| self.resolve_address_to_symbol(pid, address).ok().flatten())
            .collect())
    }

    /// Every symbol whose VA lies in `[start, start + len)`, ascending by VA,
    /// capped at `max_results`. Non-blocking like
    /// `try_resolve_addresses_to_symbols`: modules whose symbols are still
    /// loading contribute nothing. Used to annotate a memory window.
    fn symbols_in_range(&self, _pid: u32, _start: u64, _len: u64, _max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Symbol range queries not supported by this platform".to_string()))
    }

    /// Per-module symbol load status (loaded/loading/failed/not requested).
    fn get_symbol_status(&self, _pid: u32) -> Result<Vec<crate::protocol::ModuleSymbolStatus>, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Symbol status not supported by this platform".to_string()))
    }
    /// Load symbols for a module from a user-supplied PDB file.
    /// Unless `force`, the PDB's GUID/age must match the module's PE debug directory;
    /// a mismatch is a negotiable outcome (`PdbLoadOutcome::Mismatch`), not an error.
    fn load_pdb_from_path(&self, _pid: u32, _module_base: u64, _pdb_path: &str, _force: bool) -> Result<crate::protocol::PdbLoadOutcome, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Loading PDB from path not supported by this platform".to_string()))
    }
    /// Retry a failed symbol download for a module.
    fn retry_symbol_load(&self, _pid: u32, _module_base: u64) -> Result<(), SymbolError> {
        Err(SymbolError::SymbolsNotFound("Symbol retry not supported by this platform".to_string()))
    }
    /// Unload a module's symbols and every derived cache (line tables, type info,
    /// pdata, failure markers), freeing their memory.
    fn unload_module_symbols(&self, _pid: u32, _module_base: u64) -> Result<(), SymbolError> {
        Err(SymbolError::SymbolsNotFound("Symbol unload not supported by this platform".to_string()))
    }
    /// Replace the set of modules (lowercased file names) whose automatic symbol
    /// download is suppressed.
    fn set_symbol_deny_list(&self, _modules: Vec<String>) -> Result<(), SymbolError> {
        Err(SymbolError::SymbolsNotFound("Symbol deny list not supported by this platform".to_string()))
    }

    // Source line methods (PDB line tables)
    /// Resolve an address to a source file/line. Lazily parses the module's line table.
    fn resolve_address_to_line(&self, _pid: u32, _address: u64) -> Result<Option<crate::protocol::AddressLineInfo>, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Source line resolution not supported by this platform".to_string()))
    }
    /// All line→address entries for one source file of a module, plus the matched
    /// file record. `start_line`/`end_line` (inclusive, 1-based) bound the returned
    /// entries by `line_start`; `None` = whole file.
    fn get_source_file_line_map(&self, _pid: u32, _module_base: u64, _file_path: &str, _start_line: Option<u32>, _end_line: Option<u32>) -> Result<(Option<SourceFileEntry>, Vec<LineEntry>), SymbolError> {
        Err(SymbolError::SymbolsNotFound("Source line maps not supported by this platform".to_string()))
    }
    /// All source files referenced by a module's PDB line table.
    fn list_source_files(&self, _pid: u32, _module_base: u64) -> Result<Vec<SourceFileEntry>, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Source file listing not supported by this platform".to_string()))
    }

    // Type system methods (PDB TPI stream)
    /// List UDT/enum type summaries from loaded module PDBs. `module_base = None`
    /// searches all loaded modules; `filter` is a case-insensitive name substring.
    fn list_types(&self, _pid: u32, _module_base: Option<u64>, _filter: Option<&str>, _max_results: usize) -> Result<Vec<crate::protocol::TypeSummary>, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Type listing not supported by this platform".to_string()))
    }
    /// Resolve a named type's layout. `module_base = None` searches all modules.
    fn get_type(&self, _pid: u32, _module_base: Option<u64>, _name: &str) -> Result<Option<crate::protocol::TypeLayout>, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Type resolution not supported by this platform".to_string()))
    }
    /// Resolve a type by its TPI index within a specific module (nested expansion).
    fn get_type_by_index(&self, _pid: u32, _module_base: u64, _index: u32) -> Result<Option<crate::protocol::TypeLayout>, SymbolError> {
        Err(SymbolError::SymbolsNotFound("Type resolution not supported by this platform".to_string()))
    }

    // Symbolized disassembly methods
    fn disassemble_memory(&self, pid: u32, address: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError>;

    /// Like `disassemble_memory`, but bounded by bytes instead of instruction
    /// count: decodes only instructions contained entirely within
    /// `[address, address + byte_len)`. The default trims a plain
    /// `disassemble_memory` decode; platforms should override it to also bound
    /// the underlying read (`disassemble_memory` reads `count * 16` bytes and
    /// decodes past the window, wasting reads/symbolization and risking a
    /// wholesale read failure if the over-read straddles an unmapped page).
    fn disassemble_memory_bytes(&self, pid: u32, address: u64, byte_len: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        let end = address.saturating_add(byte_len as u64);
        let instructions = self.disassemble_memory(pid, address, byte_len, arch)?;
        Ok(instructions
            .into_iter()
            .take_while(|i| i.address + i.size as u64 <= end)
            .collect())
    }

    /// Disassemble up to `count` instructions ending immediately before `target`
    /// ("backward disassembly", x64dbg-style). Decodes forward from a point safely
    /// before `target` and exploits x86 self-resynchronization: a linear decode
    /// started at a slightly-wrong offset re-aligns to the true instruction stream
    /// within a few instructions. `target` is expected to be a real instruction
    /// boundary (it is when scrolling up: the address of an already-decoded row, or
    /// the trap RIP after a retired instruction). Used to let the UI scroll up past
    /// functions with no `.pdata` bounds, and to attribute HW-watchpoint accesses.
    ///
    /// The backward read is clamped to the containing memory region's base so
    /// [start, target) never touches an unmapped page (such a read fails
    /// wholesale, e.g. just before a section); platforms whose
    /// `query_memory_region` errors keep the unclamped start.
    fn disassemble_backward(&self, pid: u32, target: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        self.disassemble_backward_resync(pid, target, count, arch)
    }

    /// The plain self-resync backward decode described on `disassemble_backward`.
    /// Split out so platform overrides that anchor on known boundaries (see
    /// WindowsPlatform) can delegate here when no boundary is available, instead
    /// of duplicating this window/clamp logic.
    fn disassemble_backward_resync(&self, pid: u32, target: u64, count: usize, arch: Architecture) -> Result<Vec<Instruction>, DisassemblerError> {
        if count == 0 || target == 0 {
            return Ok(Vec::new());
        }
        let back = backward_resync_window(arch, count);
        let mut start = target.saturating_sub(back);
        // Region-clamp only when the window can cross a 4K page boundary —
        // within one page it's mapped iff `target` is, and skipping the query
        // matters on the per-access watchpoint hot path.
        if start >> 12 != (target - 1) >> 12 {
            if let Ok(region) = self.query_memory_region(pid, target - 1) {
                if region.base_address > start && region.base_address <= target {
                    start = region.base_address;
                }
            }
        }
        if start >= target {
            return Ok(Vec::new());
        }
        let window = (target - start) as usize;
        let instructions = self.disassemble_memory_bytes(pid, start, window, arch)?;
        Ok(align_backward_instructions(instructions, target, count))
    }

    // Call stack methods
    fn get_call_stack(&self, pid: u32, tid: u32) -> Result<Vec<CallFrame>, PlatformError>;
    // Process control
    fn terminate_process(&self, pid: u32) -> Result<(), PlatformError>;
    // Break into a running, debugged process (fire-and-forget)
    fn break_into(&self, pid: u32) -> Result<(), PlatformError>;
    
    // Module extra info
    fn get_module_extra_info(&self, pid: u32, module_base: u64) -> Result<crate::pe_types::ModuleExtraInfo, PlatformError>;

    // Memory region queries
    fn query_memory_region(&self, pid: u32, address: u64) -> Result<crate::protocol::MemoryRegionInfo, PlatformError>;
    fn enumerate_memory_regions(&self, pid: u32) -> Result<Vec<crate::protocol::MemoryRegionInfo>, PlatformError>;

    // Dereference/telescope
    /// Telescope `count` pointer-sized slots starting at `address`.
    ///
    /// `probe_start` says whether `address` is itself a pointer whose *target*
    /// should be described first (a register: `rip` → the instruction it points
    /// at, `rcx` → the string it points at). Pass `false` when `address` is just
    /// where a value lives (a memory slot in the hex view): then only the stored
    /// value is followed, so code bytes are reported as a plain `Value` instead
    /// of "the instruction at this slot".
    fn dereference(
        &self,
        pid: u32,
        address: u64,
        count: usize,
        reference_base: Option<u64>,
        probe_start: bool,
    ) -> Result<Vec<crate::protocol::DereferenceEntry>, PlatformError>;

    /// Telescope many independent addresses at once. The default loops
    /// `dereference`; platforms should override to enumerate memory regions only
    /// once for the whole batch (the enumeration dominates the cost, and the
    /// registers panel telescopes ~16 addresses on every step). Returns one
    /// entry list per input address, in order.
    fn dereference_batch(
        &self,
        pid: u32,
        addresses: &[u64],
        count: usize,
        reference_base: Option<u64>,
        probe_start: bool,
    ) -> Result<Vec<Vec<crate::protocol::DereferenceEntry>>, PlatformError> {
        addresses
            .iter()
            .map(|&address| self.dereference(pid, address, count, reference_base, probe_start))
            .collect()
    }

    /// Write a minidump of the process to `path` (a path on the machine running
    /// the platform). Returns the file size in bytes.
    fn write_minidump(&self, _pid: u32, _path: &str, _kind: MinidumpKind) -> Result<u64, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// Kernel handles, windows, TCP connections and token privileges of the
    /// process (the Handles window).
    fn list_process_objects(&self, _pid: u32) -> Result<ProcessObjects, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// Close a handle inside the target process.
    fn close_remote_handle(&self, _pid: u32, _handle: u64) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// Enable/disable a named privilege on the target's primary token.
    fn set_privilege(&self, _pid: u32, _name: &str, _enable: bool) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// `EnableWindow` on a window owned by the target.
    fn set_window_enabled(&self, _pid: u32, _hwnd: u64, _enabled: bool) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    // Thread Environment Block (TEB) address - used for emulator GS segment setup
    fn get_teb_address(&self, _pid: u32, _tid: u32) -> Result<u64, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// Process Environment Block (PEB) base address — used by the
    /// anti-anti-debug subsystem for PEB hiding.
    fn get_peb_address(&self, _pid: u32) -> Result<u64, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// True if the target is a 32-bit (WOW64) process on 64-bit Windows.
    /// Used to bail out of features that assume the 64-bit PEB layout.
    fn is_wow64(&self, _pid: u32) -> Result<bool, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    /// Search process memory for a byte pattern, returning matching addresses.
    /// Scans all committed, readable memory regions in 1MB chunks with overlap
    /// for cross-boundary matches. Uses rayon to parallelize across regions.
    /// Returns up to `max_results` addresses sorted by address.
    fn search_memory(&self, pid: u32, pattern: &[u8], max_results: usize) -> Result<(Vec<u64>, bool), PlatformError>
    where
        Self: Sync,
    {
        if pattern.is_empty() {
            return Err(PlatformError::Other("Search pattern must not be empty".into()));
        }

        let regions = self.enumerate_memory_regions(pid)?;
        let chunk_size: usize = 1024 * 1024; // 1MB

        const PAGE_NOACCESS: u32 = 0x01;
        const PAGE_GUARD: u32 = 0x100;
        const MEM_COMMIT: u32 = 0x1000;

        // Filter to searchable regions
        let searchable_regions: Vec<_> = regions
            .iter()
            .filter(|r| {
                r.state == MEM_COMMIT
                    && r.protect != 0
                    && (r.protect & PAGE_NOACCESS) == 0
                    && (r.protect & PAGE_GUARD) == 0
            })
            .collect();

        let total_found = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);

        let all_results: Vec<Vec<u64>> = searchable_regions
            .par_iter()
            .map(|region| {
                if stop.load(Ordering::Relaxed) {
                    return Vec::new();
                }

                let region_base = region.base_address;
                let region_size = region.region_size as usize;
                let overlap = if pattern.len() > 1 { pattern.len() - 1 } else { 0 };
                let mut offset: usize = 0;
                let mut local_results = Vec::new();

                while offset < region_size {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let read_size = (chunk_size + overlap).min(region_size - offset);
                    let read_addr = region_base + offset as u64;

                    match self.read_memory(pid, read_addr, read_size) {
                        Ok(data) => {
                            if data.len() >= pattern.len() {
                                let mut i = 0;
                                while i <= data.len() - pattern.len() {
                                    if data[i..i + pattern.len()] == *pattern {
                                        local_results.push(read_addr + i as u64);
                                        let prev = total_found.fetch_add(1, Ordering::Relaxed);
                                        if prev + 1 >= max_results * 2 {
                                            stop.store(true, Ordering::Relaxed);
                                            return local_results;
                                        }
                                    }
                                    i += 1;
                                }
                            }
                        }
                        Err(_) => {
                            // Skip unreadable chunks silently
                        }
                    }

                    if read_size <= overlap {
                        break;
                    }
                    offset += read_size - overlap;
                }

                local_results
            })
            .collect();

        let mut addresses: Vec<u64> = all_results.into_iter().flatten().collect();
        addresses.sort_unstable();
        let capped = addresses.len() > max_results;
        addresses.truncate(max_results);

        Ok((addresses, capped))
    }

    // -----------------------------------------------------------------
    // Server-side dispatch hooks
    //
    // These three methods let the connection handler delegate Continue,
    // TerminateProcess, and BreakInto requests to the platform with its
    // own locking discipline. The default impls take the platform lock
    // and call through the regular trait methods — correct for any
    // backend that does its work inside continue_exec / terminate_process
    // / break_into. WindowsPlatform overrides them so the long-running
    // OS calls (WaitForDebugEvent, etc.) happen outside the lock and
    // don't starve concurrent read-only requests.
    //
    // `Self: Sized` is required so the method can take `&Arc<RwLock<Self>>`;
    // these aren't callable via `&dyn PlatformAPI`, which is fine — they
    // run from the generic connection handler.
    // -----------------------------------------------------------------

    fn server_continue(
        platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
        tid: u32,
        pass_exception: bool,
    ) -> Result<Option<crate::protocol::DebugEvent>, PlatformError>
    where
        Self: Sized,
    {
        let _ = pass_exception;
        platform.write().unwrap().continue_exec(pid, tid)
    }

    fn server_terminate(
        platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
    ) -> Result<(), PlatformError>
    where
        Self: Sized,
    {
        platform.read().unwrap().terminate_process(pid)
    }

    fn server_break_into(
        platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
    ) -> Result<(), PlatformError>
    where
        Self: Sized,
    {
        platform.read().unwrap().break_into(pid)
    }

    /// Release an already-exited process: acknowledge its final debug event and
    /// drop the handles keeping it alive. Must NOT wait for a further debug event
    /// — the process is gone and none will come.
    ///
    /// The default impl is a no-op — backends whose debug events need an explicit
    /// acknowledgement, or that hold per-process handles (Windows), override it.
    fn server_finalize_exited_process(
        platform: &std::sync::Arc<std::sync::RwLock<Self>>,
        pid: u32,
        tid: u32,
    ) -> Result<(), PlatformError>
    where
        Self: Sized,
    {
        let _ = (platform, pid, tid);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Optional backend-specific features. Default impls return
    // NotImplemented; WindowsPlatform overrides them.
    // -----------------------------------------------------------------

    fn emulate_with_mode(
        &self,
        _pid: u32,
        _tid: u32,
        _max_instructions: usize,
        _mode: crate::protocol::EmulationMode,
        _exit_condition: Option<crate::protocol::TraceExitCondition>,
        _memory_reads: &[(u64, usize)],
    ) -> Result<crate::emulator::EmulationResult, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn trace_instructions(
        &mut self,
        _pid: u32,
        _tid: u32,
        _exit_condition: crate::protocol::TraceExitCondition,
        _max_instructions: usize,
    ) -> Result<(Vec<crate::protocol::TraceEntry>, String, u64), PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn disassemble_function(
        &self,
        _pid: u32,
        _address: u64,
        _max_instructions: usize,
        _arch: Architecture,
    ) -> Result<(Vec<Instruction>, Option<u64>, Option<u64>, Option<String>), DisassemblerError> {
        Err(DisassemblerError::CapstoneError(
            "disassemble_function not supported by this platform".into(),
        ))
    }
}

/// From a forward linear decode `ins` (ascending addresses) that was started before
/// `target` and runs past it, return up to `count` instructions immediately preceding
/// `target` — the aligned predecessors. Relies on x86 self-resynchronization: by the
/// time the decode reaches `target` it has realigned to the true instruction stream,
/// so keeping only instructions that end at or before `target` yields the correct
/// predecessors (the last one ends exactly at `target` for well-formed code). Never
/// keeps an instruction that straddles `target`, so the result can't contradict the
/// anchor row.
pub fn align_backward_instructions(ins: Vec<Instruction>, target: u64, count: usize) -> Vec<Instruction> {
    let mut v: Vec<Instruction> = ins
        .into_iter()
        .filter(|i| i.address < target && i.address + i.size as u64 <= target)
        .collect();
    let n = v.len();
    if n > count {
        v.drain(0..n - count);
    }
    v
}

impl SymbolInfo {
    pub fn format_symbol(&self) -> String {
        if self.offset == 0 {
            format!("{}!{}", self.module_name, self.symbol_name)
        } else {
            format!("{}!{}+0x{:x}", self.module_name, self.symbol_name, self.offset)
        }
    }
}
