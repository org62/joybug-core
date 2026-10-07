//! The file-format side of symbol loading, behind one object-safe trait so
//! the `SymbolManager` (background loading, caches, lookups) is written once.
//! [`PdbBackend`] is the PE/PDB implementation; the Linux backend supplies an
//! ELF/DWARF one.

use super::symbol_provider::{parse_pdb_matching_pe, parse_pdb_to_lines, parse_pdb_to_symbols, ModuleLineTable, WindowsSymbolProvider};
use super::type_provider::{parse_pdb_to_types, ModuleTypeInfo};
use crate::interfaces::{ModuleSymbol, SymbolConfig, SymbolError, SymbolProvider};
use crate::protocol::{ModuleInfo, PdbMismatchInfo};
use pelite::image::{RUNTIME_FUNCTION, UNWIND_INFO, UNW_FLAG_CHAININFO};
use pelite::pe64::exception_arm64::Arm64ExceptionExt;
use pelite::pe64::{Pe, PeFile};
use std::collections::HashMap;
use std::path::Path;
use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM64;

/// A module's function table: every function's `[begin, end)` RVA range (in
/// the x64 `RUNTIME_FUNCTION` shape whatever the source), plus, for formats
/// with PGO-split fragments, the fragment -> primary map.
pub struct FunctionTable {
    /// Entries sorted by `BeginAddress`.
    pub entries: Vec<RUNTIME_FUNCTION>,
    /// Fragment BeginAddress -> primary function BeginAddress. Only entries
    /// with `UNW_FLAG_CHAININFO` are included, so this is always empty for
    /// ARM64 PE and for ELF.
    pub chain_map: HashMap<u32, u32>,
}

pub trait SymbolBackend: Send + Sync + 'static {
    /// A provider for one worker thread (it owns its own download runtime).
    fn new_provider(&self, cfg: &SymbolConfig) -> Result<Box<dyn SymbolProvider>, SymbolError>;

    /// Symbols readable from the module file itself when no debug file is
    /// available (PE exports; ELF `.dynsym`/`.symtab`). Unsorted.
    fn fallback_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, String>;

    /// Parse a debug file's line table.
    fn parse_lines(&self, debug_file: &Path) -> Result<ModuleLineTable, SymbolError>;

    /// Parse a debug file's type information.
    fn parse_types(&self, debug_file: &Path) -> Result<ModuleTypeInfo, SymbolError>;

    /// The module's function table, from the module file.
    fn function_table(&self, module_path: &str) -> Option<FunctionTable>;

    /// Symbols from a user-supplied debug file. Unless `force`, the file must
    /// match the module; a mismatch is `Ok(Err(info))`, not an error.
    fn load_debug_file(
        &self,
        module: &ModuleInfo,
        debug_file: &Path,
        force: bool,
    ) -> Result<Result<Vec<ModuleSymbol>, PdbMismatchInfo>, SymbolError>;
}

/// PE modules with PDB debug files (Windows targets, and the offline PE
/// analysis on any OS).
pub struct PdbBackend;

impl SymbolBackend for PdbBackend {
    fn new_provider(&self, cfg: &SymbolConfig) -> Result<Box<dyn SymbolProvider>, SymbolError> {
        Ok(Box::new(WindowsSymbolProvider::with_config(cfg)?))
    }

    fn fallback_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, String> {
        parse_export_symbols(module_path)
    }

    fn parse_lines(&self, debug_file: &Path) -> Result<ModuleLineTable, SymbolError> {
        parse_pdb_to_lines(debug_file)
    }

    fn parse_types(&self, debug_file: &Path) -> Result<ModuleTypeInfo, SymbolError> {
        parse_pdb_to_types(debug_file)
    }

    fn function_table(&self, module_path: &str) -> Option<FunctionTable> {
        Self::load_pdata_for_module(module_path)
    }

    fn load_debug_file(
        &self,
        module: &ModuleInfo,
        debug_file: &Path,
        force: bool,
    ) -> Result<Result<Vec<ModuleSymbol>, PdbMismatchInfo>, SymbolError> {
        if force {
            Ok(Ok(parse_pdb_to_symbols(debug_file)?))
        } else {
            parse_pdb_matching_pe(Path::new(&module.name), debug_file)
        }
    }
}

/// Parse a module's PE export table into symbol entries (the no-PDB fallback).
/// Handles both 32- and 64-bit images. Forwarders have no RVA and are skipped;
/// unused ordinal slots (RVA 0) are skipped; nameless exports get a synthetic
/// `Ordinal{n}` name. Returned unsorted; the caller sorts by RVA.
fn parse_export_symbols(module_path: &str) -> Result<Vec<ModuleSymbol>, String> {
    // Map instead of read: only the header + export-directory pages get faulted in.
    let map = pelite::FileMap::open(module_path)
        .map_err(|e| format!("failed to read module: {}", e))?;
    // pelite::PeFile is the 32/64 Wrap; every method used here forwards to both arms.
    let pe = pelite::PeFile::from_bytes(map.as_ref())
        .map_err(|e| format!("PE parse failed: {}", e))?;
    let exports = pe.exports().map_err(|e| format!("no export directory: {}", e))?;
    let by = exports.by().map_err(|e| format!("export table unreadable: {}", e))?;
    let mut index_to_name: HashMap<usize, String> = HashMap::new();
    for (name_res, func_index) in by.iter_name_indices() {
        if let Some(name) = name_res.ok().and_then(|c| c.to_str().ok()) {
            index_to_name.insert(func_index, name.to_string());
        }
    }
    let ordinal_base = by.ordinal_base() as u32;
    let mut symbols: Vec<ModuleSymbol> = Vec::new();
    for (index, result) in by.iter().enumerate() {
        let Ok(pelite::Export::Symbol(&rva)) = result else { continue };
        if rva == 0 {
            continue; // unused ordinal slot
        }
        let name = index_to_name
            .remove(&index)
            .unwrap_or_else(|| format!("Ordinal{}", ordinal_base + index as u32));
        symbols.push(ModuleSymbol { name, rva, is_function: true });
    }
    if symbols.is_empty() {
        return Err("module exports no symbols".to_string());
    }
    Ok(symbols)
}

impl PdbBackend {
    /// Load .pdata and precompute the chain map for a module.
    /// The chain map resolves all UNW_FLAG_CHAININFO entries to their primary function.
    ///
    /// The exception directory is machine-specific: x64 entries are 12-byte
    /// `RUNTIME_FUNCTION`s, ARM64 entries are 8-byte
    /// `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY`s. Parsing an ARM64 directory with the
    /// x64 reader doesn't just misread it, it fails outright (the directory size
    /// is a multiple of 8, rarely of 12), which is why the machine type has to be
    /// consulted before picking a reader.
    pub(crate) fn load_pdata_for_module(module_path: &str) -> Option<FunctionTable> {
        let pe_bytes = std::fs::read(module_path).ok()?;
        let pe = PeFile::from_bytes(&pe_bytes).ok()?;

        if pe.file_header().Machine == IMAGE_FILE_MACHINE_ARM64 {
            return Self::load_arm64_pdata(&pe);
        }

        let exception = pe.exception().ok()?;
        let pdata = exception.image().to_vec();
        if pdata.is_empty() {
            return None;
        }

        // Build chain map: for each entry with UNW_FLAG_CHAININFO, follow the chain
        // to find the primary (non-chained) function entry.
        let mut chain_map = HashMap::new();
        for rf in &pdata {
            if let Ok(primary) = Self::follow_unwind_chain_raw(&pe, rf) {
                if primary != rf.BeginAddress {
                    chain_map.insert(rf.BeginAddress, primary);
                }
            }
        }

        Some(FunctionTable { entries: pdata, chain_map })
    }

    /// ARM64 exception directory, normalized into the x64 `RUNTIME_FUNCTION`
    /// shape the rest of the manager works with.
    ///
    /// `EndAddress` is synthesized: ARM64 entries store only a begin RVA and
    /// unwind data, from which the function length comes either packed in the
    /// entry itself or from the first word of its `.xdata` record. When neither
    /// yields a length, the next entry's begin is used as an upper bound (the
    /// last entry falls back to a zero-length range) so ranges stay ascending and
    /// non-inverted.
    ///
    /// The chain map is always empty here: ARM64 unwind info has no
    /// `UNW_FLAG_CHAININFO` equivalent. Separated function segments are marked by
    /// the packed-fragment flag, which identifies a fragment but does not name
    /// its primary, so there is nothing to map them to.
    fn load_arm64_pdata(pe: &PeFile<'_>) -> Option<FunctionTable> {
        let exception = pe.exception_arm64().ok()?;
        let functions: Vec<(u32, u32, Option<u32>)> = exception
            .functions()
            .map(|f| (f.begin_address(), f.raw_unwind_data(), f.end_address().ok().flatten()))
            .collect();
        if functions.is_empty() {
            return None;
        }

        let pdata: Vec<RUNTIME_FUNCTION> = functions
            .iter()
            .enumerate()
            .map(|(i, &(begin, unwind, end))| {
                let end = end
                    .or_else(|| functions.get(i + 1).map(|&(next_begin, _, _)| next_begin))
                    .filter(|&end| end >= begin)
                    .unwrap_or(begin);
                RUNTIME_FUNCTION { BeginAddress: begin, EndAddress: end, UnwindData: unwind }
            })
            .collect();

        Some(FunctionTable { entries: pdata, chain_map: HashMap::new() })
    }

    /// Follow RUNTIME_FUNCTION unwind chain from a single entry.
    /// Used during cache building to precompute all chains.
    fn follow_unwind_chain_raw<'a>(
        pe: &PeFile<'a>,
        rf: &RUNTIME_FUNCTION,
    ) -> Result<u32, SymbolError> {
        let unwind_info: &UNWIND_INFO = pe.derva(rf.UnwindData)
            .map_err(|e| SymbolError::PeParsingFailed(format!("{:?}", e)))?;
        let flags = unwind_info.VersionFlags >> 3;
        if (flags & UNW_FLAG_CHAININFO) == 0 {
            return Ok(rf.BeginAddress); // Not chained
        }

        // Follow chain
        let mut current_unwind_data = rf.UnwindData;
        let mut current_unwind = unwind_info;
        for _ in 0..32 {
            let count = current_unwind.CountOfCodes as u32;
            let aligned = (count + 1) & !1;
            let chain_rva = current_unwind_data + 4 + aligned * 2;
            let chained_rf: &RUNTIME_FUNCTION = pe.derva(chain_rva)
                .map_err(|e| SymbolError::PeParsingFailed(format!("{:?}", e)))?;

            // Read the chained entry's unwind info
            let next_unwind: &UNWIND_INFO = pe.derva(chained_rf.UnwindData)
                .map_err(|e| SymbolError::PeParsingFailed(format!("{:?}", e)))?;
            let next_flags = next_unwind.VersionFlags >> 3;
            if (next_flags & UNW_FLAG_CHAININFO) == 0 {
                return Ok(chained_rf.BeginAddress); // Found the primary
            }
            current_unwind_data = chained_rf.UnwindData;
            current_unwind = next_unwind;
        }
        Ok(rf.BeginAddress) // Chain too deep, give up
    }
}
