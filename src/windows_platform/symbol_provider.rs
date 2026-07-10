use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::convert::TryInto;

use msvc_demangler::DemangleFlags;
use pelite::pe64::{Pe, PeFile};
use pelite::image::IMAGE_DEBUG_TYPE_CODEVIEW;
use pelite::Error as PeliteError;
use pdb::{
    AddressMap, FallibleIterator, PdbInternalSectionOffset, ProcedureSymbol, PublicSymbol,
    SymbolData, PDB,
};
use symsrv::{SymsrvDownloader, NtSymbolPathEntry, parse_nt_symbol_path, get_symbol_path_from_environment, get_home_sym_dir};
use tracing::{trace, debug};
use uuid::Uuid;
use tokio::runtime::{Runtime, Builder};

use crate::interfaces::{Address, ModuleSymbol, ResolvedSymbol, SymbolConfig, SymbolError, SymbolProvider};
use crate::protocol::PdbMismatchInfo;

// --- PDB Identifier Logic (adapted from src/windows/symbols/pe_reader.rs) ---

/// Represents the CodeView PDB 7.0 debug information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbIdentifier {
    pub name: String,     // pdb file name
    pub guid: Uuid,       // pdb guid
    pub age: u32,         // pdb age
}

const CV_SIGNATURE_RSDS: u32 = 0x53445352; // "RSDS"

impl PdbIdentifier {
    /// Formats the PDB GUID and Age into a string suitable for SymSrv.
    /// Example: "3844DBB92DE14293A2981A8FBFD868A81" (GUID) + "1" (Age)
    pub fn to_symsrv_identifier(&self) -> String {
        // Format: GUID (uppercase hex, no dashes) followed by Age (uppercase hex)
        // Example: AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP1
        let guid_no_dashes = self.guid.as_bytes().iter().map(|b| format!("{b:02X}")).collect::<String>();
        format!("{}{:X}", guid_no_dashes, self.age)
    }
}

/// Extracts PDB identification information (name, GUID, age) from a PE file.
pub fn extract_pdb_identifier_from_file(module_path: &Path) -> Result<PdbIdentifier, SymbolError> {
    let file_map = pelite::FileMap::open(module_path).map_err(SymbolError::IoError)?;
    let pe_file = PeFile::from_bytes(&file_map)
        .map_err(|e: PeliteError| SymbolError::PeParsingFailed(format!("PE parsing for {}: {}", module_path.display(), e)))?;

    let debug_dir = pe_file.debug()
        .map_err(|e: PeliteError| SymbolError::PeParsingFailed(format!("Failed to get debug directory for {}: {}", module_path.display(), e)))?;

    for entry in debug_dir.iter() {
        if entry.image().Type == IMAGE_DEBUG_TYPE_CODEVIEW {
            let raw_data = entry.data()
                .ok_or_else(|| SymbolError::SymbolsNotFound(format!("No data for CodeView entry in {}", module_path.display())))?;
            
            if raw_data.len() >= 24 {
                let signature = u32::from_le_bytes(raw_data[0..4].try_into()
                    .map_err(|_| SymbolError::PeParsingFailed(format!("Invalid CV_SIGNATURE bytes in CV_INFO for {}", module_path.display())))?);

                if signature == CV_SIGNATURE_RSDS {
                    let guid_bytes: [u8; 16] = raw_data[4..20].try_into()
                        .map_err(|_| SymbolError::PeParsingFailed(format!("Invalid GUID bytes in CV_INFO for {}", module_path.display())))?;
                    let age_val = u32::from_le_bytes(raw_data[20..24].try_into()
                        .map_err(|_| SymbolError::PeParsingFailed(format!("Invalid Age bytes in CV_INFO for {}", module_path.display())))?);
                    
                    if raw_data.len() > 24 {
                        let pdb_path_bytes_with_nul = &raw_data[24..];
                        let nul_pos = pdb_path_bytes_with_nul.iter().position(|&b| b == 0)
                            .ok_or_else(|| SymbolError::PeParsingFailed(format!("PDB path not NUL-terminated in {}", module_path.display())))?;
                        
                        let pdb_file_name_str = std::str::from_utf8(&pdb_path_bytes_with_nul[..nul_pos])
                            .map_err(|_| SymbolError::PeParsingFailed(format!("PDB path is not valid UTF-8 in {}", module_path.display())))?;
                        
                        let final_pdb_filename = Path::new(pdb_file_name_str)
                            .file_name()
                            .ok_or_else(|| SymbolError::PeParsingFailed(format!("Could not extract PDB filename from path '{}' in {}", pdb_file_name_str, module_path.display())))?
                            .to_str()
                            .ok_or_else(|| SymbolError::PeParsingFailed(format!("PDB filename is not valid UTF-8 '{}' in {}", pdb_file_name_str, module_path.display())))?
                            .to_string();
                        
                        let data1 = u32::from_le_bytes(guid_bytes[0..4].try_into().unwrap());
                        let data2 = u16::from_le_bytes(guid_bytes[4..6].try_into().unwrap());
                        let data3 = u16::from_le_bytes(guid_bytes[6..8].try_into().unwrap());
                        let data4: [u8; 8] = guid_bytes[8..16].try_into().unwrap();
                        let guid = Uuid::from_fields(data1, data2, data3, &data4);

                        return Ok(PdbIdentifier {
                            name: final_pdb_filename,
                            guid,
                            age: age_val,
                        });
                    }
                }
            }
        }
    }
    Err(SymbolError::SymbolsNotFound(format!("RSDS PDB debug info not found in {}", module_path.display())))
}

// --- Symbol Provider Implementation ---

/// Symbols loaded for a module, plus where they came from.
struct LoadedModule {
    base: Address,
    #[allow(dead_code)]
    size: Option<usize>,
    symbols: Vec<ModuleSymbol>,
    pdb_path: Option<PathBuf>,
}

/// A Windows-specific symbol provider that uses PDB files.
/// It can download PDBs from symbol servers and parse them to provide symbol information.
pub struct WindowsSymbolProvider {
    downloader: SymsrvDownloader,
    runtime: Runtime,
    /// Loaded symbols per module path.
    loaded_modules: HashMap<String, LoadedModule>,
}

impl WindowsSymbolProvider {
    pub fn with_config(cfg: &SymbolConfig) -> Result<Self, SymbolError> {
        // Create a single-threaded tokio runtime for async operations
        // Using current_thread ensures we don't spawn extra threads that might linger
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SymbolError::SymSrvError(format!("Failed to create async runtime: {}", e)))?;

        // Precedence: explicit config > _NT_SYMBOL_PATH > Microsoft symbol server
        let symbol_path_env = get_symbol_path_from_environment();
        let symbol_path = cfg.symbol_path.as_deref()
            .or(symbol_path_env.as_deref())
            .unwrap_or("srv**https://msdl.microsoft.com/download/symbols");
        let mut parsed_symbol_path = parse_nt_symbol_path(symbol_path);

        if cfg.offline {
            // Keep local caches/directories usable but never hit the network.
            for entry in &mut parsed_symbol_path {
                if let NtSymbolPathEntry::Chain { urls, .. } = entry {
                    urls.clear();
                }
            }
        }

        // Create a downloader which follows the _NT_SYMBOL_PATH recipe
        let mut downloader = SymsrvDownloader::new(parsed_symbol_path);
        downloader.set_default_downstream_store(get_home_sym_dir());

        trace!(symbol_path, offline = cfg.offline, "Using symsrv downloader with symbol path");

        Ok(Self {
            downloader,
            runtime,
            loaded_modules: HashMap::new(),
        })
    }

    /// Path of the PDB that symbols for `module_path` were loaded from, if loaded.
    pub fn pdb_path_for(&self, module_path: &str) -> Option<String> {
        self.loaded_modules.get(module_path)
            .and_then(|m| m.pdb_path.as_ref())
            .map(|p| p.display().to_string())
    }

    /// Internal helper to fetch a PDB file using symsrv.
    fn internal_fetch_pdb(&self, pdb_filename: &str, identifier: &str) -> Result<PathBuf, SymbolError> {
        trace!(pdb_filename, identifier, "Attempting to fetch PDB using symsrv");
        
        // Use symsrv to download and cache the PDB file
        let local_path = self.runtime.block_on(async {
            self.downloader.get_file(pdb_filename, identifier).await
        }).map_err(|e| SymbolError::SymSrvError(format!("Failed to download PDB {}/{}: {}", pdb_filename, identifier, e)))?;
        
        debug!(path = %local_path.display(), "Successfully downloaded PDB using symsrv");
        Ok(local_path)
    }

}

fn open_pdb(pdb_path: &Path) -> Result<PDB<'static, File>, SymbolError> {
    let file = File::open(pdb_path).map_err(SymbolError::IoError)?;
    PDB::open(file)
        .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB::open for {}: {}", pdb_path.display(), e)))
}

/// Parse a PDB file and extract symbols as ModuleSymbols.
/// Free function so callers (e.g. user-initiated PDB loads) can parse without a provider.
pub(crate) fn parse_pdb_to_symbols(pdb_path: &Path) -> Result<Vec<ModuleSymbol>, SymbolError> {
    extract_symbols(&mut open_pdb(pdb_path)?, pdb_path)
}

/// Parse a user-supplied PDB after validating its GUID/age against the module's
/// PE debug directory, opening and parsing the PDB only once. The DBI age is
/// authoritative for symbol-store matching; falls back to the PDB info-stream age
/// when the DBI age is absent. On mismatch returns `Ok(Err(info))` without parsing
/// the symbol streams.
pub(crate) fn parse_pdb_matching_pe(
    module_path: &Path,
    pdb_path: &Path,
) -> Result<std::result::Result<Vec<ModuleSymbol>, PdbMismatchInfo>, SymbolError> {
    let pe_id = extract_pdb_identifier_from_file(module_path)?;

    let mut pdb_parser = open_pdb(pdb_path)?;
    let info = pdb_parser.pdb_information()
        .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB information from {}: {}", pdb_path.display(), e)))?;
    let pdb_age = pdb_parser.debug_information()
        .ok()
        .and_then(|dbi| dbi.age())
        .unwrap_or(info.age);

    if info.guid != pe_id.guid || pdb_age != pe_id.age {
        return Ok(Err(PdbMismatchInfo {
            pe_guid: pe_id.guid.to_string(),
            pe_age: pe_id.age,
            pdb_guid: info.guid.to_string(),
            pdb_age,
        }));
    }
    Ok(Ok(extract_symbols(&mut pdb_parser, pdb_path)?))
}

/// Extract symbols from an already-open PDB parser.
fn extract_symbols(pdb_parser: &mut PDB<'static, File>, pdb_path: &Path) -> Result<Vec<ModuleSymbol>, SymbolError> {
        trace!(path = %pdb_path.display(), "Parsing PDB file");

        // Use a HashMap to deduplicate symbols by name.
        // Procedure symbols from DBI modules are inserted first (Phase 1),
        // then public/global symbols (Phase 2). Using or_insert() means
        // procedure symbols take priority over public symbols with the same name,
        // matching WinDbg's resolution behavior for private functions.
        let mut symbols_map: HashMap<String, ModuleSymbol> = HashMap::new();

        let address_map = pdb_parser.address_map()
            .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB address_map from {}: {}", pdb_path.display(), e)))?;

        // Phase 1: Parse procedure symbols from DBI module streams.
        // These contain private function symbols (e.g., _LdrpInitialize) that
        // are not present in the global symbol stream.
        // Scoped so DebugInformation is dropped before Phase 2 calls global_symbols().
        {
            let dbi = pdb_parser.debug_information()
                .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB debug_information from {}: {}", pdb_path.display(), e)))?;
            let mut modules = dbi.modules()
                .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB modules from {}: {}", pdb_path.display(), e)))?;

            while let Ok(Some(module)) = modules.next() {
                let module_info = match pdb_parser.module_info(&module) {
                    Ok(Some(info)) => info,
                    Ok(None) => continue,
                    Err(e) => {
                        trace!(error = %e, module = %module.module_name(), "Failed to get module info, skipping");
                        continue;
                    }
                };

                let symbols = match module_info.symbols() {
                    Ok(s) => s,
                    Err(e) => {
                        trace!(error = %e, module = %module.module_name(), "Failed to get module symbols, skipping");
                        continue;
                    }
                };

                let mut sym_iter = symbols;
                loop {
                    match sym_iter.next() {
                        Ok(Some(symbol)) => {
                            if let Ok(SymbolData::Procedure(ProcedureSymbol { name, offset, .. })) = symbol.parse() {
                                insert_symbol(&name.to_string(), offset, &address_map, &mut symbols_map, true);
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            trace!(error = %e, module = %module.module_name(), "Failed to iterate module symbols, skipping rest");
                            break;
                        }
                    }
                }
            }
        }

        // Phase 2: Parse public and procedure symbols from the global symbol stream.
        // Public symbols provide exported function names. Using or_insert() ensures
        // procedure symbols from Phase 1 are not overwritten.
        let global_symbols = pdb_parser.global_symbols()
            .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB global_symbols from {}: {}", pdb_path.display(), e)))?;

        let mut iter = global_symbols.iter();
        loop {
            match iter.next() {
                Ok(Some(symbol)) => {
                    match symbol.parse() {
                        Ok(SymbolData::Public(PublicSymbol { name, offset, function, .. })) => {
                            insert_symbol(&name.to_string(), offset, &address_map, &mut symbols_map, function);
                        }
                        Ok(SymbolData::Procedure(ProcedureSymbol { name, offset, .. })) => {
                            insert_symbol(&name.to_string(), offset, &address_map, &mut symbols_map, true);
                        }
                        Ok(_other_data) => { /* Skip other symbol types */ }
                        Err(pdb_parse_err) => {
                            trace!(error = %pdb_parse_err, "Failed to parse some PDB symbol, skipping");
                        }
                    }
                }
                Ok(None) => break,
                Err(pdb_iter_err) => {
                    trace!(error = %pdb_iter_err, "Failed to iterate over some PDB symbols, skipping");
                    break;
                }
            }
        }

        let symbols_vec: Vec<ModuleSymbol> = symbols_map.into_values().collect();
        trace!(count = symbols_vec.len(), "Successfully parsed symbols from PDB");
        Ok(symbols_vec)
}

/// Helper to demangle a symbol name and insert it into the symbols map.
/// Uses `or_insert` so the first occurrence wins (procedure symbols from DBI
/// modules take priority over later public symbols with the same name).
fn insert_symbol(
    name_str: &str,
    offset: PdbInternalSectionOffset,
    address_map: &AddressMap,
    symbols_map: &mut HashMap<String, ModuleSymbol>,
    is_function: bool,
) {
    let demangled_name = if name_str.starts_with('?') {
        msvc_demangler::demangle(name_str, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| name_str.to_string())
    } else {
        name_str.to_string()
    };

    let rva = offset.to_rva(address_map).unwrap_or_default().0;

    symbols_map.entry(demangled_name.clone()).or_insert(ModuleSymbol {
        name: demangled_name,
        rva,
        is_function,
    });
}

impl SymbolProvider for WindowsSymbolProvider {
    fn load_symbols_for_module(
        &mut self,
        module_path_str: &str,
        module_base: Address,
        module_size: Option<usize>,
    ) -> Result<(), SymbolError> {
        trace!(module_path = module_path_str, module_base = format!("0x{:X}", module_base), "Loading symbols for module");

        if self.loaded_modules.contains_key(module_path_str) {
            trace!(module_path = module_path_str, "Symbols already loaded for module");
            return Ok(());
        }

        let module_path = Path::new(module_path_str);

        // Extract PDB identifier from the PE file
        let pdb_identifier = extract_pdb_identifier_from_file(module_path)?;
        let symsrv_id = pdb_identifier.to_symsrv_identifier();

        trace!(pdb_name = %pdb_identifier.name, pdb_guid = %pdb_identifier.guid, pdb_age = pdb_identifier.age, symsrv_id = %symsrv_id, "Extracted PDB identifier");

        // First, check if PDB exists in the same directory as the executable
        let pdb_path = if let Some(parent_dir) = module_path.parent() {
            let local_pdb_path = parent_dir.join(&pdb_identifier.name);
            if local_pdb_path.exists() {
                trace!(path = %local_pdb_path.display(), "Found PDB in same directory as executable");
                local_pdb_path
            } else {
                // Fall back to symsrv download
                self.internal_fetch_pdb(&pdb_identifier.name, &symsrv_id)?
            }
        } else {
            // No parent directory, fall back to symsrv download
            self.internal_fetch_pdb(&pdb_identifier.name, &symsrv_id)?
        };

        // Parse the PDB file
        let symbols = parse_pdb_to_symbols(&pdb_path)?;

        // Store the symbols
        trace!(module_path = module_path_str, symbol_count = symbols.len(), "Successfully loaded symbols for module");
        self.loaded_modules.insert(module_path_str.to_string(), LoadedModule {
            base: module_base,
            size: module_size,
            symbols,
            pdb_path: Some(pdb_path),
        });
        Ok(())
    }

    fn find_symbol(
        &self,
        symbol_name: &str,
        max_results: usize,
    ) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        let mut found_symbols = Vec::new();
        
        // Check if the symbol name contains module specification (module!symbol format)
        if let Some(exclamation_pos) = symbol_name.find('!') {
            let (target_module_name, target_symbol_name) = symbol_name.split_at(exclamation_pos);
            let target_symbol_name = &target_symbol_name[1..]; // Skip the '!' character
            
            // Search only in the specified module
            for (module_path, module) in &self.loaded_modules {
                // Extract module name from path
                let module_name = std::path::Path::new(module_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(module_path);
                
                // Check if this is the target module (case-insensitive)
                if module_name.to_lowercase() == target_module_name.to_lowercase() {
                    // Find all matching symbols in this specific module
                    for symbol in &module.symbols {
                        if symbol.name == target_symbol_name {
                            // Create ResolvedSymbol with VA calculated
                            let resolved_symbol = ResolvedSymbol {
                                name: format!("{}!{}", module_name, symbol.name),
                                module_name: module_name.to_string(),
                                rva: symbol.rva,
                                va: module.base + symbol.rva as u64,
                                is_function: symbol.is_function,
                            };
                            
                            found_symbols.push(resolved_symbol);
                            
                            // Stop if we've reached the maximum number of results
                            if found_symbols.len() >= max_results {
                                trace!(symbol_name, found_count = found_symbols.len(), max_results, "Module-specific symbol search completed (max results reached)");
                                return Ok(found_symbols);
                            }
                        }
                    }
                    break; // We found the target module, no need to continue
                }
            }
        } else {
            // Search through all loaded modules (original behavior with contains matching)
            for (module_path, module) in &self.loaded_modules {
                // Extract module name from path  
                let module_name = std::path::Path::new(module_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(module_path)
                    .to_string();
                    
                // Find all matching symbols in this module (contains-based search)
                for symbol in &module.symbols {
                    if symbol.name.to_lowercase().contains(&symbol_name.to_lowercase()) {
                        // Create ResolvedSymbol with VA calculated
                        let resolved_symbol = ResolvedSymbol {
                            name: format!("{}!{}", module_name, symbol.name),
                            module_name: module_name.clone(),
                            rva: symbol.rva,
                            va: module.base + symbol.rva as u64,
                            is_function: symbol.is_function,
                        };
                        
                        found_symbols.push(resolved_symbol);
                        
                        // Stop if we've reached the maximum number of results
                        if found_symbols.len() >= max_results {
                            trace!(symbol_name, found_count = found_symbols.len(), max_results, "Symbol search completed (max results reached)");
                            return Ok(found_symbols);
                        }
                    }
                }
            }
        }
        
        trace!(symbol_name, found_count = found_symbols.len(), max_results, "Symbol search completed");
        Ok(found_symbols)
    }

    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        if let Some(module) = self.loaded_modules.get(module_path) {
            trace!(module_path, count = module.symbols.len(), "Symbol listing completed");
            Ok(module.symbols.clone())
        } else {
            trace!(module_path, "No symbols loaded for module");
            Err(SymbolError::ModuleNotLoaded(format!("Module {} not loaded", module_path)))
        }
    }

    fn resolve_rva_to_symbol(
        &self,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<ModuleSymbol>, SymbolError> {
        if let Some(module) = self.loaded_modules.get(module_path) {
            // Find the symbol with the highest RVA that is still <= the target RVA
            let mut best_match: Option<&ModuleSymbol> = None;
            for symbol in &module.symbols {
                if symbol.rva <= rva && (best_match.is_none() || symbol.rva > best_match.unwrap().rva) {
                    best_match = Some(symbol);
                }
            }
            
            match best_match {
                Some(symbol) => {
                    trace!(module_path, rva = format!("0x{:X}", rva), symbol_name = %symbol.name, symbol_rva = format!("0x{:X}", symbol.rva), offset = rva - symbol.rva, "RVA resolved to symbol");
                    Ok(Some(symbol.clone()))
                }
                None => {
                    trace!(module_path, rva = format!("0x{:X}", rva), "No symbol found for RVA");
                    Ok(None)
                }
            }
        } else {
            trace!(module_path, rva = format!("0x{:X}", rva), "No symbols loaded for module");
            Err(SymbolError::ModuleNotLoaded(format!("Module {} not loaded", module_path)))
        }
    }
} 