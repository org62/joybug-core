use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::convert::TryInto;

use msvc_demangler::DemangleFlags;
use pelite::pe64::{Pe, PeFile};
use pelite::image::IMAGE_DEBUG_TYPE_CODEVIEW;
use pelite::Error as PeliteError;
use pdb::{PDB, PublicSymbol, SymbolData, FallibleIterator};
use symsrv::{SymsrvDownloader, parse_nt_symbol_path, get_symbol_path_from_environment, get_home_sym_dir};
use tracing::{trace, debug};
use uuid::Uuid;
use tokio::runtime::Runtime;

use crate::interfaces::{Address, Symbol, SymbolError, SymbolProvider};

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

/// A Windows-specific symbol provider that uses PDB files.
/// It can download PDBs from symbol servers and parse them to provide symbol information.
pub struct WindowsSymbolProvider {
    downloader: SymsrvDownloader,
    runtime: Runtime,
    /// Stores loaded symbols for modules.
    /// Key: Module path (String)
    /// Value: Tuple of (Module Base Address, Module Size (Option<usize>), Vec<Symbol from debugger_interface>)
    loaded_modules: HashMap<String, (Address, Option<usize>, Vec<Symbol>)>,
}

impl WindowsSymbolProvider {
    pub fn new() -> Result<Self, SymbolError> {
        // Create tokio runtime for async operations
        let runtime = Runtime::new()
            .map_err(|e| SymbolError::SymSrvError(format!("Failed to create async runtime: {}", e)))?;

        // Parse the _NT_SYMBOL_PATH environment variable using symsrv
        let symbol_path_env = get_symbol_path_from_environment();
        let symbol_path = symbol_path_env.as_deref().unwrap_or("srv**https://msdl.microsoft.com/download/symbols");
        let parsed_symbol_path = parse_nt_symbol_path(symbol_path);

        // Create a downloader which follows the _NT_SYMBOL_PATH recipe
        let mut downloader = SymsrvDownloader::new(parsed_symbol_path);
        downloader.set_default_downstream_store(get_home_sym_dir());

        trace!(symbol_path, "Using symsrv downloader with symbol path");

        Ok(Self {
            downloader,
            runtime,
            loaded_modules: HashMap::new(),
        })
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

    /// Internal helper to parse a PDB file and return a vector of `Symbol` structs.
    /// RVAs are stored as found in the PDB.
    fn internal_parse_pdb_to_symbols(&self, pdb_path: &Path) -> Result<Vec<Symbol>, SymbolError> {
        trace!(path = %pdb_path.display(), "Parsing PDB file");
        let file = File::open(pdb_path).map_err(SymbolError::IoError)?;
        let mut pdb_parser = PDB::open(file)
            .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB::open for {}: {}", pdb_path.display(), e)))?;

        let mut symbols_vec = Vec::new();

        let global_symbols = pdb_parser.global_symbols()
            .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB global_symbols from {}: {}", pdb_path.display(), e)))?;
        
        let address_map = pdb_parser.address_map()
            .map_err(|e| SymbolError::PdbParsingFailed(format!("PDB address_map from {}: {}", pdb_path.display(), e)))?;
        
        let mut iter = global_symbols.iter();
        loop {
            match iter.next() {
                Ok(Some(symbol)) => {
                    match symbol.parse() {
                        Ok(SymbolData::Public(PublicSymbol { name, offset, .. })) => {
                            let symbol_name_str = name.to_string();
                            let demangled_name = if symbol_name_str.starts_with('?') {
                                msvc_demangler::demangle(&symbol_name_str, DemangleFlags::COMPLETE)
                                    .unwrap_or_else(|_| symbol_name_str.clone().into_owned())
                            } else {
                                symbol_name_str.into_owned()
                            };
                            
                            let rva = offset.to_rva(&address_map).unwrap_or_default().0;
                            
                            symbols_vec.push(Symbol {
                                name: demangled_name,
                                rva, 
                            });
                        }
                        Ok(_other_data) => { /* Optionally handle other symbol types or log them */ }
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

        trace!(count = symbols_vec.len(), "Successfully parsed symbols from PDB");
        Ok(symbols_vec)
    }
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
        
        // Fetch the PDB file
        let downloaded_pdb_path = self.internal_fetch_pdb(&pdb_identifier.name, &symsrv_id)?;
        
        // Parse the PDB file
        let symbols = self.internal_parse_pdb_to_symbols(&downloaded_pdb_path)?;
        
        // Store the symbols
        self.loaded_modules.insert(module_path_str.to_string(), (module_base, module_size, symbols));
        
        trace!(module_path = module_path_str, symbol_count = self.loaded_modules.get(module_path_str).unwrap().2.len(), "Successfully loaded symbols for module");
        Ok(())
    }

    fn find_symbol(
        &self,
        module_path: &str,
        symbol_name: &str,
    ) -> Result<Option<Symbol>, SymbolError> {
        if let Some((_base, _size, symbols)) = self.loaded_modules.get(module_path) {
            let found_symbol = symbols.iter().find(|s| s.name == symbol_name).cloned();
            trace!(module_path, symbol_name, found = found_symbol.is_some(), "Symbol lookup completed");
            Ok(found_symbol)
        } else {
            trace!(module_path, symbol_name, "No symbols loaded for module");
            Err(SymbolError::ModuleNotLoaded(format!("Module {} not loaded", module_path)))
        }
    }

    fn list_symbols(&self, module_path: &str) -> Result<Vec<Symbol>, SymbolError> {
        if let Some((_base, _size, symbols)) = self.loaded_modules.get(module_path) {
            trace!(module_path, count = symbols.len(), "Symbol listing completed");
            Ok(symbols.clone())
        } else {
            trace!(module_path, "No symbols loaded for module");
            Err(SymbolError::ModuleNotLoaded(format!("Module {} not loaded", module_path)))
        }
    }

    fn resolve_rva_to_symbol(
        &self,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<Symbol>, SymbolError> {
        if let Some((_base, _size, symbols)) = self.loaded_modules.get(module_path) {
            // Find the symbol with the highest RVA that is still <= the target RVA
            let mut best_match: Option<&Symbol> = None;
            for symbol in symbols {
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