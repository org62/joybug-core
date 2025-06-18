use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::convert::TryInto;

use async_trait::async_trait;
use msvc_demangler::DemangleFlags;
use pelite::pe64::{Pe, PeFile};
use pelite::image::IMAGE_DEBUG_TYPE_CODEVIEW;
use pelite::Error as PeliteError;
use pdb::{PDB, PublicSymbol, SymbolData, FallibleIterator};
use symsrv::{self, SymsrvDownloader};
use tracing::{error, trace, warn};
use uuid::Uuid;

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
    /// Stores loaded symbols for modules.
    /// Key: Module path (String)
    /// Value: Tuple of (Module Base Address, Module Size (Option<usize>), Vec<Symbol from debugger_interface>)
    loaded_modules: HashMap<String, (Address, Option<usize>, Vec<Symbol>)>,
}

impl WindowsSymbolProvider {
    pub fn new() -> Result<Self, SymbolError> {
        let symbol_path_env = symsrv::get_symbol_path_from_environment();
        let symbol_path = symbol_path_env
            .as_deref()
            .unwrap_or("srv*https://msdl.microsoft.com/download/symbols");
        
        trace!(symbol_path, "Using symbol path for WindowsSymbolProvider");
        
        let parsed_symbol_path = symsrv::parse_nt_symbol_path(symbol_path);
        if parsed_symbol_path.is_empty() {
            warn!("Parsed symbol path is empty. Symbol server functionality might be limited.");
        }
        
        let mut downloader = SymsrvDownloader::new(parsed_symbol_path);
        
        if let Some(default_cache) = symsrv::get_home_sym_dir() {
            if !default_cache.exists() {
                if let Err(e) = std::fs::create_dir_all(&default_cache) {
                    warn!(path = %default_cache.display(), error = %e, "Failed to create default symbol cache directory. Caching may be affected.");
                } else {
                    trace!(path = %default_cache.display(), "Created default symbol cache directory.");
                }
            }
            downloader.set_default_downstream_store(Some(default_cache));
        } else {
            warn!("Could not determine default symbol cache directory. Symbol caching might be affected.");
        }

        Ok(Self {
            downloader,
            loaded_modules: HashMap::new(),
        })
    }

    /// Internal helper to fetch a PDB file.
    async fn internal_fetch_pdb(&self, pdb_filename: &str, identifier: &str) -> Result<PathBuf, SymbolError> {
        trace!(pdb_filename, identifier, "Attempting to fetch PDB");
        match self.downloader.get_file(pdb_filename, identifier).await {
            Ok(path_buf) => {
                trace!(path = %path_buf.display(), "Successfully fetched PDB");
                Ok(path_buf)
            }
            Err(e) => {
                let err_msg = format!("SymSrv operation for PDB '{pdb_filename}' (ID: '{identifier}') failed: {e}");
                error!(error = err_msg, "Failed to fetch PDB");
                Err(SymbolError::SymSrvError(err_msg))
            }
        }
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
                            warn!(path = %pdb_path.display(), error = %pdb_parse_err, "Failed to parse a symbol data in PDB, skipping.");
                        }
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(iter_err) => {
                     warn!(path = %pdb_path.display(), error = ?iter_err, "Error iterating PDB global symbols, stopping iteration.");
                     break; 
                }
            }
        }
        trace!(path = %pdb_path.display(), count = symbols_vec.len(), "PDB parsing complete");
        Ok(symbols_vec)
    }
}

#[async_trait]
impl SymbolProvider for WindowsSymbolProvider {
    async fn load_symbols_for_module(
        &mut self,
        module_path_str: &str,
        module_base: Address,
        module_size: Option<usize>,
    ) -> Result<(), SymbolError> {
        trace!(module_path = module_path_str, base = format!("0x{:X}", module_base), "Loading symbols for module");
        
        if self.loaded_modules.contains_key(module_path_str) {
            trace!(module_path = module_path_str, "Symbols already loaded for this module path. Skipping reload.");
            return Ok(());
        }

        let module_path_obj = Path::new(module_path_str);
        if !module_path_obj.exists() {
            error!(module_path = module_path_str, "Module file not found.");
            return Err(SymbolError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, format!("Module file not found: {module_path_str}"))));
        }

        // 1. Extract PDB identifier from the PE file
        let pdb_identifier = extract_pdb_identifier_from_file(module_path_obj)?;
        trace!(name = %pdb_identifier.name, guid = %pdb_identifier.guid, age = pdb_identifier.age, "Extracted PDB info for module {}", module_path_str);

        // 2. Fetch the PDB file
        let symsrv_id = pdb_identifier.to_symsrv_identifier();
        let downloaded_pdb_path = self.internal_fetch_pdb(&pdb_identifier.name, &symsrv_id).await?;
        
        if !downloaded_pdb_path.exists() {
            error!(path = %downloaded_pdb_path.display(), "Fetched PDB file does not exist for module {}", module_path_str);
            return Err(SymbolError::PdbNotFound(format!("Fetched PDB for {} not found at {}", pdb_identifier.name, downloaded_pdb_path.display())));
        }

        // 3. Parse the PDB file
        let symbols = self.internal_parse_pdb_to_symbols(&downloaded_pdb_path)?;
        
        // 4. Store the symbols
        self.loaded_modules.insert(module_path_str.to_string(), (module_base, module_size, symbols));
        let count = self.loaded_modules.get(module_path_str).map_or(0, |(_,_,s)| s.len());
        trace!(module_path = module_path_str, count, "Successfully loaded and parsed symbols");
        
        Ok(())
    }

    async fn find_symbol(
        &self,
        module_path: &str,
        symbol_name: &str,
    ) -> Result<Option<Symbol>, SymbolError> {
        trace!(module_path, symbol_name, "Finding symbol");
        match self.loaded_modules.get(module_path) {
            Some((_base, _size, symbols)) => {
                let found_symbol = symbols.iter().find(|s| s.name == symbol_name).cloned();
                if found_symbol.is_some() {
                    trace!(module_path, symbol_name, "Symbol found.");
                } else {
                    trace!(module_path, symbol_name, "Symbol not found in loaded symbols for module.");
                }
                Ok(found_symbol)
            }
            None => {
                warn!(module_path, symbol_name, "Symbols not loaded for module, cannot find symbol.");
                Err(SymbolError::ModuleNotLoaded(module_path.to_string()))
            }
        }
    }

    async fn list_symbols(&self, module_path: &str) -> Result<Vec<Symbol>, SymbolError> {
        trace!(module_path, "Listing symbols");
        match self.loaded_modules.get(module_path) {
            Some((_base, _size, symbols)) => {
                trace!(module_path, count = symbols.len(), "Returning list of symbols.");
                Ok(symbols.clone())
            }
            None => {
                warn!(module_path, "Symbols not loaded for module, cannot list symbols.");
                Err(SymbolError::ModuleNotLoaded(module_path.to_string()))
            }
        }
    }
    
    async fn resolve_rva_to_symbol(
        &self,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<Symbol>, SymbolError> {
        trace!(module_path, rva = format!("0x{:X}", rva), "Resolving RVA to symbol");
        match self.loaded_modules.get(module_path) {
            Some((_base, _size, symbols)) => {
                let mut best_match: Option<Symbol> = None;
                for symbol_entry in symbols {
                    if symbol_entry.rva <= rva
                        && (best_match.is_none() || symbol_entry.rva > best_match.as_ref().unwrap().rva) {
                            best_match = Some(symbol_entry.clone());
                        }
                }
                if let Some(ref found_symbol) = best_match {
                    trace!(module_path, rva = format!("0x{:X}", rva), symbol_name = %found_symbol.name, symbol_rva = format!("0x{:X}", found_symbol.rva), "RVA resolved.");
                } else {
                    trace!(module_path, rva = format!("0x{:X}", rva), "No symbol found at or before this RVA.");
                }
                Ok(best_match)
            }
            None => {
                warn!(module_path, rva = format!("0x{:X}", rva), "Symbols not loaded for module, cannot resolve RVA.");
                Err(SymbolError::ModuleNotLoaded(module_path.to_string()))
            }
        }
    }
} 