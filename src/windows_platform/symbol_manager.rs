use crate::interfaces::{ModuleSymbol, ResolvedSymbol, SymbolError, SymbolProvider};
use crate::protocol::ModuleInfo;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tracing::{trace, warn};
use crate::windows_platform::symbol_provider::WindowsSymbolProvider;

/// Cached symbols for a single module with RVA-based storage
#[derive(Debug, Clone)]
pub struct ModuleSymbols {
    pub module_base: u64, // Base address where the module is loaded
    pub symbols: Vec<ModuleSymbol>, // All symbols stored as RVAs
}

/// Manages symbol loading for modules in the Windows platform
/// Uses RVA-based storage for efficient sharing across processes
pub struct SymbolManager {
    /// Track loading tasks for modules
    loading_tasks: Arc<Mutex<HashMap<String, JoinHandle<Result<(), SymbolError>>>>>,
    /// Store loaded symbols for fast access (module_path -> ModuleSymbols)
    /// All symbols are stored as RVAs, independent of process loading addresses
    symbol_cache: Arc<Mutex<HashMap<String, ModuleSymbols>>>,
}

impl SymbolManager {
    pub fn new() -> Result<Self, SymbolError> {
        Ok(Self {
            loading_tasks: Arc::new(Mutex::new(HashMap::new())),
            symbol_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Start loading symbols for a module in the background
    pub fn start_loading_symbols(&self, module: &ModuleInfo) {
        let module_path = module.name.clone();
        let module_base = module.base;
        let module_size = module.size.map(|s| s as usize);
        
        let tasks = Arc::clone(&self.loading_tasks);
        let cache = Arc::clone(&self.symbol_cache);
        let module_path_for_task = module_path.clone();
        
        let task = std::thread::spawn(move || {
            trace!(module_path = %module_path_for_task, "Starting background symbol loading");
            
            // Create a temporary provider for this task
            let mut temp_provider = match WindowsSymbolProvider::new() {
                Ok(provider) => provider,
                Err(e) => {
                    warn!(module_path = %module_path_for_task, error = %e, "Failed to create symbol provider");
                    let mut tasks_guard = tasks.lock().unwrap();
                    tasks_guard.remove(&module_path_for_task);
                    return Err(e);
                }
            };
            
            // Load symbols synchronously
            let result = temp_provider.load_symbols_for_module(&module_path_for_task, module_base, module_size);
            
            match &result {
                Ok(()) => {
                    trace!(module_path = %module_path_for_task, "Symbol loading completed successfully");
                    // Store the loaded symbols in the cache
                    if let Ok(symbols) = temp_provider.list_symbols(&module_path_for_task) {
                        let mut cache_guard = cache.lock().unwrap();
                        let module_symbols = ModuleSymbols {
                            module_base: module_base,
                            symbols: symbols.clone(),
                        };
                        cache_guard.insert(module_path_for_task.clone(), module_symbols);
                        trace!(count = symbols.len(), "Successfully stored symbols in cache");
                    }
                },
                Err(e) => warn!(module_path = %module_path_for_task, error = %e, "Symbol loading failed"),
            }
            
            // Remove the task from tracking when done
            {
                let mut tasks_guard = tasks.lock().unwrap();
                tasks_guard.remove(&module_path_for_task);
            }
            
            result
        });
        
        // Store the task handle
        {
            let mut tasks_guard = self.loading_tasks.lock().unwrap();
            if let Some(_old_task) = tasks_guard.insert(module_path, task) {
                // Note: std::thread::JoinHandle doesn't have abort, so we just replace it
                // The old thread will complete and remove itself from the map
            }
        }
    }

    /// Wait for symbol loading to complete for a module if it's in progress
    fn wait_for_loading(&self, module_path: &str) -> Result<(), SymbolError> {
        // Check if there's a task for this module and wait for it to complete
        loop {
            let task_handle = {
                let mut tasks_guard = self.loading_tasks.lock().unwrap();
                tasks_guard.remove(module_path)
            };
            
            if let Some(handle) = task_handle {
                trace!(module_path, "Waiting for symbol loading thread to complete");
                // Wait for the thread to complete
                match handle.join() {
                    Ok(result) => {
                        match result {
                            Ok(()) => trace!(module_path, "Symbol loading completed successfully"),
                            Err(e) => warn!(module_path, error = %e, "Symbol loading failed"),
                        }
                        break;
                    }
                    Err(_) => {
                        warn!(module_path, "Symbol loading thread panicked");
                        break;
                    }
                }
            } else {
                // No task running for this module
                break;
            }
        }
        Ok(())
    }

    /// Find symbols across all loaded modules, returning up to max_results matches
    /// Supports Windows-style "module!symbol" format (e.g., "ntdll!NtCreateFile")
    pub fn find_symbol_across_all_modules(&self, symbol_name: &str, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        let cache = self.symbol_cache.lock().unwrap();
        let mut found_symbols = Vec::new();
        
        // Check if the symbol name contains module specification (module!symbol format)
        if let Some(exclamation_pos) = symbol_name.find('!') {
            let (target_module_name, target_symbol_name) = symbol_name.split_at(exclamation_pos);
            let target_symbol_name = &target_symbol_name[1..]; // Skip the '!' character
            
            // Search only in the specified module
            for (module_path, module_symbols) in cache.iter() {
                // Extract module name from path
                let module_name = std::path::Path::new(module_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(module_path);
                
                // Check if this is the target module (case-insensitive)
                if module_name.to_lowercase() == target_module_name.to_lowercase() {
                    // Find all matching symbols in this specific module
                    for symbol in &module_symbols.symbols {
                        if symbol.name.to_lowercase().contains(&target_symbol_name.to_lowercase()) {
                            let symbol_name_with_module = format!("{}!{}", module_name, symbol.name);
                            found_symbols.push(ResolvedSymbol { 
                                name: symbol_name_with_module, 
                                module_name: module_name.to_string(),
                                rva: symbol.rva,
                                va: module_symbols.module_base + symbol.rva as u64,
                            });
                            
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
            for (_module_path, module_symbols) in cache.iter() {
                // Extract module name from path
                let module_name = std::path::Path::new(_module_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(_module_path)
                    .to_string();
                    
                // Find all matching symbols in this module (contains-based search)
                for symbol in &module_symbols.symbols {
                    if symbol.name.to_lowercase().contains(&symbol_name.to_lowercase()) {
                        let symbol_name_with_module = format!("{}!{}", module_name, symbol.name);
                        found_symbols.push(ResolvedSymbol { 
                            name: symbol_name_with_module, 
                            module_name: module_name.clone(),
                            rva: symbol.rva,
                            va: module_symbols.module_base + symbol.rva as u64,
                        });
                        
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

    /// Resolve an RVA to a symbol, waiting for loading to complete if necessary
    /// This method works directly with RVAs since symbols are stored as RVAs
    pub fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<ResolvedSymbol>, SymbolError> {
        self.wait_for_loading(module_path)?;
        
        let cache = self.symbol_cache.lock().unwrap();
        if let Some(module_symbols) = cache.get(module_path) {
            // Find the symbol with the highest RVA that is still <= the target RVA
            let mut best_match: Option<&ModuleSymbol> = None;
            for symbol in &module_symbols.symbols {
                if symbol.rva <= rva && (best_match.is_none() || symbol.rva > best_match.unwrap().rva) {
                    best_match = Some(symbol);
                }
            }
            
            match best_match {
                Some(symbol) => {
                    // Extract module name from path
                    let module_name = std::path::Path::new(module_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(module_path)
                        .to_string();
                        
                    // Calculate VA for the returned symbol
                    let symbol_with_va = ResolvedSymbol {
                        name: symbol.name.clone(),
                        module_name,
                        rva: symbol.rva,
                        va: module_symbols.module_base + symbol.rva as u64,
                    };
                    
                    trace!(module_path, rva = format!("0x{:X}", rva), symbol_name = %symbol.name, symbol_rva = format!("0x{:X}", symbol.rva), symbol_va = format!("0x{:X}", symbol_with_va.va), offset = rva - symbol.rva, "RVA resolved to symbol");
                    Ok(Some(symbol_with_va))
                }
                None => {
                    trace!(module_path, rva = format!("0x{:X}", rva), "No symbol found for RVA");
                    Ok(None)
                }
            }
        } else {
            trace!(module_path, rva = format!("0x{:X}", rva), "No symbols loaded for module");
            Ok(None)
        }
    }

    /// Resolve an absolute address to a symbol by finding the appropriate module
    /// This is the new implementation that properly uses RVA-based symbol storage
    pub fn resolve_address_to_symbol(&self, modules: &[ModuleInfo], address: u64) -> Result<Option<(String, ResolvedSymbol, u64)>, SymbolError> {
        // Find the module that contains this address
        let containing_module = modules.iter().find(|module| {
            let module_end = module.base + module.size.unwrap_or(0);
            address >= module.base && address < module_end
        });

        if let Some(module) = containing_module {
            // Calculate the RVA (Relative Virtual Address) from the module base
            let rva = (address - module.base) as u32;
            
            // Use the RVA-based symbol resolution
            match self.resolve_rva_to_symbol(&module.name, rva)? {
                Some(symbol) => {
                    // Calculate offset from the symbol's RVA
                    let offset_from_symbol = address - (module.base + symbol.rva as u64);
                    // put only module name, not the full path
                    let module_name = std::path::Path::new(&module.name)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&module.name)
                        .to_string();
                    Ok(Some((module_name, symbol, offset_from_symbol)))
                }
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
    
    /// List all symbols in the specified module as raw ModuleSymbols (without VA calculation)
    pub fn list_symbols_raw(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        self.wait_for_loading(module_path)?;
        
        let cache = self.symbol_cache.lock().unwrap();
        if let Some(module_symbols) = cache.get(module_path) {
            trace!(module_path, count = module_symbols.symbols.len(), "Raw symbol listing completed");
            Ok(module_symbols.symbols.clone())
        } else {
            trace!(module_path, "No symbols loaded for module");
            Ok(Vec::new())
        }
    }

    /// Resolve an RVA to a symbol as raw ModuleSymbol (without VA calculation)
    pub fn resolve_rva_to_symbol_raw(&self, module_path: &str, rva: u32) -> Result<Option<ModuleSymbol>, SymbolError> {
        self.wait_for_loading(module_path)?;
        
        let cache = self.symbol_cache.lock().unwrap();
        if let Some(module_symbols) = cache.get(module_path) {
            // Find the symbol with the highest RVA that is still <= the target RVA
            let mut best_match: Option<&ModuleSymbol> = None;
            for symbol in &module_symbols.symbols {
                if symbol.rva <= rva && (best_match.is_none() || symbol.rva > best_match.unwrap().rva) {
                    best_match = Some(symbol);
                }
            }
            
            match best_match {
                Some(symbol) => {
                    trace!(module_path, rva = format!("0x{:X}", rva), symbol_name = %symbol.name, symbol_rva = format!("0x{:X}", symbol.rva), offset = rva - symbol.rva, "RVA resolved to raw symbol");
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

    /// Resolve an absolute address to a raw ModuleSymbol (without VA calculation)
    pub fn resolve_address_to_symbol_raw(&self, modules: &[ModuleInfo], address: u64) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError> {
        // Find the module that contains this address
        let containing_module = modules.iter().find(|module| {
            let module_end = module.base + module.size.unwrap_or(0);
            address >= module.base && address < module_end
        });

        if let Some(module) = containing_module {
            // Calculate the RVA (Relative Virtual Address) from the module base
            let rva = (address - module.base) as u32;
            
            // Use the RVA-based symbol resolution to get raw ModuleSymbol
            match self.resolve_rva_to_symbol_raw(&module.name, rva)? {
                Some(symbol) => {
                    // Calculate offset from the symbol's RVA
                    let offset_from_symbol = address - (module.base + symbol.rva as u64);
                    // Extract only module name, not the full path
                    let module_name = std::path::Path::new(&module.name)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&module.name)
                        .to_string();
                    Ok(Some((module_name, symbol, offset_from_symbol)))
                }
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

} 