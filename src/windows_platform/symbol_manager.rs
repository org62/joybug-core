use crate::interfaces::{ModuleSymbol, ResolvedSymbol, SymbolError, SymbolProvider};
use crate::protocol::ModuleInfo;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Condvar, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{trace, warn, error};
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
    /// Store loaded symbols for fast access (module_path -> ModuleSymbols)
    symbol_cache: Arc<Mutex<HashMap<String, ModuleSymbols>>>,
    
    /// Set of modules currently being loaded
    pending_loads: Arc<Mutex<HashSet<String>>>,
    /// Condvar to notify waiters when a module finishes loading
    pending_cv: Arc<Condvar>,
    
    /// Channel to send load requests to the worker thread
    worker_tx: mpsc::Sender<ModuleInfo>,
    
    /// Maximum time to wait for a symbol loading task before giving up
    wait_timeout: Duration,
    
    // worker_handle: Option<JoinHandle<()>>, // We can't easily join on Drop if we can't close the channel easily from here without taking self by value or something, but we can just let it detach.
    // Actually, if we drop the sender, the receiver will error and the thread will exit.
}

impl SymbolManager {
    pub fn new() -> Result<Self, SymbolError> {
        let symbol_cache = Arc::new(Mutex::new(HashMap::new()));
        let pending_loads = Arc::new(Mutex::new(HashSet::new()));
        let pending_cv = Arc::new(Condvar::new());
        
        let (worker_tx, worker_rx) = mpsc::channel::<ModuleInfo>();
        // Wrap receiver in Arc<Mutex> to share among multiple worker threads
        let worker_rx = Arc::new(Mutex::new(worker_rx));
        
        let worker_count = Self::read_worker_count_from_env();
        trace!(worker_count, "Starting symbol worker threads");

        for i in 0..worker_count {
            let rx = worker_rx.clone();
            let cache_clone = symbol_cache.clone();
            let pending_clone = pending_loads.clone();
            let cv_clone = pending_cv.clone();
            
            thread::spawn(move || {
                trace!(worker_id = i, "Symbol worker thread started");
                
                // Create the provider (and its Runtime) ONCE per thread
                let mut provider = match WindowsSymbolProvider::new() {
                    Ok(p) => p,
                    Err(e) => {
                        error!(worker_id = i, error = %e, "Failed to create WindowsSymbolProvider in worker thread");
                        return;
                    }
                };
                
                loop {
                    // Acquire lock to receive next job
                    let module_info = {
                        let lock = match rx.lock() {
                            Ok(guard) => guard,
                            Err(_) => break, // Poisoned mutex, exit
                        };
                        match lock.recv() {
                            Ok(m) => m,
                            Err(_) => break, // Channel closed (Sender dropped), exit
                        }
                    };

                    let module_path = module_info.name.clone();
                    trace!(worker_id = i, module_path = %module_path, "Worker processing load request");
                    
                    let module_base = module_info.base;
                    let module_size = module_info.size.map(|s| s as usize);
                    
                    // Load symbols synchronously (but provider uses its internal runtime)
                    let result = provider.load_symbols_for_module(&module_path, module_base, module_size);
                    
                    match result {
                        Ok(()) => {
                            trace!(worker_id = i, module_path = %module_path, "Symbol loading completed successfully");
                            // Store in cache
                            if let Ok(symbols) = provider.list_symbols(&module_path) {
                                let mut cache = cache_clone.lock().unwrap();
                                cache.insert(module_path.clone(), ModuleSymbols {
                                    module_base,
                                    symbols,
                                });
                            }
                        },
                        Err(e) => {
                            warn!(worker_id = i, module_path = %module_path, error = %e, "Symbol loading failed");
                        }
                    }
                    
                    // Remove from pending and notify waiters
                    {
                        let mut pending = pending_clone.lock().unwrap();
                        pending.remove(&module_path);
                    }
                    cv_clone.notify_all();
                }
                
                trace!(worker_id = i, "Symbol worker thread exiting");
            });
        }

        Ok(Self {
            symbol_cache,
            pending_loads,
            pending_cv,
            worker_tx,
            wait_timeout: Self::read_timeout_from_env(),
        })
    }

    fn read_worker_count_from_env() -> usize {
        if let Ok(count_str) = std::env::var("JOYBUG_SYMBOL_WORKER_COUNT") {
            if let Ok(count) = count_str.parse::<usize>() {
                if count > 0 {
                    return count;
                }
            }
        }
        3 // Default to 3 worker threads
    }

    fn read_timeout_from_env() -> Duration {
        // Prefer milliseconds override, then seconds; fallback 5 seconds
        if let Ok(sec_str) = std::env::var("JOYBUG_SYMBOL_WAIT_TIMEOUT_SECS") {
            if let Ok(secs) = sec_str.parse::<u64>() {
                return Duration::from_secs(secs);
            }
        }
        Duration::from_secs(5)
    }

    /// Start loading symbols for a module in the background
    pub fn start_loading_symbols(&self, module: &ModuleInfo) {
        let module_path = module.name.clone();
        
        // Check if already loaded
        {
            let cache = self.symbol_cache.lock().unwrap();
            if cache.contains_key(&module_path) {
                return;
            }
        }
        
        // Check if already pending
        {
            let mut pending = self.pending_loads.lock().unwrap();
            if pending.contains(&module_path) {
                return;
            }
            pending.insert(module_path.clone());
        }
        
        // Send to worker
        if let Err(e) = self.worker_tx.send(module.clone()) {
            error!(module_path = %module_path, error = %e, "Failed to send symbol load request to worker");
            // Remove from pending if send failed
            let mut pending = self.pending_loads.lock().unwrap();
            pending.remove(&module_path);
            self.pending_cv.notify_all();
        }
    }

    /// Wait for symbol loading to complete for a module if it's in progress, with timeout
    fn wait_for_loading(&self, module_path: &str) -> Result<(), SymbolError> {
        let start = Instant::now();
        let mut pending = self.pending_loads.lock().unwrap();
        
        while pending.contains(module_path) {
            let elapsed = start.elapsed();
            if elapsed >= self.wait_timeout {
                trace!(module_path, timeout_ms = self.wait_timeout.as_millis() as u64, "Timeout waiting for symbol loading");
                return Ok(()); // Return Ok even on timeout to allow partial results
            }
            
            let remaining = self.wait_timeout - elapsed;
            let (guard, timeout_result) = self.pending_cv.wait_timeout(pending, remaining).unwrap();
            pending = guard;
            if timeout_result.timed_out() {
                trace!(module_path, timeout_ms = self.wait_timeout.as_millis() as u64, "Timeout waiting for symbol loading (cv)");
                return Ok(());
            }
        }
        Ok(())
    }

    pub fn wait_for_all_loading(&self) {
        let start = Instant::now();
        let mut pending = self.pending_loads.lock().unwrap();
        
        while !pending.is_empty() {
            let elapsed = start.elapsed();
            if elapsed >= self.wait_timeout {
                trace!(timeout_ms = self.wait_timeout.as_millis() as u64, "Timeout waiting for all symbol loading");
                break;
            }
            
            let remaining = self.wait_timeout - elapsed;
            let (guard, timeout_result) = self.pending_cv.wait_timeout(pending, remaining).unwrap();
            pending = guard;
            if timeout_result.timed_out() {
                break;
            }
        }
    }

    /// Find symbols across all loaded modules, returning up to max_results matches
    /// Supports Windows-style "module!symbol" format (e.g., "ntdll!NtCreateFile")
    pub fn find_symbol_across_all_modules(&self, symbol_name: &str, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        self.wait_for_all_loading();
        let cache = self.symbol_cache.lock().unwrap();
        let mut found_symbols = Vec::new();

        trace!(loaded_modules = ?cache.keys(), "Searching for symbol in loaded modules");
        
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
                    // First pass: exact matches only (prioritize exact over partial)
                    for symbol in &module_symbols.symbols {
                        if symbol.name.to_lowercase() == target_symbol_name.to_lowercase() {
                            let symbol_name_with_module = format!("{}!{}", module_name, symbol.name);
                            found_symbols.push(ResolvedSymbol {
                                name: symbol_name_with_module,
                                module_name: module_name.to_string(),
                                rva: symbol.rva,
                                va: module_symbols.module_base + symbol.rva as u64,
                            });

                            if found_symbols.len() >= max_results {
                                trace!(symbol_name, found_count = found_symbols.len(), max_results, "Module-specific symbol search completed (exact match, max results reached)");
                                return Ok(found_symbols);
                            }
                        }
                    }

                    // Second pass: contains matches (only if we need more results)
                    if found_symbols.len() < max_results {
                        for symbol in &module_symbols.symbols {
                            // Skip exact matches (already added)
                            if symbol.name.to_lowercase() == target_symbol_name.to_lowercase() {
                                continue;
                            }
                            if symbol.name.to_lowercase().contains(&target_symbol_name.to_lowercase()) {
                                let symbol_name_with_module = format!("{}!{}", module_name, symbol.name);
                                found_symbols.push(ResolvedSymbol {
                                    name: symbol_name_with_module,
                                    module_name: module_name.to_string(),
                                    rva: symbol.rva,
                                    va: module_symbols.module_base + symbol.rva as u64,
                                });

                                if found_symbols.len() >= max_results {
                                    trace!(symbol_name, found_count = found_symbols.len(), max_results, "Module-specific symbol search completed (contains match, max results reached)");
                                    return Ok(found_symbols);
                                }
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
                    
                    // too much logging
                    //trace!(module_path, rva = format!("0x{:X}", rva), symbol_name = %symbol.name, symbol_rva = format!("0x{:X}", symbol.rva), symbol_va = format!("0x{:X}", symbol_with_va.va), offset = rva - symbol.rva, "RVA resolved to symbol");
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
                    //trace!(module_path, rva = format!("0x{:X}", rva), symbol_name = %symbol.name, symbol_rva = format!("0x{:X}", symbol.rva), offset = rva - symbol.rva, "RVA resolved to raw symbol");
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