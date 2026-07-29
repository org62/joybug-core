use crate::interfaces::{LineEntry, ModuleSymbol, ResolvedSymbol, SourceFileEntry, SourceLineRef, SymbolConfig, SymbolError, SymbolProvider};
use crate::protocol::{ModuleInfo, ModuleSymbolStatus, PdbLoadOutcome, SymbolLoadState};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, Condvar, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{trace, warn, error};
use crate::windows_platform::symbol_provider::{WindowsSymbolProvider, ModuleLineTable, parse_pdb_to_symbols, parse_pdb_matching_pe, parse_pdb_to_lines};
use crate::windows_platform::type_provider::{ModuleTypeInfo, parse_pdb_to_types};
use crate::protocol::{TypeLayout, TypeSummary};
use pelite::pe64::{Pe, PeFile};
use pelite::image::{RUNTIME_FUNCTION, UNWIND_INFO, UNW_FLAG_CHAININFO};

/// Where a module's cached symbols came from. `Exports` marks the PE-export
/// fallback used when no PDB is available; it carries the PDB failure reason
/// and is replaceable (a later PDB load clobbers it, a real PDB is never
/// clobbered by exports).
#[derive(Debug, Clone)]
pub enum SymbolSource {
    Pdb,
    Exports { error: String },
}

impl SymbolSource {
    /// Export stubs may be clobbered by a later real PDB load; a PDB never is.
    fn is_replaceable(&self) -> bool {
        matches!(self, SymbolSource::Exports { .. })
    }
}

/// Cached symbols for a single module with RVA-based storage
#[derive(Debug, Clone)]
pub struct ModuleSymbols {
    pub module_base: u64, // Base address where the module is loaded
    pub symbols: Vec<ModuleSymbol>, // All symbols stored as RVAs
    pub pdb_path: Option<String>, // PDB file the symbols were loaded from
    pub source: SymbolSource,
}

/// Result of a lazy per-module PDB parse (line table, type info), cached by
/// module path.
enum PdbArtifactState<T> {
    Ready(Arc<T>),
    Failed(String),
}

/// Cached PE exception data for chain resolution
struct PdataCache {
    /// Parsed .pdata entries (sorted by BeginAddress)
    pdata: Vec<RUNTIME_FUNCTION>,
    /// Precomputed map: fragment BeginAddress → primary function BeginAddress
    /// Only entries with UNW_FLAG_CHAININFO are included.
    chain_map: HashMap<u32, u32>,
}

/// Manages symbol loading for modules in the Windows platform
/// Uses RVA-based storage for efficient sharing across processes
pub struct SymbolManager {
    /// Store loaded symbols for fast access (module_path -> ModuleSymbols)
    symbol_cache: Arc<Mutex<HashMap<String, ModuleSymbols>>>,

    /// Cached .pdata + PE bytes per module for chain resolution
    pdata_cache: Mutex<HashMap<String, Option<PdataCache>>>,

    /// Lazily parsed PDB line tables per module (module_path -> state).
    /// Populated on the first source-level request, never during the
    /// background symbol load.
    line_cache: Mutex<HashMap<String, PdbArtifactState<ModuleLineTable>>>,

    /// Lazily parsed PDB type information per module (module_path -> state).
    /// Populated on the first type-level request, never during the background
    /// symbol load.
    type_cache: Mutex<HashMap<String, PdbArtifactState<ModuleTypeInfo>>>,

    /// Set of modules currently being loaded
    pending_loads: Arc<Mutex<HashSet<String>>>,
    /// Modules whose symbol load failed (module_path -> error message).
    /// Failed modules are not retried automatically; retry is explicit.
    failed_loads: Arc<Mutex<HashMap<String, String>>>,
    /// Modules (lowercased file names, e.g. "foo.dll") whose automatic symbol
    /// download the client suppressed — typically because the download failed in
    /// an earlier run. Denied modules skip the download, get recorded in
    /// `failed_loads`, and fall back to PE export names; an explicit retry lifts
    /// the suppression.
    denied_loads: Mutex<HashSet<String>>,
    /// Condvar to notify waiters when a module finishes loading
    pending_cv: Arc<Condvar>,

    /// Channel to send load requests to the worker thread
    worker_tx: mpsc::Sender<SymbolLoadRequest>,

    /// Maximum time to wait for a symbol loading task before giving up
    wait_timeout: Duration,
}

/// A unit of work for the symbol worker threads. A set `deny_error` skips the
/// PDB download entirely (deny-listed module) and goes straight to the
/// PE-export fallback, carrying the message to report as the PDB failure.
struct SymbolLoadRequest {
    module: ModuleInfo,
    deny_error: Option<String>,
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

impl SymbolManager {
    pub fn new_with_config(cfg: SymbolConfig) -> Result<Self, SymbolError> {
        let symbol_cache = Arc::new(Mutex::new(HashMap::<String, ModuleSymbols>::new()));
        let pending_loads = Arc::new(Mutex::new(HashSet::new()));
        let failed_loads = Arc::new(Mutex::new(HashMap::new()));
        let pending_cv = Arc::new(Condvar::new());

        let (worker_tx, worker_rx) = mpsc::channel::<SymbolLoadRequest>();
        // Wrap receiver in Arc<Mutex> to share among multiple worker threads
        let worker_rx = Arc::new(Mutex::new(worker_rx));

        let worker_count = Self::read_worker_count_from_env();
        trace!(worker_count, "Starting symbol worker threads");

        for i in 0..worker_count {
            let rx = worker_rx.clone();
            let cache_clone = symbol_cache.clone();
            let pending_clone = pending_loads.clone();
            let failed_clone = failed_loads.clone();
            let cv_clone = pending_cv.clone();
            let cfg_clone = cfg.clone();

            thread::spawn(move || {
                trace!(worker_id = i, "Symbol worker thread started");

                // Create the provider (and its Runtime) ONCE per thread
                let mut provider = match WindowsSymbolProvider::with_config(&cfg_clone) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(worker_id = i, error = %e, "Failed to create WindowsSymbolProvider in worker thread");
                        return;
                    }
                };
                
                loop {
                    // Acquire lock to receive next job
                    let request = {
                        let lock = match rx.lock() {
                            Ok(guard) => guard,
                            Err(_) => break, // Poisoned mutex, exit
                        };
                        match lock.recv() {
                            Ok(m) => m,
                            Err(_) => break, // Channel closed (Sender dropped), exit
                        }
                    };

                    let module_path = request.module.name.clone();
                    trace!(worker_id = i, module_path = %module_path, denied = request.deny_error.is_some(), "Worker processing load request");

                    let module_base = request.module.base;
                    let module_size = request.module.size.map(|s| s as usize);

                    // Insert a finished symbol list, but never clobber a real PDB a
                    // user loaded manually meanwhile; export stubs are replaceable.
                    let insert_symbols = |mut symbols: Vec<ModuleSymbol>, pdb_path: Option<String>, source: SymbolSource| {
                        // Sort symbols by RVA for binary search
                        symbols.sort_by_key(|s| s.rva);
                        let mut cache = cache_clone.lock().unwrap();
                        if cache.get(&module_path).is_none_or(|m| m.source.is_replaceable()) {
                            cache.insert(module_path.clone(), ModuleSymbols { module_base, symbols, pdb_path, source });
                        }
                    };

                    // The PDB failure reason: the deny message for a skipped
                    // download, or the live download's error.
                    let pdb_error = match request.deny_error {
                        Some(deny_msg) => Some(deny_msg),
                        // Load symbols synchronously (but provider uses its internal runtime)
                        None => match provider.load_symbols_for_module(&module_path, module_base, module_size) {
                            Ok(()) => {
                                trace!(worker_id = i, module_path = %module_path, "Symbol loading completed successfully");
                                // Store in cache
                                if let Ok(symbols) = provider.list_symbols(&module_path) {
                                    let pdb_path = provider.pdb_path_for(&module_path);
                                    insert_symbols(symbols, pdb_path, SymbolSource::Pdb);
                                }
                                None
                            }
                            Err(e) => {
                                warn!(worker_id = i, module_path = %module_path, error = %e, "Symbol loading failed");
                                failed_clone.lock().unwrap().insert(module_path.clone(), e.to_string());
                                Some(e.to_string())
                            }
                        },
                    };

                    // No PDB: fall back to PE export names so the module isn't
                    // completely nameless. The failure stays recorded (the client
                    // persists it), only the cache gains the export stubs.
                    if let Some(error) = pdb_error {
                        match parse_export_symbols(&module_path) {
                            Ok(symbols) => {
                                trace!(worker_id = i, module_path = %module_path, count = symbols.len(), "Loaded PE export names as symbol fallback");
                                insert_symbols(symbols, None, SymbolSource::Exports { error });
                            }
                            Err(e) => {
                                trace!(worker_id = i, module_path = %module_path, error = %e, "PE export fallback unavailable");
                            }
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
            pdata_cache: Mutex::new(HashMap::new()),
            line_cache: Mutex::new(HashMap::new()),
            type_cache: Mutex::new(HashMap::new()),
            pending_loads,
            failed_loads,
            denied_loads: Mutex::new(HashSet::new()),
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

        // A previous attempt failed: don't retry automatically (retry is explicit)
        {
            let failed = self.failed_loads.lock().unwrap();
            if failed.contains_key(&module_path) {
                return;
            }
        }

        // The client suppressed auto-download for this module (it failed in an
        // earlier run). Record the failure so a UI can offer an explicit retry,
        // but still enqueue the module so the worker loads PE export names as a
        // fallback (skipping the download).
        let deny_error = {
            let denied = self.denied_loads.lock().unwrap();
            denied.contains(&Self::short_name_lower(&module_path)).then(|| {
                let msg = "symbol download skipped (failed in a previous run; retry to download again)".to_string();
                self.failed_loads.lock().unwrap().insert(module_path.clone(), msg.clone());
                msg
            })
        };

        // Check if already pending
        {
            let mut pending = self.pending_loads.lock().unwrap();
            if pending.contains(&module_path) {
                return;
            }
            pending.insert(module_path.clone());
        }

        // Send to worker
        if let Err(e) = self.worker_tx.send(SymbolLoadRequest { module: module.clone(), deny_error }) {
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

    /// Classify a module's load state as of right now: cached → pending → failed →
    /// not requested. Single source of truth for every caller that needs to tell
    /// "no symbols" apart from "not ready yet". Returns the PDB path when loaded.
    fn load_state(&self, module_path: &str) -> (SymbolLoadState, Option<String>) {
        let cache = self.symbol_cache.lock().unwrap();
        let pending = self.pending_loads.lock().unwrap();
        let failed = self.failed_loads.lock().unwrap();

        if let Some(cached) = cache.get(module_path) {
            match &cached.source {
                SymbolSource::Pdb => {
                    (SymbolLoadState::Loaded { symbol_count: cached.symbols.len() }, cached.pdb_path.clone())
                }
                SymbolSource::Exports { error } => (
                    SymbolLoadState::ExportsOnly {
                        export_count: cached.symbols.len(),
                        error: error.clone(),
                    },
                    None,
                ),
            }
        } else if pending.contains(module_path) {
            (SymbolLoadState::Loading, None)
        } else if let Some(error) = failed.get(module_path) {
            (SymbolLoadState::Failed { error: error.clone() }, None)
        } else {
            (SymbolLoadState::NotRequested, None)
        }
    }

    /// Report the symbol load state for each of the given modules.
    /// Non-blocking: reads the cache/pending/failed sets as they are right now.
    pub fn get_symbol_status(&self, modules: Vec<ModuleInfo>) -> Vec<ModuleSymbolStatus> {
        modules.into_iter().map(|module| {
            let (state, pdb_path) = self.load_state(&module.name);
            ModuleSymbolStatus {
                module_path: module.name,
                module_base: module.base,
                state,
                pdb_path,
            }
        }).collect()
    }

    /// Load symbols for a module from a user-supplied PDB file.
    /// Unless `force`, the PDB's GUID/age must match the module's PE debug directory;
    /// a mismatch is returned as `PdbLoadOutcome::Mismatch`, not an error.
    /// A user-loaded PDB replaces any previously cached symbols for the module.
    pub fn load_pdb_from_path(&self, module: &ModuleInfo, pdb_path: &Path, force: bool) -> Result<PdbLoadOutcome, SymbolError> {
        let mut symbols = if force {
            parse_pdb_to_symbols(pdb_path)?
        } else {
            match parse_pdb_matching_pe(Path::new(&module.name), pdb_path)? {
                Ok(symbols) => symbols,
                Err(mismatch) => return Ok(PdbLoadOutcome::Mismatch(mismatch)),
            }
        };
        symbols.sort_by_key(|s| s.rva);
        let symbol_count = symbols.len();

        {
            let mut cache = self.symbol_cache.lock().unwrap();
            cache.insert(module.name.clone(), ModuleSymbols {
                module_base: module.base,
                symbols,
                pdb_path: Some(pdb_path.display().to_string()),
                source: SymbolSource::Pdb,
            });
        }
        self.failed_loads.lock().unwrap().remove(&module.name);
        self.denied_loads.lock().unwrap().remove(&Self::short_name_lower(&module.name));
        // The line/type tables came from the previous PDB; re-parse on demand.
        self.invalidate_line_table(&module.name);
        self.type_cache.lock().unwrap().remove(&module.name);

        trace!(module_path = %module.name, pdb_path = %pdb_path.display(), symbol_count, force, "Loaded user-supplied PDB");
        Ok(PdbLoadOutcome::Loaded { symbol_count })
    }

    /// Get (lazily parsing) a per-module PDB artifact from `cache` — shared body
    /// of `get_line_table` and `get_type_info`.
    /// Returns `Ok(None)` without blocking while the module's symbols are still
    /// loading (the client re-requests once symbols finish), and when no PDB is
    /// available. A failed parse is cached and returned as an error.
    fn get_pdb_artifact<T>(
        &self,
        cache: &Mutex<HashMap<String, PdbArtifactState<T>>>,
        module_path: &str,
        what: &str,
        parse: impl FnOnce(&Path) -> Result<T, SymbolError>,
    ) -> Result<Option<Arc<T>>, SymbolError> {
        {
            let cache = cache.lock().unwrap();
            match cache.get(module_path) {
                Some(PdbArtifactState::Ready(v)) => return Ok(Some(v.clone())),
                Some(PdbArtifactState::Failed(msg)) => {
                    return Err(SymbolError::PdbParsingFailed(msg.clone()));
                }
                None => {}
            }
        }

        // Symbols (and therefore the PDB download) still in flight: don't block.
        {
            let pending = self.pending_loads.lock().unwrap();
            if pending.contains(module_path) {
                return Ok(None);
            }
        }

        let pdb_path = {
            let symbols = self.symbol_cache.lock().unwrap();
            match symbols.get(module_path).and_then(|m| m.pdb_path.clone()) {
                Some(path) => path,
                None => return Ok(None), // no PDB (load failed / not requested / no path)
            }
        };

        // Parse outside all locks; a rare duplicate parse under concurrency is fine.
        let state = match parse(Path::new(&pdb_path)) {
            Ok(v) => PdbArtifactState::Ready(Arc::new(v)),
            Err(e) => {
                warn!(module_path, pdb_path = %pdb_path, error = %e, "Failed to parse PDB {}", what);
                PdbArtifactState::Failed(e.to_string())
            }
        };
        let mut cache = cache.lock().unwrap();
        let state = cache.entry(module_path.to_string()).or_insert(state);
        match state {
            PdbArtifactState::Ready(v) => Ok(Some(v.clone())),
            PdbArtifactState::Failed(msg) => Err(SymbolError::PdbParsingFailed(msg.clone())),
        }
    }

    /// Get (lazily parsing) the PDB line table for a module. See `get_pdb_artifact`
    /// for the caching/non-blocking contract.
    pub fn get_line_table(&self, module_path: &str) -> Result<Option<Arc<ModuleLineTable>>, SymbolError> {
        self.get_pdb_artifact(&self.line_cache, module_path, "line table", parse_pdb_to_lines)
    }

    /// Drop a module's cached line table (e.g. after a user loads a different PDB).
    pub fn invalidate_line_table(&self, module_path: &str) {
        self.line_cache.lock().unwrap().remove(module_path);
    }

    /// Resolve an RVA against an already-parsed line table.
    /// Picks the entry covering `[rva, rva+length)`; for zero-length entries the
    /// nearest entry at or below the RVA wins (entries are RVA-sorted).
    fn resolve_rva_in_table(table: &ModuleLineTable, rva: u32) -> Option<(SourceFileEntry, LineEntry)> {
        let idx = table.lines.partition_point(|l| l.rva <= rva);
        if idx == 0 {
            return None;
        }
        let entry = &table.lines[idx - 1];
        if entry.length > 0 && rva >= entry.rva + entry.length {
            return None; // in the gap past this entry's covered range
        }
        let file = table.files.get(entry.file_index as usize)?.clone();
        Some((file, entry.clone()))
    }

    /// Resolve an RVA to a source line, lazily parsing the module's line table.
    pub fn resolve_rva_to_line(&self, module_path: &str, rva: u32) -> Result<Option<(SourceFileEntry, LineEntry)>, SymbolError> {
        match self.get_line_table(module_path)? {
            Some(table) => Ok(Self::resolve_rva_in_table(&table, rva)),
            None => Ok(None),
        }
    }

    /// Resolve an absolute address to a source line from ALREADY-CACHED line
    /// tables only — never triggers a parse. Used by the bulk disassembly
    /// symbolizer so it can annotate instructions without ever stalling.
    pub fn try_resolve_address_to_line_cached(&self, modules: &[ModuleInfo], address: u64) -> Option<SourceLineRef> {
        let module = Self::find_module_binary_search(modules, address)?;
        let rva = (address - module.base) as u32;
        let table = {
            let cache = self.line_cache.lock().unwrap();
            match cache.get(&module.name) {
                Some(PdbArtifactState::Ready(table)) => table.clone(),
                _ => return None,
            }
        };
        let (file, entry) = Self::resolve_rva_in_table(&table, rva)?;
        Some(SourceLineRef { file_path: file.path, line: entry.line_start })
    }

    /// All line entries for one source file of a module (case-insensitive path
    /// match), plus the matched file record. Lazily parses the line table.
    /// `start_line`/`end_line` (inclusive, 1-based) bound the returned entries by
    /// `line_start` so the response stays small for very large files.
    pub fn file_line_map(&self, module_path: &str, file_path: &str, start_line: Option<u32>, end_line: Option<u32>) -> Result<(Option<SourceFileEntry>, Vec<LineEntry>), SymbolError> {
        let table = match self.get_line_table(module_path)? {
            Some(table) => table,
            None => return Ok((None, Vec::new())),
        };
        let wanted = file_path.to_lowercase();
        let file_index = table.files.iter().position(|f| f.path.to_lowercase() == wanted);
        let Some(file_index) = file_index else {
            return Ok((None, Vec::new()));
        };
        let lo = start_line.unwrap_or(0);
        let hi = end_line.unwrap_or(u32::MAX);
        // `by_file` indices are sorted by line_start, so this is a cheap filter.
        let entries = table
            .by_file
            .get(&(file_index as u32))
            .map(|indices| {
                indices
                    .iter()
                    .map(|&i| &table.lines[i as usize])
                    .filter(|e| e.line_start >= lo && e.line_start <= hi)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok((Some(table.files[file_index].clone()), entries))
    }

    /// All source files referenced by a module's line table. Lazily parses it.
    pub fn list_source_files(&self, module_path: &str) -> Result<Vec<SourceFileEntry>, SymbolError> {
        match self.get_line_table(module_path)? {
            Some(table) => Ok(table.files.clone()),
            None => Ok(Vec::new()),
        }
    }

    /// Get (lazily parsing) the PDB type information for a module. See
    /// `get_pdb_artifact` for the caching/non-blocking contract.
    fn get_type_info(&self, module_path: &str) -> Result<Option<Arc<ModuleTypeInfo>>, SymbolError> {
        self.get_pdb_artifact(&self.type_cache, module_path, "type info", parse_pdb_to_types)
    }

    /// List UDT/enum type summaries across the given modules, optionally filtered by
    /// a case-insensitive name substring, capped at `max_results`. Skips modules
    /// whose PDB isn't parsed yet (they contribute nothing rather than blocking).
    pub fn list_types(&self, modules: &[ModuleInfo], filter: Option<&str>, max_results: usize) -> Vec<TypeSummary> {
        let mut out: Vec<TypeSummary> = Vec::new();
        for module in modules {
            let info = match self.get_type_info(&module.name) {
                Ok(Some(info)) => info,
                _ => continue,
            };
            let module_name = extract_module_name(&module.name);
            // Filter before building the outgoing summaries, so a narrow query
            // against a large catalog doesn't allocate for the misses.
            for entry in info.summaries() {
                if let Some(f) = filter {
                    if !crate::string_results::contains_ascii_ci(entry.name.as_bytes(), f.as_bytes()) {
                        continue;
                    }
                }
                out.push(TypeSummary {
                    name: entry.name.clone(),
                    size: entry.size,
                    kind: entry.kind,
                    index: entry.index,
                    module_base: module.base,
                    module_name: module_name.clone(),
                });
                if out.len() >= max_results {
                    return out;
                }
            }
        }
        out
    }

    /// Resolve a named type's layout, searching the given modules in order.
    pub fn get_type(&self, modules: &[ModuleInfo], name: &str) -> Result<Option<TypeLayout>, SymbolError> {
        for module in modules {
            if let Some(info) = self.get_type_info(&module.name)? {
                if let Some(layout) = info.resolve_by_name(name, module.base) {
                    return Ok(Some(layout));
                }
            }
        }
        Ok(None)
    }

    /// Resolve a type by its TPI index within a specific module (nested expansion).
    pub fn get_type_by_index(&self, module: &ModuleInfo, index: u32) -> Result<Option<TypeLayout>, SymbolError> {
        match self.get_type_info(&module.name)? {
            Some(info) => Ok(info.resolve(index, module.base)),
            None => Ok(None),
        }
    }

    /// Retry a failed (or never-attempted) symbol download for a module.
    pub fn retry_loading_symbols(&self, module: &ModuleInfo) {
        // Evict a cached export-fallback stub so the retry re-attempts the real
        // PDB download (`start_loading_symbols` early-returns on any cache hit).
        // A real PDB is never evicted.
        {
            let mut cache = self.symbol_cache.lock().unwrap();
            if cache.get(&module.name).is_some_and(|m| m.source.is_replaceable()) {
                cache.remove(&module.name);
            }
        }
        self.denied_loads.lock().unwrap().remove(&Self::short_name_lower(&module.name));
        self.failed_loads.lock().unwrap().remove(&module.name);
        self.start_loading_symbols(module);
    }

    /// Lowercased file-name portion of a module path ("C:\\x\\Foo.DLL" -> "foo.dll").
    /// Deny-list entries use this form so they survive path differences between runs.
    fn short_name_lower(module_path: &str) -> String {
        crate::formatting::module_basename_lower(module_path)
    }

    /// Replace the set of modules whose automatic symbol download is suppressed.
    /// Entries are normalized here (see `short_name_lower`), so callers may send
    /// any identifier — full path or bare file name, any case.
    pub fn set_deny_list(&self, modules: Vec<String>) {
        let mut denied = self.denied_loads.lock().unwrap();
        denied.clear();
        denied.extend(modules.iter().map(|m| Self::short_name_lower(m)));
    }

    /// Unload a module's symbols and every derived cache (line table, type info,
    /// pdata, failure marker), freeing their memory. The module reports
    /// `NotRequested` afterwards; `retry_loading_symbols` re-downloads on demand.
    /// An in-flight background load is left alone — its result may repopulate the
    /// cache once it settles, and can then be unloaded again.
    pub fn unload_module_symbols(&self, module_path: &str) {
        self.symbol_cache.lock().unwrap().remove(module_path);
        self.pdata_cache.lock().unwrap().remove(module_path);
        self.invalidate_line_table(module_path);
        self.type_cache.lock().unwrap().remove(module_path);
        self.failed_loads.lock().unwrap().remove(module_path);
        self.denied_loads.lock().unwrap().remove(&Self::short_name_lower(module_path));
        trace!(module_path, "Unloaded module symbols and derived caches");
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
                                is_function: symbol.is_function,
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
                                    is_function: symbol.is_function,
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
                            is_function: symbol.is_function,
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

    /// Resolve an RVA to a symbol without waiting for loading to complete.
    /// Returns None immediately if the module's symbols are still loading.
    pub fn try_resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<ResolvedSymbol>, SymbolError> {
        {
            let pending = self.pending_loads.lock().unwrap();
            if pending.contains(module_path) {
                return Ok(None);
            }
        }
        self.resolve_rva_to_symbol_from_cache(module_path, rva)
    }

    /// Shared implementation: look up an RVA in the already-loaded symbol cache.
    fn resolve_rva_to_symbol_from_cache(&self, module_path: &str, rva: u32) -> Result<Option<ResolvedSymbol>, SymbolError> {
        let cache = self.symbol_cache.lock().unwrap();
        if let Some(module_symbols) = cache.get(module_path) {
            // Binary search: find the rightmost symbol with rva <= target rva
            // Symbols are sorted by RVA
            let symbols = &module_symbols.symbols;
            if symbols.is_empty() {
                return Ok(None);
            }

            // Find insertion point - first symbol with rva > target
            let idx = symbols.partition_point(|s| s.rva <= rva);

            if idx == 0 {
                // No symbol with rva <= target
                return Ok(None);
            }

            // The symbol at idx-1 is the best match (highest rva <= target)
            let symbol = &symbols[idx - 1];

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
                is_function: symbol.is_function,
            };

            Ok(Some(symbol_with_va))
        } else {
            trace!(module_path, rva = format!("0x{:X}", rva), "No symbols loaded for module");
            Ok(None)
        }
    }

    /// Resolve an absolute address to a symbol by finding the appropriate module.
    /// Follows RUNTIME_FUNCTION unwind chains for PGO-split function fragments,
    /// then falls back to nearest-below symbol search.
    /// Non-blocking: returns None immediately if the module's symbols are still
    /// loading, instead of waiting up to the timeout duration.
    pub fn try_resolve_address_to_symbol(&self, modules: &[ModuleInfo], address: u64) -> Result<Option<(String, ResolvedSymbol, u64)>, SymbolError> {
        self.resolve_address_impl(modules, address, |module_path, rva| {
            self.try_resolve_rva_to_symbol(module_path, rva)
        })
    }

    /// Shared implementation for address-to-symbol resolution.
    /// The `resolve_rva` closure controls whether resolution blocks on pending loads.
    fn resolve_address_impl<F>(&self, modules: &[ModuleInfo], address: u64, resolve_rva: F) -> Result<Option<(String, ResolvedSymbol, u64)>, SymbolError>
    where
        F: Fn(&str, u32) -> Result<Option<ResolvedSymbol>, SymbolError>,
    {
        let containing_module = Self::find_module_binary_search(modules, address);

        if let Some(module) = containing_module {
            let rva = (address - module.base) as u32;

            // Try chain resolution: if this RVA is inside a PGO fragment,
            // resolve the symbol at the primary function entry instead.
            if let Some(primary_rva) = self.lookup_chain_target(&module.name, rva) {
                if let Ok(Some(symbol)) = resolve_rva(&module.name, primary_rva) {
                    let offset = rva as u64 - symbol.rva as u64;
                    let module_name = extract_module_name(&module.name);
                    return Ok(Some((
                        module_name,
                        symbol,
                        offset,
                    )));
                }
            }

            // Normal nearest-below symbol resolution
            match resolve_rva(&module.name, rva)? {
                Some(symbol) => {
                    let offset_from_symbol = address - (module.base + symbol.rva as u64);
                    let module_name = extract_module_name(&module.name);
                    Ok(Some((module_name, symbol, offset_from_symbol)))
                }
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Check if an RVA falls in a chained RUNTIME_FUNCTION fragment, and if so
    /// return the primary function's BeginAddress. Returns None if not chained.
    fn lookup_chain_target(&self, module_path: &str, rva: u32) -> Option<u32> {
        let mut pdata_cache = self.pdata_cache.lock().unwrap();
        let cached = pdata_cache.entry(module_path.to_string()).or_insert_with(|| {
            Self::load_pdata_for_module(module_path)
        });
        let cached = cached.as_ref()?;
        if cached.chain_map.is_empty() {
            return None;
        }
        let rf = Self::find_runtime_function(&cached.pdata, rva)?;
        cached.chain_map.get(&rf.BeginAddress).copied()
    }

    /// Binary search to find the module containing an address
    /// Much faster than linear scan for large module lists
    pub(crate) fn find_module_binary_search(modules: &[ModuleInfo], address: u64) -> Option<&ModuleInfo> {
        if modules.is_empty() {
            return None;
        }

        // Binary search: find the rightmost module with base <= address
        let idx = modules.partition_point(|m| m.base <= address);

        if idx == 0 {
            // Address is before all modules
            return None;
        }

        // Check if the module at idx-1 contains the address
        let module = &modules[idx - 1];
        let module_end = module.base + module.size.unwrap_or(0);
        if address >= module.base && address < module_end {
            Some(module)
        } else {
            None
        }
    }
    
    /// Every symbol that starts exactly at `address` (offset 0), across the module
    /// that contains it. Multiple distinct names can share one RVA (e.g. ntdll's
    /// `NtClose`/`ZwClose` aliases); the nearest-below resolvers surface only one,
    /// so this exists to list them all for the disassembly label rows. Names are
    /// sorted for a stable UI. Non-blocking: returns empty while the module's
    /// symbols are still loading.
    pub fn resolve_all_at_exact_address(
        &self,
        modules: &[ModuleInfo],
        address: u64,
    ) -> Vec<crate::interfaces::SymbolInfo> {
        let Some(module) = Self::find_module_binary_search(modules, address) else {
            return Vec::new();
        };
        {
            let pending = self.pending_loads.lock().unwrap();
            if pending.contains(module.name.as_str()) {
                return Vec::new();
            }
        }
        let rva = (address - module.base) as u32;
        let cache = self.symbol_cache.lock().unwrap();
        let Some(module_symbols) = cache.get(&module.name) else {
            return Vec::new();
        };
        // symbols are sorted by RVA; collect the contiguous run with rva == target.
        let symbols = &module_symbols.symbols;
        let start = symbols.partition_point(|s| s.rva < rva);
        let module_name = extract_module_name(&module.name);
        let mut names: Vec<String> = symbols[start..]
            .iter()
            .take_while(|s| s.rva == rva)
            .map(|s| s.name.clone())
            .collect();
        names.sort();
        names
            .into_iter()
            .map(|symbol_name| crate::interfaces::SymbolInfo {
                module_name: module_name.clone(),
                symbol_name,
                offset: 0,
            })
            .collect()
    }

    /// List all symbols in the specified module as raw ModuleSymbols (without VA calculation)
    ///
    /// Waits up to the symbol wait timeout for an in-flight background load. If the
    /// load is still running after that, this reports [`SymbolError::SymbolsStillLoading`]
    /// instead of an empty list: a caller enumerating a module's functions (code
    /// coverage, symbol panels) cannot distinguish "no symbols" from "not ready yet",
    /// and a multi-hundred-megabyte PDB takes far longer than the wait timeout.
    pub fn list_symbols_raw(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        self.wait_for_loading(module_path)?;

        match self.load_state(module_path).0 {
            SymbolLoadState::Loaded { .. } | SymbolLoadState::ExportsOnly { .. } => {
                let cache = self.symbol_cache.lock().unwrap();
                let symbols = cache.get(module_path).map(|m| m.symbols.clone()).unwrap_or_default();
                trace!(module_path, count = symbols.len(), "Raw symbol listing completed");
                Ok(symbols)
            }
            SymbolLoadState::Loading => {
                trace!(module_path, "Symbols still loading; reporting to caller instead of an empty listing");
                Err(SymbolError::SymbolsStillLoading(module_path.to_string()))
            }
            SymbolLoadState::Failed { error } => {
                Err(SymbolError::SymbolsNotFound(format!("{}: {}", module_path, error)))
            }
            SymbolLoadState::NotRequested => {
                trace!(module_path, "No symbols loaded for module");
                Ok(Vec::new())
            }
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

    /// Resolve a batch of absolute addresses to raw symbols WITHOUT waiting on
    /// in-flight symbol loads: an address whose containing module is still
    /// loading resolves to `None` immediately instead of stalling behind the
    /// parse (the blocking resolvers wait up to the configured timeout — seconds
    /// for a multi-million-symbol PDB). One result per input address, in order.
    /// Callers re-request once `get_symbol_status` reports the load settled.
    /// `modules` must be sorted by base address.
    pub fn try_resolve_addresses_to_symbols_raw(
        &self,
        modules: &[ModuleInfo],
        addresses: &[u64],
    ) -> Vec<Option<(String, ModuleSymbol, u64)>> {
        addresses
            .iter()
            .map(|&address| {
                let module = Self::find_module_binary_search(modules, address)?;
                // Still loading → never enter the blocking resolvers (they wait).
                {
                    let pending = self.pending_loads.lock().unwrap();
                    if pending.contains(&module.name) {
                        return None;
                    }
                }
                // Not pending, so the blocking paths below return immediately.
                // Chain-aware resolution first (PGO fragments), then nearest-below.
                if let Ok(Some(result)) = self.resolve_address_with_chain(modules, address) {
                    return Some(result);
                }
                self.resolve_address_to_symbol_raw(modules, address).ok().flatten()
            })
            .collect()
    }

    /// Resolve an address to a symbol by following RUNTIME_FUNCTION unwind chains.
    /// This handles PGO-split functions where cold code chunks link back to the
    /// primary function entry via UNW_FLAG_CHAININFO in the unwind info.
    /// Used by the PlatformAPI trait implementation.
    pub fn resolve_address_with_chain(
        &self,
        modules: &[ModuleInfo],
        address: u64,
    ) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError> {
        let module = match Self::find_module_binary_search(modules, address) {
            Some(m) => m,
            None => return Ok(None),
        };
        let rva = (address - module.base) as u32;

        let primary_begin = match self.lookup_chain_target(&module.name, rva) {
            Some(p) => p,
            None => return Ok(None),
        };

        // Resolve the symbol at the primary entry point RVA
        self.wait_for_loading(&module.name)?;
        let cache = self.symbol_cache.lock().unwrap();
        if let Some(module_symbols) = cache.get(&module.name) {
            let symbols = &module_symbols.symbols;
            let idx = symbols.partition_point(|s| s.rva <= primary_begin);
            if idx > 0 {
                let symbol = &symbols[idx - 1];
                if primary_begin.wrapping_sub(symbol.rva) < 16 {
                    let offset = rva as u64 - symbol.rva as u64;
                    let module_name = extract_module_name(&module.name);
                    return Ok(Some((
                        module_name,
                        ModuleSymbol {
                            name: symbol.name.clone(),
                            rva: symbol.rva,
                            is_function: symbol.is_function,
                        },
                        offset,
                    )));
                }
            }
        }
        Ok(None)
    }

    /// Load .pdata and precompute the chain map for a module.
    /// The chain map resolves all UNW_FLAG_CHAININFO entries to their primary function.
    fn load_pdata_for_module(module_path: &str) -> Option<PdataCache> {
        let pe_bytes = std::fs::read(module_path).ok()?;
        let pe = PeFile::from_bytes(&pe_bytes).ok()?;
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

        Some(PdataCache { pdata, chain_map })
    }

    /// Find the RUNTIME_FUNCTION entry containing a given RVA.
    fn find_runtime_function(pdata: &[RUNTIME_FUNCTION], rva: u32) -> Option<&RUNTIME_FUNCTION> {
        let pos = pdata.partition_point(|rf| rf.BeginAddress <= rva);
        if pos == 0 {
            return None;
        }
        let rf = &pdata[pos - 1];
        if rva >= rf.BeginAddress && rva < rf.EndAddress {
            Some(rf)
        } else {
            None
        }
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

/// Extract module name (without path or extension) from a full path.
fn extract_module_name(module_path: &str) -> String {
    std::path::Path::new(module_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(module_path)
        .to_string()
}

