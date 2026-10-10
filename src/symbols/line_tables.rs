//! Source line tables: one per module, parsed from its debug file.
//!
//! Parsing one takes seconds for a large debug file, and three kinds of caller
//! want the result: a script that is willing to wait, the UI's session thread
//! that must never wait, and the disassembler that only uses what is already
//! there. So a table is parsed **once** (single-flight: whoever needs it while
//! it is being parsed waits for that parse or is told it is pending) and
//! **early**: as soon as a module's debug file is loaded the parse is queued on
//! a background thread, so that by the time anyone asks — the first pause, the
//! first look at the source view — it is usually done or well under way.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{mpsc, Arc, Condvar, Mutex, Weak};
use std::thread;

use tracing::warn;

use super::backend::SymbolBackend;
use super::symbol_manager::ModuleSymbols;
use super::symbol_provider::ModuleLineTable;
use crate::interfaces::SymbolError;
use crate::protocol::LineInfoState;

enum State {
    Parsing,
    Ready(Arc<ModuleLineTable>),
    Failed(String),
}

/// What asking for a line table found, before any parsing.
enum Claim {
    Ready(Arc<ModuleLineTable>),
    /// A parse is in progress elsewhere.
    InFlight,
    /// Nothing cached and nobody parsing: the caller now owns the parse of
    /// this debug file (the entry is `Parsing` until it calls `finish`).
    Mine(String),
    /// The module's symbols are still loading; there is no debug file yet.
    SymbolsLoading,
    /// No debug file to parse.
    Unavailable,
}

/// A line table asked for without waiting.
pub enum LineTableLookup {
    Ready(Arc<ModuleLineTable>),
    /// Loading (the table itself, or the symbols before it); ask again.
    Pending,
    Unavailable,
}

pub(super) struct LineTables {
    backend: Arc<dyn SymbolBackend>,
    /// The symbol manager's loaded symbols: where a module's debug file path is.
    symbols: Arc<Mutex<HashMap<String, ModuleSymbols>>>,
    /// Modules whose symbols are still loading.
    symbols_pending: Arc<Mutex<HashSet<String>>>,
    tables: Mutex<HashMap<String, State>>,
    /// Signalled whenever a `tables` entry leaves `Parsing`.
    parsed: Condvar,
    /// Modules to parse ahead of need, served one at a time by the warm-up
    /// thread: several large debug files parsed at once would compete with the
    /// symbol loads still running, for no gain.
    warm_queue: Mutex<mpsc::Sender<String>>,
    /// What is in `warm_queue` and not picked up yet — "loading", as far as
    /// anyone watching the status is concerned.
    queued: Mutex<HashSet<String>>,
}

impl LineTables {
    pub fn new(
        backend: Arc<dyn SymbolBackend>,
        symbols: Arc<Mutex<HashMap<String, ModuleSymbols>>>,
        symbols_pending: Arc<Mutex<HashSet<String>>>,
    ) -> Arc<Self> {
        let (warm_queue, queued) = mpsc::channel::<String>();
        let tables = Arc::new(Self {
            backend,
            symbols,
            symbols_pending,
            tables: Mutex::new(HashMap::new()),
            parsed: Condvar::new(),
            warm_queue: Mutex::new(warm_queue),
            queued: Mutex::new(HashSet::new()),
        });
        // Weak: the thread must not keep the tables (and with them the queue's
        // sender) alive, or it would never see the queue close.
        let weak: Weak<Self> = Arc::downgrade(&tables);
        thread::spawn(move || {
            while let Ok(module_path) = queued.recv() {
                let Some(tables) = weak.upgrade() else { break };
                // Claimed (now `Parsing`) before it leaves `queued`, so the
                // status never reads "not loaded" in between.
                let claim = tables.claim(&module_path);
                tables.queued.lock().unwrap().remove(&module_path);
                if let Ok(Claim::Mine(debug_file)) = claim {
                    let _ = tables.finish(&module_path, &debug_file);
                }
            }
        });
        tables
    }

    /// Parse `module_path`'s line table in the background, ahead of need. Call
    /// it when the module's debug file has just been loaded.
    pub fn warm(&self, module_path: &str) {
        if self.queued.lock().unwrap().insert(module_path.to_string())
            && self.warm_queue.lock().unwrap().send(module_path.to_string()).is_err()
        {
            self.queued.lock().unwrap().remove(module_path);
        }
    }

    /// The debug file a module's symbols were loaded from, if any.
    fn debug_file_of(&self, module_path: &str) -> Option<String> {
        self.symbols.lock().unwrap().get(module_path).and_then(|m| m.pdb_path.clone())
    }

    /// Look at a module's line table and, when there is none and nobody is
    /// parsing one, claim the parse.
    fn claim(&self, module_path: &str) -> Result<Claim, SymbolError> {
        {
            let tables = self.tables.lock().unwrap();
            match tables.get(module_path) {
                Some(State::Ready(table)) => return Ok(Claim::Ready(table.clone())),
                Some(State::Failed(msg)) => return Err(SymbolError::PdbParsingFailed(msg.clone())),
                Some(State::Parsing) => return Ok(Claim::InFlight),
                None => {}
            }
        }
        // Symbols (and therefore the debug-file download) still in flight.
        if self.symbols_pending.lock().unwrap().contains(module_path) {
            return Ok(Claim::SymbolsLoading);
        }
        let Some(debug_file) = self.debug_file_of(module_path) else {
            return Ok(Claim::Unavailable); // load failed / not requested / exports only
        };
        // Re-check under the lock: another caller may have claimed it meanwhile.
        let mut tables = self.tables.lock().unwrap();
        Ok(match tables.get(module_path) {
            Some(State::Ready(table)) => Claim::Ready(table.clone()),
            Some(State::Failed(msg)) => return Err(SymbolError::PdbParsingFailed(msg.clone())),
            Some(State::Parsing) => Claim::InFlight,
            None => {
                tables.insert(module_path.to_string(), State::Parsing);
                Claim::Mine(debug_file)
            }
        })
    }

    /// Parse the line table this caller claimed and publish the result.
    fn finish(&self, module_path: &str, debug_file: &str) -> Result<Option<Arc<ModuleLineTable>>, SymbolError> {
        /// Releases the claim if the parse unwinds, so waiters are not left
        /// waiting for a table nobody is parsing.
        struct Claimed<'a> {
            tables: &'a LineTables,
            module_path: &'a str,
            published: bool,
        }
        impl Drop for Claimed<'_> {
            fn drop(&mut self) {
                if !self.published {
                    self.tables.tables.lock().unwrap().remove(self.module_path);
                    self.tables.parsed.notify_all();
                }
            }
        }
        let mut claimed = Claimed { tables: self, module_path, published: false };

        let mut span = crate::perf::span("symbols.parse_artifact");
        if span.is_live() {
            span.attr("module_key", crate::perf::path_key(module_path));
        }
        let parsed = self.backend.parse_lines(Path::new(debug_file));
        drop(span);
        if let Err(e) = &parsed {
            warn!(module_path, debug_file, error = %e, "Failed to parse the line table");
        }

        // A different debug file was loaded for the module while this one was
        // being parsed: the result is for the wrong file. Drop it (the guard
        // releases the claim) so the next request parses the current one.
        if self.debug_file_of(module_path).as_deref() != Some(debug_file) {
            return Ok(None);
        }
        let (state, result) = match parsed {
            Ok(table) => {
                let table = Arc::new(table);
                (State::Ready(table.clone()), Ok(Some(table)))
            }
            Err(e) => (State::Failed(e.to_string()), Err(SymbolError::PdbParsingFailed(e.to_string()))),
        };
        self.tables.lock().unwrap().insert(module_path.to_string(), state);
        claimed.published = true;
        self.parsed.notify_all();
        result
    }

    /// The line table of a module, parsing it if needed and waiting for a parse
    /// already in progress. `Ok(None)` when there is no debug file, or the
    /// module's symbols are still loading. A failed parse is cached and
    /// returned as an error.
    ///
    /// This can take seconds for a large debug file: call it where waiting is
    /// fine (a background thread, an explicit request), and [`Self::try_get`]
    /// everywhere else.
    pub fn get(&self, module_path: &str) -> Result<Option<Arc<ModuleLineTable>>, SymbolError> {
        loop {
            match self.claim(module_path)? {
                Claim::Ready(table) => return Ok(Some(table)),
                Claim::SymbolsLoading | Claim::Unavailable => return Ok(None),
                Claim::Mine(debug_file) => return self.finish(module_path, &debug_file),
                Claim::InFlight => {
                    let tables = self.tables.lock().unwrap();
                    drop(self.parsed.wait_while(tables, |t| matches!(t.get(module_path), Some(State::Parsing))).unwrap());
                }
            }
        }
    }

    /// The line table of a module if it is there now. When it is not, its
    /// parse is put in hand (queued behind any other; normally it already is,
    /// since a debug file is queued the moment it loads) and the answer is
    /// `Pending`; the module's `line_info` status turns `Ready` when it lands.
    pub fn try_get(&self, module_path: &str) -> Result<LineTableLookup, SymbolError> {
        let tables = self.tables.lock().unwrap();
        Ok(match tables.get(module_path) {
            Some(State::Ready(table)) => LineTableLookup::Ready(table.clone()),
            Some(State::Failed(msg)) => return Err(SymbolError::PdbParsingFailed(msg.clone())),
            Some(State::Parsing) => LineTableLookup::Pending,
            None => {
                drop(tables);
                if self.symbols_pending.lock().unwrap().contains(module_path) {
                    LineTableLookup::Pending
                } else if self.debug_file_of(module_path).is_some() {
                    self.warm(module_path);
                    LineTableLookup::Pending
                } else {
                    LineTableLookup::Unavailable
                }
            }
        })
    }

    /// The table if it is already parsed; never starts or waits for a parse.
    pub fn cached(&self, module_path: &str) -> Option<Arc<ModuleLineTable>> {
        match self.tables.lock().unwrap().get(module_path) {
            Some(State::Ready(table)) => Some(table.clone()),
            _ => None,
        }
    }

    /// Where a module's line table stands, for the symbol status. One whose
    /// parse is queued counts as loading, like one being parsed.
    pub fn state(&self, module_path: &str) -> LineInfoState {
        match self.tables.lock().unwrap().get(module_path) {
            Some(State::Ready(_)) => return LineInfoState::Ready,
            Some(State::Parsing) => return LineInfoState::Loading,
            Some(State::Failed(_)) | None => {}
        }
        if self.queued.lock().unwrap().contains(module_path) {
            LineInfoState::Loading
        } else {
            LineInfoState::NotLoaded
        }
    }

    /// Drop a module's table (e.g. after a different debug file was loaded for
    /// it). A parse in progress notices on its own that its file is no longer
    /// current.
    pub fn invalidate(&self, module_path: &str) {
        let mut tables = self.tables.lock().unwrap();
        if !matches!(tables.get(module_path), Some(State::Parsing)) {
            tables.remove(module_path);
        }
    }
}
