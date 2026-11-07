//! Decompilation to C-like pseudocode, by the [Kuna](https://github.com/Noelo-Lab/kuna)
//! engine linked into this crate.
//!
//! Kuna works on a **file on disk**, addressed by the file's own virtual
//! addresses, and its loaded program is single-threaded (`Rc` inside). So:
//!
//! - each image stays on its own dedicated thread ([`worker`]); a
//!   [`Decompiler`] is a handle to the request router that any thread may clone;
//! - a request names an image path and an **RVA** — where the module is loaded
//!   in a live target never reaches the engine, and the answer comes back in
//!   RVAs too;
//! - the loaded program of an image is kept (a few most recent ones), since
//!   loading takes about a second for a typical module and far longer for a
//!   very large one, while one more function of a loaded image takes
//!   milliseconds;
//! - function names come from the caller's symbols ([`SymbolSet`]) rather than
//!   from a debug file Kuna would have to find itself.
//! - pending requests from a view keep its greatest frontend generation, not
//!   whichever IPC request happened to arrive last. Waiting for image readiness
//!   and waiting for a function's answer have independent deadlines; timing out
//!   during loading does not queue unwanted function work.
//!
//! The processor specifications Kuna reads from a directory are embedded in
//! this crate and unpacked on first use ([`specs`]).

pub mod specs;
mod worker;

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};

/// Function names for one image, as `(rva, name)`. Built once per symbol load
/// and shared between requests: a different set reloads the image.
#[derive(Debug)]
pub struct SymbolSet {
    names: Vec<(u64, String)>,
    fingerprint: u64,
}

impl SymbolSet {
    pub fn new(mut names: Vec<(u64, String)>) -> Arc<SymbolSet> {
        use std::hash::{Hash, Hasher};
        names.sort();
        names.dedup();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        names.hash(&mut hasher);
        Arc::new(SymbolSet { fingerprint: hasher.finish(), names })
    }

    /// The functions of a module's symbol list.
    pub fn from_module_symbols(symbols: &[crate::interfaces::ModuleSymbol]) -> Arc<SymbolSet> {
        SymbolSet::new(symbols.iter().filter(|s| s.is_function).map(|s| (s.rva as u64, s.name.clone())).collect())
    }

    pub fn names(&self) -> &[(u64, String)] { &self.names }

    /// The name of the function starting at `rva`.
    pub fn name_at(&self, rva: u64) -> Option<&str> {
        let index = self.names.partition_point(|(at, _)| *at < rva);
        self.names.get(index).filter(|(at, _)| *at == rva).map(|(_, name)| name.as_str())
    }

    pub fn fingerprint(&self) -> u64 { self.fingerprint }
}

/// A mounted view's identity and request generation, assigned before IPC.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DecompileClient {
    pub id: String,
    pub sequence: u64,
}

#[derive(Debug, Clone)]
pub struct DecompileRequest {
    /// The image file to decompile from.
    pub image_path: String,
    /// Any address inside the wanted function.
    pub rva: u64,
    /// The `(start, end)` of that function when the caller knows them (unwind
    /// data); the engine's own function list decides otherwise.
    pub function: Option<(u64, u64)>,
    pub symbols: Option<Arc<SymbolSet>>,
    /// Pending requests of the same view coalesce to their greatest sequence,
    /// even when IPC delivers an older generation later. `None` is always answered.
    pub client: Option<DecompileClient>,
}

/// The instructions one line of [`Decompiled::code`] was produced from.
#[derive(Debug, Clone)]
pub struct LineAddresses {
    /// 1-based line in `code`.
    pub line: u32,
    /// Sorted, unique.
    pub rvas: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct Decompiled {
    pub name: String,
    pub start_rva: u64,
    /// The function's extent in bytes: up to the caller's end when the request
    /// gave one, otherwise the engine's upper bound (up to the next function it
    /// knows; 0 when it could not be measured).
    pub size: u64,
    pub code: String,
    pub lines: Vec<LineAddresses>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DecompileError {
    #[error("{0}")]
    Specs(String),
    /// The image could not be loaded (unsupported format or machine, unreadable file).
    #[error("{0}")]
    Load(String),
    #[error("No function at this address")]
    NoFunction,
    /// The image is still being loaded into the engine, in the background:
    /// it took longer than a request waits. Asking again later finds it loaded.
    #[error("{0}")]
    StillLoading(String),
    /// The engine gave up on this function.
    #[error("{0}")]
    Failed(String),
    #[error("Superseded by a newer request")]
    Superseded,
    #[error("The decompiler is not running")]
    Unavailable,
}

/// Handle to the decompiler thread.
#[derive(Clone)]
pub struct Decompiler {
    jobs: mpsc::Sender<worker::Job>,
}

impl Decompiler {
    /// Start a decompiler thread that unpacks its specifications under `cache_dir`.
    pub fn start(cache_dir: PathBuf) -> Decompiler {
        Decompiler { jobs: worker::spawn(cache_dir) }
    }

    /// Queue a request; the answer arrives on the returned channel.
    pub fn submit(&self, request: DecompileRequest) -> mpsc::Receiver<Result<Decompiled, DecompileError>> {
        let (reply, answer) = mpsc::channel();
        if let Err(mpsc::SendError(job)) = self.jobs.send(worker::Job { request, reply, queued: std::time::Instant::now() }) {
            let _ = job.reply.send(Err(DecompileError::Unavailable));
        }
        answer
    }

    /// Decompile and wait for the answer. Blocks the calling thread for as long
    /// as the engine takes (and for whatever is queued before it), so not for
    /// a thread that serves anything else.
    pub fn decompile(&self, request: DecompileRequest) -> Result<Decompiled, DecompileError> {
        self.submit(request).recv().unwrap_or(Err(DecompileError::Unavailable))
    }
}

static CACHE_DIR: OnceLock<PathBuf> = OnceLock::new();
static GLOBAL: OnceLock<Decompiler> = OnceLock::new();

/// Where [`global`] unpacks the specifications. A host with a data directory
/// of its own calls this at startup; it has no effect once the decompiler runs.
pub fn set_cache_dir(dir: PathBuf) {
    let _ = CACHE_DIR.set(dir);
}

/// The process-wide decompiler, started on first use.
pub fn global() -> &'static Decompiler {
    GLOBAL.get_or_init(|| {
        let dir = CACHE_DIR.get().cloned().unwrap_or_else(|| {
            dirs::cache_dir().unwrap_or_else(std::env::temp_dir).join("joybug")
        });
        Decompiler::start(dir)
    })
}
