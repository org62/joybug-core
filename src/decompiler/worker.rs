//! The decompiler threads: the only place Kuna is called from.
//!
//! Kuna's loaded program is not `Send`, so each image lives on a thread of its
//! own (a [`Host`]) that loads it and then serves its requests. The
//! `decompiler` thread routes requests to them and waits for each answer only
//! so long: an image load cannot be interrupted, so one that takes longer goes
//! on in the background while other modules are served, and the requests for
//! it are told that it is still loading.

use super::{DecompileError, DecompileRequest, Decompiled, LineAddresses, SymbolSet};
use crate::interfaces::Architecture;
use crate::perf;
use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram, EntrySelector};
use kuna_console::project::{decompile_entry, DecompileOptions, FuncResult};
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Loaded images kept. Each holds the engine's whole analysis of one file.
const MAX_PROGRAMS: usize = 3;

/// The engine gives up on a function after this long (it checks cooperatively,
/// so this is a floor on the wait rather than a hard limit).
const FUNCTION_BUDGET: Duration = Duration::from_secs(15);

/// How long a request waits for its image to load into the engine. Past it,
/// the load goes on in the background and the request is answered
/// [`DecompileError::StillLoading`]; asking again later finds the image loaded.
const LOAD_WAIT: Duration = Duration::from_secs(20);

/// How long a request waits for a function of a loaded image: the engine's
/// budget for one, twice (the thunk-naming second pass), and some slack.
const FUNCTION_WAIT: Duration = Duration::from_secs(45);

/// Images loading at once. Each holds a whole image's analysis.
const MAX_LOADING: usize = 2;

/// The engine recurses over expression trees; a large function needs more than
/// a thread's default.
const STACK_SIZE: usize = 256 * 1024 * 1024;

// Pinned Kuna mutates KUNA_GOVERSION during bootstrap and reads it while
// initializing the architecture. Serialize that process-global environment use.
static BOOTSTRAP: Mutex<()> = Mutex::new(());

pub(super) struct Job {
    pub request: DecompileRequest,
    pub reply: mpsc::Sender<Result<Decompiled, DecompileError>>,
    /// When it was queued: the wait behind other requests is part of what the view waits.
    pub queued: Instant,
}

/// How a request ended, as the `outcome` attribute of `decompile.request`.
fn outcome_code(result: &Result<Decompiled, DecompileError>) -> u64 {
    match result {
        Ok(_) => 0,
        Err(DecompileError::NoFunction) => 1,
        Err(DecompileError::Superseded) => 2,
        Err(DecompileError::Failed(_)) => 3,
        Err(DecompileError::Load(_)) => 4,
        Err(DecompileError::Specs(_)) => 5,
        Err(DecompileError::StillLoading(_)) => 7,
        Err(_) => 6,
    }
}

pub(super) fn spawn(cache_dir: PathBuf) -> mpsc::Sender<Job> {
    let (jobs, queue) = mpsc::channel();
    std::thread::Builder::new()
        .name("decompiler".into())
        .spawn(move || Worker { cache_dir, spec_root: None, hosts: Vec::new() }.run(queue))
        .expect("spawn the decompiler thread");
    jobs
}

/// What makes a loaded program reusable: the same file, unchanged, with the
/// same names.
#[derive(Clone, PartialEq, Eq)]
struct ProgramKey {
    path: String,
    len: u64,
    modified: Option<SystemTime>,
    symbols: Option<u64>,
}

struct Program {
    key: ProgramKey,
    engine: ConsoleProgram,
    /// The file's own image base: engine address = this + RVA.
    image_base: u64,
    /// `(start, size)` of every function the engine knew after loading, sorted.
    functions: Vec<(u64, u64)>,
    symbols: Option<Arc<SymbolSet>>,
    /// x86 / x86-64 code: a `jmp rel32` thunk can be recognised by its bytes.
    x86: bool,
}

struct Worker {
    cache_dir: PathBuf,
    spec_root: Option<String>,
    /// Least recently used first.
    hosts: Vec<Host>,
}

/// One image in the engine, on its thread.
struct Host {
    key: ProgramKey,
    started: Instant,
    ready: Arc<Readiness>,
    /// A newer file/symbol key replaced this one; retain it until its work ends.
    invalidated: bool,
    /// Dropping it ends the thread, once it is done with what it is doing.
    jobs: mpsc::Sender<HostJob>,
}

#[derive(Default)]
struct Readiness {
    loaded: Mutex<bool>,
    working: AtomicBool,
    changed: Condvar,
}

impl Readiness {
    fn complete(&self) {
        *self.loaded.lock().expect("image readiness") = true;
        self.changed.notify_all();
    }

    fn is_loaded(&self) -> bool {
        *self.loaded.lock().expect("image readiness")
    }

    fn is_idle(&self) -> bool {
        self.is_loaded() && !self.working.load(Ordering::Acquire)
    }

    fn wait(&self, timeout: Duration) -> bool {
        let loaded = self.loaded.lock().expect("image readiness");
        let (loaded, _) = self.changed.wait_timeout_while(loaded, timeout, |loaded| !*loaded).expect("image readiness");
        *loaded
    }
}

struct HostJob {
    request: DecompileRequest,
    reply: mpsc::Sender<Result<Decompiled, DecompileError>>,
}

impl Host {
    fn start(key: ProgramKey, spec_root: String, symbols: Option<Arc<SymbolSet>>) -> Result<Host, DecompileError> {
        let (jobs, queue) = mpsc::channel();
        let ready = Arc::new(Readiness::default());
        let thread_key = key.clone();
        let thread_ready = Arc::clone(&ready);
        std::thread::Builder::new()
            .name("decompiler-image".into())
            .stack_size(STACK_SIZE)
            .spawn(move || host(thread_key, &spec_root, symbols, &thread_ready, queue))
            .map_err(|e| DecompileError::Load(format!("Cannot start loading the image: {e}")))?;
        Ok(Host { key, started: Instant::now(), ready, invalidated: false, jobs })
    }

    fn is_loaded(&self) -> bool {
        self.ready.is_loaded()
    }

    fn still_loading(&self) -> DecompileError {
        DecompileError::StillLoading(format!(
            "The decompiler is still analysing this image ({} MB, {} s so far). Refresh to try again.",
            self.key.len.div_ceil(1024 * 1024),
            self.started.elapsed().as_secs()
        ))
    }
}

/// A host thread: load the image, then serve its requests until the worker
/// lets go of it. A load that failed answers every request with its error,
/// so a file the engine cannot take is not loaded again for each.
fn host(key: ProgramKey, spec_root: &str, symbols: Option<Arc<SymbolSet>>, ready: &Readiness, queue: mpsc::Receiver<HostJob>) {
    let program = catch_unwind(AssertUnwindSafe(|| Program::load(key, spec_root, symbols.as_ref())))
        .unwrap_or_else(|panic| Err(DecompileError::Load(format!("The decompiler failed loading this image: {}", panic_message(&*panic)))));
    ready.complete();
    let mut program = match program {
        Ok(program) => program,
        Err(error) => {
            for job in queue.iter() {
                ready.working.store(false, Ordering::Release);
                let _ = job.reply.send(Err(error.clone()));
            }
            return;
        }
    };
    for job in queue.iter() {
        // A panic inside the engine leaves the program in whatever state the
        // unwind left: the thread ends, and the next request loads it afresh.
        let result = catch_unwind(AssertUnwindSafe(|| program.decompile(&job.request)));
        ready.working.store(false, Ordering::Release);
        match result {
            Ok(result) => {
                let _ = job.reply.send(result);
            }
            Err(panic) => {
                let message = format!("The decompiler failed on this function: {}", panic_message(&*panic));
                let _ = job.reply.send(Err(DecompileError::Failed(message)));
                return;
            }
        }
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("unknown error")
}

/// Keep at most the greatest pending generation of each view. Replacing a
/// request keeps the replacement's arrival position relative to other clients.
fn enqueue(pending: &mut VecDeque<Job>, job: Job) {
    if let Some(client) = &job.request.client {
        if let Some(index) = pending.iter().position(|other| other.request.client.as_ref().is_some_and(|other| other.id == client.id)) {
            if pending[index].request.client.as_ref().expect("matching client").sequence > client.sequence {
                let _ = job.reply.send(Err(DecompileError::Superseded));
                return;
            }
            let previous = pending.remove(index).expect("matching pending request");
            let _ = previous.reply.send(Err(DecompileError::Superseded));
        }
    }
    pending.push_back(job);
}

impl Worker {
    fn run(mut self, queue: mpsc::Receiver<Job>) {
        let mut pending: VecDeque<Job> = VecDeque::new();
        loop {
            if pending.is_empty() {
                match queue.recv() {
                    Ok(job) => enqueue(&mut pending, job),
                    Err(_) => return,
                }
            }
            for job in queue.try_iter() {
                enqueue(&mut pending, job);
            }
            let job = pending.pop_front().expect("a job is pending");
            let mut span = perf::span("decompile.request");
            span.attr_elapsed("queue_us", job.queued);
            span.attr("queued_behind", pending.len() as u64);
            span.attr("module_key", perf::path_key(&job.request.image_path));
            // A request that never ends records no span: this says one started.
            perf::record(
                "decompile.request.begin",
                perf::now_us(),
                0,
                &[("queue_us", job.queued.elapsed().as_micros() as u64), ("module_key", perf::path_key(&job.request.image_path))],
            );
            let result = self.serve(&job.request);
            span.attr("outcome", outcome_code(&result));
            drop(span);
            let _ = job.reply.send(result);
        }
    }

    fn serve(&mut self, request: &DecompileRequest) -> Result<Decompiled, DecompileError> {
        let metadata = std::fs::metadata(&request.image_path)
            .map_err(|e| DecompileError::Load(format!("Cannot read {}: {e}", request.image_path)))?;
        let key = ProgramKey {
            path: request.image_path.clone(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
            symbols: request.symbols.as_ref().map(|s| s.fingerprint()),
        };
        let index = self.host_for(key, request.symbols.as_ref())?;
        self.serve_host(index, request, LOAD_WAIT, FUNCTION_WAIT)
    }

    fn serve_host(
        &mut self,
        index: usize,
        request: &DecompileRequest,
        load_wait: Duration,
        function_wait: Duration,
    ) -> Result<Decompiled, DecompileError> {
        let host = &self.hosts[index];
        if !host.ready.wait(load_wait) {
            perf::record(
                "decompile.load.waited_out",
                perf::now_us(),
                0,
                &[("module_key", perf::path_key(&host.key.path)), ("loading_us", host.started.elapsed().as_micros() as u64)],
            );
            return Err(host.still_loading());
        }
        // A timeout cannot interrupt Kuna. Keep the active host accounted for,
        // and do not build an unseen queue behind a function still executing.
        if host.ready.working.swap(true, Ordering::AcqRel) {
            return Err(DecompileError::Failed(
                "The decompiler is still working on the previous function. Refresh to try again.".to_string(),
            ));
        }
        // Do not queue function work until loading completed: a request that
        // timed out above leaves only the shared image load running.
        let (reply, answer) = mpsc::channel();
        if host.jobs.send(HostJob { request: request.clone(), reply }).is_err() {
            host.ready.working.store(false, Ordering::Release);
            self.hosts.remove(index);
            return Err(DecompileError::Failed("The decompiler stopped on this image. Refresh to try again.".to_string()));
        }
        match answer.recv_timeout(function_wait) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                Err(DecompileError::Failed("The decompiler is taking too long on this function. Refresh to try again.".to_string()))
            }
            Err(RecvTimeoutError::Disconnected) => {
                // The host thread ended (a panic): the image is loaded afresh next time.
                self.hosts.remove(index);
                Err(DecompileError::Failed("The decompiler failed on this image. Refresh to try again.".to_string()))
            }
        }
    }

    /// The host for `key`, moved to the most-recent end, started if need be.
    fn host_for(&mut self, key: ProgramKey, symbols: Option<&Arc<SymbolSet>>) -> Result<usize, DecompileError> {
        self.prepare_hosts(&key)?;
        if let Some(index) = self.hosts.iter().position(|h| h.key == key) {
            let host = self.hosts.remove(index);
            self.hosts.push(host);
            return Ok(self.hosts.len() - 1);
        }
        let spec_root = self.spec_root()?;
        self.hosts.push(Host::start(key, spec_root, symbols.cloned())?);
        Ok(self.hosts.len() - 1)
    }

    /// Keep invalidated work accounted for until it finishes, then discard it.
    /// A timed-out function still owns its thread and image until it returns.
    fn prepare_hosts(&mut self, key: &ProgramKey) -> Result<(), DecompileError> {
        for host in &mut self.hosts {
            if host.key.path == key.path {
                host.invalidated = host.key != *key;
            }
        }
        self.hosts.retain(|host| !host.invalidated || !host.ready.is_idle());
        if self.hosts.iter().any(|host| host.key == *key) {
            return Ok(());
        }
        if self.hosts.iter().filter(|host| !host.is_loaded()).count() >= MAX_LOADING {
            return Err(DecompileError::StillLoading(
                "The decompiler is still analysing other large images. Refresh to try again.".to_string(),
            ));
        }
        if self.hosts.len() >= MAX_PROGRAMS {
            let Some(evict) = self.hosts.iter().position(|host| host.ready.is_idle()) else {
                return Err(DecompileError::Failed(
                    "The decompiler is still working on other functions. Refresh to try again.".to_string(),
                ));
            };
            self.hosts.remove(evict);
        }
        Ok(())
    }

    fn spec_root(&mut self) -> Result<String, DecompileError> {
        if self.spec_root.is_none() {
            let _span = perf::span("decompile.specs");
            let dir = super::specs::ensure_unpacked(&self.cache_dir).map_err(DecompileError::Specs)?;
            self.spec_root = Some(dir.to_string_lossy().into_owned());
        }
        Ok(self.spec_root.clone().expect("just set"))
    }
}

impl Program {
    fn load(key: ProgramKey, spec_root: &str, symbols: Option<&Arc<SymbolSet>>) -> Result<Program, DecompileError> {
        let mut span = perf::span("decompile.load");
        span.attr("module_key", perf::path_key(&key.path));
        span.attr("file_bytes", key.len);
        perf::record("decompile.load.begin", perf::now_us(), 0, &[("module_key", perf::path_key(&key.path)), ("file_bytes", key.len)]);
        let load_error = |what: &str, e: kuna_base::error::KunaError| DecompileError::Load(format!("{what}: {}", e.explain()));

        let phase = Instant::now();
        let (image_base, x86) = file_layout(&key.path).map_err(DecompileError::Load)?;
        span.attr_elapsed("layout_us", phase);
        let phase = Instant::now();
        perf::record("decompile.load.bootstrap.begin", perf::now_us(), 0, &[("module_key", perf::path_key(&key.path))]);
        let mut engine = {
            // A panic in upstream bootstrap may poison the lock, but must not
            // prevent an unrelated image from being initialized afterward.
            let _bootstrap = BOOTSTRAP.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            bootstrap_from_object(&key.path, "", &[spec_root.to_string()])
                .map_err(|e| load_error("The decompiler cannot load this image", e))?
        };
        span.attr_elapsed("bootstrap_us", phase);
        // Kuna's own size policy: thorough on a small image, cheap on a large one.
        let mode = kuna_decomp::modes::resolve_mode_for_size(None, key.len).unwrap_or("fast");
        engine.arch_mut().apply_mode(mode).map_err(|e| load_error("Decompiler mode", e))?;
        if mode == "fast" {
            // The large-image mode still walks every function to discover more
            // (24 s of the load on an 84 MB image). We do not need it: the
            // functions are seeded below and the caller's unwind bounds declare
            // any the engine does not list (`decompile_at`).
            engine.arch_mut().analysis_fast_funcdisc = false;
        }
        engine.arch_mut().kuna_fn_budget = Some(FUNCTION_BUDGET);

        let phase = Instant::now();
        if let Some(symbols) = symbols {
            span.attr("symbols", symbols.names().len() as u64);
            let space = engine.arch().manage().get_default_code_space().cloned();
            if let Some(space) = space {
                let names: Vec<(String, Address)> = symbols
                    .names()
                    .iter()
                    .map(|(rva, name)| (name.clone(), Address::new(space.clone(), image_base + rva)))
                    .collect();
                engine.seed_function_inventory(&names).map_err(|e| load_error("Function names", e))?;
            }
        }
        span.attr_elapsed("seed_us", phase);
        let phase = Instant::now();
        perf::record("decompile.load.analysis.begin", perf::now_us(), 0, &[("module_key", perf::path_key(&key.path))]);
        engine.commit_pending_analysis().map_err(|e| load_error("Image analysis", e))?;
        span.attr_elapsed("analysis_us", phase);

        let mut functions: Vec<(u64, u64)> =
            engine.function_entries_executable().iter().map(|f| (f.addr.get_offset(), f.size)).collect();
        functions.sort_unstable();
        span.attr("functions", functions.len() as u64);
        Ok(Program { key, engine, image_base, functions, symbols: symbols.cloned(), x86 })
    }

    fn decompile(&mut self, request: &DecompileRequest) -> Result<Decompiled, DecompileError> {
        let mut span = perf::span("decompile.function");
        span.attr("module_key", perf::path_key(&self.key.path));
        perf::record("decompile.function.begin", perf::now_us(), 0, &[("module_key", perf::path_key(&self.key.path))]);
        let base = self.image_base;
        let address = base + request.rva;
        let hint = request.function.map(|(start, _)| base + start);
        // A jump thunk nobody lists is a function of its own, not the tail of
        // whichever function the engine knows before it.
        let unlisted_thunk = hint.is_none() && !self.is_listed(address) && self.jump_thunk_target(address).is_some();
        let start = if unlisted_thunk { Some(address) } else { function_start(&self.functions, address, hint) };
        let start = start.ok_or(DecompileError::NoFunction)?;

        let phase = Instant::now();
        let mut result = self.decompile_at(start)?;
        span.attr_elapsed("first_pass_us", phase);
        // Naming the thunks it calls changes how those calls print.
        if result.code.as_deref().is_some_and(|code| self.name_called_thunks(code)) {
            span.attr("second_pass", 1);
            result = self.decompile_at(start)?;
        }

        let code = match (result.code, result.error) {
            (Some(code), None) => code,
            (_, Some(error)) => return Err(DecompileError::Failed(error)),
            (None, None) => return Err(DecompileError::Failed("The decompiler produced no output".to_string())),
        };
        let lines: Vec<LineAddresses> = result
            .line_mappings
            .into_iter()
            .map(|mapping| LineAddresses {
                line: mapping.line_number as u32,
                rvas: mapping.addresses.into_iter().filter_map(|a| a.checked_sub(base)).collect(),
            })
            .filter(|line| !line.rvas.is_empty())
            .collect();
        span.attr("code_bytes", code.len() as u64);
        span.attr("mapped_lines", lines.len() as u64);
        let size = match request.function {
            Some((_, end)) if base + end > start => base + end - start,
            _ => result.size.max(0) as u64,
        };
        Ok(Decompiled {
            name: result.name,
            start_rva: start - base,
            size,
            code,
            lines,
        })
    }

    fn is_listed(&self, start: u64) -> bool {
        self.functions.binary_search_by_key(&start, |&(s, _)| s).is_ok()
    }

    fn code_address(&self, address: u64) -> Option<Address> {
        let space = self.engine.arch().manage().get_default_code_space().cloned()?;
        Some(Address::new(space, address))
    }

    /// Decompile the function starting at `start`, telling the engine first
    /// that one starts there if only the caller knew.
    fn decompile_at(&mut self, start: u64) -> Result<FuncResult, DecompileError> {
        if !self.is_listed(start) {
            let at = self.code_address(start).ok_or(DecompileError::NoFunction)?;
            self.engine.declare_function(at, None, 0).map_err(|e| DecompileError::Failed(e.explain().to_string()))?;
        }
        let entry = self
            .engine
            .resolve_body_entry(&EntrySelector::Numeric(start))
            .map_err(|_| DecompileError::NoFunction)?;
        let options = DecompileOptions { single_target: true, want_provenance: true, ..Default::default() };
        Ok(decompile_entry(&mut self.engine, entry, &options))
    }

    /// Where the `jmp rel32` at `address` leads, if that is what is there.
    fn jump_thunk_target(&self, address: u64) -> Option<u64> {
        const JMP_REL32: u8 = 0xE9;
        let mut bytes = Vec::new();
        if !self.x86 || !self.engine.read_bytes_into(address, 5, &mut bytes) || bytes[0] != JMP_REL32 {
            return None;
        }
        let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        Some(address.wrapping_add(5).wrapping_add_signed(displacement as i64))
    }

    /// Name the jump thunks `code` calls by address (`sub_140001041`) after
    /// the function each leads to (`j_xtea_encrypt`). Returns whether any was.
    ///
    /// An incrementally linked MSVC image (every debug build) calls each
    /// function through a 5-byte `jmp` thunk that no symbol names, so without
    /// this a caller reads as calls to addresses.
    fn name_called_thunks(&mut self, code: &str) -> bool {
        let Some(symbols) = self.symbols.clone() else { return false };
        let base = self.image_base;
        let unnamed: std::collections::BTreeSet<u64> = code
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter_map(|word| u64::from_str_radix(word.strip_prefix("sub_")?, 16).ok())
            .collect();
        let mut named = false;
        for address in unnamed {
            let target = self.jump_thunk_target(address).and_then(|target| target.checked_sub(base));
            let (Some(name), Some(at)) = (target.and_then(|rva| symbols.name_at(rva)), self.code_address(address)) else {
                continue;
            };
            named |= self.engine.declare_function(at, Some(&format!("j_{name}")), 5).is_ok();
        }
        named
    }
}

/// The start of the function containing `address`: the nearest start at or
/// below it that the engine (`functions`: sorted `(start, size)`) or the caller
/// (`hint`) knows. The engine's extent for a function runs up to the next one
/// *it* knows, so a caller's start between the two wins.
fn function_start(functions: &[(u64, u64)], address: u64, hint: Option<u64>) -> Option<u64> {
    let hint = hint.filter(|&start| start <= address);
    let known = functions[..functions.partition_point(|&(start, _)| start <= address)].last().copied();
    match known {
        Some((start, _)) if hint.is_some_and(|h| h > start) => hint,
        Some((start, size)) if size == 0 || address - start < size => Some(start),
        _ => hint,
    }
}

/// What the engine's view of the file hangs on: the image base the file
/// itself declares (PE `ImageBase`, the lowest ELF segment address — engine
/// addresses are relative to it), and whether its code is x86.
fn file_layout(path: &str) -> Result<(u64, bool), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let (info, arch) = if bytes.starts_with(b"\x7fELF") {
        use object::Object;
        let arch = match object::File::parse(&*bytes).map(|file| file.architecture()) {
            Ok(object::Architecture::X86_64) => Some(Architecture::X64),
            Ok(object::Architecture::I386) => Some(Architecture::X86),
            _ => None,
        };
        (crate::elf::info::module_extra_info_from_bytes(&bytes, Path::new(path)), arch)
    } else {
        let info = crate::symbols::module_extra::parse_module_extra_info_from_bytes(&bytes);
        let arch = info.as_ref().ok().and_then(|info| Architecture::from_machine(info.nt_headers.FileHeader.Machine));
        (info, arch)
    };
    let info = info.map_err(|e| format!("{path} is not an image the decompiler can load: {e:?}"))?;
    Ok((info.nt_headers.OptionalHeader.ImageBase, matches!(arch, Some(Architecture::X64 | Architecture::X86))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::DecompileClient;

    fn request(rva: u64, client: Option<(&str, u64)>) -> DecompileRequest {
        DecompileRequest {
            image_path: "image".into(),
            rva,
            function: None,
            symbols: None,
            client: client.map(|(id, sequence)| DecompileClient { id: id.into(), sequence }),
        }
    }

    fn enqueue_request(
        pending: &mut VecDeque<Job>,
        rva: u64,
        client: Option<(&str, u64)>,
    ) -> mpsc::Receiver<Result<Decompiled, DecompileError>> {
        let (reply, answer) = mpsc::channel();
        enqueue(pending, Job { request: request(rva, client), reply, queued: Instant::now() });
        answer
    }

    fn key(path: &str, generation: u64) -> ProgramKey {
        ProgramKey { path: path.into(), len: generation, modified: None, symbols: Some(generation) }
    }

    fn fake_host(key: ProgramKey) -> (Host, mpsc::Receiver<HostJob>) {
        let (jobs, queue) = mpsc::channel();
        (Host { key, started: Instant::now(), ready: Arc::new(Readiness::default()), invalidated: false, jobs }, queue)
    }

    fn worker(hosts: Vec<Host>) -> Worker {
        Worker { cache_dir: PathBuf::new(), spec_root: None, hosts }
    }

    #[test]
    fn pending_generations_keep_the_maximum_and_unrelated_fifo() {
        let mut pending = VecDeque::new();
        let older = enqueue_request(&mut pending, 1, Some(("view-a", 1)));
        let _unrelated = enqueue_request(&mut pending, 2, Some(("view-b", 1)));
        let _noncoalesced = enqueue_request(&mut pending, 3, None);
        let _newest = enqueue_request(&mut pending, 4, Some(("view-a", 3)));
        let late_older = enqueue_request(&mut pending, 5, Some(("view-a", 2)));
        let _another_noncoalesced = enqueue_request(&mut pending, 6, None);

        assert!(matches!(older.try_recv(), Ok(Err(DecompileError::Superseded))));
        assert!(matches!(late_older.try_recv(), Ok(Err(DecompileError::Superseded))));
        assert_eq!(pending.iter().map(|job| job.request.rva).collect::<Vec<_>>(), vec![2, 3, 4, 6]);
    }

    #[test]
    fn same_path_invalidated_loads_still_count_until_complete() {
        let (first, first_queue) = fake_host(key("same-image", 1));
        let (second, second_queue) = fake_host(key("same-image", 2));
        let first_ready = Arc::clone(&first.ready);
        let second_ready = Arc::clone(&second.ready);
        let mut worker = worker(vec![first, second]);

        assert!(matches!(worker.prepare_hosts(&key("same-image", 3)), Err(DecompileError::StillLoading(_))));
        assert_eq!(worker.hosts.len(), MAX_LOADING);
        assert!(worker.hosts.iter().all(|host| host.invalidated));
        assert!(matches!(first_queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert!(matches!(second_queue.try_recv(), Err(mpsc::TryRecvError::Empty)));

        first_ready.complete();
        worker.prepare_hosts(&key("same-image", 3)).unwrap();
        assert_eq!(worker.hosts.len(), 1);
        assert!(matches!(first_queue.try_recv(), Err(mpsc::TryRecvError::Disconnected)));
        assert!(matches!(second_queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        second_ready.complete();
        // Completed invalidated loads are also pruned for an unrelated image.
        worker.prepare_hosts(&key("other-image", 1)).unwrap();
        assert!(worker.hosts.is_empty());
        assert!(matches!(second_queue.try_recv(), Err(mpsc::TryRecvError::Disconnected)));
    }

    #[test]
    fn cache_capacity_evicts_a_complete_host_not_a_loading_one() {
        let (first, first_queue) = fake_host(key("first", 1));
        let (second, second_queue) = fake_host(key("second", 1));
        let (third, third_queue) = fake_host(key("third", 1));
        second.ready.complete();
        third.ready.complete();
        let mut worker = worker(vec![first, second, third]);

        worker.prepare_hosts(&key("fourth", 1)).unwrap();
        let (fourth, _fourth_queue) = fake_host(key("fourth", 1));
        worker.hosts.push(fourth);
        assert_eq!(worker.hosts.len(), MAX_PROGRAMS);
        assert!(matches!(first_queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert!(matches!(second_queue.try_recv(), Err(mpsc::TryRecvError::Disconnected)));
        assert!(matches!(third_queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn load_timeout_queues_nothing_and_ready_retry_gets_function_wait() {
        let (host, queue) = fake_host(key("image", 1));
        let ready = Arc::clone(&host.ready);
        let mut worker = worker(vec![host]);
        let request = request(0x1000, None);

        assert!(matches!(
            worker.serve_host(0, &request, Duration::ZERO, Duration::ZERO),
            Err(DecompileError::StillLoading(_))
        ));
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));

        ready.complete();
        let responder = std::thread::spawn(move || {
            let job = queue.recv().unwrap();
            assert_eq!(job.request.rva, 0x1000);
            job.reply.send(Err(DecompileError::NoFunction)).unwrap();
        });
        assert!(matches!(
            worker.serve_host(0, &request, Duration::ZERO, Duration::from_secs(5)),
            Err(DecompileError::NoFunction)
        ));
        responder.join().unwrap();
    }

    #[test]
    fn timed_out_functions_are_not_evicted_or_queued_again() {
        let (first, first_queue) = fake_host(key("first", 1));
        let (second, second_queue) = fake_host(key("second", 1));
        let (third, third_queue) = fake_host(key("third", 1));
        for host in [&first, &second, &third] {
            host.ready.complete();
        }
        let mut worker = worker(vec![first, second, third]);
        let request = request(0x1000, None);
        let mut running = Vec::new();
        for (index, queue) in [&first_queue, &second_queue, &third_queue].into_iter().enumerate() {
            assert!(matches!(
                worker.serve_host(index, &request, Duration::ZERO, Duration::ZERO),
                Err(DecompileError::Failed(_))
            ));
            running.push(queue.try_recv().expect("the function is still running"));
        }

        let _ = worker.serve_host(0, &request, Duration::ZERO, Duration::ZERO);
        assert!(matches!(first_queue.try_recv(), Err(mpsc::TryRecvError::Empty)), "a retry must not queue behind a stalled function");
        assert!(worker.prepare_hosts(&key("first", 2)).is_err(), "a stalled image must remain accounted for");
        assert_eq!(worker.hosts.len(), MAX_PROGRAMS);
        drop(running);
    }

    #[test]
    fn function_start_prefers_the_nearest_known_start() {
        let functions = [(0x1000, 0x40), (0x1040, 0x100), (0x2000, 0)];
        assert_eq!(function_start(&functions, 0x1000, None), Some(0x1000));
        assert_eq!(function_start(&functions, 0x103f, None), Some(0x1000));
        assert_eq!(function_start(&functions, 0x1050, None), Some(0x1040));
        // Past the extent of the last function before it: nothing of the engine's.
        assert_eq!(function_start(&functions, 0x1200, None), None);
        assert_eq!(function_start(&functions, 0x0800, None), None);
        // An unmeasured extent contains whatever follows it.
        assert_eq!(function_start(&functions, 0x2abc, None), Some(0x2000));

        // The caller's start wins when it is nearer than the engine's...
        assert_eq!(function_start(&functions, 0x10c0, Some(0x10a0)), Some(0x10a0));
        assert_eq!(function_start(&functions, 0x1200, Some(0x11f0)), Some(0x11f0));
        // ...and loses when the engine knows a nearer one, or it lies above the address.
        assert_eq!(function_start(&functions, 0x1050, Some(0x1000)), Some(0x1040));
        assert_eq!(function_start(&functions, 0x1010, Some(0x1020)), Some(0x1000));
        assert_eq!(function_start(&[], 0x1010, Some(0x1000)), Some(0x1000));
        assert_eq!(function_start(&[], 0x1010, None), None);
    }
}
