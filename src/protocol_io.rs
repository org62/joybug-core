use crate::interfaces::{Architecture, Instruction, ModuleSymbol};
use crate::pe_types::ModuleExtraInfo;
pub use crate::protocol::{
    AddressLineInfo, DebuggerRequest, DebuggerResponse, DebugEvent, EmulationMode,
    HardwareBreakpointSize, HardwareBreakpointType, MinidumpKind, ModuleInfo, ModuleSymbolStatus,
    PdbLoadOutcome, PdbMismatchInfo, ProcessInfo, ScanCompareType, ScanRegionFilter, ScanValue,
    ScanValueType, StepAction, StepKind, StringEncodingFilter, StringHit, StringSortKey,
    SymbolLoadState, ThreadContext, ThreadInfo, ProcessObjects,
    TraceExitCondition, TypeClass, TypeEnumValue, TypeLayout, TypeMember, TypeRef, TypeSummary,
    UdtKind,
};

/// Result from trace_instructions()
#[derive(Debug, Clone)]
pub struct TenetTraceResult {
    pub trace_text: String,
    pub stop_reason: String,
    pub trace_time_us: u64,
    pub stats_text: String,
    /// PC after the last traced instruction (emulation traces only).
    pub final_pc: Option<u64>,
    pub instructions_executed: usize,
}

/// Result from emulate_instructions()
#[derive(Debug, Clone)]
pub enum EmulateResult {
    Trace(TenetTraceResult),
    Emulation(EmulationResultData),
}

/// Emulation result data for non-trace modes
#[derive(Debug, Clone)]
pub struct EmulationResultData {
    pub final_pc: u64,
    pub instructions_executed: usize,
    pub stop_reason: String,
    pub emulation_time_us: u64,
    pub pages_loaded: usize,
    pub basic_blocks: Vec<u64>,
    pub stats_text: String,
    /// Memory snapshots read from emulator state after execution
    pub memory_snapshots: Vec<(u64, Vec<u8>)>,
}
use std::collections::HashMap;
pub use std::net::TcpStream;
use std::sync::Mutex;
use crate::framed_json_stream::FramedJsonStream;
use tracing::{debug, error, info, warn};

/// What the debugger should do when encountering an exception
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionAction {
    /// Pass to application (DBG_EXCEPTION_NOT_HANDLED) and auto-continue
    PassToApplication,
    /// Handle by debugger (DBG_CONTINUE) and auto-continue
    HandledByDebugger,
    /// Stop execution and let the user decide
    Stop,
}

/// Per-exception-code configuration
#[derive(Debug, Clone)]
pub struct ExceptionCodeConfig {
    pub first_chance: ExceptionAction,
    pub second_chance: ExceptionAction,
}

/// Exception handling configuration
#[derive(Debug, Clone)]
pub struct ExceptionConfig {
    /// Default for first-chance exceptions not in per_code map
    pub default_first_chance: ExceptionAction,
    /// Default for second-chance exceptions
    pub default_second_chance: ExceptionAction,
    /// Per-exception-code overrides
    pub per_code: HashMap<u32, ExceptionCodeConfig>,
}

impl Default for ExceptionConfig {
    fn default() -> Self {
        Self {
            default_first_chance: ExceptionAction::Stop,
            default_second_chance: ExceptionAction::Stop,
            per_code: HashMap::new(),
        }
    }
}

impl ExceptionConfig {
    /// Look up the action for a given exception code and chance
    pub fn action_for(&self, code: u32, first_chance: bool) -> ExceptionAction {
        if let Some(config) = self.per_code.get(&code) {
            if first_chance { config.first_chance } else { config.second_chance }
        } else if first_chance {
            self.default_first_chance
        } else {
            self.default_second_chance
        }
    }
}

pub fn send_request(stream: &mut FramedJsonStream, req: &DebuggerRequest) -> anyhow::Result<()> {
    debug!("Sending request: {:?}", req);
    stream.send(req)
}

pub fn receive_response(stream: &mut FramedJsonStream) -> anyhow::Result<DebuggerResponse> {
    let resp: DebuggerResponse = stream.receive()?;
    // Print only the response type, and for Instructions include the count
    let summary = match &resp {
        DebuggerResponse::Instructions { instructions } => {
            format!("Instructions ({} instructions)", instructions.len())
        }
        DebuggerResponse::HardwareBreakpointSet { dr_index } => format!("HardwareBreakpointSet(dr={})", dr_index),
        DebuggerResponse::MinidumpWritten { size_bytes } => format!("MinidumpWritten({} bytes)", size_bytes),
        DebuggerResponse::Ack => "Ack".to_string(),
        DebuggerResponse::Error { .. } => "Error".to_string(),
        DebuggerResponse::Event { .. } => "Event".to_string(),
        DebuggerResponse::MemoryData { .. } => "MemoryData".to_string(),
        DebuggerResponse::WriteAck => "WriteAck".to_string(),
        DebuggerResponse::ThreadContext { .. } => "ThreadContext".to_string(),
        DebuggerResponse::SetContextAck => "SetContextAck".to_string(),
        DebuggerResponse::ModuleList { .. } => "ModuleList".to_string(),
        DebuggerResponse::ThreadList { .. } => "ThreadList".to_string(),
        DebuggerResponse::ProcessArchitecture { arch } => format!("ProcessArchitecture({:?})", arch),
        DebuggerResponse::ProcessObjects { .. } => "ProcessObjects".to_string(),
        DebuggerResponse::ProcessList { .. } => "ProcessList".to_string(),
        DebuggerResponse::Symbol { .. } => "Symbol".to_string(),
        DebuggerResponse::SymbolList { .. } => "SymbolList".to_string(),
        DebuggerResponse::ResolvedSymbolList { .. } => "ResolvedSymbolList".to_string(),
        DebuggerResponse::CoverageResults { hits } => format!("CoverageResults ({} entries)", hits.len()),
        DebuggerResponse::CoverageTargetList { targets } => format!("CoverageTargetList ({} entries)", targets.len()),
        DebuggerResponse::WatchpointAccesses { accesses } => format!("WatchpointAccesses ({} entries)", accesses.len()),
        DebuggerResponse::AddressSymbol { .. } => "AddressSymbol".to_string(),
        DebuggerResponse::AddressSymbolBatch { results } => format!("AddressSymbolBatch ({} addresses)", results.len()),
        DebuggerResponse::CallStack { .. } => "CallStack".to_string(),
        DebuggerResponse::FunctionArguments { .. } => "FunctionArguments".to_string(),
        DebuggerResponse::WideStringData { .. } => "WideStringData".to_string(),
        DebuggerResponse::ModuleExtraInfo { .. } => "ModuleExtraInfo".to_string(),
        DebuggerResponse::MemoryRegionInfo { .. } => "MemoryRegionInfo".to_string(),
        DebuggerResponse::MemoryRegionList { regions } => format!("MemoryRegionList ({} regions)", regions.len()),
        DebuggerResponse::DereferenceResult { entries } => format!("DereferenceResult ({} entries)", entries.len()),
        DebuggerResponse::DereferenceBatchResult { results } => format!("DereferenceBatchResult ({} addresses)", results.len()),
        DebuggerResponse::FunctionDisassembly { instructions, .. } => format!("FunctionDisassembly ({} instructions)", instructions.len()),
        DebuggerResponse::EmulationResult { instructions_executed, .. } => format!("EmulationResult ({} instructions)", instructions_executed),
        DebuggerResponse::TenetTrace { trace_text, .. } => format!("TenetTrace ({} bytes)", trace_text.len()),
        DebuggerResponse::MemorySearchResult { addresses, capped } => format!("MemorySearchResult ({} matches, capped={})", addresses.len(), capped),
        DebuggerResponse::ScanMemoryResult { match_count, .. } => format!("ScanMemoryResult ({} matches)", match_count),
        DebuggerResponse::ScanMemoryResults { addresses, total_count, .. } => format!("ScanMemoryResults ({}/{} returned)", addresses.len(), total_count),
        DebuggerResponse::PointerScanResult { match_count, .. } => format!("PointerScanResult ({} paths)", match_count),
        DebuggerResponse::PointerScanResults { paths, total_count } => format!("PointerScanResults ({}/{} returned)", paths.len(), total_count),
        DebuggerResponse::StringScanResult { match_count, capped, .. } => format!("StringScanResult ({} strings{})", match_count, if *capped { ", capped" } else { "" }),
        DebuggerResponse::StringScanResults { strings, total_count } => format!("StringScanResults ({}/{} returned)", strings.len(), total_count),
        DebuggerResponse::PebHideResult { report } => format!(
            "PebHideResult (peb=0x{:X}, applied={}, failed={})",
            report.peb_address, report.applied.len(), report.failures.len(),
        ),
        DebuggerResponse::FreezeValueStarted { freeze_id } => format!("FreezeValueStarted (id={})", freeze_id),
        DebuggerResponse::SymbolStatusList { statuses } => format!("SymbolStatusList ({} modules)", statuses.len()),
        DebuggerResponse::PdbLoaded { symbol_count } => format!("PdbLoaded ({} symbols)", symbol_count),
        DebuggerResponse::PdbMismatch(_) => "PdbMismatch".to_string(),
        DebuggerResponse::AddressLine { .. } => "AddressLine".to_string(),
        DebuggerResponse::SourceFileLineMap { entries, .. } => format!("SourceFileLineMap ({} entries)", entries.len()),
        DebuggerResponse::SourceFileList { files } => format!("SourceFileList ({} files)", files.len()),
        DebuggerResponse::TypeList { types } => format!("TypeList ({} types)", types.len()),
        DebuggerResponse::TypeResult { layout } => format!("TypeResult ({})", layout.as_ref().map(|l| l.name.as_str()).unwrap_or("none")),
        DebuggerResponse::TebAddress { .. } => "TebAddress".to_string(),
        DebuggerResponse::PebAddress { .. } => "PebAddress".to_string(),
    };
    debug!("Received response: {}", summary);
    Ok(resp)
}

struct SteppingInfo<S> {
    handler: Box<
        dyn FnMut(&mut DebugSession<S>, u32, u32, u64, crate::protocol::StepKind) -> Result<StepAction, anyhow::Error>
            + Send
            + 'static,
    >,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointDecision {
    Keep,
    Remove,
}

/// Debug session with state management
pub struct DebugSession<S> {
    pub stream: Mutex<FramedJsonStream>,
    pub state: S,
    on_initial_breakpoint: Option<Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + 'static>>,
    single_shot_handlers:
        HashMap<u64, Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + 'static>>,
    breakpoint_handlers: HashMap<u64, Vec<Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<BreakpointDecision> + Send + 'static>>>,
    stepping_info: Option<SteppingInfo<S>>,
    on_dll_loaded:
        Option<Box<dyn FnMut(&mut Self, u32, u32, &str, u64) -> anyhow::Result<()> + Send + 'static>>,
    on_dll_unloaded:
        Option<Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + 'static>>,
        on_thread_created:
        Option<Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + Sync + 'static>>,
    on_process_exited:
        Option<Box<dyn FnMut(&mut Self, u32, u32) -> anyhow::Result<()> + Send + 'static>>,
    on_thread_exited:
        Option<Box<dyn FnMut(&mut Self, u32, u32, u32) -> anyhow::Result<()> + Send + Sync + 'static>>,
    on_process_created:
        Option<Box<dyn FnMut(&mut Self, u32, u32, &str, u64) -> anyhow::Result<()> + Send + 'static>>,
    on_event: Option<Box<dyn FnMut(&mut Self, &DebugEvent) -> anyhow::Result<bool> + Send + 'static>>,
    /// Exception handling configuration
    exception_config: ExceptionConfig,
    /// Handler called on exception events; overrides exception_config if set.
    /// Receives (session, pid, tid, code, address, first_chance, parameters) and returns the desired action.
    on_exception: Option<Box<dyn FnMut(&mut Self, u32, u32, u32, u64, bool, &[u64]) -> anyhow::Result<ExceptionAction> + Send + 'static>>,
    /// PID of the root (first) process. Used in multi-process mode to distinguish
    /// root process exit (terminates session) from child process exit (auto-continues).
    root_pid: Option<u32>,
}

/// TCP keepalive idle: proactively detect a silently-dropped connection (NAT /
/// firewall idle-eviction, server host gone) instead of only noticing on the
/// next request. Safe on every connection — a live server's TCP stack ACKs the
/// probes regardless of application state, so an idle debug-loop connection
/// waiting for the next event is never torn down while the server is alive.
const KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// Triage a response to a request whose success answer is a bare `Ack`.
/// Shared by `DebugSession::ack_request` and the Lua bindings, which talk to
/// different client types but need identical Ack / Error / unexpected handling.
pub fn expect_ack(what: &str, resp: DebuggerResponse) -> anyhow::Result<()> {
    match resp {
        DebuggerResponse::Ack => Ok(()),
        DebuggerResponse::Error { message } => Err(anyhow::anyhow!("{} failed: {}", what, message)),
        other => Err(anyhow::anyhow!("Unexpected response to {}: {:?}", what, other)),
    }
}

impl<S> DebugSession<S> {
    pub fn new(state: S, addr: Option<&str>) -> anyhow::Result<Self> {
        let addr = addr.unwrap_or("127.0.0.1:9000");
        let stream = TcpStream::connect(addr)?;
        Self::configure_socket(&stream);
        let framed_stream = FramedJsonStream::new(stream);
        Ok(Self {
            stream: Mutex::new(framed_stream),
            state,
            on_initial_breakpoint: None,
            single_shot_handlers: HashMap::new(),
            breakpoint_handlers: HashMap::new(),
            stepping_info: None,
            on_dll_loaded: None,
            on_dll_unloaded: None,
            on_thread_created: None,
            on_process_exited: None,
            on_thread_exited: None,
            on_process_created: None,
            on_event: None,
            exception_config: ExceptionConfig::default(),
            on_exception: None,
            root_pid: None,
        })
    }

    /// Tune the client connection: disable Nagle (latency) and enable keepalive
    /// (dead-peer detection).
    fn configure_socket(stream: &TcpStream) {
        // Disable Nagle's algorithm. This is a request/response protocol with
        // small framed messages; Nagle interacting with the peer's delayed-ACK
        // stalls each exchange by ~40-200ms over a real TCP link (host ↔ sandbox
        // guest) — invisible on loopback, but the dominant per-command cost when
        // debugging into a VM. TCP_NODELAY sends each frame immediately.
        if let Err(e) = stream.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY: {}", e);
        }
        let ka = socket2::TcpKeepalive::new().with_time(KEEPALIVE_IDLE);
        let sock = socket2::SockRef::from(stream);
        if let Err(e) = sock.set_tcp_keepalive(&ka) {
            warn!("Failed to enable TCP keepalive: {}", e);
        }
    }

    /// Bound how long a single request waits for its response. Intended for
    /// request/response (OOB) clients — NOT the debug-loop connection, which
    /// legitimately blocks for arbitrarily long between debug events. `None`
    /// restores blocking reads.
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> anyhow::Result<()> {
        self.stream.lock().unwrap().set_read_timeout(dur)?;
        Ok(())
    }

    /// Handle the initial process breakpoint
    /// Callback receives: (session, pid, tid, address)
    pub fn on_initial_breakpoint<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + 'static,
    {
        self.on_initial_breakpoint = Some(Box::new(handler));
        self
    }

    /// Set a single-shot breakpoint with a dedicated handler
    /// Callback receives: (session, pid, tid, address)
    pub fn set_single_shot_breakpoint<F>(
        &mut self,
        pid: u32,
        symbol_name: &str,
        handler: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + 'static,
    {
        let address = self.setup_single_shot_breakpoint(pid, symbol_name)?;
        self.single_shot_handlers.insert(address, Box::new(handler));
        Ok(())
    }

    /// Set a single-shot breakpoint at a raw address with a dedicated handler
    /// Callback receives: (session, pid, tid, address)
    pub fn set_single_shot_breakpoint_at<F>(
        &mut self,
        pid: u32,
        address: u64,
        handler: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + 'static,
    {
        match self.send_and_receive(&DebuggerRequest::SetSingleShotBreakpoint { pid, addr: address })? {
            DebuggerResponse::Ack => {}
            DebuggerResponse::Error { message } => {
                return Err(anyhow::anyhow!("Failed to set single-shot breakpoint at 0x{:x}: {}", address, message));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected response to SetSingleShotBreakpoint: {:?}", other));
            }
        }
        self.single_shot_handlers.insert(address, Box::new(handler));
        Ok(())
    }

    pub fn step<F>(
        &mut self,
        pid: u32,
        tid: u32,
        initial_kind: StepKind,
        handler: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, u32, u32, u64, StepKind) -> Result<StepAction, anyhow::Error> + Send + 'static,
    {
        // TODO: handle multiple step requests, currently relaxed due to UI unbreak
        //if self.stepping_info.is_some() {
        //    return Err(anyhow::anyhow!(
        //        "Another stepping operation is already in progress."
        //    ));
        //}

        self.stepping_info = Some(SteppingInfo {
            handler: Box::new(handler),
        });
        let req = DebuggerRequest::Step {
            pid,
            tid,
            kind: initial_kind,
        };
        // Send step request and synchronously verify Ack/Error so caller can react to failures
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Event { event } => {
                // Pass StepFailed through as an error to the caller; continue to allow UI to handle
                match &event {
                    DebugEvent::StepFailed { message, .. } => {
                        return Err(anyhow::anyhow!(message.clone()));
                    }
                    _ => {}
                }
                Ok(())
            }
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(message)),
            other => Err(anyhow::anyhow!("Unexpected response to Step: {:?}", other)),
        }
    }

    /// Handle DLL load events (great for testing call stacks)
    /// Callback receives: (session, pid, tid, dll_name, base_address)
    pub fn on_dll_loaded<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32, &str, u64) -> anyhow::Result<()> + Send + 'static,
    {
        self.on_dll_loaded = Some(Box::new(handler));
        self
    }

    /// Handle DLL unload events
    /// Callback receives: (session, pid, tid, base_address)
    pub fn on_dll_unloaded<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + 'static,
    {
        self.on_dll_unloaded = Some(Box::new(handler));
        self
    }

    /// Handle thread creation events
    /// Callback receives: (session, pid, tid, start_address)
        pub fn on_thread_created<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + Sync + 'static,
    {
        self.on_thread_created = Some(Box::new(handler));
        self
    }

    /// Handle process exit events
    /// Callback receives: (session, pid, exit_code)
    pub fn on_process_exited<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32) -> anyhow::Result<()> + Send + 'static,
    {
        self.on_process_exited = Some(Box::new(handler));
        self
    }

    /// Handle thread exit events
    /// Callback receives: (session, pid, tid, exit_code)
    pub fn on_thread_exited<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32, u32) -> anyhow::Result<()> + Send + Sync + 'static,
    {
        self.on_thread_exited = Some(Box::new(handler));
        self
    }

    /// Handle process creation
    /// Callback receives: (session, pid, tid, image_name, base_address)
    pub fn on_process_created<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32, &str, u64) -> anyhow::Result<()> + Send + 'static,
    {
        self.on_process_created = Some(Box::new(handler));
        self
    }

    /// Generic event handler
    pub fn on_event<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, &DebugEvent) -> anyhow::Result<bool> + Send + 'static,
    {
        self.on_event = Some(Box::new(handler));
        self
    }

    /// Set exception handling configuration
    pub fn exception_config(mut self, config: ExceptionConfig) -> Self {
        self.exception_config = config;
        self
    }

    /// Set a per-exception-code action
    pub fn set_exception_action(mut self, code: u32, first_chance: ExceptionAction, second_chance: ExceptionAction) -> Self {
        self.exception_config.per_code.insert(code, ExceptionCodeConfig {
            first_chance,
            second_chance,
        });
        self
    }

    /// Set a handler called on exception events that overrides the exception_config.
    /// Handler receives (session, pid, tid, code, address, first_chance, parameters)
    /// and returns the desired ExceptionAction.
    pub fn on_exception<F>(mut self, handler: F) -> Self
    where
        F: FnMut(&mut Self, u32, u32, u32, u64, bool, &[u64]) -> anyhow::Result<ExceptionAction> + Send + 'static,
    {
        self.on_exception = Some(Box::new(handler));
        self
    }

    /// Launch a process and run the debug session with the configured callbacks
    /// Returns the final state after the session completes
    pub fn launch(self, command: String) -> anyhow::Result<S> {
        self.launch_inner(command, false, None, None)
    }

    /// Launch a process with child-process debugging enabled
    pub fn launch_with_children(self, command: String) -> anyhow::Result<S> {
        self.launch_inner(command, true, None, None)
    }

    /// Launch with an optional working directory and optional extra environment
    /// variables (merged over the server's environment, override by name).
    pub fn launch_with_options(
        self,
        command: String,
        working_directory: Option<String>,
        environment: Option<Vec<(String, String)>>,
    ) -> anyhow::Result<S> {
        self.launch_inner(command, false, working_directory, environment)
    }

    fn launch_inner(mut self, command: String, debug_children: bool, working_directory: Option<String>, environment: Option<Vec<(String, String)>>) -> anyhow::Result<S> {
        let launch = DebuggerRequest::Launch { command, debug_children, working_directory, environment };
        self.send(&launch)?;
        self.run_session_loop(None)?;
        Ok(self.state)
    }

    pub fn attach(mut self, pid: u32) -> anyhow::Result<S> {
        let req = DebuggerRequest::Attach { pid };
        let resp = self.send_and_receive(&req)?;
        match resp {
            DebuggerResponse::Event { event } => self.run_session_loop(Some(event))?,
            DebuggerResponse::Ack => self.run_session_loop(None)?,
            _ => return Err(anyhow::anyhow!("Unexpected response: {:?}", resp)),
        }
        Ok(self.state)
    }

    fn run_session_loop(&mut self, initial_event: Option<DebugEvent>) -> anyhow::Result<()> {
        if let Some(event) = initial_event {
            if !self.handle_session_event(&event)? {
                return Ok(());
            }
        }

        loop {
            let mut stream = self.stream.lock().unwrap();
            let resp = receive_response(&mut stream)?;
            drop(stream);
            match resp {
                DebuggerResponse::Event { event } => {
                    if !self.handle_session_event(&event)? {
                        break;
                    }
                }
                DebuggerResponse::Error { message } => {
                    return Err(anyhow::anyhow!("Server error: {}", message));
                }
                other => {
                    info!("Received non-event response: {:?}, ignoring.", other);
                }
            }
        }
        Ok(())
    }

    fn handle_session_event(&mut self, event: &DebugEvent) -> anyhow::Result<bool> {
        // Temporarily take ownership of handlers to avoid borrow checker issues
        // when handlers themselves need to modify the session (e.g., add new breakpoints)
        let mut on_initial_breakpoint = self.on_initial_breakpoint.take();
        let mut on_dll_loaded = self.on_dll_loaded.take();
        let mut on_dll_unloaded = self.on_dll_unloaded.take();
        let mut on_thread_created = self.on_thread_created.take();
        let mut on_process_created = self.on_process_created.take();
        let mut on_process_exited = self.on_process_exited.take();
        let mut on_thread_exited = self.on_thread_exited.take();
        let mut on_event = self.on_event.take();
        let mut on_exception = self.on_exception.take();

        // Check if on_event handler wants to stop the session
        let mut should_continue = true;
        // For exceptions: whether to pass exception to application on auto-continue
        let mut pass_exception = false;
        if let Some(ref mut handler) = on_event {
            // The handler returns Result<bool> where false means stop the session
            should_continue = handler(self, event)?;
        }

        match event {
            DebugEvent::Output { pid, tid, output } => {
                info!(pid, tid, msg = %output, "OutputDebugString");
            }
            DebugEvent::StepFailed { pid, tid, kind, message } => {
                info!("StepFailed received: pid={}, tid={}, kind={:?}, message={}", pid, tid, kind, message);
                // Do not panic; let higher-level on_event handler decide whether to stop/continue
            }
            DebugEvent::InitialBreakpoint { pid, tid, address } => {
                if let Some(ref mut handler) = on_initial_breakpoint {
                    handler(self, *pid, *tid, *address)?;
                }
            }
            DebugEvent::SingleShotBreakpoint { pid, tid, address } => {
                if let Some(mut handler) = self.single_shot_handlers.remove(address) {
                    handler(self, *pid, *tid, *address)?;
                }
            }
            DebugEvent::Breakpoint { pid, tid, address } => {
                // Move handlers out to avoid holding a mutable borrow while invoking callbacks
                if let Some(handlers_vec) = self.breakpoint_handlers.remove(address) {
                    let mut kept: Vec<Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<BreakpointDecision> + Send + 'static>> = Vec::with_capacity(handlers_vec.len());
                    for mut handler in handlers_vec.into_iter() {
                        let decision = handler(self, *pid, *tid, *address)?;
                        if decision == BreakpointDecision::Keep {
                            kept.push(handler);
                        } else {
                            // Remove on server
                            let _ = self.send_and_receive(&DebuggerRequest::RemoveBreakpoint { pid: *pid, addr: *address });
                        }
                    }
                    // Put handlers back
                    self.breakpoint_handlers.insert(*address, kept);
                }
            }
            DebugEvent::HardwareBreakpoint { pid, tid, address, .. } => {
                // Dispatch to breakpoint_handlers, same as software breakpoints
                if let Some(handlers_vec) = self.breakpoint_handlers.remove(address) {
                    let mut kept: Vec<Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<BreakpointDecision> + Send + 'static>> = Vec::with_capacity(handlers_vec.len());
                    for mut handler in handlers_vec.into_iter() {
                        let decision = handler(self, *pid, *tid, *address)?;
                        if decision == BreakpointDecision::Keep {
                            kept.push(handler);
                        } else {
                            // Remove the hardware breakpoint on server
                            let _ = self.send_and_receive(&DebuggerRequest::RemoveHardwareBreakpoint { pid: *pid, addr: *address });
                        }
                    }
                    // Put handlers back
                    self.breakpoint_handlers.insert(*address, kept);
                }
            }
            DebugEvent::DllLoaded {
                pid,
                tid,
                dll_name,
                base_of_dll,
                ..
            } => {
                if let Some(ref mut handler) = on_dll_loaded {
                    let name = dll_name.as_deref().unwrap_or("<unknown>");
                    handler(self, *pid, *tid, name, *base_of_dll)?;
                }
            }
            DebugEvent::DllUnloaded { pid, tid, base_of_dll } => {
                if let Some(ref mut handler) = on_dll_unloaded {
                    handler(self, *pid, *tid, *base_of_dll)?;
                }
            }
            DebugEvent::ThreadCreated {
                pid,
                tid,
                start_address,
            } => {
                if let Some(ref mut handler) = on_thread_created {
                    handler(self, *pid, *tid, *start_address)?;
                }
            }
            DebugEvent::ProcessCreated {
                pid,
                tid,
                image_file_name,
                base_of_image,
                ..
            } => {
                if self.root_pid.is_none() {
                    self.root_pid = Some(*pid);
                }
                if let Some(ref mut handler) = on_process_created {
                    let name = image_file_name.as_deref().unwrap_or("<unknown>");
                    handler(self, *pid, *tid, name, *base_of_image)?;
                }
            }
            DebugEvent::ThreadExited { pid, tid, exit_code } => {
                if let Some(ref mut handler) = on_thread_exited {
                    handler(self, *pid, *tid, *exit_code)?;
                }
            }
            DebugEvent::ProcessExited { pid, exit_code, .. } => {
                if let Some(ref mut handler) = on_process_exited {
                    handler(self, *pid, *exit_code)?;
                }
            }
            DebugEvent::StepComplete {
                pid,
                tid,
                address,
                kind,
            } => {
                if let Some(info) = self.stepping_info.take() {
                    let mut handler = info.handler;
                    let action = handler(self, *pid, *tid, *address, *kind)?;

                    match action {
                        StepAction::Continue(next_kind) => {
                            let req = DebuggerRequest::Step {
                                pid: *pid,
                                tid: *tid,
                                kind: next_kind,
                            };
                            self.send(&req)?;
                            self.stepping_info = Some(SteppingInfo { handler });
                        }
                        StepAction::Stop => {
                            // debug loop continues on itself we just don't need to setup the next step
                        }
                    }
                } else {
                    warn!("No stepping info, sending continue request");
                };

            }
            DebugEvent::Exception { pid, tid, code, address, first_chance, parameters } => {
                // Determine what to do with this exception
                let action = if let Some(ref mut handler) = on_exception {
                    handler(self, *pid, *tid, *code, *address, *first_chance, parameters)?
                } else {
                    self.exception_config.action_for(*code, *first_chance)
                };

                match action {
                    ExceptionAction::Stop => {
                        should_continue = false;
                    }
                    ExceptionAction::PassToApplication => {
                        pass_exception = true;
                    }
                    ExceptionAction::HandledByDebugger => {
                        // pass_exception stays false (DBG_CONTINUE)
                    }
                }
            }
            _ => {
                panic!("Unhandled event in handle_session_event: {}", event);
            }
        }

        // Restore handlers
        self.on_initial_breakpoint = on_initial_breakpoint;
        self.on_dll_loaded = on_dll_loaded;
        self.on_thread_created = on_thread_created;
        self.on_process_exited = on_process_exited;
        self.on_thread_exited = on_thread_exited;
        self.on_process_created = on_process_created;
        self.on_dll_unloaded = on_dll_unloaded;
        self.on_event = on_event;
        self.on_exception = on_exception;

        // The root process exiting ends the session no matter what the handler
        // decided, so this runs before the `should_continue` check below — a
        // handler that stops (e.g. the user picking "stop" over "go" at a break on
        // process exit) must not skip the release.
        //
        // The final debug event is still outstanding at this point: Windows keeps
        // the dead process object alive until the debugger acknowledges it, which
        // is what makes a break on `ProcessExited` inspectable — and what leaves a
        // zombie behind if we just walk away.
        if let DebugEvent::ProcessExited { pid, tid, .. } = event {
            if self.root_pid.is_none_or(|root| root == *pid) {
                // Best-effort: a server too old to know the request drops the
                // connection, and we're tearing that down anyway.
                let req = DebuggerRequest::FinalizeExitedProcess { pid: *pid, tid: *tid };
                match self.send_and_receive(&req) {
                    Ok(DebuggerResponse::Ack) => debug!("Released exited process {}", pid),
                    Ok(other) => warn!("FinalizeExitedProcess: unexpected response {:?}", other),
                    Err(e) => debug!("FinalizeExitedProcess not acknowledged (server too old?): {}", e),
                }
                return Ok(false);
            }
        }

        // If the on_event handler wants to stop, respect that
        if !should_continue {
            return Ok(false);
        }

        // Handle automatic continuation for most events
        match event {
            DebugEvent::ProcessExited { pid, tid, .. } => {
                // Root exits returned above; only a child process reaches here.
                let cont = DebuggerRequest::Continue {
                    pid: *pid,
                    tid: *tid,
                    pass_exception: false,
                };
                let mut stream = self.stream.lock().unwrap();
                debug!("Auto-continue on child process exit: {}", event);
                send_request(&mut stream, &cont)?;
            }

            DebugEvent::Exception { pid, tid, .. } => {
                let cont = DebuggerRequest::Continue {
                    pid: *pid,
                    tid: *tid,
                    pass_exception,
                };
                let mut stream = self.stream.lock().unwrap();
                debug!("Auto-continue on exception (pass_exception={}): {}", pass_exception, event);
                send_request(&mut stream, &cont)?;
            }

            DebugEvent::ProcessCreated { pid, tid, .. }
            | DebugEvent::DllLoaded { pid, tid, .. }
            | DebugEvent::DllUnloaded { pid, tid, .. }
            | DebugEvent::ThreadCreated { pid, tid, .. }
            | DebugEvent::ThreadExited { pid, tid, .. }
            | DebugEvent::Breakpoint { pid, tid, .. }
            | DebugEvent::HardwareBreakpoint { pid, tid, .. }
            | DebugEvent::InitialBreakpoint { pid, tid, .. }
            | DebugEvent::Output { pid, tid, .. }
            | DebugEvent::StepComplete { pid, tid, .. }
            | DebugEvent::SingleShotBreakpoint { pid, tid, .. }
            | DebugEvent::RipEvent { pid, tid, .. } => {
                let cont = DebuggerRequest::Continue {
                    pid: *pid,
                    tid: *tid,
                    pass_exception: false,
                };
                let mut stream = self.stream.lock().unwrap();
                debug!("Auto-continue on event: {}", event);
                send_request(&mut stream, &cont)?;
            }
            DebugEvent::StepFailed { .. } => {
                // Do not auto-continue on step failure; let UI control flow
                debug!("Not auto-continuing on StepFailed: {}", event);
            }
            DebugEvent::Unknown { .. } => {}
        }

        Ok(true)
    }

    pub fn list_processes(&mut self) -> anyhow::Result<Vec<ProcessInfo>> {
        let req = DebuggerRequest::ListProcesses;
        let resp = self.send_and_receive(&req)?;
        if let DebuggerResponse::ProcessList { processes } = resp {
            Ok(processes)
        } else {
            Err(anyhow::anyhow!("Unexpected response: {:?}", resp))
        }
    }

    pub fn list_modules(&mut self, pid: u32) -> anyhow::Result<Vec<ModuleInfo>> {
        let req = DebuggerRequest::ListModules { pid };
        let resp = self.send_and_receive(&req)?;
        if let DebuggerResponse::ModuleList { modules } = resp {
            Ok(modules)
        } else {
            Err(anyhow::anyhow!("Unexpected response: {:?}", resp))
        }
    }

    /// The debuggee's instruction-set architecture (`X86` for a WOW64 process).
    pub fn get_process_architecture(&mut self, pid: u32) -> anyhow::Result<crate::interfaces::Architecture> {
        let req = DebuggerRequest::GetProcessArchitecture { pid };
        let resp = self.send_and_receive(&req)?;
        match resp {
            DebuggerResponse::ProcessArchitecture { arch } => Ok(arch),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("GetProcessArchitecture failed: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub fn list_threads(&mut self, pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
        let req = DebuggerRequest::ListThreads { pid };
        let resp = self.send_and_receive(&req)?;
        if let DebuggerResponse::ThreadList { threads } = resp {
            Ok(threads)
        } else {
            Err(anyhow::anyhow!("Unexpected response: {:?}", resp))
        }
    }

    /// Handles, windows, TCP connections and privileges of `pid` in one trip.
    pub fn list_process_objects(&mut self, pid: u32) -> anyhow::Result<ProcessObjects> {
        let req = DebuggerRequest::ListProcessObjects { pid };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ProcessObjects { objects } => Ok(objects),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("{}", message)),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub fn close_remote_handle(&mut self, pid: u32, handle: u64) -> anyhow::Result<()> {
        self.ack_request(DebuggerRequest::CloseRemoteHandle { pid, handle }, "CloseRemoteHandle")
    }

    pub fn set_privilege(&mut self, pid: u32, name: &str, enable: bool) -> anyhow::Result<()> {
        self.ack_request(DebuggerRequest::SetPrivilege { pid, name: name.to_string(), enable }, "SetPrivilege")
    }

    pub fn set_window_enabled(&mut self, pid: u32, hwnd: u64, enabled: bool) -> anyhow::Result<()> {
        self.ack_request(DebuggerRequest::SetWindowEnabled { pid, hwnd, enabled }, "SetWindowEnabled")
    }

    /// Open a process non-invasively (no debugger attach) so read-only features
    /// (memory, modules, threads, disassembly, symbols, call stacks) work.
    pub fn open_process(&mut self, pid: u32) -> anyhow::Result<()> {
        let resp = self.send_and_receive(&DebuggerRequest::OpenProcess { pid })?;
        match resp {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("OpenProcess failed: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to OpenProcess: {:?}", other)),
        }
    }

    /// Release a non-invasively opened process.
    pub fn close_process(&mut self, pid: u32) -> anyhow::Result<()> {
        let resp = self.send_and_receive(&DebuggerRequest::CloseProcess { pid })?;
        match resp {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("CloseProcess failed: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to CloseProcess: {:?}", other)),
        }
    }

    pub fn send_and_receive(
        &mut self,
        req: &crate::protocol::DebuggerRequest,
    ) -> anyhow::Result<crate::protocol::DebuggerResponse> {
        let mut stream = self.stream.lock().unwrap();
        send_request(&mut stream, req)?;
        receive_response(&mut stream)
    }

    pub fn send(&mut self, req: &crate::protocol::DebuggerRequest) -> anyhow::Result<()> {
        let mut stream = self.stream.lock().unwrap();
        send_request(&mut stream, req)
    }

    pub fn receive(&mut self) -> anyhow::Result<crate::protocol::DebuggerResponse> {
        let mut stream = self.stream.lock().unwrap();
        receive_response(&mut stream)
    }

    /// Get call stack
    pub fn get_call_stack(
        &mut self,
        pid: u32,
        tid: u32,
    ) -> anyhow::Result<Vec<crate::interfaces::CallFrame>> {
        match self.send_and_receive(&DebuggerRequest::GetCallStack { pid, tid })? {
            DebuggerResponse::CallStack { frames } => Ok(frames),
            DebuggerResponse::Error { message } => {
                error!("Call stack error: {}", message);
                Err(anyhow::anyhow!("Call stack error: {}", message))
            }
            other => {
                error!("Unexpected response to GetCallStack: {:?}", other);
                Err(anyhow::anyhow!(
                "Unexpected response to GetCallStack: {:?}",
                other))
            }
        }
    }

    pub fn find_symbols(
        &mut self,
        symbol_name: &str,
        max_results: usize,
    ) -> anyhow::Result<Vec<crate::interfaces::ResolvedSymbol>> {
        let req = DebuggerRequest::FindSymbol {
            symbol_name: symbol_name.to_string(),
            max_results,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ResolvedSymbolList { symbols } => Ok(symbols),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to find symbol '{}': {}",
                symbol_name,
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to FindSymbol: {:?}",
                other
            )),
        }
    }

    /// List every symbol in a loaded module (raw RVAs, no VA calculation).
    /// `module_path` is the module's full path (`ModuleInfo.name`). Unlike
    /// `find_symbols`, this enumerates the whole module without a pattern/limit.
    pub fn list_symbols(
        &mut self,
        module_path: &str,
    ) -> anyhow::Result<Vec<crate::interfaces::ModuleSymbol>> {
        let req = DebuggerRequest::ListSymbols { module_path: module_path.to_string() };
        match self.send_and_receive(&req)? {
            DebuggerResponse::SymbolList { symbols } => Ok(symbols),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to list symbols for '{}': {}",
                module_path,
                message
            )),
            other => Err(anyhow::anyhow!("Unexpected response to ListSymbols: {:?}", other)),
        }
    }

    /// Every address in `module_path` worth arming code coverage on: `.pdata`
    /// RUNTIME_FUNCTION starts unioned with symbols, with symbols the PDB does
    /// not mark as functions filtered by a code-sanity check. Returns targets
    /// even when the module has no symbols at all; feed the addresses to
    /// [`start_coverage`].
    /// `sources` restricts which tiers contribute (empty = all): pass
    /// `[CoverageTargetSource::Pdata]` for exception-directory functions only,
    /// which involves no heuristics.
    pub fn enumerate_coverage_targets(
        &mut self,
        pid: u32,
        module_path: &str,
        sources: Vec<crate::protocol::CoverageTargetSource>,
    ) -> anyhow::Result<Vec<crate::protocol::CoverageTarget>> {
        let req = DebuggerRequest::EnumerateCoverageTargets {
            pid,
            module_path: module_path.to_string(),
            sources,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::CoverageTargetList { targets } => Ok(targets),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to enumerate coverage targets for '{}': {}",
                module_path,
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to EnumerateCoverageTargets: {:?}",
                other
            )),
        }
    }

    /// Arm code-coverage breakpoints on every address in `addrs`. Hits are counted
    /// server-side and the debuggee auto-continues silently; poll with
    /// [`get_coverage`]. `limit` is the hit count after which each is auto-removed
    /// (`0` = never, `1` = remove on first hit = pure coverage).
    pub fn start_coverage(&mut self, pid: u32, addrs: Vec<u64>, limit: u64) -> anyhow::Result<()> {
        match self.send_and_receive(&DebuggerRequest::StartCodeCoverage { pid, addrs, limit })? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to start code coverage: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to StartCodeCoverage: {:?}", other)),
        }
    }

    /// Fetch a [`crate::protocol::CoverageHit`] (address, hit count, first-hit
    /// order, thread ids) for every coverage breakpoint hit at least once
    /// (never-hit addresses are omitted; the caller knows the armed set).
    pub fn get_coverage(&mut self, pid: u32) -> anyhow::Result<Vec<crate::protocol::CoverageHit>> {
        match self.send_and_receive(&DebuggerRequest::GetCodeCoverage { pid })? {
            DebuggerResponse::CoverageResults { hits } => Ok(hits),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get code coverage: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to GetCodeCoverage: {:?}", other)),
        }
    }

    /// Remove all coverage breakpoints and clear coverage state.
    pub fn stop_coverage(&mut self, pid: u32) -> anyhow::Result<()> {
        match self.send_and_receive(&DebuggerRequest::StopCodeCoverage { pid })? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to stop code coverage: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to StopCodeCoverage: {:?}", other)),
        }
    }

    /// Arm a hardware watchpoint at `addr` in silent "access trace" mode: every
    /// read/write is recorded server-side (the accessing instruction) and the target
    /// auto-continues instead of breaking. Poll with [`get_watchpoint_accesses`] and
    /// tear down with [`stop_watchpoint_trace`]. `bp_type` should be `Write` or
    /// `ReadWrite` (x86 hardware cannot trap read-only).
    pub fn start_watchpoint_trace(&mut self, pid: u32, addr: u64, bp_type: crate::protocol::HardwareBreakpointType, size: crate::protocol::HardwareBreakpointSize) -> anyhow::Result<()> {
        match self.send_and_receive(&DebuggerRequest::StartWatchpointTrace { pid, addr, bp_type, size })? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to start watchpoint trace: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to StartWatchpointTrace: {:?}", other)),
        }
    }

    /// Fetch a [`crate::protocol::WatchpointAccess`] (accessing instruction pointer,
    /// hit count, first-access order, thread ids) for every distinct instruction
    /// that has accessed the watched `addr` at least once.
    pub fn get_watchpoint_accesses(&mut self, pid: u32, addr: u64) -> anyhow::Result<Vec<crate::protocol::WatchpointAccess>> {
        match self.send_and_receive(&DebuggerRequest::GetWatchpointAccesses { pid, addr })? {
            DebuggerResponse::WatchpointAccesses { accesses } => Ok(accesses),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get watchpoint accesses: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to GetWatchpointAccesses: {:?}", other)),
        }
    }

    /// Remove the watchpoint at `addr` and clear its collected accesses.
    pub fn stop_watchpoint_trace(&mut self, pid: u32, addr: u64) -> anyhow::Result<()> {
        match self.send_and_receive(&DebuggerRequest::StopWatchpointTrace { pid, addr })? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to stop watchpoint trace: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to StopWatchpointTrace: {:?}", other)),
        }
    }

    /// Per-module symbol load status (loaded/loading/failed/not requested).
    pub fn get_symbol_status(&mut self, pid: u32) -> anyhow::Result<Vec<ModuleSymbolStatus>> {
        match self.send_and_receive(&DebuggerRequest::GetSymbolStatus { pid })? {
            DebuggerResponse::SymbolStatusList { statuses } => Ok(statuses),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get symbol status: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to GetSymbolStatus: {:?}", other)),
        }
    }

    /// Load symbols for a module from a user-supplied PDB file.
    /// Returns `Mismatch` (not an error) when the PDB doesn't match the PE and `force` is false.
    pub fn load_pdb_from_path(
        &mut self,
        pid: u32,
        module_base: u64,
        pdb_path: &str,
        force: bool,
    ) -> anyhow::Result<PdbLoadOutcome> {
        let req = DebuggerRequest::LoadPdbFromPath {
            pid,
            module_base,
            pdb_path: pdb_path.to_string(),
            force,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::PdbLoaded { symbol_count } => {
                Ok(PdbLoadOutcome::Loaded { symbol_count })
            }
            DebuggerResponse::PdbMismatch(info) => Ok(PdbLoadOutcome::Mismatch(info)),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to load PDB '{}': {}", pdb_path, message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to LoadPdbFromPath: {:?}", other)),
        }
    }

    /// Retry a failed symbol download for a module.
    pub fn retry_symbol_load(&mut self, pid: u32, module_base: u64) -> anyhow::Result<()> {
        match self.send_and_receive(&DebuggerRequest::RetrySymbolLoad { pid, module_base })? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to retry symbol load: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to RetrySymbolLoad: {:?}", other)),
        }
    }

    /// Unload a module's symbols and every derived server-side cache, freeing
    /// their memory. The module reports `NotRequested` afterwards.
    pub fn unload_module_symbols(&mut self, pid: u32, module_base: u64) -> anyhow::Result<()> {
        match self.send_and_receive(&DebuggerRequest::UnloadModuleSymbols { pid, module_base })? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to unload module symbols: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to UnloadModuleSymbols: {:?}", other)),
        }
    }

    /// Replace the set of modules (lowercased file names, e.g. "foo.dll") whose
    /// automatic symbol download is suppressed.
    pub fn set_symbol_deny_list(&mut self, modules: Vec<String>) -> anyhow::Result<()> {
        match self.send_and_receive(&DebuggerRequest::SetSymbolDenyList { modules })? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to set symbol deny list: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to SetSymbolDenyList: {:?}", other)),
        }
    }

    /// List UDT/enum types from loaded module PDBs. `module_base = None` searches
    /// all loaded modules; `filter` is a case-insensitive substring on the name.
    pub fn list_types(
        &mut self,
        pid: u32,
        module_base: Option<u64>,
        filter: Option<&str>,
        max_results: usize,
    ) -> anyhow::Result<Vec<TypeSummary>> {
        let req = DebuggerRequest::ListTypes {
            pid,
            module_base,
            filter: filter.map(|s| s.to_string()),
            max_results,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::TypeList { types } => Ok(types),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to list types: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to ListTypes: {:?}", other)),
        }
    }

    /// Resolve a named type's layout. `module_base = None` searches all modules.
    pub fn get_type(
        &mut self,
        pid: u32,
        module_base: Option<u64>,
        name: &str,
    ) -> anyhow::Result<Option<TypeLayout>> {
        let req = DebuggerRequest::GetType {
            pid,
            module_base,
            name: name.to_string(),
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::TypeResult { layout } => Ok(layout),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get type '{}': {}", name, message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to GetType: {:?}", other)),
        }
    }

    /// Resolve a type by its TPI index within a specific module (nested expansion).
    pub fn get_type_by_index(
        &mut self,
        pid: u32,
        module_base: u64,
        index: u32,
    ) -> anyhow::Result<Option<TypeLayout>> {
        let req = DebuggerRequest::GetTypeByIndex { pid, module_base, index };
        match self.send_and_receive(&req)? {
            DebuggerResponse::TypeResult { layout } => Ok(layout),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get type by index {}: {}", index, message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to GetTypeByIndex: {:?}", other)),
        }
    }

    /// TEB base address of thread `tid`.
    pub fn get_teb_address(&mut self, pid: u32, tid: u32) -> anyhow::Result<u64> {
        match self.send_and_receive(&DebuggerRequest::GetTebAddress { pid, tid })? {
            DebuggerResponse::TebAddress { address } => Ok(address),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get TEB address: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to GetTebAddress: {:?}", other)),
        }
    }

    /// PEB base address of a process.
    pub fn get_peb_address(&mut self, pid: u32) -> anyhow::Result<u64> {
        match self.send_and_receive(&DebuggerRequest::GetPebAddress { pid })? {
            DebuggerResponse::PebAddress { address } => Ok(address),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get PEB address: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to GetPebAddress: {:?}", other)),
        }
    }

    /// Convenience: TEB (for `tid`) and PEB base addresses, with `None` for an
    /// address that fails to resolve (e.g. a platform without TEB support).
    pub fn get_teb_peb_addresses(
        &mut self,
        pid: u32,
        tid: u32,
    ) -> anyhow::Result<(Option<u64>, Option<u64>)> {
        Ok((self.get_teb_address(pid, tid).ok(), self.get_peb_address(pid).ok()))
    }

    // removed older helper to avoid duplicate names; use set_breakpoint_by_symbol with handler below

    /// Set up a single-shot breakpoint at a symbol
    pub fn setup_single_shot_breakpoint(
        &mut self,
        pid: u32,
        symbol_name: &str,
    ) -> anyhow::Result<u64> {
        let symbols = self.find_symbols(symbol_name, 1)?;

        if symbols.is_empty() {
            return Err(anyhow::anyhow!(
                "Could not find symbol '{}' for testing single-shot breakpoint",
                symbol_name
            ));
        }

        let address = symbols[0].va;
        println!(
            "Setting single-shot breakpoint at {} (0x{:x})",
            symbol_name, address
        );

        match self.send_and_receive(&DebuggerRequest::SetSingleShotBreakpoint { pid, addr: address })?
        {
            DebuggerResponse::Ack => Ok(address),
            _ => Err(anyhow::anyhow!("Failed to set single-shot breakpoint")),
        }
    }

    /// Internal: set persistent breakpoint at address
    fn setup_persistent_breakpoint(&mut self, pid: u32, address: u64, tid: Option<u32>) -> anyhow::Result<()> {
        let req = DebuggerRequest::SetBreakpoint { pid, addr: address, tid };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            other => Err(anyhow::anyhow!(
                "Unexpected response to SetBreakpoint: {:?}",
                other
            )),
        }
    }

    /// Set a persistent breakpoint at a symbol with optional thread filter
    pub fn set_breakpoint_by_symbol<F>(
        &mut self,
        pid: u32,
        symbol_name: &str,
        tid: Option<u32>,
        handler: F,
    ) -> anyhow::Result<u64>
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<BreakpointDecision> + Send + 'static,
    {
        let symbols = self.find_symbols(symbol_name, 1)?;
        if symbols.is_empty() {
            return Err(anyhow::anyhow!(
                "Could not find symbol '{}' for persistent breakpoint",
                symbol_name
            ));
        }
        let address = symbols[0].va;
        self.setup_persistent_breakpoint(pid, address, tid)?;
        self.breakpoint_handlers
            .entry(address)
            .or_default()
            .push(Box::new(handler));
        Ok(address)
    }

    /// Set a persistent breakpoint at an address with optional thread filter
    pub fn set_breakpoint_at<F>(
        &mut self,
        pid: u32,
        address: u64,
        tid: Option<u32>,
        handler: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<BreakpointDecision> + Send + 'static,
    {
        self.setup_persistent_breakpoint(pid, address, tid)?;
        self.breakpoint_handlers
            .entry(address)
            .or_default()
            .push(Box::new(handler));
        Ok(())
    }

    /// Get arguments for the current function context
    pub fn get_arguments(&mut self, pid: u32, tid: u32, count: usize) -> anyhow::Result<Vec<u64>> {
        match self.send_and_receive(&DebuggerRequest::GetFunctionArguments { pid, tid, count })? {
            DebuggerResponse::FunctionArguments { arguments } => Ok(arguments),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to get function arguments: {}",
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to GetFunctionArguments: {:?}",
                other
            )),
        }
    }

    /// Read a UTF-16 wide string from the target process's memory
    pub fn read_wide_string(
        &mut self,
        pid: u32,
        address: u64,
        max_len: Option<usize>,
    ) -> anyhow::Result<String> {
        let read_req = DebuggerRequest::ReadWideString {
            pid,
            address,
            max_len,
        };
        match self.send_and_receive(&read_req)? {
            DebuggerResponse::WideStringData { data } => Ok(data),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to read wide string: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to ReadWideString: {:?}",
                other
            )),
        }
    }

    pub fn resolve_address_to_symbol(
        &mut self,
        pid: u32,
        address: u64,
    ) -> anyhow::Result<(Option<String>, Option<ModuleSymbol>, Option<u64>)> {
        let req = DebuggerRequest::ResolveAddressToSymbol { pid, address };
        match self.send_and_receive(&req)? {
            DebuggerResponse::AddressSymbol {
                module_path,
                symbol,
                offset,
            } => Ok((module_path, symbol, offset)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to resolve address to symbol: {}",
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to ResolveAddressToSymbol: {:?}",
                other
            )),
        }
    }

    /// Resolve many addresses to symbols in a single round-trip, never waiting
    /// on in-flight symbol loads: addresses in still-loading modules come back
    /// `None` (re-request once symbol status settles). One result per input
    /// address, in order.
    pub fn try_resolve_addresses_to_symbols(
        &mut self,
        pid: u32,
        addresses: Vec<u64>,
    ) -> anyhow::Result<Vec<Option<(String, ModuleSymbol, u64)>>> {
        let req = DebuggerRequest::TryResolveAddressesToSymbols { pid, addresses };
        match self.send_and_receive(&req)? {
            DebuggerResponse::AddressSymbolBatch { results } => Ok(results),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to resolve addresses to symbols: {}",
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to TryResolveAddressesToSymbols: {:?}",
                other
            )),
        }
    }

    /// Every symbol whose VA lies in `[start, start + len)`, ascending by VA,
    /// at most `max_results`. Non-blocking: modules whose symbols are still
    /// loading contribute nothing (re-request once symbol status settles).
    pub fn symbols_in_range(
        &mut self,
        pid: u32,
        start: u64,
        len: u64,
        max_results: usize,
    ) -> anyhow::Result<Vec<crate::interfaces::ResolvedSymbol>> {
        let req = DebuggerRequest::SymbolsInRange { pid, start, len, max_results };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ResolvedSymbolList { symbols } => Ok(symbols),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to list symbols in range: {}",
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to SymbolsInRange: {:?}",
                other
            )),
        }
    }

    /// Resolve an address to a source file/line via the module's PDB line table.
    pub fn resolve_address_to_line(
        &mut self,
        pid: u32,
        address: u64,
    ) -> anyhow::Result<Option<crate::protocol::AddressLineInfo>> {
        let req = DebuggerRequest::ResolveAddressToLine { pid, address };
        match self.send_and_receive(&req)? {
            DebuggerResponse::AddressLine { info } => Ok(info),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to resolve address to line: {}",
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to ResolveAddressToLine: {:?}",
                other
            )),
        }
    }

    /// All line→address entries for one source file of a module. `start_line`/
    /// `end_line` (inclusive, 1-based) bound the response; `None` = whole file.
    pub fn get_source_file_line_map(
        &mut self,
        pid: u32,
        module_base: u64,
        file_path: &str,
        start_line: Option<u32>,
        end_line: Option<u32>,
    ) -> anyhow::Result<(Option<crate::interfaces::SourceFileEntry>, Vec<crate::interfaces::LineEntry>)> {
        let req = DebuggerRequest::GetSourceFileLineMap {
            pid,
            module_base,
            file_path: file_path.to_string(),
            start_line,
            end_line,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::SourceFileLineMap { file, entries } => Ok((file, entries)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to get source file line map: {}",
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to GetSourceFileLineMap: {:?}",
                other
            )),
        }
    }

    /// All source files referenced by a module's PDB line table.
    pub fn list_source_files(
        &mut self,
        pid: u32,
        module_base: u64,
    ) -> anyhow::Result<Vec<crate::interfaces::SourceFileEntry>> {
        let req = DebuggerRequest::ListSourceFiles { pid, module_base };
        match self.send_and_receive(&req)? {
            DebuggerResponse::SourceFileList { files } => Ok(files),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!(
                "Failed to list source files: {}",
                message
            )),
            other => Err(anyhow::anyhow!(
                "Unexpected response to ListSourceFiles: {:?}",
                other
            )),
        }
    }

    pub fn disassemble_memory(
        &mut self,
        pid: u32,
        address: u64,
        count: usize,
        arch: Architecture,
    ) -> anyhow::Result<Vec<Instruction>> {
        let req = DebuggerRequest::DisassembleMemory {
            pid,
            address,
            count,
            arch,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Instructions { instructions } => Ok(instructions),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to disassemble memory: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to DisassembleMemory: {:?}",
                other
            )),
        }
    }

    /// Disassemble a function with bounds detection using exception directory
    pub fn disassemble_function(
        &mut self,
        pid: u32,
        address: u64,
        max_instructions: usize,
        arch: Architecture,
    ) -> anyhow::Result<(Vec<Instruction>, Option<u64>, Option<u64>, Option<String>)> {
        let req = DebuggerRequest::DisassembleFunction {
            pid,
            address,
            max_instructions,
            arch,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::FunctionDisassembly {
                instructions,
                function_start,
                function_end,
                function_name,
            } => Ok((instructions, function_start, function_end, function_name)),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to disassemble function: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to DisassembleFunction: {:?}",
                other
            )),
        }
    }

    /// Backward disassembly: up to `count` instructions ending immediately before
    /// `target` (x64dbg-style self-resynchronizing decode).
    pub fn disassemble_backward(
        &mut self,
        pid: u32,
        target: u64,
        count: usize,
        arch: Architecture,
    ) -> anyhow::Result<Vec<Instruction>> {
        let req = DebuggerRequest::DisassembleBackward {
            pid,
            target,
            count,
            arch,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Instructions { instructions } => Ok(instructions),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to disassemble backward: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to DisassembleBackward: {:?}",
                other
            )),
        }
    }

    pub fn get_thread_context(&mut self, pid: u32, tid: u32) -> anyhow::Result<ThreadContext> {
        let req = DebuggerRequest::GetThreadContext { pid, tid };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ThreadContext { context } => Ok(context),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get thread context: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to GetThreadContext: {:?}",
                other
            )),
        }
    }

    pub fn set_thread_context(
        &mut self,
        pid: u32,
        tid: u32,
        context: ThreadContext,
    ) -> anyhow::Result<()> {
        let req = DebuggerRequest::SetThreadContext { pid, tid, context };
        match self.send_and_receive(&req)? {
            DebuggerResponse::SetContextAck => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to set thread context: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to SetThreadContext: {:?}",
                other
            )),
        }
    }

    pub fn read_memory(&mut self, pid: u32, address: u64, size: usize) -> anyhow::Result<Vec<u8>> {
        let req = DebuggerRequest::ReadMemory { pid, address, size };
        match self.send_and_receive(&req)? {
            DebuggerResponse::MemoryData { data } => Ok(data),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to read memory: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to ReadMemory: {:?}",
                other
            )),
        }
    }

    pub fn get_module_extra_info(&mut self, pid: u32, module_base: u64) -> anyhow::Result<ModuleExtraInfo> {
        let req = DebuggerRequest::GetModuleExtraInfo { pid, module_base };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ModuleExtraInfo { info } => Ok(info),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to get module extra info: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to GetModuleExtraInfo: {:?}", other)),
        }
    }

    pub fn write_memory(&mut self, pid: u32, address: u64, data: Vec<u8>) -> anyhow::Result<()> {
        let req = DebuggerRequest::WriteMemory { pid, address, data };
        match self.send_and_receive(&req)? {
            DebuggerResponse::WriteAck => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to write memory: {}", message))
            }
            other => {
                Err(anyhow::anyhow!("Unexpected response to WriteMemory: {:?}", other))
            }
        }
    }

    /// Register a server-side value freeze: a thread on the server continuously
    /// writes `data` to the target (every `interval_ms`, default ~30ms) until
    /// stopped, returning the freeze id used to update/stop it. With an empty
    /// `offsets` the fixed `address` is locked; otherwise `address` is a static
    /// base and the server re-follows the pointer chain each tick so the lock
    /// tracks a moving target (e.g. a level reload).
    pub fn freeze_value(
        &mut self,
        pid: u32,
        address: u64,
        data: Vec<u8>,
        interval_ms: Option<u64>,
        offsets: Vec<u64>,
    ) -> anyhow::Result<u64> {
        let req = DebuggerRequest::FreezeValueStart { pid, address, data, interval_ms, offsets };
        match self.send_and_receive(&req)? {
            DebuggerResponse::FreezeValueStarted { freeze_id } => Ok(freeze_id),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to start freeze: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to FreezeValueStart: {:?}", other)),
        }
    }

    /// Change the value written by an active freeze without re-registering it.
    pub fn update_freeze_value(&mut self, freeze_id: u64, data: Vec<u8>) -> anyhow::Result<()> {
        let req = DebuggerRequest::FreezeValueUpdate { freeze_id, data };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to update freeze: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to FreezeValueUpdate: {:?}", other)),
        }
    }

    /// Stop an active value freeze.
    pub fn unfreeze_value(&mut self, freeze_id: u64) -> anyhow::Result<()> {
        let req = DebuggerRequest::FreezeValueStop { freeze_id };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to stop freeze: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to FreezeValueStop: {:?}", other)),
        }
    }

    /// Apply anti-anti-debug PEB patches to the target process. See
    /// [`crate::anti_anti_debug::peb::hide_peb`] for the field-by-field semantics.
    pub fn hide_peb(
        &mut self,
        pid: u32,
        options: crate::anti_anti_debug::PebHideOptions,
    ) -> anyhow::Result<crate::anti_anti_debug::PebHideReport> {
        let req = DebuggerRequest::HidePeb { pid, options };
        match self.send_and_receive(&req)? {
            DebuggerResponse::PebHideResult { report } => Ok(report),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to hide PEB: {}", message))
            }
            other => Err(anyhow::anyhow!("Unexpected response to HidePeb: {:?}", other)),
        }
    }

    fn ack_request(&mut self, req: DebuggerRequest, what: &str) -> anyhow::Result<()> {
        expect_ack(what, self.send_and_receive(&req)?)
    }

    pub fn suspend_thread(&mut self, pid: u32, tid: u32) -> anyhow::Result<()> {
        self.ack_request(DebuggerRequest::SuspendThread { pid, tid }, "SuspendThread")
    }

    pub fn resume_thread(&mut self, pid: u32, tid: u32) -> anyhow::Result<()> {
        self.ack_request(DebuggerRequest::ResumeThread { pid, tid }, "ResumeThread")
    }

    pub fn terminate_thread(&mut self, pid: u32, tid: u32, exit_code: u32) -> anyhow::Result<()> {
        self.ack_request(DebuggerRequest::TerminateThread { pid, tid, exit_code }, "TerminateThread")
    }

    pub fn terminate_process(&mut self, pid: u32) -> anyhow::Result<()> {
        let req = DebuggerRequest::TerminateProcess { pid };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to terminate process: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to TerminateProcess: {:?}", other)),
        }
    }

    pub fn query_memory_region(&mut self, pid: u32, address: u64) -> anyhow::Result<crate::protocol::MemoryRegionInfo> {
        let req = DebuggerRequest::QueryMemoryRegion { pid, address };
        match self.send_and_receive(&req)? {
            DebuggerResponse::MemoryRegionInfo { info } => Ok(info),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to query memory region: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to QueryMemoryRegion: {:?}", other)),
        }
    }

    pub fn enumerate_memory_regions(&mut self, pid: u32) -> anyhow::Result<Vec<crate::protocol::MemoryRegionInfo>> {
        let req = DebuggerRequest::EnumerateMemoryRegions { pid };
        match self.send_and_receive(&req)? {
            DebuggerResponse::MemoryRegionList { regions } => Ok(regions),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to enumerate memory regions: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to EnumerateMemoryRegions: {:?}", other)),
        }
    }

    pub fn search_memory(
        &mut self,
        pid: u32,
        pattern: Vec<u8>,
        max_results: usize,
    ) -> anyhow::Result<(Vec<u64>, bool)> {
        let req = DebuggerRequest::SearchMemory { pid, pattern, max_results };
        match self.send_and_receive(&req)? {
            DebuggerResponse::MemorySearchResult { addresses, capped } => Ok((addresses, capped)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to search memory: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to SearchMemory: {:?}", other)),
        }
    }

    /// Write a minidump of `pid` to `path` (on the server machine). Returns the
    /// size of the written file in bytes.
    pub fn write_minidump(&mut self, pid: u32, path: &str, kind: MinidumpKind) -> anyhow::Result<u64> {
        let req = DebuggerRequest::WriteMinidump { pid, path: path.to_string(), kind };
        match self.send_and_receive(&req)? {
            DebuggerResponse::MinidumpWritten { size_bytes } => Ok(size_bytes),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to write minidump: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to WriteMinidump: {:?}", other)),
        }
    }

    pub fn scan_memory_start(
        &mut self,
        pid: u32,
        value_type: ScanValueType,
        compare_type: ScanCompareType,
        value: Option<ScanValue>,
        value2: Option<ScanValue>,
        alignment: Option<usize>,
        float_tolerance: Option<f64>,
        writable_only: bool,
        thread_count: Option<usize>,
    ) -> anyhow::Result<(u64, u64, u64)> {
        let req = DebuggerRequest::ScanMemoryStart { pid, value_type, compare_type, value, value2, alignment, float_tolerance, writable_only: Some(writable_only), thread_count };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ScanMemoryResult { scan_id, match_count, scan_time_us } => Ok((scan_id, match_count, scan_time_us)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to start scan: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to ScanMemoryStart: {:?}", other)),
        }
    }

    pub fn scan_memory_next(
        &mut self,
        scan_id: u64,
        compare_type: ScanCompareType,
        value: Option<ScanValue>,
        value2: Option<ScanValue>,
        float_tolerance: Option<f64>,
    ) -> anyhow::Result<(u64, u64)> {
        let req = DebuggerRequest::ScanMemoryNext { scan_id, compare_type, value, value2, float_tolerance };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ScanMemoryResult { scan_id: _, match_count, scan_time_us } => Ok((match_count, scan_time_us)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to next scan: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to ScanMemoryNext: {:?}", other)),
        }
    }

    pub fn scan_memory_get_results(
        &mut self,
        scan_id: u64,
        offset: u64,
        count: u64,
    ) -> anyhow::Result<(Vec<u64>, Vec<ScanValue>, u64)> {
        let req = DebuggerRequest::ScanMemoryGetResults { scan_id, offset, count };
        match self.send_and_receive(&req)? {
            DebuggerResponse::ScanMemoryResults { addresses, values, total_count } => Ok((addresses, values, total_count)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to get scan results: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to ScanMemoryGetResults: {:?}", other)),
        }
    }

    pub fn scan_memory_reset(&mut self, scan_id: u64) -> anyhow::Result<()> {
        let req = DebuggerRequest::ScanMemoryReset { scan_id };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to reset scan: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to ScanMemoryReset: {:?}", other)),
        }
    }

    /// Start a pointer scan: find static pointer paths that resolve to `target_address`.
    /// Returns `(scan_id, match_count, scan_time_us)`.
    #[allow(clippy::too_many_arguments)]
    pub fn pointer_scan_start(
        &mut self,
        pid: u32,
        target_address: u64,
        max_offset: u64,
        max_depth: u32,
        alignment: Option<usize>,
        max_results: Option<u64>,
        modules: Option<Vec<u64>>,
        thread_count: Option<usize>,
        writable_only: bool,
    ) -> anyhow::Result<(String, u64, u64)> {
        let req = DebuggerRequest::PointerScanStart {
            pid, target_address, max_offset, max_depth, alignment, max_results, modules, thread_count, writable_only,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us } => Ok((results_path, match_count, scan_time_us)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to start pointer scan: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to PointerScanStart: {:?}", other)),
        }
    }

    pub fn pointer_scan_get_results(
        &mut self,
        pid: u32,
        results_path: String,
        offset: u64,
        count: u64,
        offset_filter: Vec<u64>,
    ) -> anyhow::Result<(Vec<crate::protocol::PointerPath>, u64)> {
        let req = DebuggerRequest::PointerScanGetResults { pid, results_path, offset, count, offset_filter };
        match self.send_and_receive(&req)? {
            DebuggerResponse::PointerScanResults { paths, total_count } => Ok((paths, total_count)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to get pointer scan results: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to PointerScanGetResults: {:?}", other)),
        }
    }

    /// Re-resolve `results_path`'s paths and keep only those that still resolve to
    /// `target_address`. Returns `(new_results_path, match_count, scan_time_us)`.
    pub fn pointer_scan_rescan(&mut self, pid: u32, results_path: String, target_address: u64) -> anyhow::Result<(String, u64, u64)> {
        let req = DebuggerRequest::PointerScanRescan { pid, results_path, target_address };
        match self.send_and_receive(&req)? {
            DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us } => Ok((results_path, match_count, scan_time_us)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to rescan pointers: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to PointerScanRescan: {:?}", other)),
        }
    }

    /// Reduce `results_path` to only the paths whose chain offsets contain every
    /// value in `offset_filter`. Returns `(new_results_path, match_count, us)`.
    pub fn pointer_scan_apply_filter(&mut self, results_path: String, offset_filter: Vec<u64>) -> anyhow::Result<(String, u64, u64)> {
        let req = DebuggerRequest::PointerScanApplyFilter { results_path, offset_filter };
        match self.send_and_receive(&req)? {
            DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us } => Ok((results_path, match_count, scan_time_us)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to apply pointer-scan filter: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to PointerScanApplyFilter: {:?}", other)),
        }
    }

    pub fn pointer_scan_reset(&mut self, results_path: String) -> anyhow::Result<()> {
        let req = DebuggerRequest::PointerScanReset { results_path };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to reset pointer scan: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to PointerScanReset: {:?}", other)),
        }
    }

    /// Start a string scan over `[start_address, start_address+size)`, visiting
    /// only regions matching `region_filter`, detecting only `encodings`, and
    /// (when `contains` is non-empty) storing only strings containing it.
    /// Returns `(results_path, match_count, scan_time_us, capped)`.
    #[allow(clippy::too_many_arguments)]
    pub fn string_scan_start(
        &mut self,
        pid: u32,
        start_address: u64,
        size: u64,
        min_length: u32,
        max_results: Option<u64>,
        thread_count: Option<usize>,
        region_filter: ScanRegionFilter,
        encodings: StringEncodingFilter,
        contains: String,
    ) -> anyhow::Result<(String, u64, u64, bool)> {
        let req = DebuggerRequest::StringScanStart { pid, start_address, size, min_length, max_results, thread_count, region_filter, encodings, contains };
        match self.send_and_receive(&req)? {
            DebuggerResponse::StringScanResult { results_path, match_count, scan_time_us, capped } => Ok((results_path, match_count, scan_time_us, capped)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to start string scan: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to StringScanStart: {:?}", other)),
        }
    }

    /// Read a page of string-scan results, filtered and sorted server-side.
    pub fn string_scan_get_results(
        &mut self,
        results_path: String,
        offset: u64,
        count: u64,
        filter: String,
        sort: StringSortKey,
        ascending: bool,
    ) -> anyhow::Result<(Vec<StringHit>, u64)> {
        let req = DebuggerRequest::StringScanGetResults { results_path, offset, count, filter, sort, ascending };
        match self.send_and_receive(&req)? {
            DebuggerResponse::StringScanResults { strings, total_count } => Ok((strings, total_count)),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to get string scan results: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to StringScanGetResults: {:?}", other)),
        }
    }

    pub fn string_scan_reset(&mut self, results_path: String) -> anyhow::Result<()> {
        let req = DebuggerRequest::StringScanReset { results_path };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to reset string scan: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to StringScanReset: {:?}", other)),
        }
    }

    /// Dereference memory addresses, following pointer chains (telescope/dereference command).
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `address` - Starting address to dereference
    /// * `count` - Number of consecutive pointer-sized slots to examine
    /// * `reference_base` - Optional base address for offset calculation (defaults to `address`)
    /// * `probe_start` - `true` when `address` is itself a pointer (a register) whose
    ///   target is described first; `false` for a memory slot, where only the stored
    ///   value is followed. See `PlatformAPI::dereference`.
    pub fn dereference(
        &mut self,
        pid: u32,
        address: u64,
        count: usize,
        reference_base: Option<u64>,
        probe_start: bool,
    ) -> anyhow::Result<Vec<crate::protocol::DereferenceEntry>> {
        let req = DebuggerRequest::Dereference { pid, address, count, reference_base, probe_start };
        match self.send_and_receive(&req)? {
            DebuggerResponse::DereferenceResult { entries } => Ok(entries),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to dereference: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to Dereference: {:?}", other)),
        }
    }

    /// Telescope many addresses in a single round-trip; the server enumerates
    /// memory regions once for the whole batch. Returns one entry list per input
    /// address, in order.
    pub fn dereference_batch(
        &mut self,
        pid: u32,
        addresses: Vec<u64>,
        count: usize,
        reference_base: Option<u64>,
        probe_start: bool,
    ) -> anyhow::Result<Vec<Vec<crate::protocol::DereferenceEntry>>> {
        let req = DebuggerRequest::DereferenceBatch { pid, addresses, count, reference_base, probe_start };
        match self.send_and_receive(&req)? {
            DebuggerResponse::DereferenceBatchResult { results } => Ok(results),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to dereference batch: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to DereferenceBatch: {:?}", other)),
        }
    }

    /// Re-arm a persistent breakpoint at the given address.
    ///
    /// Sends SetBreakpoint to the server to update stored original bytes and
    /// write the breakpoint instruction. Does NOT register a new callback handler —
    /// existing handlers are preserved.
    ///
    /// Use this after temporarily removing a breakpoint (e.g. to read original
    /// bytes or apply a patch) when the handler is still registered.
    pub fn rearm_breakpoint(&mut self, pid: u32, addr: u64) -> anyhow::Result<()> {
        self.setup_persistent_breakpoint(pid, addr, None)
    }

    /// Remove a breakpoint at the specified address.
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `addr` - Address of the breakpoint to remove
    pub fn remove_breakpoint(&mut self, pid: u32, addr: u64) -> anyhow::Result<()> {
        let req = DebuggerRequest::RemoveBreakpoint { pid, addr };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to remove breakpoint: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to RemoveBreakpoint: {:?}",
                other
            )),
        }
    }

    /// Set a hardware breakpoint. Returns the debug register index (0-3).
    pub fn set_hardware_breakpoint(
        &mut self,
        pid: u32,
        addr: u64,
        bp_type: crate::protocol::HardwareBreakpointType,
        size: crate::protocol::HardwareBreakpointSize,
    ) -> anyhow::Result<u8> {
        let req = DebuggerRequest::SetHardwareBreakpoint { pid, addr, bp_type, size };
        match self.send_and_receive(&req)? {
            DebuggerResponse::HardwareBreakpointSet { dr_index } => Ok(dr_index),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to set hardware breakpoint: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to SetHardwareBreakpoint: {:?}",
                other
            )),
        }
    }

    /// Set a hardware breakpoint by symbol name with a handler.
    /// Returns the resolved address.
    pub fn set_hardware_breakpoint_by_symbol<F>(
        &mut self,
        pid: u32,
        symbol_name: &str,
        bp_type: crate::protocol::HardwareBreakpointType,
        size: crate::protocol::HardwareBreakpointSize,
        handler: F,
    ) -> anyhow::Result<u64>
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<BreakpointDecision> + Send + 'static,
    {
        let symbols = self.find_symbols(symbol_name, 1)?;
        if symbols.is_empty() {
            return Err(anyhow::anyhow!(
                "Could not find symbol '{}' for hardware breakpoint",
                symbol_name
            ));
        }
        let address = symbols[0].va;
        self.set_hardware_breakpoint(pid, address, bp_type, size)?;
        self.breakpoint_handlers
            .entry(address)
            .or_default()
            .push(Box::new(handler));
        Ok(address)
    }

    /// Set a hardware breakpoint at an address with a handler.
    pub fn set_hardware_breakpoint_at<F>(
        &mut self,
        pid: u32,
        addr: u64,
        bp_type: crate::protocol::HardwareBreakpointType,
        size: crate::protocol::HardwareBreakpointSize,
        handler: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<BreakpointDecision> + Send + 'static,
    {
        self.set_hardware_breakpoint(pid, addr, bp_type, size)?;
        self.breakpoint_handlers
            .entry(addr)
            .or_default()
            .push(Box::new(handler));
        Ok(())
    }

    /// Remove a hardware breakpoint at the specified address.
    pub fn remove_hardware_breakpoint(&mut self, pid: u32, addr: u64) -> anyhow::Result<()> {
        let req = DebuggerRequest::RemoveHardwareBreakpoint { pid, addr };
        match self.send_and_receive(&req)? {
            DebuggerResponse::Ack => Ok(()),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to remove hardware breakpoint: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to RemoveHardwareBreakpoint: {:?}",
                other
            )),
        }
    }

    /// Trace instructions using trap flag, capturing register state at each step.
    /// Returns Tenet format trace data.
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `tid` - Thread ID
    /// * `exit_condition` - When to stop tracing (address or instruction limit)
    /// * `max_instructions` - Maximum instructions to trace
    pub fn trace_instructions(
        &mut self,
        pid: u32,
        tid: u32,
        exit_condition: TraceExitCondition,
        max_instructions: usize,
    ) -> anyhow::Result<TenetTraceResult> {
        let req = DebuggerRequest::TraceInstructions {
            pid,
            tid,
            exit_condition,
            max_instructions,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::TenetTrace {
                trace_text,
                stop_reason,
                trace_time_us,
                stats_text,
                final_pc,
                instructions_executed,
            } => Ok(TenetTraceResult {
                trace_text,
                stop_reason,
                trace_time_us,
                stats_text,
                final_pc,
                instructions_executed,
            }),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to trace instructions: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to TraceInstructions: {:?}",
                other
            )),
        }
    }

    /// Emulate instructions using Unicorn engine.
    /// Returns either a trace result (for InstructionTrace mode) or emulation data.
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `tid` - Thread ID
    /// * `max_instructions` - Maximum instructions to emulate
    /// * `mode` - Emulation mode (Basic, InstructionTrace, BasicBlock, ModuleTransition, Syscall)
    /// * `exit_condition` - Optional exit condition (stop at address)
    /// * `memory_reads` - Memory addresses to read from emulator state after execution
    pub fn emulate_instructions(
        &mut self,
        pid: u32,
        tid: u32,
        max_instructions: usize,
        mode: EmulationMode,
        exit_condition: Option<TraceExitCondition>,
        memory_reads: Vec<(u64, usize)>,
    ) -> anyhow::Result<EmulateResult> {
        let req = DebuggerRequest::EmulateInstructions {
            pid,
            tid,
            max_instructions,
            mode,
            exit_condition,
            memory_reads,
        };
        match self.send_and_receive(&req)? {
            DebuggerResponse::TenetTrace {
                trace_text,
                stop_reason,
                trace_time_us,
                stats_text,
                final_pc,
                instructions_executed,
            } => Ok(EmulateResult::Trace(TenetTraceResult {
                trace_text,
                stop_reason,
                trace_time_us,
                stats_text,
                final_pc,
                instructions_executed,
            })),
            DebuggerResponse::EmulationResult {
                final_pc,
                instructions_executed,
                stop_reason,
                emulation_time_us,
                pages_loaded,
                basic_blocks,
                stats_text,
                memory_snapshots,
            } => Ok(EmulateResult::Emulation(EmulationResultData {
                final_pc,
                instructions_executed,
                stop_reason,
                emulation_time_us,
                pages_loaded,
                basic_blocks,
                stats_text,
                memory_snapshots,
            })),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to emulate instructions: {}", message))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected response to EmulateInstructions: {:?}",
                other
            )),
        }
    }
} 