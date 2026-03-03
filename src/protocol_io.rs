use crate::interfaces::{Architecture, Instruction, ModuleSymbol};
use crate::pe_types::ModuleExtraInfo;
pub use crate::protocol::{
    DebuggerRequest, DebuggerResponse, DebugEvent, EmulationMode, HardwareBreakpointSize,
    HardwareBreakpointType, ModuleInfo, ProcessInfo, StepAction, StepKind, ThreadContext,
    ThreadInfo, TraceExitCondition,
};

/// Result from trace_instructions()
#[derive(Debug, Clone)]
pub struct TenetTraceResult {
    pub trace_text: String,
    pub stop_reason: String,
    pub trace_time_us: u64,
    pub stats_text: String,
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
        DebuggerResponse::Ack => "Ack".to_string(),
        DebuggerResponse::Error { .. } => "Error".to_string(),
        DebuggerResponse::Event { .. } => "Event".to_string(),
        DebuggerResponse::MemoryData { .. } => "MemoryData".to_string(),
        DebuggerResponse::WriteAck => "WriteAck".to_string(),
        DebuggerResponse::ThreadContext { .. } => "ThreadContext".to_string(),
        DebuggerResponse::SetContextAck => "SetContextAck".to_string(),
        DebuggerResponse::ModuleList { .. } => "ModuleList".to_string(),
        DebuggerResponse::ThreadList { .. } => "ThreadList".to_string(),
        DebuggerResponse::ProcessList { .. } => "ProcessList".to_string(),
        DebuggerResponse::Symbol { .. } => "Symbol".to_string(),
        DebuggerResponse::SymbolList { .. } => "SymbolList".to_string(),
        DebuggerResponse::ResolvedSymbolList { .. } => "ResolvedSymbolList".to_string(),
        DebuggerResponse::AddressSymbol { .. } => "AddressSymbol".to_string(),
        DebuggerResponse::CallStack { .. } => "CallStack".to_string(),
        DebuggerResponse::FunctionArguments { .. } => "FunctionArguments".to_string(),
        DebuggerResponse::WideStringData { .. } => "WideStringData".to_string(),
        DebuggerResponse::ModuleExtraInfo { .. } => "ModuleExtraInfo".to_string(),
        DebuggerResponse::MemoryRegionInfo { .. } => "MemoryRegionInfo".to_string(),
        DebuggerResponse::MemoryRegionList { regions } => format!("MemoryRegionList ({} regions)", regions.len()),
        DebuggerResponse::DereferenceResult { entries } => format!("DereferenceResult ({} entries)", entries.len()),
        DebuggerResponse::FunctionDisassembly { instructions, .. } => format!("FunctionDisassembly ({} instructions)", instructions.len()),
        DebuggerResponse::EmulationResult { instructions_executed, .. } => format!("EmulationResult ({} instructions)", instructions_executed),
        DebuggerResponse::TenetTrace { trace_text, .. } => format!("TenetTrace ({} bytes)", trace_text.len()),
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
}

impl<S> DebugSession<S> {
    pub fn new(state: S, addr: Option<&str>) -> anyhow::Result<Self> {
        let addr = addr.unwrap_or("127.0.0.1:9000");
        let stream = TcpStream::connect(addr)?;
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
        })
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
    pub fn launch(mut self, command: String) -> anyhow::Result<S> {
        let launch = DebuggerRequest::Launch { command };
        self.send(&launch)?;
        // Don't wait for a response here, run_session_loop will handle it
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
            if let DebuggerResponse::Event { event } = resp {
                if !self.handle_session_event(&event)? {
                    break;
                }
            } else {
                info!("Received non-event response: {:?}, ignoring.", resp);
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
            DebugEvent::ProcessExited { pid, exit_code } => {
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

        // If the on_event handler wants to stop, respect that
        if !should_continue {
            return Ok(false);
        }

        // Handle automatic continuation for most events
        match event {
            DebugEvent::ProcessExited { .. } => return Ok(false),

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
            DebugEvent::Unknown => {}
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

    pub fn list_threads(&mut self, pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
        let req = DebuggerRequest::ListThreads { pid };
        let resp = self.send_and_receive(&req)?;
        if let DebuggerResponse::ThreadList { threads } = resp {
            Ok(threads)
        } else {
            Err(anyhow::anyhow!("Unexpected response: {:?}", resp))
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

    /// Dereference memory addresses, following pointer chains (telescope/dereference command).
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `address` - Starting address to dereference
    /// * `count` - Number of consecutive pointer-sized slots to examine
    /// * `reference_base` - Optional base address for offset calculation (defaults to `address`)
    pub fn dereference(
        &mut self,
        pid: u32,
        address: u64,
        count: usize,
        reference_base: Option<u64>,
    ) -> anyhow::Result<Vec<crate::protocol::DereferenceEntry>> {
        let req = DebuggerRequest::Dereference { pid, address, count, reference_base };
        match self.send_and_receive(&req)? {
            DebuggerResponse::DereferenceResult { entries } => Ok(entries),
            DebuggerResponse::Error { message } => Err(anyhow::anyhow!("Failed to dereference: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response to Dereference: {:?}", other)),
        }
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
            } => Ok(TenetTraceResult {
                trace_text,
                stop_reason,
                trace_time_us,
                stats_text,
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
            } => Ok(EmulateResult::Trace(TenetTraceResult {
                trace_text,
                stop_reason,
                trace_time_us,
                stats_text,
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