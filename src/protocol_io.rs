use crate::interfaces::{Architecture, Instruction, ModuleSymbol};
pub use crate::protocol::{
    DebuggerRequest, DebuggerResponse, DebugEvent, ModuleInfo, ProcessInfo, StepAction, StepKind,
    ThreadContext, ThreadInfo,
};
use std::collections::HashMap;
pub use std::net::TcpStream;
use std::sync::Mutex;
use crate::framed_json_stream::FramedJsonStream;
use tracing::{debug, error, info};

pub fn send_request(stream: &mut FramedJsonStream, req: &DebuggerRequest) -> anyhow::Result<()> {
    debug!("Sending request: {:?}", req);
    stream.send(req)
}

pub fn receive_response(stream: &mut FramedJsonStream) -> anyhow::Result<DebuggerResponse> {
    let resp: DebuggerResponse = stream.receive()?;
    debug!("Received response: {:?}", resp);
    if let DebuggerResponse::Error { message } = &resp {
        panic!("Error: {}", message);
    }
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
        on_thread_created:
        Option<Box<dyn FnMut(&mut Self, u32, u32, u64) -> anyhow::Result<()> + Send + Sync + 'static>>,
    on_process_exited:
        Option<Box<dyn FnMut(&mut Self, u32, u32) -> anyhow::Result<()> + Send + 'static>>,
    on_thread_exited:
        Option<Box<dyn FnMut(&mut Self, u32, u32, u32) -> anyhow::Result<()> + Send + Sync + 'static>>,
    on_process_created:
        Option<Box<dyn FnMut(&mut Self, u32, u32, &str, u64) -> anyhow::Result<()> + Send + 'static>>,
    on_event: Option<Box<dyn FnMut(&mut Self, &DebugEvent) -> anyhow::Result<bool> + Send + 'static>>,
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
            on_thread_created: None,
            on_process_exited: None,
            on_thread_exited: None,
            on_process_created: None,
            on_event: None,
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
        self.send(&req)?;
        Ok(())
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
        let mut on_thread_created = self.on_thread_created.take();
        let mut on_process_created = self.on_process_created.take();
        let mut on_process_exited = self.on_process_exited.take();
        let mut on_thread_exited = self.on_thread_exited.take();
        let mut on_event = self.on_event.take();

        // Check if on_event handler wants to stop the session
        let mut should_continue = true;
        if let Some(ref mut handler) = on_event {
            // The handler returns Result<bool> where false means stop the session
            should_continue = handler(self, event)?;
        }

        match event {
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
                    // TODO: handle multiple step requests, currently relaxed due to UI unbreak
                    // panic!("No stepping info, sending continue request");
                };

            }
            DebugEvent::Exception { .. } => {
                // No-op. Auto-continue will handle it below.
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
        self.on_event = on_event;

        // If the on_event handler wants to stop, respect that
        if !should_continue {
            return Ok(false);
        }

        // Handle automatic continuation for most events
        match event {
            DebugEvent::ProcessExited { .. } => return Ok(false),

            DebugEvent::ProcessCreated { pid, tid, .. }
            | DebugEvent::DllLoaded { pid, tid, .. }
            | DebugEvent::DllUnloaded { pid, tid, .. }
            | DebugEvent::ThreadCreated { pid, tid, .. }
            | DebugEvent::ThreadExited { pid, tid, .. }
            | DebugEvent::Breakpoint { pid, tid, .. }
            | DebugEvent::InitialBreakpoint { pid, tid, .. }
            | DebugEvent::Output { pid, tid, .. }
            | DebugEvent::Exception { pid, tid, .. }
            | DebugEvent::StepComplete { pid, tid, .. }
            | DebugEvent::SingleShotBreakpoint { pid, tid, .. }
            | DebugEvent::RipEvent { pid, tid, .. } => {
                let cont = DebuggerRequest::Continue {
                    pid: *pid,
                    tid: *tid,
                };
                let mut stream = self.stream.lock().unwrap();
                send_request(&mut stream, &cont)?;
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
} 