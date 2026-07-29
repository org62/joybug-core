//! DebugClient: Lua-facing debugger session that owns the TCP stream.
//!
//! Instead of wrapping DebugSession (which uses Rust closures for callbacks),
//! this operates directly on FramedJsonStream, sending DebuggerRequest and
//! receiving DebuggerResponse. Lua functions are stored via mlua::RegistryKey.

use std::collections::HashMap;
use std::net::TcpStream;

use mlua::prelude::*;
use tracing::{info, warn};

use crate::framed_json_stream::FramedJsonStream;
use crate::interfaces::{CallFrame, Instruction, ResolvedSymbol};
use crate::protocol::*;
use crate::protocol_io::{send_request, receive_response};


/// Handler registry for Lua callback functions.
pub struct HandlerRegistry {
    pub on_initial_breakpoint: Option<LuaRegistryKey>,
    pub breakpoint_handlers: HashMap<u64, LuaRegistryKey>,
    pub hw_breakpoint_handlers: HashMap<u64, LuaRegistryKey>,
    pub single_shot_handlers: HashMap<u64, LuaRegistryKey>,
    pub on_dll_loaded: Option<LuaRegistryKey>,
    pub on_dll_unloaded: Option<LuaRegistryKey>,
    pub on_exception: Option<LuaRegistryKey>,
    pub on_process_exited: Option<LuaRegistryKey>,
    pub on_process_created: Option<LuaRegistryKey>,
    pub on_thread_created: Option<LuaRegistryKey>,
    pub on_thread_exited: Option<LuaRegistryKey>,
    pub repl_on_break: bool,
}

impl HandlerRegistry {
    fn new() -> Self {
        Self {
            on_initial_breakpoint: None,
            breakpoint_handlers: HashMap::new(),
            hw_breakpoint_handlers: HashMap::new(),
            single_shot_handlers: HashMap::new(),
            on_dll_loaded: None,
            on_dll_unloaded: None,
            on_exception: None,
            on_process_exited: None,
            on_process_created: None,
            on_thread_created: None,
            on_thread_exited: None,
            repl_on_break: false,
        }
    }
}

/// What type of handler to invoke for auto-continue events.
pub enum HandlerType {
    DllLoaded { name: String, base: u64 },
    DllUnloaded { base: u64 },
    ProcessCreated { name: String, base: u64 },
    ThreadCreated { start: u64 },
    ThreadExited { exit_code: u32 },
}

/// Action determined by prepare_event, to be executed outside the borrow.
pub enum EventAction {
    InitialBreakpoint { pid: u32, tid: u32, address: u64, has_handler: bool, repl_on_break: bool },
    Breakpoint { pid: u32, tid: u32, address: u64, has_handler: bool, repl_on_break: bool },
    HwBreakpoint { pid: u32, tid: u32, address: u64, has_handler: bool, repl_on_break: bool, dr_index: u8, bp_type: HardwareBreakpointType },
    SingleShotBreakpoint { pid: u32, tid: u32, address: u64, has_handler: bool },
    Exception { pid: u32, tid: u32, code: u32, address: u64, first_chance: bool, has_handler: bool, repl_on_break: bool },
    ProcessExited { pid: u32, tid: u32, exit_code: u32, is_root: bool, has_handler: bool },
    AutoContinue { pid: u32, tid: u32, handler_type: Option<HandlerType> },
}

/// The Lua-facing debug client. Stored as Lua UserData.
pub struct DebugClient {
    stream: FramedJsonStream,
    pub handlers: HandlerRegistry,
    /// Current stopped pid (set on break events)
    pub current_pid: Option<u32>,
    /// Current stopped tid (set on break events)
    pub current_tid: Option<u32>,
    /// Current stopped address
    pub current_address: Option<u64>,
    /// Flag set by dbg:repl() — event loop checks this after handler returns
    pub wants_repl: bool,
    /// Root process PID
    pub root_pid: Option<u32>,
}

impl DebugClient {
    /// Connect to a joybug-core server.
    pub fn connect(addr: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let framed = FramedJsonStream::new(stream);
        Ok(Self {
            stream: framed,
            handlers: HandlerRegistry::new(),
            current_pid: None,
            current_tid: None,
            current_address: None,
            wants_repl: false,
            root_pid: None,
        })
    }

    /// Resolve an address to a symbol string for display (e.g. "ntdll!LdrpDoDebuggerBreak+0x30").
    /// Returns just the hex address if resolution fails.
    pub fn format_address(&mut self, pid: u32, addr: u64) -> String {
        let resp = self.send_and_receive(&DebuggerRequest::ResolveAddressToSymbol {
            pid, address: addr,
        });
        if let Ok(DebuggerResponse::AddressSymbol { module_path, symbol, offset }) = resp {
            if let (Some(module), Some(sym)) = (module_path, symbol) {
                // Extract just the filename from the full path
                let module_name = module.rsplit(&['\\', '/'][..]).next().unwrap_or(&module);
                // Strip extension
                let module_short = module_name.rsplit_once('.').map(|(n, _)| n).unwrap_or(module_name);
                let off = offset.unwrap_or(0);
                if off == 0 {
                    return format!("{}!{}", module_short, sym.name);
                } else {
                    return format!("{}!{}+0x{:x}", module_short, sym.name, off);
                }
            }
        }
        format!("0x{:X}", addr)
    }

    /// Send a request without waiting for a response.
    pub fn send_request_only(&mut self, req: &DebuggerRequest) -> anyhow::Result<()> {
        send_request(&mut self.stream, req)
    }

    /// Send a request and receive a response.
    pub fn send_and_receive(&mut self, req: &DebuggerRequest) -> anyhow::Result<DebuggerResponse> {
        send_request(&mut self.stream, req)?;
        receive_response(&mut self.stream)
    }

    /// Send a Continue request.
    pub fn continue_process(&mut self, pid: u32, tid: u32, pass_exception: bool) -> anyhow::Result<()> {
        send_request(&mut self.stream, &DebuggerRequest::Continue {
            pid, tid, pass_exception,
        })?;
        Ok(())
    }

    /// Receive a single event from the stream.
    /// Returns Ok(Some(event)) for events, Ok(None) for non-event responses,
    /// Err for errors.
    pub fn receive_event(&mut self) -> anyhow::Result<Option<DebugEvent>> {
        let resp = receive_response(&mut self.stream)?;
        match resp {
            DebuggerResponse::Event { event } => Ok(Some(event)),
            DebuggerResponse::Error { message } => {
                Err(anyhow::anyhow!("Server error: {}", message))
            }
            _ => {
                info!("Ignoring non-event response during event loop");
                Ok(None)
            }
        }
    }

    /// Phase 1: Update state and determine what action the event requires.
    /// Returns the action to take (which Lua handler to call, whether to REPL, etc.)
    /// This borrows self briefly, then releases so Lua handlers can re-borrow.
    pub fn prepare_event(&mut self, event: &DebugEvent) -> EventAction {
        let _pid = event.pid();
        let _tid = event.tid();

        match event {
            DebugEvent::InitialBreakpoint { pid, tid, address } => {
                self.current_pid = Some(*pid);
                self.current_tid = Some(*tid);
                self.current_address = Some(*address);
                if self.root_pid.is_none() {
                    self.root_pid = Some(*pid);
                }
                let has_handler = self.handlers.on_initial_breakpoint.is_some();
                let repl_on_break = self.handlers.repl_on_break;
                EventAction::InitialBreakpoint {
                    pid: *pid, tid: *tid, address: *address,
                    has_handler, repl_on_break,
                }
            }
            DebugEvent::Breakpoint { pid, tid, address } => {
                self.current_pid = Some(*pid);
                self.current_tid = Some(*tid);
                self.current_address = Some(*address);
                let has_handler = self.handlers.breakpoint_handlers.contains_key(address);
                let repl_on_break = self.handlers.repl_on_break;
                EventAction::Breakpoint {
                    pid: *pid, tid: *tid, address: *address,
                    has_handler, repl_on_break,
                }
            }
            DebugEvent::HardwareBreakpoint { pid, tid, address, dr_index, bp_type } => {
                self.current_pid = Some(*pid);
                self.current_tid = Some(*tid);
                self.current_address = Some(*address);
                let has_handler = self.handlers.hw_breakpoint_handlers.contains_key(address);
                let repl_on_break = self.handlers.repl_on_break;
                EventAction::HwBreakpoint {
                    pid: *pid, tid: *tid, address: *address,
                    has_handler, repl_on_break,
                    dr_index: *dr_index, bp_type: *bp_type,
                }
            }
            DebugEvent::SingleShotBreakpoint { pid, tid, address } => {
                self.current_pid = Some(*pid);
                self.current_tid = Some(*tid);
                self.current_address = Some(*address);
                let has_handler = self.handlers.single_shot_handlers.contains_key(address);
                EventAction::SingleShotBreakpoint {
                    pid: *pid, tid: *tid, address: *address, has_handler,
                }
            }
            DebugEvent::Exception { pid, tid, code, address, first_chance, parameters: _ } => {
                self.current_pid = Some(*pid);
                self.current_tid = Some(*tid);
                self.current_address = Some(*address);
                let has_handler = self.handlers.on_exception.is_some();
                let repl_on_break = self.handlers.repl_on_break;
                EventAction::Exception {
                    pid: *pid, tid: *tid, code: *code, address: *address,
                    first_chance: *first_chance, has_handler, repl_on_break,
                }
            }
            DebugEvent::ProcessExited { pid, exit_code, tid } => {
                let is_root = self.root_pid == Some(*pid);
                let has_handler = self.handlers.on_process_exited.is_some();
                EventAction::ProcessExited {
                    pid: *pid, tid: *tid, exit_code: *exit_code,
                    is_root, has_handler,
                }
            }
            DebugEvent::DllLoaded { pid, tid, dll_name, base_of_dll, .. } => {
                let has_handler = self.handlers.on_dll_loaded.is_some();
                EventAction::AutoContinue {
                    pid: *pid, tid: *tid,
                    handler_type: if has_handler { Some(HandlerType::DllLoaded {
                        name: dll_name.clone().unwrap_or_default(), base: *base_of_dll,
                    }) } else { None },
                }
            }
            DebugEvent::DllUnloaded { pid, tid, base_of_dll } => {
                let has_handler = self.handlers.on_dll_unloaded.is_some();
                EventAction::AutoContinue {
                    pid: *pid, tid: *tid,
                    handler_type: if has_handler { Some(HandlerType::DllUnloaded { base: *base_of_dll }) } else { None },
                }
            }
            DebugEvent::ProcessCreated { pid, tid, image_file_name, base_of_image, .. } => {
                if self.root_pid.is_none() {
                    self.root_pid = Some(*pid);
                }
                let has_handler = self.handlers.on_process_created.is_some();
                EventAction::AutoContinue {
                    pid: *pid, tid: *tid,
                    handler_type: if has_handler { Some(HandlerType::ProcessCreated {
                        name: image_file_name.clone().unwrap_or_default(), base: *base_of_image,
                    }) } else { None },
                }
            }
            DebugEvent::ThreadCreated { pid, tid, start_address } => {
                let has_handler = self.handlers.on_thread_created.is_some();
                EventAction::AutoContinue {
                    pid: *pid, tid: *tid,
                    handler_type: if has_handler { Some(HandlerType::ThreadCreated { start: *start_address }) } else { None },
                }
            }
            DebugEvent::ThreadExited { pid, tid, exit_code } => {
                let has_handler = self.handlers.on_thread_exited.is_some();
                EventAction::AutoContinue {
                    pid: *pid, tid: *tid,
                    handler_type: if has_handler { Some(HandlerType::ThreadExited { exit_code: *exit_code }) } else { None },
                }
            }
            DebugEvent::StepComplete { pid, tid, address, .. } => {
                self.current_pid = Some(*pid);
                self.current_tid = Some(*tid);
                self.current_address = Some(*address);
                EventAction::AutoContinue { pid: *pid, tid: *tid, handler_type: None }
            }
            DebugEvent::Output { pid, tid, output } => {
                eprintln!("[output pid={} tid={}] {}", pid, tid, output);
                EventAction::AutoContinue { pid: *pid, tid: *tid, handler_type: None }
            }
            DebugEvent::StepFailed { pid, tid, kind, message } => {
                warn!("Step failed: {:?} - {}", kind, message);
                EventAction::AutoContinue { pid: *pid, tid: *tid, handler_type: None }
            }
            DebugEvent::RipEvent { pid, tid, error, event_type } => {
                warn!("RIP event: error={}, type={}", error, event_type);
                EventAction::AutoContinue { pid: *pid, tid: *tid, handler_type: None }
            }
            DebugEvent::Unknown { pid, tid, debug_event_code, error } => {
                warn!("Unknown debug event {}: {}", debug_event_code, error);
                EventAction::AutoContinue { pid: *pid, tid: *tid, handler_type: None }
            }
        }
    }

    /// Phase 3: Continue the process after handling an event.
    pub fn do_continue(&mut self, pid: u32, tid: u32, pass_exception: bool) -> mlua::Result<()> {
        self.continue_process(pid, tid, pass_exception)
            .map_err(|e| mlua::Error::external(e))
    }


    /// Step and wait for StepComplete.
    ///
    /// Protocol: Send Step → receive Ack → send Continue → receive Event.
    /// The Step request sets up the trap flag. The Continue request resumes
    /// execution and blocks until the next debug event (which should be
    /// StepComplete after the trap flag fires). Intermediate events (DLL loads,
    /// thread events) are auto-continued until StepComplete arrives.
    pub fn step_and_wait(&mut self, pid: u32, tid: u32, kind: StepKind) -> mlua::Result<u64> {
        // 1. Send Step request — sets up trap flag
        let resp = self.send_and_receive(&DebuggerRequest::Step { pid, tid, kind })
            .map_err(|e| mlua::Error::external(e))?;
        match resp {
            DebuggerResponse::Ack => {}
            DebuggerResponse::Event { event } => {
                if let DebugEvent::StepFailed { message, .. } = event {
                    return Err(mlua::Error::external(anyhow::anyhow!("Step failed: {}", message)));
                }
            }
            DebuggerResponse::Error { message } => {
                return Err(mlua::Error::external(anyhow::anyhow!("Step error: {}", message)));
            }
            _ => {}
        }

        // 2. Send Continue to resume execution, wait for StepComplete event.
        // Intermediate events (DLL loads, thread create/exit, etc.) may fire on a
        // *different* thread than the one we're stepping. ContinueDebugEvent must be
        // called with the thread that actually reported the event, otherwise the OS
        // returns ERROR_INVALID_PARAMETER (87). Track the continue target and update
        // it from each event's own pid/tid.
        let mut cont_pid = pid;
        let mut cont_tid = tid;
        loop {
            let resp = self.send_and_receive(&DebuggerRequest::Continue {
                pid: cont_pid, tid: cont_tid, pass_exception: false,
            }).map_err(|e| mlua::Error::external(e))?;

            match resp {
                DebuggerResponse::Event { event } => {
                    match &event {
                        DebugEvent::StepComplete { address, .. } => {
                            self.current_pid = Some(pid);
                            self.current_tid = Some(tid);
                            self.current_address = Some(*address);
                            return Ok(*address);
                        }
                        DebugEvent::StepFailed { message, .. } => {
                            return Err(mlua::Error::external(
                                anyhow::anyhow!("Step failed: {}", message),
                            ));
                        }
                        DebugEvent::ProcessExited { pid: ep, exit_code, .. } => {
                            return Err(mlua::Error::external(
                                anyhow::anyhow!("Process {} exited (code {}) during step", ep, exit_code),
                            ));
                        }
                        // Intermediate events (DLL loads, etc.) — continue the thread
                        // that reported this event, not the one we're stepping.
                        _ => {
                            cont_pid = event.pid();
                            cont_tid = event.tid();
                        }
                    }
                }
                DebuggerResponse::Error { message } => {
                    return Err(mlua::Error::external(
                        anyhow::anyhow!("Server error during step: {}", message),
                    ));
                }
                _ => {}
            }
        }
    }

    /// Resolve an address to its (file, line) via the module's PDB line table.
    fn resolve_line(&mut self, pid: u32, address: u64) -> Option<(String, u32)> {
        match self.send_and_receive(&DebuggerRequest::ResolveAddressToLine { pid, address }).ok()? {
            DebuggerResponse::AddressLine { info: Some(info) } => {
                Some((info.file.path, info.line_entry.line_start))
            }
            _ => None,
        }
    }

    /// Step by one source line: repeatedly `step_and_wait` until the PC leaves
    /// the starting source line (or leaves mapped source). `kind` chooses Into vs
    /// Over granularity. Degrades to a single step when the start has no line info.
    pub fn step_source_line_and_wait(&mut self, pid: u32, tid: u32, kind: StepKind) -> mlua::Result<u64> {
        const MAX_STEPS: u32 = 50_000;
        let start = self.current_address.and_then(|pc| self.resolve_line(pid, pc));
        let mut last = self.current_address.unwrap_or(0);
        for _ in 0..MAX_STEPS {
            last = self.step_and_wait(pid, tid, kind)?;
            let Some(ref start) = start else { break }; // no start line info → single step
            match self.resolve_line(pid, last) {
                Some(ref cur) if cur == start => continue,
                _ => break,
            }
        }
        Ok(last)
    }
}

// ---- Lua type conversion helpers ----

/// Convert a ThreadContext to a Lua table with named register fields.
pub fn context_to_lua_table(lua: &Lua, ctx: &ThreadContext) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    match ctx {
        #[cfg(windows)]
        ThreadContext::Win32RawContext(c) => {
            #[cfg(target_arch = "x86_64")]
            {
                table.set("rax", c.Rax)?;
                table.set("rbx", c.Rbx)?;
                table.set("rcx", c.Rcx)?;
                table.set("rdx", c.Rdx)?;
                table.set("rsi", c.Rsi)?;
                table.set("rdi", c.Rdi)?;
                table.set("rbp", c.Rbp)?;
                table.set("rsp", c.Rsp)?;
                table.set("r8", c.R8)?;
                table.set("r9", c.R9)?;
                table.set("r10", c.R10)?;
                table.set("r11", c.R11)?;
                table.set("r12", c.R12)?;
                table.set("r13", c.R13)?;
                table.set("r14", c.R14)?;
                table.set("r15", c.R15)?;
                table.set("rip", c.Rip)?;
                table.set("rflags", c.EFlags as u64)?;
            }
            #[cfg(target_arch = "aarch64")]
            {
                unsafe {
                    let x_regs = c.Anonymous.X;
                    let x_table = lua.create_table()?;
                    for i in 0..29 {
                        x_table.set(i + 1, x_regs[i])?; // Lua 1-based
                    }
                    table.set("x", x_table)?;
                    table.set("fp", c.Anonymous.Anonymous.Fp)?;
                    table.set("lr", c.Anonymous.Anonymous.Lr)?;
                    table.set("sp", c.Sp)?;
                    table.set("pc", c.Pc)?;
                    table.set("cpsr", c.Cpsr as u64)?;
                }
            }
        }
    }
    Ok(table)
}

/// Convert a Lua table back to a ThreadContext (for set_context).
#[cfg(windows)]
pub fn lua_table_to_context(table: &LuaTable, original: &ThreadContext) -> mlua::Result<ThreadContext> {
    match original {
        ThreadContext::Win32RawContext(_orig_ctx) => {
            let mut ctx = original.clone();
            match &mut ctx {
                ThreadContext::Win32RawContext(c) => {
                    #[cfg(target_arch = "x86_64")]
                    {
                        if let Ok(v) = table.get::<u64>("rax") { c.Rax = v; }
                        if let Ok(v) = table.get::<u64>("rbx") { c.Rbx = v; }
                        if let Ok(v) = table.get::<u64>("rcx") { c.Rcx = v; }
                        if let Ok(v) = table.get::<u64>("rdx") { c.Rdx = v; }
                        if let Ok(v) = table.get::<u64>("rsi") { c.Rsi = v; }
                        if let Ok(v) = table.get::<u64>("rdi") { c.Rdi = v; }
                        if let Ok(v) = table.get::<u64>("rbp") { c.Rbp = v; }
                        if let Ok(v) = table.get::<u64>("rsp") { c.Rsp = v; }
                        if let Ok(v) = table.get::<u64>("r8") { c.R8 = v; }
                        if let Ok(v) = table.get::<u64>("r9") { c.R9 = v; }
                        if let Ok(v) = table.get::<u64>("r10") { c.R10 = v; }
                        if let Ok(v) = table.get::<u64>("r11") { c.R11 = v; }
                        if let Ok(v) = table.get::<u64>("r12") { c.R12 = v; }
                        if let Ok(v) = table.get::<u64>("r13") { c.R13 = v; }
                        if let Ok(v) = table.get::<u64>("r14") { c.R14 = v; }
                        if let Ok(v) = table.get::<u64>("r15") { c.R15 = v; }
                        if let Ok(v) = table.get::<u64>("rip") { c.Rip = v; }
                        if let Ok(v) = table.get::<u64>("rflags") { c.EFlags = v as u32; }
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        unsafe {
                            if let Ok(x_table) = table.get::<LuaTable>("x") {
                                for i in 0..29usize {
                                    if let Ok(v) = x_table.get::<u64>(i + 1) {
                                        c.Anonymous.X[i] = v;
                                    }
                                }
                            }
                            if let Ok(v) = table.get::<u64>("fp") { c.Anonymous.Anonymous.Fp = v; }
                            if let Ok(v) = table.get::<u64>("lr") { c.Anonymous.Anonymous.Lr = v; }
                            if let Ok(v) = table.get::<u64>("sp") { c.Sp = v; }
                            if let Ok(v) = table.get::<u64>("pc") { c.Pc = v; }
                            if let Ok(v) = table.get::<u64>("cpsr") { c.Cpsr = v as u32; }
                        }
                    }
                }
            }
            Ok(ctx)
        }
    }
}

/// Convert an Instruction to a Lua table.
pub fn instruction_to_lua_table(lua: &Lua, inst: &Instruction) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("address", inst.address)?;
    table.set("mnemonic", inst.mnemonic.as_str())?;
    table.set("operands", inst.symbolized_op_str.as_deref().unwrap_or(&inst.op_str))?;
    table.set("size", inst.size)?;
    table.set("is_call", inst.is_call)?;
    table.set("is_jump", inst.is_jump)?;
    table.set("is_ret", inst.is_ret)?;
    if let Some(target) = inst.jump_target {
        table.set("jump_target", target)?;
    }
    if let Some(mem) = inst.mem_ref {
        table.set("mem_ref", mem)?;
    }
    if let Some(ref sym) = inst.symbol_info {
        table.set("symbol", sym.format_symbol())?;
    }
    // Every name starting exactly at this address (aliases like NtClose/ZwClose).
    if !inst.symbols_at_address.is_empty() {
        let names = lua.create_table()?;
        for (i, sym) in inst.symbols_at_address.iter().enumerate() {
            names.set(i + 1, sym.format_symbol())?;
        }
        table.set("symbols", names)?;
    }
    // Raw bytes as Lua string
    table.set("bytes", lua.create_string(&inst.bytes)?)?;
    Ok(table)
}

/// Convert a CallFrame to a Lua table.
pub fn callframe_to_lua_table(lua: &Lua, frame: &CallFrame) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("address", frame.instruction_pointer)?;
    table.set("sp", frame.stack_pointer)?;
    table.set("fp", frame.frame_pointer)?;
    if let Some(ref sym) = frame.symbol {
        table.set("symbol", sym.format_symbol())?;
        table.set("module", sym.module_name.as_str())?;
    }
    Ok(table)
}

/// Convert a ModuleInfo to a Lua table.
pub fn module_to_lua_table(lua: &Lua, m: &ModuleInfo) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("name", m.name.as_str())?;
    table.set("base", m.base)?;
    if let Some(size) = m.size {
        table.set("size", size)?;
    }
    Ok(table)
}

/// Convert a ResolvedSymbol to a Lua table.
pub fn resolved_symbol_to_lua_table(lua: &Lua, sym: &ResolvedSymbol) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("name", sym.name.as_str())?;
    table.set("module", sym.module_name.as_str())?;
    table.set("rva", sym.rva as u64)?;
    table.set("va", sym.va)?;
    table.set("is_function", sym.is_function)?;
    Ok(table)
}

/// Convert a MemoryRegionInfo to a Lua table.
pub fn region_to_lua_table(lua: &Lua, r: &MemoryRegionInfo) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("base_address", r.base_address)?;
    table.set("allocation_base", r.allocation_base)?;
    table.set("region_size", r.region_size)?;
    table.set("protect", r.protect)?;
    table.set("state", r.state)?;
    table.set("region_type", r.region_type)?;
    Ok(table)
}

/// Convert a DereferenceEntry to a Lua table.
pub fn deref_entry_to_lua_table(lua: &Lua, entry: &DereferenceEntry) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("address", entry.address)?;
    table.set("offset", entry.offset)?;

    let chain = lua.create_table()?;
    for (i, val) in entry.chain.iter().enumerate() {
        let val_table = lua.create_table()?;
        match val {
            DereferenceValue::Pointer(addr, sym) => {
                val_table.set("type", "pointer")?;
                val_table.set("address", *addr)?;
                if let Some(s) = sym {
                    val_table.set("symbol", s.as_str())?;
                }
            }
            DereferenceValue::Value(v) => {
                val_table.set("type", "value")?;
                val_table.set("value", *v)?;
            }
            DereferenceValue::String(s) => {
                val_table.set("type", "string")?;
                val_table.set("value", s.as_str())?;
            }
            DereferenceValue::Instruction(mnem, sym) => {
                val_table.set("type", "instruction")?;
                val_table.set("mnemonic", mnem.as_str())?;
                if let Some(s) = sym {
                    val_table.set("symbol", s.as_str())?;
                }
            }
            DereferenceValue::LoopDetected(addr) => {
                val_table.set("type", "loop")?;
                val_table.set("address", *addr)?;
            }
        }
        chain.set(i + 1, val_table)?;
    }
    table.set("chain", chain)?;
    Ok(table)
}
