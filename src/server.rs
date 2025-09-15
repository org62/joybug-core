use crate::protocol::{DebuggerRequest, DebuggerResponse};
use crate::interfaces::{PlatformAPI, Stepper};
use tokio::net::TcpListener;
use tracing::{info, error, debug};

use std::sync::{Arc, Mutex};

#[cfg(windows)]
type PlatformImpl = crate::windows_platform::WindowsPlatform;

use crate::framed_json_stream::FramedJsonStream;


fn handle_connection(stream: std::net::TcpStream, platform: Arc<Mutex<PlatformImpl>>) {
    let mut framed_stream = FramedJsonStream::new(stream);
    loop {
        let req: DebuggerRequest = match framed_stream.receive() {
            Ok(req) => req,
            Err(e) => {
                if let Some(io_err) = e.root_cause().downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                        debug!("Client disconnected");
                        break;
                    }
                }
                error!(?e, "Failed to receive request from client");
                break;
            }
        };
        debug!(?req, "Received request");

        // Handle termination without taking the platform lock to avoid deadlock with WaitForDebugEvent
        if let DebuggerRequest::TerminateProcess { pid } = req {
            #[cfg(windows)]
            {
                info!(pid, "TerminateProcess (unlocked) request received");
                let resp = match crate::windows_platform::process::terminate_process_unlocked(pid) {
                    Ok(()) => { info!(pid, "TerminateProcess executed successfully"); DebuggerResponse::Ack }
                    Err(e) => { error!(pid, error = %e, "TerminateProcess failed"); DebuggerResponse::Error { message: e.to_string() } }
                };
                if let Err(e) = framed_stream.send(&resp) { error!(?e, "Failed to write response to socket"); break; }
                continue;
            }
            #[cfg(not(windows))]
            {
                let resp = DebuggerResponse::Error { message: "TerminateProcess not supported on this platform".to_string() };
                if let Err(e) = framed_stream.send(&resp) { error!(?e, "Failed to write response to socket"); break; }
                continue;
            }
        }

        // Handle Continue without holding the platform lock across the blocking wait
        if let DebuggerRequest::Continue { pid, tid } = req {
            #[cfg(windows)]
            {
                // 1) Continue without lock
                match crate::windows_platform::debug_events::continue_only(pid, tid) {
                    Ok(()) => {}
                    Err(e) => {
                        let resp = DebuggerResponse::Error { message: e.to_string() };
                        if let Err(e) = framed_stream.send(&resp) { error!(?e, "Failed to write response to socket"); break; }
                        continue;
                    }
                }

                // 2) Wait for next debug event without lock
                let debug_event = match crate::windows_platform::debug_events::wait_for_debug_event_blocking() {
                    Ok(ev) => ev,
                    Err(e) => {
                        let resp = DebuggerResponse::Error { message: e.to_string() };
                        if let Err(e) = framed_stream.send(&resp) { error!(?e, "Failed to write response to socket"); break; }
                        continue;
                    }
                };

                // 3) Reacquire lock only to handle the event and mutate state
                let mut platform_guard = platform.lock().unwrap();
                let resp = match crate::windows_platform::debug_events::handle_debug_event(&mut *platform_guard, &debug_event) {
                    Ok(Some(event)) => DebuggerResponse::Event { event },
                    Ok(None) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                };
                if let Err(e) = framed_stream.send(&resp) { error!(?e, "Failed to write response to socket"); break; }
                continue;
            }
        }

        let resp = {
            let mut platform = platform.lock().unwrap();
            match req {
                DebuggerRequest::Attach { pid } => {
                    match platform.attach(pid) {
                        Ok(Some(event)) => DebuggerResponse::Event { event },
                        Ok(None) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::Detach { pid } => {
                    match platform.detach(pid) {
                        Ok(_) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::Continue { pid, tid } => {
                    match platform.continue_exec(pid, tid) {
                        Ok(Some(event)) => DebuggerResponse::Event { event },
                        Ok(None) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::SetBreakpoint { pid, addr, tid } => {
                    match platform.set_breakpoint(pid, addr, tid) {
                        Ok(_) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::SetSingleShotBreakpoint { pid, addr } => {
                    match platform.set_single_shot_breakpoint(pid, addr) {
                        Ok(_) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::RemoveBreakpoint { pid, addr } => {
                    match platform.remove_breakpoint(pid, addr) {
                        Ok(_) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::Launch { command } => {
                    match platform.launch(&command) {
                        Ok(Some(event)) => DebuggerResponse::Event { event },
                        Ok(None) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ReadMemory { pid, address, size } => {
                    match platform.read_memory(pid, address, size) {
                        Ok(data) => DebuggerResponse::MemoryData { data },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::WriteMemory { pid, address, data } => {
                    match platform.write_memory(pid, address, &data) {
                        Ok(_) => DebuggerResponse::WriteAck,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ReadWideString { pid, address, max_len } => {
                    match platform.read_wide_string(pid, address, max_len) {
                        Ok(data) => DebuggerResponse::WideStringData { data },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::GetThreadContext { pid, tid } => {
                    match platform.get_thread_context(pid, tid) {
                        Ok(context) => DebuggerResponse::ThreadContext { context },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::GetFunctionArguments { pid, tid, count } => {
                    match platform.get_function_arguments(pid, tid, count) {
                        Ok(arguments) => DebuggerResponse::FunctionArguments { arguments },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::SetThreadContext { pid, tid, context } => {
                    match platform.set_thread_context(pid, tid, context) {
                        Ok(_) => DebuggerResponse::SetContextAck,
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ListModules { pid } => {
                    match platform.list_modules(pid) {
                        Ok(modules) => DebuggerResponse::ModuleList { modules },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ListThreads { pid } => {
                    match platform.list_threads(pid) {
                        Ok(threads) => DebuggerResponse::ThreadList { threads },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ListProcesses => {
                    match platform.list_processes() {
                        Ok(processes) => DebuggerResponse::ProcessList { processes },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::FindSymbol { symbol_name, max_results } => {
                    match platform.find_symbol(&symbol_name, max_results) {
                        Ok(symbols) => DebuggerResponse::ResolvedSymbolList { symbols },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ListSymbols { module_path } => {
                    match platform.list_symbols(&module_path) {
                        Ok(symbols) => DebuggerResponse::SymbolList { symbols },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ResolveRvaToSymbol { module_path, rva } => {
                    match platform.resolve_rva_to_symbol(&module_path, rva) {
                        Ok(symbol) => DebuggerResponse::Symbol { symbol },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::ResolveAddressToSymbol { pid, address } => {
                    match platform.resolve_address_to_symbol(pid, address) {
                        Ok(Some((module_path, symbol, offset))) => DebuggerResponse::AddressSymbol { 
                            module_path: Some(module_path), 
                            symbol: Some(symbol), 
                            offset: Some(offset) 
                        },
                        Ok(None) => DebuggerResponse::AddressSymbol { 
                            module_path: None, 
                            symbol: None, 
                            offset: None 
                        },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::DisassembleMemory { pid, address, count, arch } => {
                    match platform.disassemble_memory(pid, address, count, arch) {
                        Ok(instructions) => DebuggerResponse::Instructions { instructions },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::GetCallStack { pid, tid } => {
                    match platform.get_call_stack(pid, tid) {
                        Ok(frames) => DebuggerResponse::CallStack { frames },
                        Err(e) => DebuggerResponse::Error { message: e.to_string() },
                    }
                }
                DebuggerRequest::TerminateProcess { pid } => { let _ = pid; unreachable!() }
                DebuggerRequest::Step { pid, tid, kind } => {
                    // Set up stepping state; if it fails, translate to an error-like event so client can surface it without panic
                    match platform.step(pid, tid, kind) {
                        Ok(_) => DebuggerResponse::Ack,
                        Err(e) => DebuggerResponse::Event { event: crate::protocol::DebugEvent::StepFailed {
                            pid,
                            tid,
                            kind,
                            message: e.to_string(),
                        }},
                    }
                }
            }
        };
        debug!(resp = %match &resp {
            DebuggerResponse::Event { event } => event.to_string(),
            DebuggerResponse::ThreadContext { context } => {
                format!("ThreadContext {{ pc: 0x{:016x} }}", context.get_pc())
            },
            DebuggerResponse::ModuleList { modules } => format!("ModuleList {{ modules: [..{} modules] }}", modules.len()),
            DebuggerResponse::ThreadList { threads } => format!("ThreadList {{ threads: [..{} threads] }}", threads.len()),
            DebuggerResponse::ProcessList { processes } => format!("ProcessList {{ processes: [..{} processes] }}", processes.len()),
            DebuggerResponse::Instructions { instructions } => {
                format!(
                    "Instructions {{ instructions: [..{} instructions] }}",
                    instructions.len()
                )
            },
            DebuggerResponse::WideStringData { data } => format!("WideStringData {{ data: \"{}\" }}", data),
            DebuggerResponse::SymbolList { symbols } => format!("SymbolList {{ symbols: [..{} symbols] }}", symbols.len()),
            DebuggerResponse::ResolvedSymbolList { symbols } => format!("ResolvedSymbolList {{ symbols: [..{} symbols] }}", symbols.len()),
            DebuggerResponse::CallStack { frames } => format!(
                "CallStack {{ frames: [..{} frames] }}",
                frames.len()
            ),
            _ => format!("{:?}", resp),
        }, "Sending response");
        if let Err(e) = framed_stream.send(&resp) {
            error!(?e, "Failed to write response to socket");
            break;
        }
    }
}

pub async fn run_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9000").await?;
    info!("Server listening on 127.0.0.1:9000");
    
    // Create a single shared platform instance
    let shared_platform = Arc::new(Mutex::new(PlatformImpl::new()));
    
    loop {
        let (socket, addr) = listener.accept().await?;
        info!(%addr, "Accepted connection");
        let std_stream = socket.into_std()?;
        std_stream.set_nonblocking(false)?;
        
        // Clone the Arc for the new thread
        let platform = Arc::clone(&shared_platform);
        std::thread::spawn(move || {
            handle_connection(std_stream, platform);
        });
    }
}
