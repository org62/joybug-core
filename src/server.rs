#![allow(unused_imports, dead_code)]
use crate::protocol::{DebuggerRequest, DebuggerResponse};
use crate::interfaces::{PlatformAPI, PlatformError};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tracing::{info, error, debug};
use std::io::{Read, Write};
use std::sync::Mutex;

#[cfg(windows)]
type PlatformImpl = crate::windows_platform::WindowsPlatform;
#[cfg(not(windows))]
struct DummyPlatform;
#[cfg(not(windows))]
#[async_trait::async_trait]
impl PlatformAPI for DummyPlatform {
    async fn attach(&mut self, _pid: u32) -> Result<Option<crate::protocol::DebugEvent>, PlatformError> { Ok(None) }
    async fn continue_exec(&mut self) -> Result<(), PlatformError> { Ok(()) }
    async fn set_breakpoint(&mut self, _addr: u64) -> Result<(), PlatformError> { Ok(()) }
    async fn launch(&mut self, _command: &str) -> Result<(), PlatformError> { Ok(()) }
    async fn list_processes(&self) -> Result<Vec<crate::protocol::ProcessInfo>, PlatformError> { Ok(vec![]) }
}

fn handle_connection(mut stream: std::net::TcpStream) {
    let mut buf = [0u8; 4096];
    let mut platform = PlatformImpl::new();
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => {
                debug!("Connection closed");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                error!(?e, "Failed to read from socket");
                break;
            }
        };
        let req: Result<DebuggerRequest, _> = serde_json::from_slice(&buf[0..n]);
        debug!(req = %match &req {
            Ok(DebuggerRequest::ReadMemory { pid, address, size }) => format!("ReadMemory {{ pid: {}, address: 0x{:X}, size: {} }}", pid, address, size),
            Ok(DebuggerRequest::WriteMemory { pid, address, data }) => format!("WriteMemory {{ pid: {}, address: 0x{:X}, data: [..{} bytes] }}", pid, address, data.len()),
            Ok(DebuggerRequest::ListModules { pid }) => format!("ListModules {{ pid: {} }}", pid),
            Ok(DebuggerRequest::ListProcesses) => "ListProcesses".to_string(),
            _ => format!("{:?}", req),
        }, "Received request");
        let resp = match req {
            Ok(DebuggerRequest::Attach { pid }) => {
                match platform.attach(pid) {
                    Ok(Some(event)) => DebuggerResponse::Event { event },
                    Ok(None) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::Continue { pid, tid }) => {
                match platform.continue_exec(pid, tid) {
                    Ok(Some(event)) => DebuggerResponse::Event { event },
                    Ok(None) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::SetBreakpoint { addr }) => {
                match platform.set_breakpoint(addr) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::Launch { command }) => {
                match platform.launch(&command) {
                    Ok(Some(event)) => DebuggerResponse::Event { event },
                    Ok(None) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::ReadMemory { pid, address, size }) => {
                match platform.read_memory(pid, address, size) {
                    Ok(data) => DebuggerResponse::MemoryData { data },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::WriteMemory { pid, address, data }) => {
                match platform.write_memory(pid, address, &data) {
                    Ok(_) => DebuggerResponse::WriteAck,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::GetThreadContext { pid, tid }) => {
                match platform.get_thread_context(pid, tid) {
                    Ok(context) => DebuggerResponse::ThreadContext { context },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::SetThreadContext { pid, tid, context }) => {
                match platform.set_thread_context(pid, tid, context) {
                    Ok(_) => DebuggerResponse::SetContextAck,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::ListModules { pid }) => {
                match platform.list_modules(pid) {
                    Ok(modules) => DebuggerResponse::ModuleList { modules },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::ListThreads { pid }) => {
                match platform.list_threads(pid) {
                    Ok(threads) => DebuggerResponse::ThreadList { threads },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::ListProcesses) => {
                match platform.list_processes() {
                    Ok(processes) => DebuggerResponse::ProcessList { processes },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::FindSymbol { module_path, symbol_name }) => {
                match platform.find_symbol(&module_path, &symbol_name) {
                    Ok(symbol) => DebuggerResponse::Symbol { symbol },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::ListSymbols { module_path }) => {
                match platform.list_symbols(&module_path) {
                    Ok(symbols) => DebuggerResponse::SymbolList { symbols },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::ResolveRvaToSymbol { module_path, rva }) => {
                match platform.resolve_rva_to_symbol(&module_path, rva) {
                    Ok(symbol) => DebuggerResponse::Symbol { symbol },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            Ok(DebuggerRequest::ResolveAddressToSymbol { pid, address }) => {
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
            Err(e) => DebuggerResponse::Error { message: format!("Invalid request: {}", e) },
        };
        debug!(resp = %match &resp {
            DebuggerResponse::Event { event } => event.to_string(),
            DebuggerResponse::ThreadContext { context } => context.to_string(),
            DebuggerResponse::ModuleList { modules } => format!("ModuleList {{ modules: [..{} modules] }}", modules.len()),
            DebuggerResponse::ThreadList { threads } => format!("ThreadList {{ threads: [..{} threads] }}", threads.len()),
            DebuggerResponse::ProcessList { processes } => format!("ProcessList {{ processes: [..{} processes] }}", processes.len()),
            _ => format!("{:?}", resp),
        }, "Sending response");
        let resp_json = serde_json::to_vec(&resp).unwrap();
        if let Err(e) = stream.write_all(&resp_json) {
            error!(?e, "Failed to write to socket");
            break;
        }
    }
}

pub async fn run_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9000").await?;
    info!("Server listening on 127.0.0.1:9000");
    loop {
        let (socket, addr) = listener.accept().await?;
        info!(%addr, "Accepted connection");
        let std_stream = socket.into_std()?;
        std_stream.set_nonblocking(false)?;
        std::thread::spawn(move || {
            handle_connection(std_stream);
        });
    }
}
