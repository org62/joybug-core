#![allow(unused_imports, dead_code)]
use crate::protocol::{DebuggerRequest, DebuggerResponse};
use crate::interfaces::{PlatformAPI, PlatformError};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tracing::{info, error, debug};

#[cfg(windows)]
type PlatformImpl = crate::windows_platform::WindowsPlatform;
#[cfg(not(windows))]
struct DummyPlatform;
#[cfg(not(windows))]
#[async_trait::async_trait]
impl PlatformAPI for DummyPlatform {
    async fn attach(&mut self, _pid: u32) -> Result<(), PlatformError> { Ok(()) }
    async fn continue_exec(&mut self) -> Result<(), PlatformError> { Ok(()) }
    async fn set_breakpoint(&mut self, _addr: u64) -> Result<(), PlatformError> { Ok(()) }
    async fn launch(&mut self, _command: &str) -> Result<(), PlatformError> { Ok(()) }
}

pub async fn run_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9000").await?;
    info!("Server listening on 127.0.0.1:9000");
    let platform = Arc::new(tokio::sync::Mutex::new(PlatformImpl::new()));
    loop {
        let (mut socket, addr) = listener.accept().await?;
        let platform = platform.clone();
        info!(%addr, "Accepted connection");
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(n) if n == 0 => {
                        error!("Connection closed");
                        break;
                    }
                    Ok(n) => {
                        let req: Result<DebuggerRequest, _> = serde_json::from_slice(&buf[0..n]);
                        debug!(req = %match &req {
                            Ok(DebuggerRequest::ReadMemory { pid, address, size }) => format!("ReadMemory {{ pid: {}, address: 0x{:X}, size: {} }}", pid, address, size),
                            Ok(DebuggerRequest::WriteMemory { pid, address, data }) => format!("WriteMemory {{ pid: {}, address: 0x{:X}, data: [..{} bytes] }}", pid, address, data.len()),
                            _ => format!("{:?}", req),
                        }, "Received request");
                        let resp = match req {
                            Ok(DebuggerRequest::Attach { pid }) => {
                                let mut plat = platform.lock().await;
                                match plat.attach(pid).await {
                                    Ok(_) => DebuggerResponse::Ack,
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::Continue { pid, tid }) => {
                                let mut plat = platform.lock().await;
                                match plat.continue_exec(pid, tid).await {
                                    Ok(Some(event)) => DebuggerResponse::Event { event },
                                    Ok(None) => DebuggerResponse::Ack,
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::SetBreakpoint { addr }) => {
                                let mut plat = platform.lock().await;
                                match plat.set_breakpoint(addr).await {
                                    Ok(_) => DebuggerResponse::Ack,
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::Launch { command }) => {
                                let mut plat = platform.lock().await;
                                match plat.launch(&command).await {
                                    Ok(Some(event)) => DebuggerResponse::Event { event },
                                    Ok(None) => DebuggerResponse::Ack,
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::ReadMemory { pid, address, size }) => {
                                let mut plat = platform.lock().await;
                                match plat.read_memory(pid, address, size).await {
                                    Ok(data) => DebuggerResponse::MemoryData { data },
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::WriteMemory { pid, address, data }) => {
                                let mut plat = platform.lock().await;
                                match plat.write_memory(pid, address, &data).await {
                                    Ok(_) => DebuggerResponse::WriteAck,
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::GetThreadContext { pid, tid }) => {
                                let mut plat = platform.lock().await;
                                match plat.get_thread_context(pid, tid).await {
                                    Ok(context) => DebuggerResponse::ThreadContext { context },
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::SetThreadContext { pid, tid, context }) => {
                                let mut plat = platform.lock().await;
                                match plat.set_thread_context(pid, tid, context).await {
                                    Ok(_) => DebuggerResponse::SetContextAck,
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Err(e) => DebuggerResponse::Error { message: format!("Invalid request: {}", e) },
                        };
                        debug!(resp = %match &resp {
                            DebuggerResponse::Event { event } => event.to_string(),
                            DebuggerResponse::ThreadContext { context } => context.to_string(),
                            _ => format!("{:?}", resp),
                        }, "Sending response");
                        let resp_json = serde_json::to_vec(&resp).unwrap();
                        if socket.write_all(&resp_json).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(?e, "Failed to read from socket");
                        break;
                    }
                }
            }
        });
    }
}
