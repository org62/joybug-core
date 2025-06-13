#![allow(unused_imports, dead_code)]
use crate::protocol::{DebuggerRequest, DebuggerResponse};
use crate::interfaces::{PlatformAPI, PlatformError};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

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
    println!("Server listening on 127.0.0.1:9000");
    let platform = Arc::new(tokio::sync::Mutex::new(PlatformImpl::new()));
    loop {
        let (mut socket, addr) = listener.accept().await?;
        let platform = platform.clone();
        println!("Accepted connection from {}", addr);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(n) if n == 0 => break,
                    Ok(n) => {
                        let req: Result<DebuggerRequest, _> = serde_json::from_slice(&buf[0..n]);
                        let resp = match req {
                            Ok(DebuggerRequest::Attach { pid }) => {
                                let mut plat = platform.lock().await;
                                match plat.attach(pid).await {
                                    Ok(_) => DebuggerResponse::Ack,
                                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                                }
                            }
                            Ok(DebuggerRequest::Continue) => {
                                let mut plat = platform.lock().await;
                                match plat.continue_exec().await {
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
                            Err(e) => DebuggerResponse::Error { message: format!("Invalid request: {}", e) },
                        };
                        let resp_json = serde_json::to_vec(&resp).unwrap();
                        if socket.write_all(&resp_json).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("failed to read from socket; err = {:?}", e);
                        break;
                    }
                }
            }
        });
    }
}
