pub use crate::protocol::{DebuggerRequest, DebuggerResponse};
pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub use tokio::net::TcpStream;

pub async fn send_request(stream: &mut TcpStream, req: &DebuggerRequest) -> anyhow::Result<()> {
    let data = serde_json::to_vec(req)?;
    stream.write_all(&data).await?;
    Ok(())
}

pub async fn receive_response(stream: &mut TcpStream) -> anyhow::Result<DebuggerResponse> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let resp = serde_json::from_slice(&buf[..n])?;
    Ok(resp)
} 