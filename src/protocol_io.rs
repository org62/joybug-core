pub use crate::protocol::{DebuggerRequest, DebuggerResponse, DebugEvent};
use std::io::{Read, Write};
pub use std::net::TcpStream;

pub fn send_request(stream: &mut TcpStream, req: &DebuggerRequest) -> anyhow::Result<()> {
    let data = serde_json::to_vec(req)?;
    stream.write_all(&data)?;
    Ok(())
}

pub fn receive_response(stream: &mut TcpStream) -> anyhow::Result<DebuggerResponse> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let resp = serde_json::from_slice(&buf[..n])?;
    Ok(resp)
}

pub struct DebugClient {
    pub(crate) stream: TcpStream,
}

impl DebugClient {
    pub fn connect(addr: Option<&str>) -> anyhow::Result<Self> {
        let addr = addr.unwrap_or("127.0.0.1:9000");
        let stream = TcpStream::connect(addr)?;
        Ok(Self { stream })
    }

    pub fn launch<S, F>(
        &mut self,
        command: String,
        state: &mut S,
        mut handler: F,
    ) -> anyhow::Result<()> 
    where
        F: for<'a> FnMut(&'a mut Self, &mut S, DebuggerResponse) -> bool,
    {
        let launch = DebuggerRequest::Launch { command };
        send_request(&mut self.stream, &launch)?;

        loop {
            let resp = receive_response(&mut self.stream)?;
            let should_continue = handler(self, state, resp.clone());
            if let DebuggerResponse::Event { event } = &resp {
                match event {
                    DebugEvent::ProcessExited { .. } => break,
                    DebugEvent::ProcessCreated { pid, tid, .. }
                    | DebugEvent::DllLoaded { pid, tid, .. }
                    | DebugEvent::DllUnloaded { pid, tid, .. }
                    | DebugEvent::ThreadCreated { pid, tid, .. }
                    | DebugEvent::ThreadExited { pid, tid, .. }
                    | DebugEvent::Breakpoint { pid, tid, .. }
                    | DebugEvent::Output { pid, tid, .. }
                    | DebugEvent::Exception { pid, tid, .. }
                    | DebugEvent::RipEvent { pid, tid, .. } => {
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut self.stream, &cont)?;
                    }
                    DebugEvent::Unknown => {}
                }
            }
            if !should_continue {
                break;
            }
        }
        Ok(())
    }

    pub fn send_and_receive(&mut self, req: &crate::protocol::DebuggerRequest) -> anyhow::Result<crate::protocol::DebuggerResponse> {
        send_request(&mut self.stream, req)?;
        receive_response(&mut self.stream)
    }
} 