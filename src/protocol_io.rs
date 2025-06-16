pub use crate::protocol::{DebuggerRequest, DebuggerResponse, DebugEvent, ModuleInfo, ProcessInfo};
use std::io::{Read, Write};
pub use std::net::TcpStream;

pub fn send_request(stream: &mut TcpStream, req: &DebuggerRequest) -> anyhow::Result<()> {
    let data = serde_json::to_vec(req)?;
    stream.write_all(&data)?;
    Ok(())
}

pub fn receive_response(stream: &mut TcpStream) -> anyhow::Result<DebuggerResponse> {
    let mut buf = vec![0u8; 4096*1024];
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

    pub fn attach<S, F>(
        &mut self,
        pid: u32,
        state: &mut S,
        handler: F,
    ) -> anyhow::Result<()>
    where
        F: for<'a> FnMut(&'a mut Self, &mut S, DebuggerResponse) -> bool,
    {
        let req = DebuggerRequest::Attach { pid };
        let resp = self.send_and_receive(&req)?;
        match resp {
            DebuggerResponse::Event { event } => self.start_debug_loop(Some(event), state, handler),
            DebuggerResponse::Ack => self.start_debug_loop(None, state, handler),
            _ => Err(anyhow::anyhow!("Unexpected response: {:?}", resp)),
        }
    }

    pub fn start_debug_loop<S, F>(
        &mut self,
        initial_event: Option<DebugEvent>,
        state: &mut S,
        mut handler: F,
    ) -> anyhow::Result<()>
    where
        F: for<'a> FnMut(&'a mut Self, &mut S, DebuggerResponse) -> bool,
    {
        if let Some(event) = initial_event {
            if !self.handle_event(event, state, &mut handler) {
                return Ok(());
            }
        }

        loop {
            let resp = receive_response(&mut self.stream)?;
            if let DebuggerResponse::Event { event } = resp.clone() {
                if !self.handle_event(event, state, &mut handler) {
                    break;
                }
            } else {
                if !handler(self, state, resp) {
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_event<S, F>(
        &mut self,
        event: DebugEvent,
        state: &mut S,
        handler: &mut F,
    ) -> bool
    where
        F: for<'a> FnMut(&'a mut Self, &mut S, DebuggerResponse) -> bool,
    {
        let should_continue = handler(self, state, DebuggerResponse::Event { event: event.clone() });

        if !should_continue {
            return false;
        }

        if let DebuggerResponse::Event { event } = (DebuggerResponse::Event { event }) {
            match event {
                DebugEvent::ProcessExited { .. } => return false,
                DebugEvent::ProcessCreated { pid, tid, .. }
                | DebugEvent::DllLoaded { pid, tid, .. }
                | DebugEvent::DllUnloaded { pid, tid, .. }
                | DebugEvent::ThreadCreated { pid, tid, .. }
                | DebugEvent::ThreadExited { pid, tid, .. }
                | DebugEvent::Breakpoint { pid, tid, .. }
                | DebugEvent::Output { pid, tid, .. }
                | DebugEvent::Exception { pid, tid, .. }
                | DebugEvent::RipEvent { pid, tid, .. } => {
                    let cont = DebuggerRequest::Continue { pid, tid };
                    send_request(&mut self.stream, &cont).unwrap();
                }
                DebugEvent::Unknown => {}
            }
        }
        return true;
    }

    pub fn launch<S, F>(
        &mut self,
        command: String,
        state: &mut S,
        handler: F,
    ) -> anyhow::Result<()> 
    where
        F: for<'a> FnMut(&'a mut Self, &mut S, DebuggerResponse) -> bool,
    {
        let launch = DebuggerRequest::Launch { command };
        send_request(&mut self.stream, &launch)?;
        let resp = receive_response(&mut self.stream)?;
        if let DebuggerResponse::Event { event } = resp {
            self.start_debug_loop(Some(event), state, handler)
        } else {
            Err(anyhow::anyhow!("Expected event after launch, got {:?}", resp))
        }
    }

    pub fn send_and_receive(&mut self, req: &crate::protocol::DebuggerRequest) -> anyhow::Result<crate::protocol::DebuggerResponse> {
        send_request(&mut self.stream, req)?;
        receive_response(&mut self.stream)
    }
} 