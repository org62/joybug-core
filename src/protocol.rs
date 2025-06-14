pub use serde::{Serialize, Deserialize};

pub use self::request_response::*;

mod request_response {
    use super::*;
    use std::fmt;

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", content = "data")]
    pub enum DebuggerRequest {
        Attach { pid: u32 },
        Continue,
        SetBreakpoint { addr: u64 },
        Launch { command: String },
        ReadMemory { pid: u32, address: u64, size: usize },
        WriteMemory { pid: u32, address: u64, data: Vec<u8> },
        // ... add more as needed
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", content = "data")]
    pub enum DebuggerResponse {
        Ack,
        Error { message: String },
        Event { event: DebugEvent },
        MemoryData { data: Vec<u8> },
        WriteAck,
        // ... add more as needed
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "event_type", content = "data")]
    pub enum DebugEvent {
        ProcessStarted { pid: u32 },
        ProcessExited { pid: u32, exit_code: u32 },
        Output { output: String },
        Exception {
            pid: u32,
            tid: u32,
            code: u32,
            address: u64,
            first_chance: bool,
        },
        Breakpoint {
            pid: u32,
            tid: u32,
            address: u64,
        },
        ProcessCreated {
            pid: u32,
            tid: u32,
            image_file_name: Option<String>,
            base_of_image: u64,
            size_of_image: Option<u64>,
        },
        ThreadCreated {
            pid: u32,
            tid: u32,
            start_address: u64,
        },
        ThreadExited {
            pid: u32,
            tid: u32,
            exit_code: u32,
        },
        DllLoaded {
            pid: u32,
            tid: u32,
            dll_name: Option<String>,
            base_of_dll: u64,
            size_of_dll: Option<u64>,
        },
        DllUnloaded {
            pid: u32,
            tid: u32,
            base_of_dll: u64,
        },
        RipEvent {
            pid: u32,
            tid: u32,
            error: u32,
            event_type: u32,
        },
        Unknown,
    }

    impl fmt::Display for DebugEvent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                DebugEvent::ProcessStarted { pid } => write!(f, "ProcessStarted {{ pid: {} }}", pid),
                DebugEvent::ProcessExited { pid, exit_code } => write!(f, "ProcessExited {{ pid: {}, exit_code: {} }}", pid, exit_code),
                DebugEvent::Output { output } => write!(f, "Output {{ output: {} }}", output),
                DebugEvent::Exception { pid, tid, code, address, first_chance } => write!(f, "Exception {{ pid: {}, tid: {}, code: 0x{:X}, address: 0x{:X}, first_chance: {} }}", pid, tid, code, address, first_chance),
                DebugEvent::Breakpoint { pid, tid, address } => write!(f, "Breakpoint {{ pid: {}, tid: {}, address: 0x{:X} }}", pid, tid, address),
                DebugEvent::ProcessCreated { pid, tid, image_file_name, base_of_image, size_of_image } => write!(f, "ProcessCreated {{ pid: {}, tid: {}, image_file_name: {:?}, base_of_image: 0x{:X}, size_of_image: {:?} }}", pid, tid, image_file_name, base_of_image, size_of_image.as_ref().map(|v| format!("0x{:X}", v))),
                DebugEvent::ThreadCreated { pid, tid, start_address } => write!(f, "ThreadCreated {{ pid: {}, tid: {}, start_address: 0x{:X} }}", pid, tid, start_address),
                DebugEvent::ThreadExited { pid, tid, exit_code } => write!(f, "ThreadExited {{ pid: {}, tid: {}, exit_code: {} }}", pid, tid, exit_code),
                DebugEvent::DllLoaded { pid, tid, dll_name, base_of_dll, size_of_dll } => write!(f, "DllLoaded {{ pid: {}, tid: {}, dll_name: {:?}, base_of_dll: 0x{:X}, size_of_dll: {:?} }}", pid, tid, dll_name, base_of_dll, size_of_dll.as_ref().map(|v| format!("0x{:X}", v))),
                DebugEvent::DllUnloaded { pid, tid, base_of_dll } => write!(f, "DllUnloaded {{ pid: {}, tid: {}, base_of_dll: 0x{:X} }}", pid, tid, base_of_dll),
                DebugEvent::RipEvent { pid, tid, error, event_type } => write!(f, "RipEvent {{ pid: {}, tid: {}, error: 0x{:X}, event_type: 0x{:X} }}", pid, tid, error, event_type),
                DebugEvent::Unknown => write!(f, "Unknown"),
            }
        }
    }
} 