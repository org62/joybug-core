pub use serde::{Serialize, Deserialize};

pub use self::request_response::*;

mod request_response {
    use super::*;
    use std::fmt;

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", content = "data")]
    pub enum DebuggerRequest {
        Attach { pid: u32 },
        Continue { pid: u32, tid: u32 },
        SetBreakpoint { addr: u64 },
        Launch { command: String },
        ReadMemory { pid: u32, address: u64, size: usize },
        WriteMemory { pid: u32, address: u64, data: Vec<u8> },
        GetThreadContext { pid: u32, tid: u32 },
        SetThreadContext { pid: u32, tid: u32, context: ThreadContext },
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
        ThreadContext { context: ThreadContext },
        SetContextAck,
        // ... add more as needed
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "event_type", content = "data")]
    pub enum DebugEvent {
        //ProcessStarted { pid: u32 },
        ProcessExited { pid: u32, exit_code: u32 },
        Output { pid: u32, tid: u32, output: String },
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

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "arch", content = "context")]
    pub enum ThreadContext {
        X64 { regs: X64Context },
        Arm64 { regs: Arm64Context },
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct X64Context {
        pub rax: u64,
        pub rbx: u64,
        pub rcx: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub rsp: u64,
        pub rbp: u64,
        pub r8: u64,
        pub r9: u64,
        pub r10: u64,
        pub r11: u64,
        pub r12: u64,
        pub r13: u64,
        pub r14: u64,
        pub r15: u64,
        pub rip: u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Arm64Context {
        pub x: [u64; 31], // x0-x30
        pub sp: u64,
        pub pc: u64,
        pub pstate: u64,
    }

    impl fmt::Display for DebugEvent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                DebugEvent::ProcessExited { pid, exit_code } => write!(f, "ProcessExited {{ pid: {}, exit_code: {} }}", pid, exit_code),
                DebugEvent::Output { pid, tid, output } => write!(f, "Output {{ pid: {}, tid: {}, output: {} }}", pid, tid, output),
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

    impl fmt::Display for ThreadContext {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ThreadContext::X64 { regs } => write!(f, "X64 {{ {} }}", regs),
                ThreadContext::Arm64 { regs } => write!(f, "Arm64 {{ {} }}", regs),
            }
        }
    }

    impl fmt::Display for X64Context {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f,
                "rax=0x{:016X} rbx=0x{:016X} rcx=0x{:016X} rdx=0x{:016X} rsi=0x{:016X} rdi=0x{:016X} \
                rsp=0x{:016X} rbp=0x{:016X} r8=0x{:016X} r9=0x{:016X} r10=0x{:016X} r11=0x{:016X} \
                r12=0x{:016X} r13=0x{:016X} r14=0x{:016X} r15=0x{:016X} rip=0x{:016X}",
                self.rax, self.rbx, self.rcx, self.rdx, self.rsi, self.rdi,
                self.rsp, self.rbp, self.r8, self.r9, self.r10, self.r11,
                self.r12, self.r13, self.r14, self.r15, self.rip
            )
        }
    }

    impl fmt::Display for Arm64Context {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "x=[")?;
            for (i, reg) in self.x.iter().enumerate() {
                if i > 0 { write!(f, ", ")?; }
                write!(f, "x{}=0x{:016X}", i, reg)?;
            }
            write!(f, "] sp=0x{:016X} pc=0x{:016X} pstate=0x{:016X}", self.sp, self.pc, self.pstate)
        }
    }
}
