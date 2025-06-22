pub use serde::{Serialize, Deserialize};

pub use self::request_response::*;

mod request_response {
    use super::*;

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
        ListModules { pid: u32 },
        ListThreads { pid: u32 },
        ListProcesses,
        // Symbol-related requests
        FindSymbol { module_path: String, symbol_name: String },
        ListSymbols { module_path: String },
        ResolveRvaToSymbol { module_path: String, rva: u32 },
        ResolveAddressToSymbol { pid: u32, address: u64 },
        DisassembleMemory { pid: u32, address: u64, count: usize, arch: crate::interfaces::Architecture },
        // ... add more as needed
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    #[serde(tag = "type", content = "data")]
    pub enum DebuggerResponse {
        Ack,
        Error { message: String },
        Event { event: DebugEvent },
        MemoryData { data: Vec<u8> },
        WriteAck,
        ThreadContext { context: ThreadContext },
        SetContextAck,
        ModuleList { modules: Vec<ModuleInfo> },
        ThreadList { threads: Vec<ThreadInfo> },
        ProcessList { processes: Vec<ProcessInfo> },
        // Symbol-related responses
        Symbol { symbol: Option<crate::interfaces::Symbol> },
        SymbolList { symbols: Vec<crate::interfaces::Symbol> },
        AddressSymbol { module_path: Option<String>, symbol: Option<crate::interfaces::Symbol>, offset: Option<u64> },
        // Disassembly responses
        Instructions { instructions: Vec<crate::interfaces::Instruction> },
        // ... add more as needed
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
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
            parameters: Vec<u64>,
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

    impl DebugEvent {
        pub fn pid(&self) -> u32 {
            match self {
                DebugEvent::ProcessExited { pid, .. } => *pid,
                DebugEvent::Output { pid, .. } => *pid,
                DebugEvent::Exception { pid, .. } => *pid,
                DebugEvent::Breakpoint { pid, .. } => *pid,
                DebugEvent::ProcessCreated { pid, .. } => *pid,
                DebugEvent::ThreadCreated { pid, .. } => *pid,
                DebugEvent::ThreadExited { pid, .. } => *pid,
                DebugEvent::DllLoaded { pid, .. } => *pid,
                DebugEvent::DllUnloaded { pid, .. } => *pid,
                DebugEvent::RipEvent { pid, .. } => *pid,
                DebugEvent::Unknown => 0, // Or handle as an error
            }
        }

        pub fn tid(&self) -> u32 {
            match self {
                DebugEvent::Output { tid, .. } => *tid,
                DebugEvent::Exception { tid, .. } => *tid,
                DebugEvent::Breakpoint { tid, .. } => *tid,
                DebugEvent::ProcessCreated { tid, .. } => *tid,
                DebugEvent::ThreadCreated { tid, .. } => *tid,
                DebugEvent::ThreadExited { tid, .. } => *tid,
                DebugEvent::DllLoaded { tid, .. } => *tid,
                DebugEvent::DllUnloaded { tid, .. } => *tid,
                DebugEvent::RipEvent { tid, .. } => *tid,
                DebugEvent::ProcessExited { .. } => 0,
                DebugEvent::Unknown => 0,
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct ProcessInfo {
        pub pid: u32,
        pub name: String,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ModuleInfo {
        pub name: String,
        pub base: u64,
        pub size: Option<u64>,
    }



    #[derive(Clone)]
    pub enum ThreadContext {
        #[cfg(windows)]
        Win32RawContext(crate::protocol::CONTEXT),
    }

    #[cfg(windows)]
    impl serde::Serialize for ThreadContext {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                ThreadContext::Win32RawContext(ctx) => {
                    use serde::ser::SerializeStruct;
                    let mut s = serializer.serialize_struct("ThreadContext", 2)?;
                    s.serialize_field("arch", "Win32RawContext")?;
                    let bytes = crate::protocol::windows_context_serde::serialize(ctx);
                    s.serialize_field("context", &bytes)?;
                    s.end()
                }
            }
        }
    }

    #[cfg(windows)]
    impl<'de> serde::Deserialize<'de> for ThreadContext {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            struct Helper {
                arch: String,
                context: Vec<u8>,
            }
            let helper = Helper::deserialize(deserializer)?;
            if helper.arch == "Win32RawContext" {
                let ctx = crate::protocol::windows_context_serde::deserialize(&helper.context)?;
                Ok(ThreadContext::Win32RawContext(ctx))
            } else {
                Err(serde::de::Error::custom("Unknown arch variant for ThreadContext"))
            }
        }
    }





    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct ThreadInfo {
        pub tid: u32,
        pub start_address: u64,
    }
}

#[cfg(windows)]
pub use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

#[cfg(windows)]
pub mod windows_context_serde {
    use super::CONTEXT;
    pub fn serialize(ctx: &CONTEXT) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                ctx as *const CONTEXT as *const u8,
                std::mem::size_of::<CONTEXT>(),
            ).to_vec()
        }
    }
    pub fn deserialize<'de, D: serde::de::Error>(bytes: &[u8]) -> Result<CONTEXT, D> {
        if bytes.len() != std::mem::size_of::<CONTEXT>() {
            return Err(D::custom("Invalid CONTEXT size"));
        }
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut ctx as *mut CONTEXT as *mut u8,
                std::mem::size_of::<CONTEXT>(),
            );
        }
        Ok(ctx)
    }
}
