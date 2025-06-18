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

    impl std::fmt::Debug for ModuleInfo {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut ds = f.debug_struct("ModuleInfo");
            ds.field("name", &self.name);
            ds.field("base", &format_args!("0x{:X}", self.base));
            if let Some(size) = self.size {
                ds.field("size", &format_args!("0x{:X}", size));
            } else {
                ds.field("size", &self.size);
            }
            ds.finish()
        }
    }

    impl std::fmt::Display for ModuleInfo {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{} [{}] @ 0x{:X}",
                self.name,
                self.size
                    .map(|s| format!("0x{:X}", s))
                    .as_deref()
                    .unwrap_or("N/A"),
                self.base
            )
        }
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

    impl std::fmt::Debug for ThreadContext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let ThreadContext::Win32RawContext(ctx) = self;
                return write!(f,
                    "rax=0x{:016X} rbx=0x{:016X} rcx=0x{:016X} rdx=0x{:016X} rsi=0x{:016X} rdi=0x{:016X} rsp=0x{:016X} rbp=0x{:016X} r8=0x{:016X} r9=0x{:016X} r10=0x{:016X} r11=0x{:016X} r12=0x{:016X} r13=0x{:016X} r14=0x{:016X} r15=0x{:016X} rip=0x{:016X}",
                    ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi,
                    ctx.Rsp, ctx.Rbp, ctx.R8, ctx.R9, ctx.R10, ctx.R11,
                    ctx.R12, ctx.R13, ctx.R14, ctx.R15, ctx.Rip
                );
            }
        }
    }

    impl std::fmt::Display for DebugEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                DebugEvent::ProcessExited { pid, exit_code } => write!(f, "ProcessExited {{ pid: {}, exit_code: 0x{:X} }}", pid, exit_code),
                DebugEvent::Output { pid, tid, output } => write!(f, "Output {{ pid: {}, tid: {}, output: {} }}", pid, tid, output),
                DebugEvent::Exception { pid, tid, code, address, first_chance, parameters } => write!(f, "Exception {{ pid: {}, tid: {}, code: 0x{:X}, address: 0x{:X}, first_chance: {}, parameters: {:?} }}", pid, tid, code, address, first_chance, parameters),
                DebugEvent::Breakpoint { pid, tid, address } => write!(f, "Breakpoint {{ pid: {}, tid: {}, address: 0x{:X} }}", pid, tid, address),
                DebugEvent::ProcessCreated { pid, tid, image_file_name, base_of_image, size_of_image } => write!(f, "ProcessCreated {{ pid: {}, tid: {}, image_file_name: {:?}, base_of_image: 0x{:X}, size_of_image: {:?} }}", pid, tid, image_file_name, base_of_image, size_of_image.as_ref().map(|v| format!("0x{:X}", v))),
                DebugEvent::ThreadCreated { pid, tid, start_address } => write!(f, "ThreadCreated {{ pid: {}, tid: {}, start_address: 0x{:X} }}", pid, tid, start_address),
                DebugEvent::ThreadExited { pid, tid, exit_code } => write!(f, "ThreadExited {{ pid: {}, tid: {}, exit_code: 0x{:X} }}", pid, tid, exit_code),
                DebugEvent::DllLoaded { pid, tid, dll_name, base_of_dll, size_of_dll } => write!(f, "DllLoaded {{ pid: {}, tid: {}, dll_name: {:?}, base_of_dll: 0x{:X}, size_of_dll: {:?} }}", pid, tid, dll_name, base_of_dll, size_of_dll.as_ref().map(|v| format!("0x{:X}", v))),
                DebugEvent::DllUnloaded { pid, tid, base_of_dll } => write!(f, "DllUnloaded {{ pid: {}, tid: {}, base_of_dll: 0x{:X} }}", pid, tid, base_of_dll),
                DebugEvent::RipEvent { pid, tid, error, event_type } => write!(f, "RipEvent {{ pid: {}, tid: {}, error: 0x{:X}, event_type: 0x{:X} }}", pid, tid, error, event_type),
                DebugEvent::Unknown => write!(f, "Unknown"),
            }
        }
    }

    impl std::fmt::Display for ThreadContext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let ThreadContext::Win32RawContext(ctx) = self;
                return write!(f,
                    "rax=0x{:016X} rbx=0x{:016X} rcx=0x{:016X} rdx=0x{:016X} rsi=0x{:016X} rdi=0x{:016X} rsp=0x{:016X} rbp=0x{:016X} r8=0x{:016X} r9=0x{:016X} r10=0x{:016X} r11=0x{:016X} r12=0x{:016X} r13=0x{:016X} r14=0x{:016X} r15=0x{:016X} rip=0x{:016X}",
                    ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi,
                    ctx.Rsp, ctx.Rbp, ctx.R8, ctx.R9, ctx.R10, ctx.R11,
                    ctx.R12, ctx.R13, ctx.R14, ctx.R15, ctx.Rip
                );
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
