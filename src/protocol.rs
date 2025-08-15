pub use serde::{Serialize, Deserialize};

pub use self::request_response::*;

pub mod request_response {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum StepKind {
        Into,
        Over,
        Out,
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum StepAction {
        Continue(StepKind),
        Stop,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    #[serde(tag = "type", content = "data")]
    pub enum DebuggerRequest {
        ListProcesses,
        ListModules {
            pid: u32,
        },
        ListThreads {
            pid: u32,
        },
        Attach {
            pid: u32,
        },
        Detach {
            pid: u32,
        },
        Launch {
            command: String,
        },
        Continue {
            pid: u32,
            tid: u32,
        },
        SetBreakpoint {
            pid: u32,
            addr: u64,
            tid: Option<u32>,
        },
        SetSingleShotBreakpoint {
            pid: u32,
            addr: u64,
        },
        RemoveBreakpoint {
            pid: u32,
            addr: u64,
        },
        ReadMemory {
            pid: u32,
            address: u64,
            size: usize,
        },
        WriteMemory {
            pid: u32,
            address: u64,
            data: Vec<u8>,
        },
        GetThreadContext {
            pid: u32,
            tid: u32,
        },
        SetThreadContext {
            pid: u32,
            tid: u32,
            context: ThreadContext,
        },
        // Symbol-related requests
        FindSymbol {
            symbol_name: String,
            max_results: usize,
        },
        ListSymbols {
            module_path: String,
        },
        ResolveRvaToSymbol {
            module_path: String,
            rva: u32,
        },
        ResolveAddressToSymbol {
            pid: u32,
            address: u64,
        },
        DisassembleMemory {
            pid: u32,
            address: u64,
            count: usize,
            arch: crate::interfaces::Architecture,
        },
        GetCallStack {
            pid: u32,
            tid: u32,
        },
        // Step request
        Step {
            pid: u32,
            tid: u32,
            kind: StepKind,
        },
        // Get function arguments
        GetFunctionArguments {
            pid: u32,
            tid: u32,
            count: usize,
        },
        // Read wide string
        ReadWideString {
            pid: u32,
            address: u64,
            max_len: Option<usize>,
        },
    }

    #[derive(Serialize, Deserialize, Clone)]
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
        Symbol { symbol: Option<crate::interfaces::ModuleSymbol> },
        SymbolList { symbols: Vec<crate::interfaces::ModuleSymbol> },
        ResolvedSymbolList { symbols: Vec<crate::interfaces::ResolvedSymbol> },
        AddressSymbol {
            module_path: Option<String>,
            symbol: Option<crate::interfaces::ModuleSymbol>,
            offset: Option<u64>,
        },
        // Disassembly responses
        Instructions { instructions: Vec<crate::interfaces::Instruction> },
        // Call stack responses
        CallStack { frames: Vec<crate::interfaces::CallFrame> },
        // Argument responses
        FunctionArguments { arguments: Vec<u64> },
        // String responses
        WideStringData { data: String },
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
        InitialBreakpoint {
            pid: u32,
            tid: u32,
            address: u64,
        },
        SingleShotBreakpoint {
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
        StepComplete {
            pid: u32,
            tid: u32,
            kind: StepKind,
            address: u64,
        },
        StepFailed {
            pid: u32,
            tid: u32,
            kind: StepKind,
            message: String,
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
                DebugEvent::InitialBreakpoint { pid, .. } => *pid,
                DebugEvent::SingleShotBreakpoint { pid, .. } => *pid,
                DebugEvent::ProcessCreated { pid, .. } => *pid,
                DebugEvent::ThreadCreated { pid, .. } => *pid,
                DebugEvent::ThreadExited { pid, .. } => *pid,
                DebugEvent::DllLoaded { pid, .. } => *pid,
                DebugEvent::DllUnloaded { pid, .. } => *pid,
                DebugEvent::RipEvent { pid, .. } => *pid,
                DebugEvent::StepComplete { pid, .. } => *pid,
                DebugEvent::StepFailed { pid, .. } => *pid,
                DebugEvent::Unknown => 0, // Or handle as an error
            }
        }

        pub fn tid(&self) -> u32 {
            match self {
                DebugEvent::Output { tid, .. } => *tid,
                DebugEvent::Exception { tid, .. } => *tid,
                DebugEvent::Breakpoint { tid, .. } => *tid,
                DebugEvent::InitialBreakpoint { tid, .. } => *tid,
                DebugEvent::SingleShotBreakpoint { tid, .. } => *tid,
                DebugEvent::ProcessCreated { tid, .. } => *tid,
                DebugEvent::ThreadCreated { tid, .. } => *tid,
                DebugEvent::ThreadExited { tid, .. } => *tid,
                DebugEvent::DllLoaded { tid, .. } => *tid,
                DebugEvent::DllUnloaded { tid, .. } => *tid,
                DebugEvent::RipEvent { tid, .. } => *tid,
                DebugEvent::StepComplete { tid, .. } => *tid,
                DebugEvent::StepFailed { tid, .. } => *tid,
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



    pub enum ThreadContext {
        #[cfg(windows)]
        Win32RawContext(crate::protocol::CONTEXT),
    }

    // get PC from ThreadContext, on x64 it's RIP on arm64 it's PC
    impl ThreadContext {
        pub fn get_pc(&self) -> u64 {
            #[cfg(target_arch = "x86_64")]
            {
                match self {
                    ThreadContext::Win32RawContext(ctx) => ctx.Rip,
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                match self {
                    ThreadContext::Win32RawContext(ctx) => ctx.Pc,
                }
            }
        }
    }

    #[cfg(windows)]
    impl Clone for ThreadContext {
        fn clone(&self) -> Self {
            match self {
                ThreadContext::Win32RawContext(ctx) => {
                    let mut new_ctx: CONTEXT = unsafe { std::mem::zeroed() };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            ctx as *const CONTEXT as *const u8,
                            &mut new_ctx as *mut CONTEXT as *mut u8,
                            std::mem::size_of::<CONTEXT>(),
                        );
                    }
                    ThreadContext::Win32RawContext(new_ctx)
                }
            }
        }
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
