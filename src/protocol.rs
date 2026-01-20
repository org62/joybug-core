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

    /// Memory access type for tracing
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum MemoryAccessType {
        Read,
        Write,
        ReadWrite,
    }

    /// Memory access record for tracing
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct MemoryAccess {
        pub access_type: MemoryAccessType,
        pub address: u64,
        pub data: Vec<u8>,
    }

    /// Register snapshot for x64 - captures all general-purpose registers
    #[derive(Debug, Serialize, Deserialize, Clone, Default)]
    pub struct RegisterSnapshot {
        pub rax: u64,
        pub rbx: u64,
        pub rcx: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub rbp: u64,
        pub rsp: u64,
        pub r8: u64,
        pub r9: u64,
        pub r10: u64,
        pub r11: u64,
        pub r12: u64,
        pub r13: u64,
        pub r14: u64,
        pub r15: u64,
        pub rip: u64,
        pub rflags: u64,
    }

    impl RegisterSnapshot {
        /// Create from Windows CONTEXT (x64)
        #[cfg(all(windows, target_arch = "x86_64"))]
        pub fn from_context(ctx: &super::CONTEXT) -> Self {
            Self {
                rax: ctx.Rax,
                rbx: ctx.Rbx,
                rcx: ctx.Rcx,
                rdx: ctx.Rdx,
                rsi: ctx.Rsi,
                rdi: ctx.Rdi,
                rbp: ctx.Rbp,
                rsp: ctx.Rsp,
                r8: ctx.R8,
                r9: ctx.R9,
                r10: ctx.R10,
                r11: ctx.R11,
                r12: ctx.R12,
                r13: ctx.R13,
                r14: ctx.R14,
                r15: ctx.R15,
                rip: ctx.Rip,
                rflags: ctx.EFlags as u64,
            }
        }
    }

    /// Instruction trace entry - address, size, register state, and memory accesses
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TraceEntry {
        pub address: u64,
        pub size: usize,
        pub registers: RegisterSnapshot,
        /// Memory accesses for this instruction (optional for backward compatibility)
        #[serde(default)]
        pub memory_accesses: Vec<MemoryAccess>,
    }

    /// Exit condition for instruction tracing
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum TraceExitCondition {
        /// Stop when execution reaches this address
        ReachAddress(u64),
        /// Stop after executing this many instructions
        InstructionLimit(usize),
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum StepAction {
        Continue(StepKind),
        Stop,
    }

    /// Emulation mode determines which hooks are installed during emulation
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
    pub enum EmulationMode {
        /// Run N instructions with no per-instruction hooks (fastest)
        #[default]
        Basic,
        /// Record every instruction (address, size) - CODE hook overhead
        InstructionTrace,
        /// Collect basic block addresses - efficient BLOCK hook
        BasicBlock,
        /// Stop when execution moves to different module
        ModuleTransition,
        /// Stop on first syscall
        Syscall,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
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
        BreakInto {
            pid: u32,
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
        TerminateProcess {
            pid: u32,
        },
        GetModuleExtraInfo {
            pid: u32,
            module_base: u64,
        },
        QueryMemoryRegion {
            pid: u32,
            address: u64,
        },
        EnumerateMemoryRegions {
            pid: u32,
        },
        Dereference {
            pid: u32,
            address: u64,
            count: usize,
            reference_base: Option<u64>,
        },
        /// Disassemble a function with bounds detection using exception directory
        DisassembleFunction {
            pid: u32,
            address: u64,
            max_instructions: usize,
            arch: crate::interfaces::Architecture,
        },
        // Emulator requests (one-shot: create, emulate, destroy in single call)
        /// Emulate N instructions from current debugger state
        EmulateInstructions {
            pid: u32,
            tid: u32,
            max_instructions: usize,
            #[serde(default)]
            mode: EmulationMode,
            /// Optional exit condition (stop at address)
            #[serde(default)]
            exit_condition: Option<TraceExitCondition>,
        },
        /// Trace instructions using trap flag, capturing register state at each step
        /// Returns TenetTrace with delta-encoded register/memory state
        TraceInstructions {
            pid: u32,
            tid: u32,
            exit_condition: TraceExitCondition,
            max_instructions: usize,
        },
    }

    #[derive(Serialize, Deserialize, Clone)]
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
        /// Function disassembly with bounds from exception directory
        FunctionDisassembly {
            instructions: Vec<crate::interfaces::Instruction>,
            function_start: Option<u64>,
            function_end: Option<u64>,
            function_name: Option<String>,
        },
        // Call stack responses
        CallStack { frames: Vec<crate::interfaces::CallFrame> },
        // Argument responses
        FunctionArguments { arguments: Vec<u64> },
        // String responses
        WideStringData { data: String },
        ModuleExtraInfo { info: crate::pe_types::ModuleExtraInfo },
        MemoryRegionInfo { info: MemoryRegionInfo },
        MemoryRegionList { regions: Vec<MemoryRegionInfo> },
        DereferenceResult { entries: Vec<DereferenceEntry> },
        // Emulator responses (for non-trace modes: Basic, BasicBlock, ModuleTransition, Syscall)
        EmulationResult {
            final_pc: u64,
            instructions_executed: usize,
            stop_reason: String,
            /// Time taken for emulation in microseconds
            emulation_time_us: u64,
            /// Number of pages loaded during emulation
            pages_loaded: usize,
            basic_blocks: Vec<u64>,
        },
        /// Tenet format trace result (for TraceInstructions and EmulateInstructions with InstructionTrace mode)
        TenetTrace {
            trace_text: String,
            stop_reason: String,
            trace_time_us: u64,
        },
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
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

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct MemoryRegionInfo {
        pub base_address: u64,
        pub allocation_base: u64,
        pub allocation_protect: u32,
        pub region_size: u64,
        pub state: u32,          // MEM_COMMIT=0x1000, MEM_RESERVE=0x2000, MEM_FREE=0x10000
        pub protect: u32,        // PAGE_* flags
        pub region_type: u32,    // MEM_PRIVATE=0x20000, MEM_MAPPED=0x40000, MEM_IMAGE=0x1000000
    }

    /// Entry for a single address in a dereference chain
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct DereferenceEntry {
        /// Memory address being examined
        pub address: u64,
        /// Offset from reference_base
        pub offset: i64,
        /// Chain of dereferenced values
        pub chain: Vec<DereferenceValue>,
    }

    /// A single value in the dereference chain
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum DereferenceValue {
        /// Valid pointer to next address (address, optional symbol)
        Pointer(u64, Option<String>),
        /// Non-pointer value (cannot be dereferenced)
        Value(u64),
        /// Points to readable string
        String(String),
        /// Points to executable code (mnemonic + operands, optional symbol)
        Instruction(String, Option<String>),
        /// Pointer loop back to earlier address in chain
        LoopDetected(u64),
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
