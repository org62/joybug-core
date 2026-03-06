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
    pub enum HardwareBreakpointType {
        Execute,
        Write,
        ReadWrite,
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum HardwareBreakpointSize {
        Byte1,
        Byte2,
        Byte4,
        Byte8,
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
    pub struct X64RegisterSnapshot {
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

    /// Register snapshot for ARM64 - captures all general-purpose registers
    #[derive(Debug, Serialize, Deserialize, Clone, Default)]
    pub struct Arm64RegisterSnapshot {
        pub x: [u64; 29],  // X0-X28
        pub fp: u64,       // X29 (frame pointer)
        pub lr: u64,       // X30 (link register)
        pub sp: u64,
        pub pc: u64,
        pub cpsr: u64,
    }

    /// Architecture-aware register snapshot
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum RegisterSnapshot {
        X64(X64RegisterSnapshot),
        Arm64(Arm64RegisterSnapshot),
    }

    impl Default for RegisterSnapshot {
        fn default() -> Self {
            #[cfg(target_arch = "x86_64")]
            { RegisterSnapshot::X64(X64RegisterSnapshot::default()) }
            #[cfg(target_arch = "aarch64")]
            { RegisterSnapshot::Arm64(Arm64RegisterSnapshot::default()) }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            { RegisterSnapshot::X64(X64RegisterSnapshot::default()) }
        }
    }

    impl RegisterSnapshot {
        /// Create from Windows CONTEXT (x64)
        #[cfg(all(windows, target_arch = "x86_64"))]
        pub fn from_context(ctx: &super::CONTEXT) -> Self {
            RegisterSnapshot::X64(X64RegisterSnapshot {
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
            })
        }

        /// Create from Windows CONTEXT (ARM64)
        #[cfg(all(windows, target_arch = "aarch64"))]
        pub fn from_context(ctx: &super::CONTEXT) -> Self {
            unsafe {
                let x_regs = ctx.Anonymous.X;
                RegisterSnapshot::Arm64(Arm64RegisterSnapshot {
                    x: [
                        x_regs[0], x_regs[1], x_regs[2], x_regs[3], x_regs[4],
                        x_regs[5], x_regs[6], x_regs[7], x_regs[8], x_regs[9],
                        x_regs[10], x_regs[11], x_regs[12], x_regs[13], x_regs[14],
                        x_regs[15], x_regs[16], x_regs[17], x_regs[18], x_regs[19],
                        x_regs[20], x_regs[21], x_regs[22], x_regs[23], x_regs[24],
                        x_regs[25], x_regs[26], x_regs[27], x_regs[28],
                    ],
                    fp: ctx.Anonymous.Anonymous.Fp,
                    lr: ctx.Anonymous.Anonymous.Lr,
                    sp: ctx.Sp,
                    pc: ctx.Pc,
                    cpsr: ctx.Cpsr as u64,
                })
            }
        }

        /// Get program counter (RIP on x64, PC on ARM64)
        pub fn pc(&self) -> u64 {
            match self {
                RegisterSnapshot::X64(snap) => snap.rip,
                RegisterSnapshot::Arm64(snap) => snap.pc,
            }
        }

        /// Get stack pointer (RSP on x64, SP on ARM64)
        pub fn sp(&self) -> u64 {
            match self {
                RegisterSnapshot::X64(snap) => snap.rsp,
                RegisterSnapshot::Arm64(snap) => snap.sp,
            }
        }

        /// Get frame pointer (RBP on x64, FP/X29 on ARM64)
        pub fn fp(&self) -> u64 {
            match self {
                RegisterSnapshot::X64(snap) => snap.rbp,
                RegisterSnapshot::Arm64(snap) => snap.fp,
            }
        }

        /// Get flags register (RFLAGS on x64, CPSR on ARM64)
        pub fn flags(&self) -> u64 {
            match self {
                RegisterSnapshot::X64(snap) => snap.rflags,
                RegisterSnapshot::Arm64(snap) => snap.cpsr,
            }
        }

        /// Check if this is an x64 snapshot
        pub fn is_x64(&self) -> bool {
            matches!(self, RegisterSnapshot::X64(_))
        }

        /// Check if this is an ARM64 snapshot
        pub fn is_arm64(&self) -> bool {
            matches!(self, RegisterSnapshot::Arm64(_))
        }

        /// Get x64 snapshot if this is x64, None otherwise
        pub fn as_x64(&self) -> Option<&X64RegisterSnapshot> {
            match self {
                RegisterSnapshot::X64(snap) => Some(snap),
                _ => None,
            }
        }

        /// Get ARM64 snapshot if this is ARM64, None otherwise
        pub fn as_arm64(&self) -> Option<&Arm64RegisterSnapshot> {
            match self {
                RegisterSnapshot::Arm64(snap) => Some(snap),
                _ => None,
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

    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum ScanValueType {
        U8, U16, U32, U64, F32, F64,
    }

    impl ScanValueType {
        pub fn size(&self) -> usize {
            match self {
                ScanValueType::U8 => 1,
                ScanValueType::U16 => 2,
                ScanValueType::U32 | ScanValueType::F32 => 4,
                ScanValueType::U64 | ScanValueType::F64 => 8,
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum ScanCompareType {
        ExactValue,
        UnknownInitialValue,
        BiggerThan,
        SmallerThan,
        ValueBetween,
        IncreasedValue,
        DecreasedValue,
        IncreasedValueBy,
        DecreasedValueBy,
        Changed,
        Unchanged,
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Copy)]
    pub enum ScanValue {
        U8(u8),
        U16(u16),
        U32(u32),
        U64(u64),
        F32(f32),
        F64(f64),
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
            #[serde(default)]
            pass_exception: bool,
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
        SetHardwareBreakpoint {
            pid: u32,
            addr: u64,
            bp_type: HardwareBreakpointType,
            size: HardwareBreakpointSize,
        },
        RemoveHardwareBreakpoint {
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
            /// Memory addresses to read from emulator state after execution.
            /// Each entry is (address, size). Results returned in memory_snapshots.
            #[serde(default)]
            memory_reads: Vec<(u64, usize)>,
        },
        /// Trace instructions using trap flag, capturing register state at each step
        /// Returns TenetTrace with delta-encoded register/memory state
        TraceInstructions {
            pid: u32,
            tid: u32,
            exit_condition: TraceExitCondition,
            max_instructions: usize,
        },
        SearchMemory {
            pid: u32,
            pattern: Vec<u8>,
            max_results: usize,
        },
        ScanMemoryStart {
            pid: u32,
            value_type: ScanValueType,
            compare_type: ScanCompareType,
            value: Option<ScanValue>,
            value2: Option<ScanValue>,
            alignment: Option<usize>,
            float_tolerance: Option<f64>,
            /// If true (default), only scan writable memory regions.
            #[serde(default)]
            writable_only: Option<bool>,
        },
        ScanMemoryNext {
            scan_id: u64,
            compare_type: ScanCompareType,
            value: Option<ScanValue>,
            value2: Option<ScanValue>,
        },
        ScanMemoryGetResults {
            scan_id: u64,
            offset: u64,
            count: u64,
        },
        ScanMemoryReset {
            scan_id: u64,
        },
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub enum DebuggerResponse {
        Ack,
        Error { message: String },
        HardwareBreakpointSet { dr_index: u8 },
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
            /// Detailed timing breakdown
            stats_text: String,
            /// Memory snapshots read from emulator state after execution.
            /// Each entry is (address, data).
            #[serde(default)]
            memory_snapshots: Vec<(u64, Vec<u8>)>,
        },
        MemorySearchResult {
            addresses: Vec<u64>,
            capped: bool,
        },
        ScanMemoryResult {
            scan_id: u64,
            match_count: u64,
            scan_time_us: u64,
        },
        ScanMemoryResults {
            addresses: Vec<u64>,
            values: Vec<ScanValue>,
            total_count: u64,
        },
        /// Tenet format trace result (for TraceInstructions and EmulateInstructions with InstructionTrace mode)
        TenetTrace {
            trace_text: String,
            stop_reason: String,
            trace_time_us: u64,
            /// Detailed timing breakdown
            stats_text: String,
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
        HardwareBreakpoint {
            pid: u32,
            tid: u32,
            address: u64,
            dr_index: u8,
            bp_type: HardwareBreakpointType,
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
                DebugEvent::HardwareBreakpoint { pid, .. } => *pid,
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
                DebugEvent::HardwareBreakpoint { tid, .. } => *tid,
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

        pub fn get_sp(&self) -> u64 {
            #[cfg(target_arch = "x86_64")]
            {
                match self {
                    ThreadContext::Win32RawContext(ctx) => ctx.Rsp,
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                match self {
                    ThreadContext::Win32RawContext(ctx) => ctx.Sp,
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
