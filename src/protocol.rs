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
        /// Open a process non-invasively (OpenProcess only, no DebugActiveProcess).
        OpenProcess {
            pid: u32,
        },
        /// Release a non-invasively opened process.
        CloseProcess {
            pid: u32,
        },
        Launch {
            command: String,
            #[serde(default)]
            debug_children: bool,
            #[serde(default)]
            working_directory: Option<String>,
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
        /// Enumerate every address in `module_path` worth arming coverage on:
        /// `.pdata` RUNTIME_FUNCTION starts unioned with symbols, where symbols
        /// the PDB does not mark as functions must first pass a code-sanity
        /// check. Works with no symbols at all. See
        /// `PlatformAPI::enumerate_coverage_targets`.
        EnumerateCoverageTargets {
            pid: u32,
            module_path: String,
            /// Which sources to draw targets from; empty means all of them.
            /// Restricting this is how a caller opts out of the heuristic tier:
            /// `[Pdata]` alone is the exception directory, which involves no
            /// guessing at all. Sources that aren't asked for are never computed,
            /// so narrowing also skips the sanity sweep.
            #[serde(default)]
            sources: Vec<CoverageTargetSource>,
        },
        /// Arm code-coverage breakpoints (silent, server-side counted) at every
        /// address in `addrs`. `limit` is the hit count after which each is
        /// auto-removed (`0` = never, `1` = remove on first hit = pure coverage).
        StartCodeCoverage {
            pid: u32,
            addrs: Vec<u64>,
            limit: u64,
        },
        /// Fetch a [`CoverageHit`] (address, hit count, first-hit order, thread
        /// ids) for every coverage breakpoint hit at least once (never-hit
        /// addresses are omitted).
        GetCodeCoverage {
            pid: u32,
        },
        /// Remove all coverage breakpoints and clear the coverage map.
        StopCodeCoverage {
            pid: u32,
        },
        /// Arm a hardware watchpoint at `addr` in silent "access trace" mode: every
        /// read/write is recorded server-side (the accessing instruction pointer)
        /// and the target auto-continues instead of breaking. Reuses the DR0-DR3 /
        /// ARM64 watchpoint machinery of `SetHardwareBreakpoint`.
        StartWatchpointTrace {
            pid: u32,
            addr: u64,
            bp_type: HardwareBreakpointType,
            size: HardwareBreakpointSize,
        },
        /// Fetch a [`WatchpointAccess`] (accessing instruction pointer, hit count,
        /// first-hit order, thread ids) for every distinct instruction that has
        /// accessed the watched `addr` at least once.
        GetWatchpointAccesses {
            pid: u32,
            addr: u64,
        },
        /// Remove the watchpoint at `addr` and clear its collected accesses.
        StopWatchpointTrace {
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
        /// `SuspendThread` on one thread (counts nest); answers `Ack`.
        SuspendThread {
            pid: u32,
            tid: u32,
        },
        /// `ResumeThread` on one thread; answers `Ack`.
        ResumeThread {
            pid: u32,
            tid: u32,
        },
        /// `TerminateThread` with `exit_code`; answers `Ack`.
        TerminateThread {
            pid: u32,
            tid: u32,
            exit_code: u32,
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
        GetSymbolStatus {
            pid: u32,
        },
        LoadPdbFromPath {
            pid: u32,
            module_base: u64,
            pdb_path: String,
            #[serde(default)]
            force: bool,
        },
        RetrySymbolLoad {
            pid: u32,
            module_base: u64,
        },
        /// Unload a module's symbols and every derived server-side cache (line
        /// tables, type info, pdata, failure markers), freeing their memory. The
        /// module reports `NotRequested` afterwards; `RetrySymbolLoad` re-downloads.
        UnloadModuleSymbols {
            pid: u32,
            module_base: u64,
        },
        /// Replace the set of modules (lowercased file names, e.g. "foo.dll")
        /// whose automatic symbol download is suppressed. Suppressed modules
        /// report `Failed` instead of downloading; `RetrySymbolLoad` lifts the
        /// suppression for its module. Typically sent once at session start with
        /// the modules whose downloads failed in earlier runs.
        SetSymbolDenyList {
            modules: Vec<String>,
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
        /// Resolve many addresses to symbols in one round-trip, never waiting
        /// on in-flight symbol loads: addresses in still-loading modules come
        /// back `None` (re-request once symbol status settles). See
        /// `PlatformAPI::try_resolve_addresses_to_symbols`.
        TryResolveAddressesToSymbols {
            pid: u32,
            addresses: Vec<u64>,
        },
        /// Resolve an address to a source file/line via the module's PDB line table.
        ResolveAddressToLine {
            pid: u32,
            address: u64,
        },
        /// All line→address entries for one source file of a module. When
        /// `start_line`/`end_line` are set, only entries whose `line_start` falls
        /// in that inclusive range are returned — bounding the response for very
        /// large files (windowed source view). `None` = whole file.
        GetSourceFileLineMap {
            pid: u32,
            module_base: u64,
            file_path: String,
            #[serde(default)]
            start_line: Option<u32>,
            #[serde(default)]
            end_line: Option<u32>,
        },
        /// All source files referenced by a module's PDB line table.
        ListSourceFiles {
            pid: u32,
            module_base: u64,
        },
        /// List UDT/enum types from loaded module PDBs. `module_base = None` searches
        /// all loaded modules; `filter` is a case-insensitive substring on the name.
        ListTypes {
            pid: u32,
            #[serde(default)]
            module_base: Option<u64>,
            #[serde(default)]
            filter: Option<String>,
            max_results: usize,
        },
        /// Resolve a named type's layout. `module_base = None` searches all modules.
        GetType {
            pid: u32,
            #[serde(default)]
            module_base: Option<u64>,
            name: String,
        },
        /// Resolve a type by its TPI index within a specific module (nested expansion).
        GetTypeByIndex {
            pid: u32,
            module_base: u64,
            index: u32,
        },
        /// TEB base address of thread `tid` — anchor for overlaying `_TEB`.
        GetTebAddress {
            pid: u32,
            tid: u32,
        },
        /// PEB base address of a process — anchor for overlaying `_PEB`.
        GetPebAddress {
            pid: u32,
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
        /// Release a process that has already reported `ProcessExited`: issues the
        /// final `ContinueDebugEvent` for that event and drops the debugger's
        /// handles on it. Unlike `Continue` it never waits for another debug event
        /// (there will not be one), so the connection stays responsive.
        ///
        /// The client sends this when it is done inspecting the exited process —
        /// until it does, the process object is kept alive by the pending debug
        /// event, which is what makes a break on `ProcessExited` inspectable at all.
        FinalizeExitedProcess {
            pid: u32,
            tid: u32,
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
        /// Telescope many addresses at once, enumerating memory regions only once
        /// for the whole batch (see `PlatformAPI::dereference_batch`).
        DereferenceBatch {
            pid: u32,
            addresses: Vec<u64>,
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
        /// Backward disassembly: up to `count` instructions ending immediately
        /// before `target` (x64dbg-style self-resynchronizing decode). Reuses the
        /// `Instructions` response.
        DisassembleBackward {
            pid: u32,
            target: u64,
            count: usize,
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
            /// Number of threads to use for the scan. `None`/`Some(0)` = all cores.
            #[serde(default)]
            thread_count: Option<usize>,
        },
        ScanMemoryNext {
            scan_id: u64,
            compare_type: ScanCompareType,
            value: Option<ScanValue>,
            value2: Option<ScanValue>,
            /// Absolute epsilon for float exact-match (see ScanMemoryStart). When
            /// omitted, the tolerance from the initial scan is reused.
            #[serde(default)]
            float_tolerance: Option<f64>,
        },
        ScanMemoryGetResults {
            scan_id: u64,
            offset: u64,
            count: u64,
        },
        ScanMemoryReset {
            scan_id: u64,
        },
        // Pointer scan: find static pointer paths leading to a target address
        PointerScanStart {
            pid: u32,
            target_address: u64,
            /// Max offset window scanned at each level (struct size). Default 0x1000.
            max_offset: u64,
            /// Max pointer chain depth (number of indirections). Default 5.
            max_depth: u32,
            /// Slot alignment when scanning memory. `None` = pointer size (8).
            #[serde(default)]
            alignment: Option<usize>,
            /// Cap on the number of returned paths. `None` = engine default.
            #[serde(default)]
            max_results: Option<u64>,
            /// Restrict static bases to modules with these base addresses.
            /// `None` (or empty) considers every loaded module.
            #[serde(default)]
            modules: Option<Vec<u64>>,
            /// Number of threads to use. `None`/`Some(0)` = all cores.
            #[serde(default)]
            thread_count: Option<usize>,
            /// If true, only scan writable regions (heap/stack/.data) for pointer
            /// slots — faster, but misses static roots in read-only sections.
            #[serde(default)]
            writable_only: bool,
        },
        PointerScanGetResults {
            pid: u32,
            results_path: String,
            offset: u64,
            count: u64,
            /// Quick filter: keep only paths whose chain offsets contain *every*
            /// value listed here (order-independent). Empty = no filter. `offset`/
            /// `count` then page over the filtered set, and `total_count` in the
            /// response reflects the number of matches.
            #[serde(default)]
            offset_filter: Vec<u64>,
        },
        PointerScanReset {
            results_path: String,
        },
        /// Reduce a prior scan to only the paths whose chain offsets contain every
        /// value in `offset_filter`. Writes the survivors to a new file and returns
        /// its path (the old file is deleted) — i.e. commit a quick filter.
        PointerScanApplyFilter {
            results_path: String,
            offset_filter: Vec<u64>,
        },
        /// Re-resolve a prior scan's paths against the live process and keep only
        /// those that still resolve to `target_address`. Writes the survivors to a
        /// new file and returns its path (the old file is deleted).
        PointerScanRescan {
            pid: u32,
            results_path: String,
            target_address: u64,
        },
        // String scan: find printable ASCII/UTF-16 strings in a memory span
        StringScanStart {
            pid: u32,
            /// Start of the span to scan (e.g. a module base).
            start_address: u64,
            /// Length of the span in bytes (e.g. a module size).
            size: u64,
            /// Minimum string length in characters (clamped to 2..=128).
            min_length: u32,
            /// Cap on stored hits. `None` = engine default (1,000,000).
            #[serde(default)]
            max_results: Option<u64>,
            /// Number of threads to use. `None`/`Some(0)` = all cores.
            #[serde(default)]
            thread_count: Option<usize>,
            /// Which memory regions inside the span to scan.
            #[serde(default)]
            region_filter: ScanRegionFilter,
            /// Which string encodings to detect.
            #[serde(default)]
            encodings: StringEncodingFilter,
            /// Case-insensitive substring a string must contain to be stored.
            /// Empty = keep every string.
            #[serde(default)]
            contains: String,
        },
        StringScanGetResults {
            results_path: String,
            offset: u64,
            count: u64,
            /// Case-insensitive substring filter. Empty = no filter. `offset`/
            /// `count` page over the filtered set; `total_count` is the match count.
            #[serde(default)]
            filter: String,
            #[serde(default)]
            sort: StringSortKey,
            #[serde(default = "default_true")]
            ascending: bool,
        },
        StringScanReset {
            results_path: String,
        },
        // Anti-anti-debug
        HidePeb {
            pid: u32,
            options: crate::anti_anti_debug::PebHideOptions,
        },
        // Value freeze: a server-side thread continuously writes `data` to `address`
        // so the client doesn't have to stream repeated writes over the protocol.
        FreezeValueStart {
            pid: u32,
            address: u64,
            data: Vec<u8>,
            /// Write interval in milliseconds. `None` = engine default (~30ms).
            #[serde(default)]
            interval_ms: Option<u64>,
            /// Optional pointer chain. When non-empty, `address` is the *static
            /// base* and the freeze re-resolves the target each tick as
            /// `addr = base; for off in offsets { addr = read_u64(addr) + off }`
            /// before writing — so the lock follows the value even when the chain
            /// repoints (e.g. a level reload). Empty = freeze the fixed `address`.
            #[serde(default)]
            offsets: Vec<u64>,
        },
        /// Change the value written by an active freeze without re-registering it.
        FreezeValueUpdate {
            freeze_id: u64,
            data: Vec<u8>,
        },
        FreezeValueStop {
            freeze_id: u64,
        },
    }

    /// Where a coverage target came from, so a UI can tell a PDB-named function
    /// from one recovered purely from the exception directory.
    ///
    /// The serde form (`"pdata"` / `"function_symbol"` / `"validated_symbol"`,
    /// mirrored by [`Self::as_str`] and `FromStr`) is the one vocabulary every
    /// client speaks — Lua, the UI, and the wire all use these strings.
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum CoverageTargetSource {
        /// A `.pdata` RUNTIME_FUNCTION start — the authoritative function table.
        Pdata,
        /// A symbol the PDB marks as a function.
        FunctionSymbol,
        /// A symbol *not* marked as a function that passed the code-sanity
        /// check: obfuscated block labels, and publics from PDBs that never set
        /// `CV_PUBSYMFLAGS_Function`.
        ValidatedSymbol,
    }

    impl CoverageTargetSource {
        /// The serde spelling, for building client-facing tables without a
        /// serializer round-trip.
        pub fn as_str(self) -> &'static str {
            match self {
                CoverageTargetSource::Pdata => "pdata",
                CoverageTargetSource::FunctionSymbol => "function_symbol",
                CoverageTargetSource::ValidatedSymbol => "validated_symbol",
            }
        }
    }

    impl std::str::FromStr for CoverageTargetSource {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "pdata" => Ok(CoverageTargetSource::Pdata),
                "function_symbol" => Ok(CoverageTargetSource::FunctionSymbol),
                "validated_symbol" => Ok(CoverageTargetSource::ValidatedSymbol),
                other => Err(format!(
                    "Unknown coverage target source '{}' (expected pdata, function_symbol or validated_symbol)",
                    other
                )),
            }
        }
    }

    /// One address worth arming a coverage breakpoint on, from
    /// `EnumerateCoverageTargets`.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct CoverageTarget {
        pub address: u64,
        pub rva: u32,
        /// Best available name — the symbol starting exactly here, else the
        /// nearest one before it within the same function as `name+0xN`, else
        /// `None` when nothing names the address.
        pub symbol: Option<String>,
        pub source: CoverageTargetSource,
    }

    /// One code-coverage breakpoint that has been hit at least once.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct CoverageHit {
        pub address: u64,
        pub hit_count: u64,
        /// 1-based first-execution order across the whole coverage run (1 = the
        /// first covered address executed). Assigned once on the first hit and
        /// never changed; reset by `StopCodeCoverage`.
        pub first_hit_seq: u64,
        /// Microseconds from the start of the coverage run (the moment arming
        /// finished) to this address' *first* hit, so the gap between two
        /// functions is the difference of their values. Stamped once alongside
        /// `first_hit_seq`; later hits of the same address are not timed, which
        /// is why this says nothing about a heat-map run's repeat hits.
        #[serde(default)]
        pub first_hit_us: u64,
        /// Distinct thread ids that hit this address, in first-hit order (the
        /// first element is the thread that executed it first).
        pub thread_ids: Vec<u32>,
    }

    /// One distinct instruction that has accessed a watched address at least once
    /// (produced by a hardware access trace).
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct WatchpointAccess {
        /// The attributed accessing instruction. On x86 the hardware traps *after*
        /// the access, so the server back-steps from the trap RIP to attribute it;
        /// on ARM64 it is the exact faulting PC. Equals `accessor_raw_rip` when
        /// attribution is not possible.
        pub accessor: u64,
        /// The raw trap instruction pointer (the instruction *following* the access
        /// on x86; equal to `accessor` on ARM64).
        pub accessor_raw_rip: u64,
        pub hit_count: u64,
        /// 1-based first-access order across the whole trace run (1 = the first
        /// instruction that touched the watched address).
        pub first_seq: u64,
        /// Distinct thread ids whose instruction accessed the address, in first-hit
        /// order.
        pub thread_ids: Vec<u32>,
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
        SymbolStatusList { statuses: Vec<ModuleSymbolStatus> },
        PdbLoaded { symbol_count: usize },
        /// Returned by LoadPdbFromPath when the PDB's GUID/age doesn't match the PE
        /// and `force` was not set. The client may retry with `force: true`.
        PdbMismatch(PdbMismatchInfo),
        Symbol { symbol: Option<crate::interfaces::ModuleSymbol> },
        SymbolList { symbols: Vec<crate::interfaces::ModuleSymbol> },
        ResolvedSymbolList { symbols: Vec<crate::interfaces::ResolvedSymbol> },
        /// Code-coverage results: one [`CoverageHit`] per coverage breakpoint
        /// hit at least once.
        CoverageResults { hits: Vec<CoverageHit> },
        /// Armable addresses for a module, from `EnumerateCoverageTargets`.
        CoverageTargetList { targets: Vec<CoverageTarget> },
        /// Access-trace results: one [`WatchpointAccess`] per distinct instruction
        /// that touched the watched address at least once.
        WatchpointAccesses { accesses: Vec<WatchpointAccess> },
        AddressSymbol {
            module_path: Option<String>,
            symbol: Option<crate::interfaces::ModuleSymbol>,
            offset: Option<u64>,
        },
        /// One `(module_name, symbol, offset)` per requested address, in order;
        /// `None` for unresolved / still-loading addresses.
        AddressSymbolBatch {
            results: Vec<Option<(String, crate::interfaces::ModuleSymbol, u64)>>,
        },
        // Source line responses
        AddressLine { info: Option<AddressLineInfo> },
        SourceFileLineMap {
            file: Option<crate::interfaces::SourceFileEntry>,
            entries: Vec<crate::interfaces::LineEntry>,
        },
        SourceFileList { files: Vec<crate::interfaces::SourceFileEntry> },
        // Type system responses
        TypeList { types: Vec<TypeSummary> },
        TypeResult { layout: Option<TypeLayout> },
        TebAddress { address: u64 },
        PebAddress { address: u64 },
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
        DereferenceBatchResult { results: Vec<Vec<DereferenceEntry>> },
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
        PointerScanResult {
            /// Path of the disk file holding this scan's results.
            results_path: String,
            match_count: u64,
            scan_time_us: u64,
        },
        PointerScanResults {
            paths: Vec<PointerPath>,
            total_count: u64,
        },
        StringScanResult {
            /// Path of the disk file holding this scan's results.
            results_path: String,
            match_count: u64,
            scan_time_us: u64,
            /// True if more strings were found than the cap; only the first
            /// `match_count` (in address order) are stored.
            capped: bool,
        },
        StringScanResults {
            strings: Vec<StringHit>,
            total_count: u64,
        },
        /// Tenet format trace result (for TraceInstructions and EmulateInstructions with InstructionTrace mode)
        TenetTrace {
            trace_text: String,
            stop_reason: String,
            trace_time_us: u64,
            /// Detailed timing breakdown
            stats_text: String,
            /// PC after the last traced instruction (emulation traces only).
            #[serde(default)]
            final_pc: Option<u64>,
            /// Number of instructions actually executed.
            #[serde(default)]
            instructions_executed: usize,
        },
        // Anti-anti-debug
        PebHideResult {
            report: crate::anti_anti_debug::PebHideReport,
        },
        // Value freeze
        FreezeValueStarted {
            freeze_id: u64,
        },
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum DebugEvent {
        //ProcessStarted { pid: u32 },
        ProcessExited { pid: u32, tid: u32, exit_code: u32 },
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
        Unknown {
            pid: u32,
            tid: u32,
            debug_event_code: u32,
            error: String,
        },
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
                DebugEvent::Unknown { pid, .. } => *pid,
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
                DebugEvent::ProcessExited { tid, .. } => *tid,
                DebugEvent::Unknown { tid, .. } => *tid,
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

    /// Symbol load state for a single module.
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
    pub enum SymbolLoadState {
        Loaded { symbol_count: usize },
        /// No PDB is available; PE export names were loaded as a fallback.
        /// `error` is the reason the PDB itself couldn't be loaded.
        ExportsOnly { export_count: usize, error: String },
        Loading,
        Failed { error: String },
        NotRequested,
    }

    /// Per-module symbol load status, as reported by `GetSymbolStatus`.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct ModuleSymbolStatus {
        pub module_path: String,
        pub module_base: u64,
        pub state: SymbolLoadState,
        /// Path of the PDB the symbols were loaded from, when loaded.
        pub pdb_path: Option<String>,
    }

    /// A resolved address → source line mapping, as returned by `ResolveAddressToLine`.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct AddressLineInfo {
        pub module_path: String,
        pub module_base: u64,
        pub rva: u32,
        pub file: crate::interfaces::SourceFileEntry,
        pub line_entry: crate::interfaces::LineEntry,
    }

    /// PE vs PDB identity (GUID + age) details for a rejected PDB load.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct PdbMismatchInfo {
        pub pe_guid: String,
        pub pe_age: u32,
        pub pdb_guid: String,
        pub pdb_age: u32,
    }

    /// Outcome of a `LoadPdbFromPath` request: symbols loaded, or the PDB rejected
    /// because its identity doesn't match the PE (retry with `force` to load anyway).
    #[derive(Debug, Clone)]
    pub enum PdbLoadOutcome {
        Loaded { symbol_count: usize },
        Mismatch(PdbMismatchInfo),
    }

    // ---------------------------------------------------------------------
    // Type system (parsed from the PDB TPI stream)
    // ---------------------------------------------------------------------

    /// Struct/class/union/enum discriminator.
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum UdtKind {
        Struct,
        Class,
        Union,
        Enum,
    }

    /// Broad value category of a type — enough for the UI to render raw bytes and
    /// decide whether a member is expandable. Recursive for pointers/arrays.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum TypeClass {
        /// Signed integer of the ref's `size` bytes.
        Int,
        /// Unsigned integer.
        UInt,
        /// IEEE floating point (2/4/8/10/16 bytes).
        Float,
        /// Boolean.
        Bool,
        /// Narrow character (1 byte).
        Char,
        /// Wide character (2 bytes).
        WChar,
        /// `void` / uncharacterized — rendered as raw bytes.
        Void,
        /// Pointer to `pointee` (ref `size` is the pointer width, usually 8).
        Pointer { pointee: Box<TypeRef> },
        /// Fixed-length array of `element` with `count` elements.
        Array { element: Box<TypeRef>, count: u32 },
        /// Named struct/class/union; `index` is the TPI type index in the owning
        /// module's PDB, for lazy layout expansion via `GetTypeByIndex`.
        Udt { index: u32 },
        /// Enumeration; `index` for value→name lookup via `GetTypeByIndex`.
        Enum { index: u32 },
        /// Anything not modeled yet — rendered as raw bytes.
        Unknown,
    }

    /// A reference to a type: display name, byte size, and value class.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TypeRef {
        /// Human-readable type name, e.g. "unsigned long", "_PEB *", "wchar_t[16]".
        pub name: String,
        /// Size in bytes (0 if unknown).
        pub size: u32,
        pub class: TypeClass,
    }

    /// One field of a struct/class/union type.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TypeMember {
        pub name: String,
        /// Byte offset from the start of the containing type.
        pub offset: u32,
        pub type_ref: TypeRef,
        /// Bit offset within the field, for a bitfield member.
        #[serde(default)]
        pub bit_position: Option<u8>,
        /// Bit width, for a bitfield member.
        #[serde(default)]
        pub bit_length: Option<u8>,
    }

    /// An enumerator (name/value pair) of an enum type.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TypeEnumValue {
        pub name: String,
        pub value: i64,
    }

    /// A fully resolved type layout, one level deep: nested UDT members are
    /// referenced by index in their `type_ref` and expanded on demand.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TypeLayout {
        pub name: String,
        pub size: u32,
        pub kind: UdtKind,
        /// TPI type index of this type within the owning module's PDB.
        pub index: u32,
        /// Base address of the module whose PDB defines this type.
        pub module_base: u64,
        pub members: Vec<TypeMember>,
        /// For enums: the enumerator (name, value) pairs.
        #[serde(default)]
        pub enum_values: Vec<TypeEnumValue>,
    }

    /// Lightweight type descriptor for browsing/listing.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TypeSummary {
        pub name: String,
        pub size: u32,
        pub kind: UdtKind,
        pub index: u32,
        pub module_base: u64,
        /// Owning module file name (for display/grouping).
        pub module_name: String,
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

    /// A single pointer path found by the pointer scanner. Resolves to the scan
    /// target via: `addr = module_base + base_offset; for off in offsets { addr = read_u64(addr) + off }`.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct PointerPath {
        /// Index into the module list at scan time, or -1 if the base is non-static.
        pub module_index: i32,
        /// Base address of the module the static base lives in.
        pub module_base: u64,
        /// Offset of the static pointer within its module (`static_addr - module_base`).
        pub base_offset: u64,
        /// Offset chain, ordered from base toward the target (applied per indirection).
        pub offsets: Vec<u64>,
        /// Address this path resolves to (equals the scan target at scan time).
        pub resolved: u64,
    }

    fn default_true() -> bool {
        true
    }

    /// Encoding of a discovered string.
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub enum StringEncoding {
        Ascii,
        Utf16,
    }

    impl StringEncoding {
        /// Canonical lowercase name used by every string-facing surface (UI, Lua).
        pub fn as_str(self) -> &'static str {
            match self {
                StringEncoding::Ascii => "ascii",
                StringEncoding::Utf16 => "utf16",
            }
        }
    }

    /// Sort key for paging string-scan results.
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
    pub enum StringSortKey {
        /// Ascending memory address (the file's natural order).
        #[default]
        Address,
        /// Lexicographic by string value (case-insensitive).
        Value,
        /// By string length in characters (ties stay address-ordered).
        Length,
    }

    impl std::str::FromStr for StringSortKey {
        type Err = String;

        /// Parses the canonical lowercase names "address" / "value" / "length".
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "address" => Ok(StringSortKey::Address),
                "value" => Ok(StringSortKey::Value),
                "length" => Ok(StringSortKey::Length),
                _ => Err(format!("unknown string sort key '{}'", s)),
            }
        }
    }

    /// Which memory regions a scan should visit. Every variant implies the base
    /// requirements (committed, not NOACCESS, not guard); the protection/type
    /// variants narrow further.
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
    pub enum ScanRegionFilter {
        /// Any readable committed memory (the base filter alone).
        #[default]
        Readable,
        /// Writable pages only.
        Writable,
        /// Executable pages only.
        Executable,
        /// Image-backed regions (loaded modules, MEM_IMAGE).
        Image,
        /// Mapped-file regions (MEM_MAPPED).
        Mapped,
        /// Private regions — heaps, stacks, VirtualAlloc'd memory (MEM_PRIVATE).
        Private,
    }

    impl std::str::FromStr for ScanRegionFilter {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "readable" => Ok(ScanRegionFilter::Readable),
                "writable" => Ok(ScanRegionFilter::Writable),
                "executable" => Ok(ScanRegionFilter::Executable),
                "image" => Ok(ScanRegionFilter::Image),
                "mapped" => Ok(ScanRegionFilter::Mapped),
                "private" => Ok(ScanRegionFilter::Private),
                _ => Err(format!("unknown region filter '{}'", s)),
            }
        }
    }

    /// Which string encodings a string scan detects.
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
    pub enum StringEncodingFilter {
        /// Detect both ASCII and UTF-16 strings.
        #[default]
        Both,
        /// Detect ASCII strings only.
        Ascii,
        /// Detect UTF-16 strings only.
        Utf16,
    }

    impl std::str::FromStr for StringEncodingFilter {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "both" => Ok(StringEncodingFilter::Both),
                "ascii" => Ok(StringEncodingFilter::Ascii),
                "utf16" => Ok(StringEncodingFilter::Utf16),
                _ => Err(format!("unknown encoding filter '{}'", s)),
            }
        }
    }

    /// A single string found by the string scanner.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct StringHit {
        /// Address of the first byte of the string.
        pub address: u64,
        pub encoding: StringEncoding,
        /// True length in characters (may exceed the stored `text` length).
        pub length: u32,
        /// The string text, truncated to a fixed cap of characters.
        pub text: String,
        /// True if `text` was truncated (i.e. `length` exceeds the stored cap).
        pub truncated: bool,
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

    #[derive(Debug, Serialize, Deserialize, Clone, Default)]
    pub struct ThreadInfo {
        pub tid: u32,
        pub start_address: u64,
        /// Live user-mode suspend count (`SuspendThread` nesting); 0 = runnable.
        /// A debugger-event pause does not count. Queried at list time.
        #[serde(default)]
        pub suspend_count: u32,
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
