use crate::protocol::*;
use crate::interfaces::*;

// Memory region formatting utilities
#[cfg(windows)]
pub mod memory {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };

    /// Convert memory state to string representation
    pub fn state_to_str(state: u32) -> &'static str {
        match state {
            MEM_COMMIT => "MEM_COMMIT",
            MEM_RESERVE => "MEM_RESERVE",
            MEM_FREE => "MEM_FREE",
            _ => "UNKNOWN",
        }
    }

    /// Convert memory type to string representation
    pub fn type_to_str(region_type: u32) -> &'static str {
        match region_type {
            MEM_PRIVATE => "MEM_PRIVATE",
            MEM_MAPPED => "MEM_MAPPED",
            MEM_IMAGE => "MEM_IMAGE",
            0 => "NONE",
            _ => "UNKNOWN",
        }
    }

    /// Convert memory protection flags to string representation
    pub fn protect_to_str(protect: u32) -> &'static str {
        match protect & 0xFF {
            PAGE_NOACCESS => "PAGE_NOACCESS",
            PAGE_READONLY => "PAGE_READONLY",
            PAGE_READWRITE => "PAGE_READWRITE",
            PAGE_WRITECOPY => "PAGE_WRITECOPY",
            PAGE_EXECUTE => "PAGE_EXECUTE",
            PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ",
            PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY",
            0 => "NONE",
            _ => "OTHER",
        }
    }
}

// Protocol Display and Debug implementations
impl std::fmt::Debug for DebuggerResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebuggerResponse::CallStack { frames } => {
                let mut ds = f.debug_struct("CallStack");
                ds.field("frames", &frames.iter().map(|frame| format!("{}", frame)).collect::<Vec<_>>());
                ds.finish()
            }
            // Add other variants here, using a default debug format
            DebuggerResponse::HardwareBreakpointSet { dr_index } => f.debug_struct("HardwareBreakpointSet").field("dr_index", dr_index).finish(),
            DebuggerResponse::Ack => write!(f, "Ack"),
            DebuggerResponse::Error { message } => f.debug_struct("Error").field("message", message).finish(),
            DebuggerResponse::Event { event } => f.debug_struct("Event").field("event", &format_args!("{}", event)).finish(),
            DebuggerResponse::MemoryData { data } => f.debug_struct("MemoryData").field("data", data).finish(),
            DebuggerResponse::WriteAck => write!(f, "WriteAck"),
            DebuggerResponse::ThreadContext { context } => f.debug_struct("ThreadContext").field("context", context).finish(),
            DebuggerResponse::SetContextAck => write!(f, "SetContextAck"),
            DebuggerResponse::ModuleList { modules } => f.debug_struct("ModuleList").field("modules", modules).finish(),
            DebuggerResponse::ThreadList { threads } => f.debug_struct("ThreadList").field("threads", threads).finish(),
            DebuggerResponse::ProcessList { processes } => f.debug_struct("ProcessList").field("processes", processes).finish(),
            DebuggerResponse::Symbol { symbol } => f.debug_struct("Symbol").field("symbol", symbol).finish(),
            DebuggerResponse::SymbolList { symbols } => f.debug_struct("SymbolList").field("symbols", symbols).finish(),
            DebuggerResponse::ResolvedSymbolList { symbols } => f.debug_struct("ResolvedSymbolList").field("symbols", symbols).finish(),
            DebuggerResponse::CoverageResults { hits } => f.debug_struct("CoverageResults").field("count", &hits.len()).finish(),
            DebuggerResponse::WatchpointAccesses { accesses } => f.debug_struct("WatchpointAccesses").field("count", &accesses.len()).finish(),
            DebuggerResponse::AddressSymbol { module_path, symbol, offset } => f.debug_struct("AddressSymbol").field("module_path", module_path).field("symbol", symbol).field("offset", offset).finish(),
            DebuggerResponse::AddressSymbolBatch { results } => f.debug_struct("AddressSymbolBatch")
                .field("addresses", &results.len())
                .field("resolved", &results.iter().filter(|r| r.is_some()).count())
                .finish(),
            DebuggerResponse::AddressLine { info } => f.debug_struct("AddressLine")
                .field("info", &info.as_ref().map(|i| format!("{}:{} (rva 0x{:X})", i.file.path, i.line_entry.line_start, i.rva)))
                .finish(),
            DebuggerResponse::SourceFileLineMap { file, entries } => f.debug_struct("SourceFileLineMap")
                .field("file", &file.as_ref().map(|f| f.path.as_str()))
                .field("entries", &entries.len())
                .finish(),
            DebuggerResponse::SourceFileList { files } => f.debug_struct("SourceFileList")
                .field("count", &files.len())
                .finish(),
            DebuggerResponse::Instructions { instructions } => f.debug_struct("Instructions").field("instructions", instructions).finish(),
            DebuggerResponse::FunctionArguments { arguments } => f.debug_struct("FunctionArguments").field("arguments", arguments).finish(),
            DebuggerResponse::WideStringData { data } => f.debug_struct("WideStringData").field("data", data).finish(),
            DebuggerResponse::ModuleExtraInfo { info } => f.debug_struct("ModuleExtraInfo")
                .field("dos_header", &info.dos_header)
                .field("nt_headers", &info.nt_headers)
                .finish(),
            DebuggerResponse::MemoryRegionInfo { info } => f.debug_struct("MemoryRegionInfo")
                .field("base_address", &format_args!("0x{:X}", info.base_address))
                .field("region_size", &format_args!("0x{:X}", info.region_size))
                .field("state", &format_args!("0x{:X}", info.state))
                .field("protect", &format_args!("0x{:X}", info.protect))
                .finish(),
            DebuggerResponse::MemoryRegionList { regions } => f.debug_struct("MemoryRegionList")
                .field("count", &regions.len())
                .finish(),
            DebuggerResponse::DereferenceResult { entries } => f.debug_struct("DereferenceResult")
                .field("count", &entries.len())
                .finish(),
            DebuggerResponse::DereferenceBatchResult { results } => f.debug_struct("DereferenceBatchResult")
                .field("addresses", &results.len())
                .finish(),
            DebuggerResponse::MemorySearchResult { addresses, capped } => f.debug_struct("MemorySearchResult")
                .field("matches", &addresses.len())
                .field("capped", capped)
                .finish(),
            DebuggerResponse::TypeList { types } => f.debug_struct("TypeList")
                .field("count", &types.len())
                .finish(),
            DebuggerResponse::TypeResult { layout } => f.debug_struct("TypeResult")
                .field("name", &layout.as_ref().map(|l| &l.name))
                .field("members", &layout.as_ref().map(|l| l.members.len()))
                .finish(),
            DebuggerResponse::TebAddress { address } => f.debug_struct("TebAddress")
                .field("address", &format_args!("0x{:X}", address))
                .finish(),
            DebuggerResponse::PebAddress { address } => f.debug_struct("PebAddress")
                .field("address", &format_args!("0x{:X}", address))
                .finish(),
            DebuggerResponse::FunctionDisassembly { instructions, function_start, function_end, function_name } => {
                f.debug_struct("FunctionDisassembly")
                    .field("instructions_count", &instructions.len())
                    .field("function_start", &function_start.map(|a| format!("0x{:X}", a)))
                    .field("function_end", &function_end.map(|a| format!("0x{:X}", a)))
                    .field("function_name", function_name)
                    .finish()
            }
            DebuggerResponse::EmulationResult { final_pc, instructions_executed, stop_reason, emulation_time_us, pages_loaded, basic_blocks, .. } => {
                f.debug_struct("EmulationResult")
                    .field("final_pc", &format_args!("0x{:X}", final_pc))
                    .field("instructions_executed", instructions_executed)
                    .field("stop_reason", stop_reason)
                    .field("emulation_time_us", emulation_time_us)
                    .field("pages_loaded", pages_loaded)
                    .field("basic_blocks_count", &basic_blocks.len())
                    .finish()
            }
            DebuggerResponse::TenetTrace { trace_text, stop_reason, trace_time_us, .. } => {
                f.debug_struct("TenetTrace")
                    .field("trace_text_len", &trace_text.len())
                    .field("stop_reason", stop_reason)
                    .field("trace_time_us", trace_time_us)
                    .finish()
            }
            DebuggerResponse::ScanMemoryResult { scan_id, match_count, scan_time_us } => {
                f.debug_struct("ScanMemoryResult")
                    .field("scan_id", scan_id)
                    .field("match_count", match_count)
                    .field("scan_time_us", scan_time_us)
                    .finish()
            }
            DebuggerResponse::ScanMemoryResults { addresses, total_count, .. } => {
                f.debug_struct("ScanMemoryResults")
                    .field("returned", &addresses.len())
                    .field("total_count", total_count)
                    .finish()
            }
            DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us } => {
                f.debug_struct("PointerScanResult")
                    .field("results_path", results_path)
                    .field("match_count", match_count)
                    .field("scan_time_us", scan_time_us)
                    .finish()
            }
            DebuggerResponse::PointerScanResults { paths, total_count } => {
                f.debug_struct("PointerScanResults")
                    .field("returned", &paths.len())
                    .field("total_count", total_count)
                    .finish()
            }
            DebuggerResponse::StringScanResult { results_path, match_count, scan_time_us, capped } => {
                f.debug_struct("StringScanResult")
                    .field("results_path", results_path)
                    .field("match_count", match_count)
                    .field("scan_time_us", scan_time_us)
                    .field("capped", capped)
                    .finish()
            }
            DebuggerResponse::StringScanResults { strings, total_count } => {
                f.debug_struct("StringScanResults")
                    .field("returned", &strings.len())
                    .field("total_count", total_count)
                    .finish()
            }
            DebuggerResponse::PebHideResult { report } => {
                f.debug_struct("PebHideResult")
                    .field("peb_address", &format_args!("0x{:X}", report.peb_address))
                    .field("applied", &report.applied)
                    .field("failures", &report.failures)
                    .field("wow64_skipped", &report.wow64_skipped)
                    .finish()
            }
            DebuggerResponse::FreezeValueStarted { freeze_id } => {
                f.debug_struct("FreezeValueStarted")
                    .field("freeze_id", freeze_id)
                    .finish()
            }
            DebuggerResponse::SymbolStatusList { statuses } => {
                f.debug_struct("SymbolStatusList")
                    .field("count", &statuses.len())
                    .finish()
            }
            DebuggerResponse::PdbLoaded { symbol_count } => {
                f.debug_struct("PdbLoaded")
                    .field("symbol_count", symbol_count)
                    .finish()
            }
            DebuggerResponse::PdbMismatch(info) => {
                f.debug_tuple("PdbMismatch").field(info).finish()
            }
        }
    }
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
        
        #[cfg(all(windows, target_arch = "aarch64"))]
        {
            let ThreadContext::Win32RawContext(ctx) = self;
            
            return unsafe { write!(f,
                "X0:   {:016X}   X1:   {:016X}   X2:   {:016X}   \n\
                 X3:   {:016X}   X4:   {:016X}   X5:   {:016X}   \n\
                 X6:   {:016X}   X7:   {:016X}   X8:   {:016X}   \n\
                 X9:   {:016X}   X10:  {:016X}   X11:  {:016X}   \n\
                 X12:  {:016X}   X13:  {:016X}   X14:  {:016X}   \n\
                 X15:  {:016X}   X16:  {:016X}   X17:  {:016X}   \n\
                 X18:  {:016X}   X19:  {:016X}   X20:  {:016X}   \n\
                 X21:  {:016X}   X22:  {:016X}   X23:  {:016X}   \n\
                 X24:  {:016X}   X25:  {:016X}   X26:  {:016X}   \n\
                 X27:  {:016X}   X28:  {:016X}   FP:   {:016X}   \n\
                 LR:   {:016X}   SP:   {:016X}   PC:   {:016X}   \n\
                 CPSR: {:08X}",
                // X0-X2
                ctx.Anonymous.X[0], ctx.Anonymous.X[1], ctx.Anonymous.X[2],
                // X3-X5  
                ctx.Anonymous.X[3], ctx.Anonymous.X[4], ctx.Anonymous.X[5],
                // X6-X8
                ctx.Anonymous.X[6], ctx.Anonymous.X[7], ctx.Anonymous.X[8],
                // X9-X11
                ctx.Anonymous.X[9], ctx.Anonymous.X[10], ctx.Anonymous.X[11],
                // X12-X14
                ctx.Anonymous.X[12], ctx.Anonymous.X[13], ctx.Anonymous.X[14],
                // X15-X17
                ctx.Anonymous.X[15], ctx.Anonymous.X[16], ctx.Anonymous.X[17],
                // X18-X20
                ctx.Anonymous.X[18], ctx.Anonymous.X[19], ctx.Anonymous.X[20],
                // X21-X23
                ctx.Anonymous.X[21], ctx.Anonymous.X[22], ctx.Anonymous.X[23],
                // X24-X26
                ctx.Anonymous.X[24], ctx.Anonymous.X[25], ctx.Anonymous.X[26],
                // X27-X28, FP (X29)
                ctx.Anonymous.X[27], ctx.Anonymous.X[28], ctx.Anonymous.X[29],
                // LR (X30), SP, PC
                ctx.Anonymous.X[30], ctx.Sp, ctx.Pc,
                // CPSR
                ctx.Cpsr, 
            ) };
        }
        
        #[cfg(not(any(all(windows, target_arch = "x86_64"), all(windows, target_arch = "aarch64"))))]
        {
            // Fallback for non-Windows x86_64/ARM64 platforms
            match self {
                #[cfg(windows)]
                ThreadContext::Win32RawContext(_) => write!(f, "ThreadContext::Win32RawContext(<unsupported on this architecture>)"),
                #[allow(unreachable_patterns)]
                _ => write!(f, "ThreadContext(<unsupported platform>)"),
            }
        }
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

impl std::fmt::Display for DebugEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugEvent::ProcessExited { pid, tid, exit_code } => {
                write!(f, "ProcessExited(pid={}, tid={}, exit_code=0x{:X})", pid, tid, exit_code)
            }
            DebugEvent::Output { pid, tid, output } => {
                write!(f, "Output(pid={}, tid={}, output={})", pid, tid, output)
            }
            DebugEvent::Exception { pid, tid, code, address, first_chance, .. } => {
                write!(f, "Exception(pid={}, tid={}, code=0x{:X}, address=0x{:X}, first_chance={})", pid, tid, code, address, first_chance)
            }
            DebugEvent::Breakpoint { pid, tid, address } => {
                write!(f, "Breakpoint(pid={}, tid={}, address=0x{:X})", pid, tid, address)
            }
            DebugEvent::HardwareBreakpoint { pid, tid, address, dr_index, bp_type } => {
                write!(f, "HardwareBreakpoint(pid={}, tid={}, address=0x{:X}, dr={}, type={:?})", pid, tid, address, dr_index, bp_type)
            }
            DebugEvent::InitialBreakpoint { pid, tid, address } => {
                write!(f, "InitialBreakpoint(pid={}, tid={}, address=0x{:X})", pid, tid, address)
            }
            DebugEvent::SingleShotBreakpoint { pid, tid, address } => {
                write!(f, "SingleShotBreakpoint(pid={}, tid={}, address=0x{:X})", pid, tid, address)
            }
            DebugEvent::ProcessCreated { pid, tid, image_file_name, base_of_image, size_of_image } => {
                write!(f, "ProcessCreated(pid={}, tid={}, image={}, base=0x{:X}, size={:X?})", 
                    pid, tid, image_file_name.as_deref().unwrap_or("<unknown>"), base_of_image, size_of_image)
            }
            DebugEvent::ThreadCreated { pid, tid, start_address } => {
                write!(f, "ThreadCreated(pid={}, tid={}, start=0x{:X})", pid, tid, start_address)
            }
            DebugEvent::ThreadExited { pid, tid, exit_code } => {
                write!(f, "ThreadExited(pid={}, tid={}, exit_code=0x{:X})", pid, tid, exit_code)
            }
            DebugEvent::DllLoaded { pid, tid, dll_name, base_of_dll, size_of_dll } => {
                write!(f, "DllLoaded(pid={}, tid={}, dll={}, base=0x{:X}, size={:X?})", 
                    pid, tid, dll_name.as_deref().unwrap_or("<unknown>"), base_of_dll, size_of_dll)
            }
            DebugEvent::DllUnloaded { pid, tid, base_of_dll } => {
                write!(f, "DllUnloaded(pid={}, tid={}, base=0x{:X})", pid, tid, base_of_dll)
            }
            DebugEvent::RipEvent { pid, tid, error, event_type } => {
                write!(f, "RipEvent(pid={}, tid={}, error=0x{:X}, type=0x{:X})", pid, tid, error, event_type)
            }
            DebugEvent::StepComplete { pid, tid, kind, address } => {
                write!(f, "StepComplete(pid={}, tid={}, kind={:?}, address=0x{:X})", pid, tid, kind, address)
            }
            DebugEvent::StepFailed { pid, tid, kind, message } => {
                write!(f, "StepFailed(pid={}, tid={}, kind={:?}, message={})", pid, tid, kind, message)
            }
            DebugEvent::Unknown { pid, tid, debug_event_code, error } => {
                write!(f, "Unknown(pid={}, tid={}, event_code={}, error={})", pid, tid, debug_event_code, error)
            }
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
        
        #[cfg(all(windows, target_arch = "aarch64"))]
        {
            let ThreadContext::Win32RawContext(ctx) = self;

            return unsafe { write!(f,
                "X0:   {:016X}   X1:   {:016X}   X2:   {:016X}   \n\
                 X3:   {:016X}   X4:   {:016X}   X5:   {:016X}   \n\
                 X6:   {:016X}   X7:   {:016X}   X8:   {:016X}   \n\
                 X9:   {:016X}   X10:  {:016X}   X11:  {:016X}   \n\
                 X12:  {:016X}   X13:  {:016X}   X14:  {:016X}   \n\
                 X15:  {:016X}   X16:  {:016X}   X17:  {:016X}   \n\
                 X18:  {:016X}   X19:  {:016X}   X20:  {:016X}   \n\
                 X21:  {:016X}   X22:  {:016X}   X23:  {:016X}   \n\
                 X24:  {:016X}   X25:  {:016X}   X26:  {:016X}   \n\
                 X27:  {:016X}   X28:  {:016X}   FP:   {:016X}   \n\
                 LR:   {:016X}   SP:   {:016X}   PC:   {:016X}   \n\
                 CPSR: {:08X}",
                // X0-X2
                ctx.Anonymous.X[0], ctx.Anonymous.X[1], ctx.Anonymous.X[2],
                // X3-X5
                ctx.Anonymous.X[3], ctx.Anonymous.X[4], ctx.Anonymous.X[5],
                // X6-X8
                ctx.Anonymous.X[6], ctx.Anonymous.X[7], ctx.Anonymous.X[8],
                // X9-X11
                ctx.Anonymous.X[9], ctx.Anonymous.X[10], ctx.Anonymous.X[11],
                // X12-X14
                ctx.Anonymous.X[12], ctx.Anonymous.X[13], ctx.Anonymous.X[14],
                // X15-X17
                ctx.Anonymous.X[15], ctx.Anonymous.X[16], ctx.Anonymous.X[17],
                // X18-X20
                ctx.Anonymous.X[18], ctx.Anonymous.X[19], ctx.Anonymous.X[20],
                // X21-X23
                ctx.Anonymous.X[21], ctx.Anonymous.X[22], ctx.Anonymous.X[23],
                // X24-X26
                ctx.Anonymous.X[24], ctx.Anonymous.X[25], ctx.Anonymous.X[26],
                // X27-X28, FP (X29)
                ctx.Anonymous.X[27], ctx.Anonymous.X[28], ctx.Anonymous.X[29],
                // LR (X30), SP, PC
                ctx.Anonymous.X[30], ctx.Sp, ctx.Pc,
                // CPSR
                ctx.Cpsr,
            ) };
        }
        
        #[cfg(not(any(all(windows, target_arch = "x86_64"), all(windows, target_arch = "aarch64"))))]
        {
            // Fallback for non-Windows x86_64/ARM64 platforms
            match self {
                #[cfg(windows)]
                ThreadContext::Win32RawContext(_) => write!(f, "ThreadContext::Win32RawContext(<unsupported on this architecture>)"),
                #[allow(unreachable_patterns)]
                _ => write!(f, "ThreadContext(<unsupported platform>)"),
            }
        }
    }
}

// Interfaces Display implementations
impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format bytes as hex string with padding
        let bytes_str = self.bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        // Pad bytes to a consistent width (up to 15 bytes shown, 45 chars max)
        let bytes_padded = format!("{:<20}", bytes_str);
        
        // Use symbolized operands if available, otherwise use original
        let op_str = self.symbolized_op_str.as_ref().unwrap_or(&self.op_str);
        
        // Combine mnemonic and operands
        let instruction_str = if op_str.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, op_str)
        };
        
        // Format address with optional symbol information
        let address_str = if let Some(ref sym) = self.symbol_info {
            format!("{}!{}+0x{:x}", sym.module_name, sym.symbol_name, sym.offset)
        } else {
            format!("0x{:016x}", self.address)
        };
        
        write!(f, "{}: {} {}", address_str, bytes_padded, instruction_str)
    }
} 

impl std::fmt::Display for CallFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref sym) = self.symbol {
            write!(
                f,
                "0x{:016x} {}!{}+0x{:x}",
                self.instruction_pointer, sym.module_name, sym.symbol_name, sym.offset
            )
        } else {
            write!(f, "0x{:016x}", self.instruction_pointer)
        }
    }
} 