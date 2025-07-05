use crate::protocol::*;
use crate::interfaces::*;

// Protocol Display and Debug implementations
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
        
        #[cfg(all(windows, target_arch = "aarch64"))]
        {
            let ThreadContext::Win32RawContext(ctx) = self;
            
            // TODO: Replace with actual register access once CONTEXT_0 layout is confirmed
            // The Anonymous union should contain X0-X30 registers, possibly as:
            // - ctx.Anonymous.X[0] through ctx.Anonymous.X[30], or
            // - ctx.Anonymous.X0 through ctx.Anonymous.X30
            
            // For now, using placeholder values but with the correct format
            return write!(f,
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
                 CPSR: {:08X}   ELR:  {:016X}   SPSR: {:016X}   \n\
                 LastErrorValue: 0x{:08X}\n\
                 LastStatusValue: 0x{:08X}",
                // X0-X2
                0, 0, 0,
                // X3-X5  
                0, 0, 0,
                // X6-X8
                0, 0, 0,
                // X9-X11
                0, 0, 0,
                // X12-X14
                0, 0, 0,
                // X15-X17
                0, 0, 0,
                // X18-X20
                0, 0, 0,
                // X21-X23
                0, 0, 0,
                // X24-X26
                0, 0, 0,
                // X27-X28, FP (X29)
                0, 0, 0,
                // LR (X30), SP, PC
                0, ctx.Sp, ctx.Pc,
                // CPSR, ELR, SPSR (placeholder values for ELR and SPSR)
                ctx.Cpsr, 0u64, 0u64,
                // LastErrorValue, LastStatusValue (placeholder values)
                0u32, 0u32
            );
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