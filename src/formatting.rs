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