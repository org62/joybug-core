use crate::interfaces::{PlatformError, CallFrame, SymbolInfo, Architecture, PlatformAPI};
use crate::windows_platform::WindowsPlatform;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::SystemInformation::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64};
use windows_sys::Win32::Foundation::*;
use tracing::{debug, warn, trace, error};
use std::mem;

const MAX_STACK_FRAMES: usize = 100;

/// Masks the upper bits of addresses on aarch64 platforms to handle garbage bits
#[cfg(target_arch = "aarch64")]
fn mask_aarch64_addresses(
    stack_frame: &mut STACKFRAME64,
    raw_context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    // Note: 0x000007FFFFFFFFFF is a super stupid fix, however on my machine it adds garbage
    // to the upper bits on aarch64. Github's CI runners are ok.
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces

    // For debugging, just print the context and see the values
    // trace!("context: {:#?}", crate::protocol::ThreadContext::Win32RawContext(raw_context));

    const MAX_ADDRESS: u64 = 0x00007FFFFFFFFFFFu64;
    stack_frame.AddrPC.Offset &= MAX_ADDRESS;
    unsafe {
        raw_context.Pc &= MAX_ADDRESS;
        raw_context.Anonymous.Anonymous.Lr &= MAX_ADDRESS;
    }
}

/// Get the call stack for a specific thread within a debugged process
pub fn get_call_stack(
    platform: &mut WindowsPlatform,
    pid: u32,
    tid: u32,
) -> Result<Vec<CallFrame>, PlatformError> {
    debug!(pid, tid, "Getting call stack");
    
    // Get the process and thread information
    let process = platform.get_process(pid)?;
    let process_handle = process.process_handle.0;
    let architecture = process.architecture;
    
    // Get the list of modules for address validation
    let modules = process.module_manager.list_modules();
    
    // Get the thread handle from the thread manager
    let thread_handle = process.thread_manager.get_thread_handle(tid)
        .filter(|h| !h.is_null())
        .ok_or_else(|| PlatformError::OsError(format!("Failed to get thread handle for {}", tid)))?;

    // Get the thread context
    let context = platform.get_thread_context(pid, tid)?;
    
    // Initialize the stack frame and extract the raw context
    let (mut stack_frame, mut raw_context) = initialize_stack_frame_with_context(&context, architecture)?;
    
    // Walk the stack
    let mut frames = Vec::new();
    let machine_type = match architecture {
        Architecture::X64 => IMAGE_FILE_MACHINE_AMD64 as u32,
        Architecture::Arm64 => IMAGE_FILE_MACHINE_ARM64 as u32,
    };
    
    for i in 0..MAX_STACK_FRAMES {
        let result = unsafe {
            StackWalk64(
                machine_type,
                process_handle,
                thread_handle,
                &mut stack_frame,
                &mut raw_context as *mut _ as *mut _,
                Some(read_process_memory_proc),
                Some(SymFunctionTableAccess64),
                Some(SymGetModuleBase64),
                None,
            )
        };
        
        if result == FALSE {
            debug!("StackWalk64 returned FALSE, end of stack after {} frames", i);
            break;
        }
        
        #[cfg(target_arch = "aarch64")]
        mask_aarch64_addresses(&mut stack_frame, &mut raw_context);
        
        let (instruction_pointer, stack_pointer, frame_pointer) = (
            stack_frame.AddrPC.Offset,
            stack_frame.AddrStack.Offset,
            stack_frame.AddrFrame.Offset
        );
        
        // Skip invalid frames
        if instruction_pointer == 0 {
            debug!("Skipping frame with IP=0");
            continue;
        }
        trace!("Frame {}: IP=0x{:016x}, SP=0x{:016x}, FP=0x{:016x}", i, instruction_pointer, stack_pointer, frame_pointer);
        
        // Validate that the instruction pointer is within a loaded module
        // Don't issue a warning if there is less than 2 modules (main executable is only loaded when process is started, but address is in ntdll)
        if modules.len() > 1 && !is_valid_instruction_pointer(instruction_pointer, &modules) {
            panic!("Instruction pointer 0x{:016x} not in any loaded module. Including frame without symbols.", instruction_pointer);
        }
        
        // Resolve symbol information
        let symbol_info = if is_valid_instruction_pointer(instruction_pointer, &modules) {
            match platform.resolve_address_to_symbol(pid, instruction_pointer) {
                Ok(Some((module_path, symbol, offset_from_symbol))) => {
                    //debug!("Frame {}: resolved symbol {}+0x{:x} in module {}", 
                    //       i, symbol.name, offset_from_symbol, module_path);
                    
                    Some(SymbolInfo {
                        module_name: module_path,
                        symbol_name: symbol.name,
                        offset: offset_from_symbol,
                    })
                }
                Ok(None) => {
                    //debug!("Frame {}: no symbol found for address 0x{:016x}", i, instruction_pointer);
                    None
                }
                Err(e) => {
                    warn!("Frame {}: symbol resolution failed: {}", i, e);
                    None
                }
            }
        } else {
            None
        };
        
        debug!("Frame {}: IP=0x{:016x}, SP=0x{:016x}, FP=0x{:016x}", 
               i, instruction_pointer, stack_pointer, frame_pointer);
        
        frames.push(CallFrame {
            instruction_pointer,
            stack_pointer,
            frame_pointer,
            symbol: symbol_info,
        });
    }
    
    debug!(pid, tid, frame_count = frames.len(), "Retrieved call stack");
    Ok(frames)
}

/// Check if an instruction pointer is within the bounds of any loaded module
fn is_valid_instruction_pointer(ip: u64, modules: &[crate::protocol::ModuleInfo]) -> bool {
    modules.iter().any(|module| {
        let module_end = module.base + module.size.unwrap_or(0);
        ip >= module.base && ip < module_end
    })
}

/// Initialize the STACKFRAME_EX structure and return both the frame and the raw context
fn initialize_stack_frame_with_context(
    context: &crate::protocol::ThreadContext,
    architecture: Architecture,
) -> Result<(STACKFRAME64, windows_sys::Win32::System::Diagnostics::Debug::CONTEXT), PlatformError> {
    let mut stack_frame: STACKFRAME64 = unsafe { mem::zeroed() };
    
    match context {
        #[cfg(windows)]
        crate::protocol::ThreadContext::Win32RawContext(ctx) => {
            #[cfg(target_arch = "x86_64")]
            {
                if architecture != Architecture::X64 {
                    return Err(PlatformError::NotImplemented);
                }

                stack_frame.AddrPC.Offset = ctx.Rip;
                stack_frame.AddrPC.Mode = AddrModeFlat;
                stack_frame.AddrStack.Offset = ctx.Rsp;
                stack_frame.AddrStack.Mode = AddrModeFlat;
                //stack_frame.AddrFrame.Offset = ctx.Rbp;
                //stack_frame.AddrFrame.Mode = AddrModeFlat;
                stack_frame.AddrReturn.Offset = 0;
                stack_frame.AddrReturn.Mode = AddrModeFlat;

                debug!("Initialized stack frame: IP=0x{:016x}, SP=0x{:016x}, FP=0x{:016x}", 
                       ctx.Rip, ctx.Rsp, ctx.Rbp);
                       
                Ok((stack_frame, *ctx))
            }
            #[cfg(target_arch = "aarch64")]
            {
                if architecture != Architecture::Arm64 {
                    return Err(PlatformError::NotImplemented);
                }

                stack_frame.AddrPC.Offset = ctx.Pc;
                stack_frame.AddrPC.Mode = AddrModeFlat;
                stack_frame.AddrStack.Offset = ctx.Sp;
                stack_frame.AddrStack.Mode = AddrModeFlat;
                // The CONTEXT struct for ARM64 has an anonymous union.
                // We need to access Fp (Frame Pointer) and Lr (Link Register) through it.
                // Fp is X29, Lr is X30.
                unsafe {
                    stack_frame.AddrFrame.Offset = ctx.Anonymous.Anonymous.Fp;
                    stack_frame.AddrReturn.Offset = ctx.Anonymous.Anonymous.Lr;
                }
                stack_frame.AddrFrame.Mode = AddrModeFlat;
                stack_frame.AddrReturn.Mode = AddrModeFlat;

                debug!("Initialized stack frame: IP=0x{:016x}, SP=0x{:016x}, FP=0x{:016x}", 
                       ctx.Pc, ctx.Sp, unsafe { ctx.Anonymous.Anonymous.Fp });
                       
                Ok((stack_frame, *ctx))
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                Err(PlatformError::NotImplemented)
            }
        }
    }
}

/// Custom memory reading function for StackWalk2
unsafe extern "system" fn read_process_memory_proc(
    process: HANDLE,
    base_address: u64,
    buffer: *mut core::ffi::c_void,
    size: u32,
    number_of_bytes_read: *mut u32,
) -> BOOL {
    let mut bytes_read_sz: usize = 0;
    let ok = unsafe { ReadProcessMemory(
        process,
        base_address as *const core::ffi::c_void,
        buffer,
        size as usize,
        &mut bytes_read_sz as *mut usize,
    ) };

    if !number_of_bytes_read.is_null() {
        let clamped = bytes_read_sz.min(u32::MAX as usize) as u32;
        unsafe { *number_of_bytes_read = clamped; }
    }

    if ok == 0 {
        let err = unsafe { GetLastError() };
        // treat ERROR_PARTIAL_COPY  with some bytes read as success for StackWalk64
        if err == ERROR_PARTIAL_COPY && bytes_read_sz > 0 {
            error!("ReadProcessMemory ERROR_PARTIAL_COPY at 0x{:016x}: size {}", base_address, bytes_read_sz);
            return 0;
        }
    }
    ok
}