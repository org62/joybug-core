//! Reading a function's arguments at its entry, per calling convention.

use crate::interfaces::PlatformError;
use crate::protocol::ThreadContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Windows x64: rcx, rdx, r8, r9, then the stack above the 32-byte shadow space.
    Win64,
    /// System V AMD64 (Linux, macOS): rdi, rsi, rdx, rcx, r8, r9, then the stack.
    SysV64,
    /// 32-bit cdecl/stdcall: everything on the stack, 4 bytes each.
    Cdecl32,
    /// ARM64 AAPCS64: x0-x7, then the stack.
    Aapcs64,
}

/// The first `count` arguments of the function the thread is entering.
pub fn function_arguments(
    cc: CallingConvention,
    context: &ThreadContext,
    count: usize,
    read: impl Fn(u64, usize) -> Result<Vec<u8>, PlatformError>,
) -> Result<Vec<u64>, PlatformError> {
    let mut arguments = Vec::with_capacity(count);
    match (cc, context) {
        #[cfg(target_arch = "x86_64")]
        (CallingConvention::Win64, ThreadContext::Win32RawContext(ctx)) => {
            // First 4 arguments are in registers: RCX, RDX, R8, R9
            if count > 0 { arguments.push(ctx.Rcx); }
            if count > 1 { arguments.push(ctx.Rdx); }
            if count > 2 { arguments.push(ctx.R8); }
            if count > 3 { arguments.push(ctx.R9); }

            // Subsequent arguments are on the stack
            if count > 4 {
                let stack_ptr = ctx.Rsp;
                // The first stack argument is at RSP+0x28 (after return address and space for register args)
                let stack_args_ptr = stack_ptr + 0x28;
                let num_stack_args = count - 4;
                let stack_data = read(stack_args_ptr, num_stack_args * 8)?;
                for chunk in stack_data.chunks_exact(8) {
                    arguments.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        (CallingConvention::SysV64, ThreadContext::Win32RawContext(ctx)) => {
            // First 6 arguments are in registers: RDI, RSI, RDX, RCX, R8, R9
            for (i, value) in [ctx.Rdi, ctx.Rsi, ctx.Rdx, ctx.Rcx, ctx.R8, ctx.R9].into_iter().enumerate() {
                if count > i { arguments.push(value); }
            }
            // The rest sit right above the return address; no shadow space.
            if count > 6 {
                let num_stack_args = count - 6;
                let stack_data = read(ctx.Rsp + 8, num_stack_args * 8)?;
                for chunk in stack_data.chunks_exact(8) {
                    arguments.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        // 32-bit cdecl/stdcall: every argument is on the stack, 4 bytes each,
        // starting just above the return address.
        (CallingConvention::Cdecl32, ThreadContext::Wow64RawContext(ctx)) => {
            if count > 0 {
                let stack_data = read(ctx.Esp as u64 + 4, count * 4)?;
                for chunk in stack_data.chunks_exact(4) {
                    arguments.push(u32::from_le_bytes(chunk.try_into().unwrap()) as u64);
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        (CallingConvention::Aapcs64, ThreadContext::Win32RawContext(ctx)) => {
            // First 8 arguments are in registers X0-X7
            for i in 0..std::cmp::min(count, 8) {
                arguments.push(unsafe { ctx.Anonymous.X[i] });
            }

            // Subsequent arguments are on the stack
            if count > 8 {
                let stack_ptr = ctx.Sp;
                let num_stack_args = count - 8;
                let stack_data = read(stack_ptr, num_stack_args * 8)?;
                for chunk in stack_data.chunks_exact(8) {
                    arguments.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        _ => return Err(PlatformError::NotImplemented),
    }
    Ok(arguments)
}
