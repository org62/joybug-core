#![cfg(windows)]

use joybug2::protocol::ThreadContext;
use joybug2::protocol_io::DebugSession;
use joybug2::interfaces::{Architecture, InstructionFormatter};
use std::thread;
use tokio;

/// Clean, simple test state for tracking events
struct TestState {
    initial_breakpoint_hit: bool,
}

impl TestState {
    fn new() -> Self {
        Self {
            initial_breakpoint_hit: false,
        }
    }
}

#[test]
fn test_debug_client_ctx_mem_test() {
    joybug2::init_tracing();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });

    let final_state = DebugSession::new(TestState::new(), None)
        .expect("connect")
        .on_initial_breakpoint(|session, pid, tid, address| {
            session.state.initial_breakpoint_hit = true;

            // Try to resolve the breakpoint address to a symbol
            let (module_path, symbol, offset) = session.resolve_address_to_symbol(pid, address).unwrap();
            if let (Some(module), Some(sym), Some(off)) = (module_path, symbol, offset) {
                println!("Breakpoint at 0x{:X} resolved to symbol '{}' in module '{}' + 0x{:X}", address, sym.name, module, off);
                // Assert that the symbol name is LdrpDoDebuggerBreak
                assert_eq!(sym.name, "LdrpDoDebuggerBreak", "Expected symbol name to be LdrpDoDebuggerBreak");
            } else {
                panic!("Expected symbol information to be available for breakpoint at 0x{:X}", address);
            }

            // Disassemble instructions around the breakpoint
            println!("Disassembling instructions around breakpoint at 0x{:X}", address);

            let arch = if cfg!(target_arch = "x86_64") { Architecture::X64 } else { Architecture::Arm64 };
            let instructions = session.disassemble_memory(pid, address, 10, arch).unwrap();
            println!("Instructions from memory disassembly:");
            println!("{}", instructions.format_disassembly());

            // Request thread context
            let context = session.get_thread_context(pid, tid).unwrap();
            match context {
                joybug2::protocol::ThreadContext::Win32RawContext(ctx) => {
                    // Try round-trip: set the same context back
                    session.set_thread_context(pid, tid, ThreadContext::Win32RawContext(ctx.clone())).unwrap();
                }
                #[cfg(not(windows))]
                _ => {
                    panic!("Unexpected thread context type");
                }
            }

            // Read memory at breakpoint, on x64 read 1 byte, on arm64 read 4 bytes
            let read_size = if cfg!(target_arch = "x86_64") { 1 } else { 4 };

            let data = session.read_memory(pid, address, read_size).unwrap();
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(data[0], 0xCC, "Expected int3 at breakpoint");
                // Overwrite with NOP
                session.write_memory(pid, address, vec![0x90]).unwrap();
                // Confirm overwrite
                let data = session.read_memory(pid, address, 1).unwrap();
                assert_eq!(data[0], 0x90, "Expected NOP at breakpoint after write");
            }
            #[cfg(target_arch = "aarch64")]
            {
                // d43e0000 brk #0xF000
                // d503201f nop
                let nop_bytes = vec![0x1f, 0x20, 0x03, 0xd5];
                let brk_bytes = vec![0x00, 0x00, 0x3e, 0xd4];
                assert_eq!(data, brk_bytes);
                // Overwrite with NOP
                session.write_memory(pid, address, nop_bytes.clone()).unwrap();
                // Confirm overwrite
                let data = session.read_memory(pid, address, read_size).unwrap();
                assert_eq!(data, nop_bytes, "Expected NOP at breakpoint after write");
                println!("data: {:?}", data);
            }
            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("debug loop");

    assert!(final_state.initial_breakpoint_hit, "Should have handled a breakpoint event");
} 