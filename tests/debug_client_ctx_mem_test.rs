#![cfg(windows)]

use joybug2::protocol::{DebuggerResponse, DebugEvent, DebuggerRequest, ThreadContext};
use joybug2::protocol_io::DebugClient;
use joybug2::interfaces::{Architecture, InstructionFormatter};
use std::thread;
use tokio;

#[test]
fn test_debug_client_ctx_mem_test() {
    joybug2::init_tracing();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(joybug2::server::run_server()).unwrap();
    });
    let mut client = DebugClient::connect(None).expect("connect");
    let mut handled_breakpoint = false;

    client.launch("cmd.exe /c echo test".to_string(), &mut handled_breakpoint, |client, handled_breakpoint, resp| {
        match resp {
            DebuggerResponse::Event { event } => {
                if let DebugEvent::Breakpoint { pid, tid, address } = event {
                    // Try to resolve the breakpoint address to a symbol
                    let symbol_req = DebuggerRequest::ResolveAddressToSymbol { pid, address };
                    let symbol_resp = client.send_and_receive(&symbol_req).unwrap();
                    match symbol_resp {
                        DebuggerResponse::AddressSymbol { module_path, symbol, offset } => {
                            if let (Some(module), Some(sym), Some(off)) = (module_path, symbol, offset) {
                                println!("Breakpoint at 0x{:X} resolved to symbol '{}' in module '{}' + 0x{:X}", address, sym.name, module, off);
                                // Assert that the symbol name is LdrpDoDebuggerBreak
                                assert_eq!(sym.name, "LdrpDoDebuggerBreak", "Expected symbol name to be LdrpDoDebuggerBreak");
                            } else {
                                panic!("Expected symbol information to be available for breakpoint at 0x{:X}", address);
                            }
                        }
                        _ => panic!("Failed to resolve symbol for breakpoint at 0x{:X}", address),
                    }

                    // Disassemble instructions around the breakpoint
                    println!("Disassembling instructions around breakpoint at 0x{:X}", address);

                    let arch = if cfg!(target_arch = "x86_64") { Architecture::X64 } else { Architecture::Arm64 };
                    let disasm_req = DebuggerRequest::DisassembleMemory { pid, address, count: 10, arch };
                    let resp = client.send_and_receive(&disasm_req).unwrap();
                    if let DebuggerResponse::Instructions { instructions } = resp {
                        println!("Instructions from memory disassembly:");
                        println!("{}", instructions.format_disassembly());
                    } else {
                        println!("Failed to disassemble memory: {:?}", resp);
                    }

                    // Request thread context
                    let req = DebuggerRequest::GetThreadContext { pid, tid };
                    let resp = client.send_and_receive(&req).unwrap();
                    if let DebuggerResponse::ThreadContext { context } = resp {
                        match context {
                            #[cfg(windows)]
                            joybug2::protocol::ThreadContext::Win32RawContext(ctx) => {
                                // Try round-trip: set the same context back
                                let set_ctx_req = DebuggerRequest::SetThreadContext { pid, tid, context: ThreadContext::Win32RawContext(ctx.clone()) };
                                let resp = client.send_and_receive(&set_ctx_req).unwrap();
                                println!("resp: {:?}", resp);
                                assert!(matches!(resp, DebuggerResponse::SetContextAck));
                            }
                        }
                    } else {
                        panic!("Expected ThreadContext response");
                    }

                    // Read memory at breakpoint, on x64 read 1 byte, on arm64 read 4 bytes
                    let read_size = if cfg!(target_arch = "x86_64") { 1 } else { 4 };

                    let read_req = DebuggerRequest::ReadMemory { pid, address, size: read_size };
                    let resp = client.send_and_receive(&read_req).unwrap();
                    if let DebuggerResponse::MemoryData { data } = resp {
                        #[cfg(target_arch = "x86_64")]
                        {
                            assert_eq!(data[0], 0xCC, "Expected int3 at breakpoint");
                            // Overwrite with NOP
                            let write_req = DebuggerRequest::WriteMemory { pid, address, data: vec![0x90] };
                            let resp = client.send_and_receive(&write_req).unwrap();
                            assert!(matches!(resp, DebuggerResponse::WriteAck));
                            // Confirm overwrite
                            let read_req = DebuggerRequest::ReadMemory { pid, address, size: 1 };
                            let resp = client.send_and_receive(&read_req).unwrap();
                            if let DebuggerResponse::MemoryData { data } = resp {
                                assert_eq!(data[0], 0x90, "Expected NOP at breakpoint after write");
                            } else {
                                panic!("Expected MemoryData response, got: {:?}", resp);
                            }
                        }
                        #[cfg(target_arch = "aarch64")]
                        {
                            // d43e0000 brk #0xF000
                            // d503201f nop
                            let nop_bytes = vec![0x1f, 0x20, 0x03, 0xd5];
                            let brk_bytes = vec![0x00, 0x00, 0x3e, 0xd4];
                            assert_eq!(data, brk_bytes);
                            // Overwrite with NOP
                            let write_req = DebuggerRequest::WriteMemory { pid, address, data: nop_bytes.clone() };
                            let resp = client.send_and_receive(&write_req).unwrap();
                            assert!(matches!(resp, DebuggerResponse::WriteAck));
                            // Confirm overwrite
                            let read_req = DebuggerRequest::ReadMemory { pid, address, size: read_size };
                            let resp = client.send_and_receive(&read_req).unwrap();
                            if let DebuggerResponse::MemoryData { data } = resp {
                                assert_eq!(data, nop_bytes, "Expected NOP at breakpoint after write");
                                println!("data: {:?}", data);
                            } else {
                                panic!("Expected MemoryData response, got: {:?}", resp);
                            }
                        }
                    }
                    *handled_breakpoint = true;
                    return false; // Stop after handling one breakpoint
                }
            }
            _ => {}
        }
        true
    }).expect("debug loop");

    assert!(handled_breakpoint, "Should have handled a breakpoint event");
} 