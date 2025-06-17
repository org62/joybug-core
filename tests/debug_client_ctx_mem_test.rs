#![cfg(windows)]

use joybug2::protocol::{DebuggerResponse, DebugEvent, DebuggerRequest, ThreadContext};
use joybug2::protocol_io::DebugClient;
use std::thread;
use tokio;

#[test]
fn test_debug_client_breakpoint_context() {
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
                    // Read memory at breakpoint
                    let read_req = DebuggerRequest::ReadMemory { pid, address, size: 1 };
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
                            panic!("AArch64 breakpoint not implemented");
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