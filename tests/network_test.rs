#![allow(unused_imports)]
#![cfg(windows)]

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use std::process::Command;
use joybug_basics_tests1::protocol::{DebuggerRequest, DebuggerResponse};
use joybug_basics_tests1::protocol_io::{send_request, receive_response};

#[tokio::test]
async fn test_network_protocol_cmd_echo() {
    joybug_basics_tests1::init_tracing();
    // Start the server in a background task
    tokio::spawn(async move {
        joybug_basics_tests1::server::run_server().await.unwrap();
    });

    // Connect as a client
    let mut stream = TcpStream::connect("127.0.0.1:9000").await.expect("connect");

    // Use the enum directly
    let launch = DebuggerRequest::Launch { command: "cmd.exe /c echo test".to_string() };
    send_request(&mut stream, &launch).await.unwrap();

    loop {
        let resp = receive_response(&mut stream).await.unwrap();

        match &resp {
            DebuggerResponse::Event { event } => {
                println!("Continue response: Event {{ event: {} }}", event);
                match event {
                    joybug_basics_tests1::protocol::DebugEvent::Output { pid, tid, output } => {
                        println!("Received output: {}", output);
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut stream, &cont).await.unwrap();
                    },
                    joybug_basics_tests1::protocol::DebugEvent::ProcessCreated { pid, tid, .. } => {
                        println!("Process created: pid: {}, tid: {}", pid, tid);
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut stream, &cont).await.unwrap();
                    },
                    joybug_basics_tests1::protocol::DebugEvent::ProcessExited { pid, exit_code } => {
                        println!("Process exited: pid: {}, exit_code: {}", pid, exit_code);
                        break;
                    },
                    joybug_basics_tests1::protocol::DebugEvent::DllLoaded { pid, tid, .. } => {
                        println!("Dll loaded: pid: {}, tid: {}", pid, tid);
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut stream, &cont).await.unwrap();
                    },
                    joybug_basics_tests1::protocol::DebugEvent::DllUnloaded { pid, tid, .. } => {
                        println!("Dll unloaded: pid: {}, tid: {}", pid, tid);
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut stream, &cont).await.unwrap();
                    },
                    joybug_basics_tests1::protocol::DebugEvent::ThreadExited { pid, tid, exit_code } => {
                        println!("Thread exited: pid: {}, tid: {}, exit_code: {}", pid, tid, exit_code);
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut stream, &cont).await.unwrap();
                    },
                    joybug_basics_tests1::protocol::DebugEvent::ThreadCreated { pid, tid, .. } => {
                        println!("Thread created: pid: {}, tid: {}", pid, tid);
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut stream, &cont).await.unwrap();
                    },
                    joybug_basics_tests1::protocol::DebugEvent::Breakpoint { pid, address, tid, .. } => {
                        // Read thread context and check RIP
                        let get_ctx_req = DebuggerRequest::GetThreadContext { pid: *pid, tid: *tid };
                        send_request(&mut stream, &get_ctx_req).await.unwrap();
                        let resp = receive_response(&mut stream).await.unwrap();
                        if let DebuggerResponse::ThreadContext { context } = resp {
                            match context {
                                joybug_basics_tests1::protocol::ThreadContext::X64 { regs } => {
                                    let mut rip = regs.rip;
                                    #[cfg(target_arch = "x86_64")]
                                    {
                                        rip -= 1;
                                    }
                                    if rip != *address {
                                        println!("Breakpoint address: {:#x}", address);
                                        assert_eq!(regs.rip, *address, "RIP should match breakpoint address");
                                    }
                                },
                                _ => panic!("Expected x64 context"),
                            }
                        }
                        else {
                            panic!("Expected ThreadContext response, got: {:?}", resp);
                        }
                        // Read memory at breakpoint
                        let read_req = DebuggerRequest::ReadMemory { pid: *pid, address: *address, size: 1 };
                        send_request(&mut stream, &read_req).await.unwrap();
                        let resp = receive_response(&mut stream).await.unwrap();
                        if let DebuggerResponse::MemoryData { data } = resp {
                            #[cfg(target_arch = "x86_64")]
                            {
                                assert_eq!(data[0], 0xCC, "Expected int3 at breakpoint");
                                // Overwrite with NOP
                                let write_req = DebuggerRequest::WriteMemory { pid: *pid, address: *address, data: vec![0x90] };
                                send_request(&mut stream, &write_req).await.unwrap();
                                let resp = receive_response(&mut stream).await.unwrap();
                                assert!(matches!(resp, DebuggerResponse::WriteAck));
                                // Confirm overwrite
                                let read_req = DebuggerRequest::ReadMemory { pid: *pid, address: *address, size: 1 };
                                send_request(&mut stream, &read_req).await.unwrap();
                                let resp = receive_response(&mut stream).await.unwrap();
                                if let DebuggerResponse::MemoryData { data } = resp {
                                    assert_eq!(data[0], 0x90, "Expected NOP at breakpoint after write");
                                }
                                else {
                                    panic!("Expected MemoryData response, got: {:?}", resp);
                                }
                            }
                            #[cfg(target_arch = "aarch64")]
                            {
                                panic!("AArch64 breakpoint not implemented");
                            }
                        }
                        let cont = DebuggerRequest::Continue { pid: *pid, tid: *tid };
                        send_request(&mut stream, &cont).await.unwrap();
                    },
                    _ => {
                        panic!("Unexpected event: {:?}", event);
                    },
                }
            },
            DebuggerResponse::Error { .. } => break,
            _ => println!("Continue response: {:?}", resp),
        }
    }
} 