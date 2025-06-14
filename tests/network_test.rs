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
    // Start the server in a background task
    tokio::spawn(async move {
        joybug_basics_tests1::server::run_server().await.unwrap();
    });

    // Connect as a client
    let mut stream = TcpStream::connect("127.0.0.1:9000").await.expect("connect");

    // Use the enum directly
    let launch = DebuggerRequest::Launch { command: "cmd.exe /c echo test".to_string() };
    send_request(&mut stream, &launch).await.unwrap();
    let resp = receive_response(&mut stream).await.unwrap();
    println!("Launch response: {:?}", resp);
    match resp {
        DebuggerResponse::Event { ref event } => {
            match event {
                joybug_basics_tests1::protocol::DebugEvent::ProcessStarted { .. } => {},
                _ => panic!("Expected ProcessStarted event on launch, got: {}", event),
            }
        },
        _ => panic!("Expected Event response on launch, got: {:?}", resp),
    }

    loop {
        let cont = DebuggerRequest::Continue;
        send_request(&mut stream, &cont).await.unwrap();
        let resp = receive_response(&mut stream).await.unwrap();
        match &resp {
            DebuggerResponse::Event { event } => {
                println!("Continue response: Event {{ event: {} }}", event);
                match event {
                    joybug_basics_tests1::protocol::DebugEvent::Output { output } => {
                        println!("Received output: {}", output);
                    },
                    joybug_basics_tests1::protocol::DebugEvent::ProcessExited { .. } => {
                        println!("Process exited");
                        break;
                    },
                    joybug_basics_tests1::protocol::DebugEvent::Breakpoint { pid, address, .. } => {
                        // Read memory at breakpoint
                        let read_req = DebuggerRequest::ReadMemory { pid: *pid, address: *address, size: 1 };
                        send_request(&mut stream, &read_req).await.unwrap();
                        let resp = receive_response(&mut stream).await.unwrap();
                        if let DebuggerResponse::MemoryData { data } = resp {
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
                        }
                    },
                    _ => {},
                }
            },
            DebuggerResponse::Error { .. } => break,
            _ => println!("Continue response: {:?}", resp),
        }
    }
} 