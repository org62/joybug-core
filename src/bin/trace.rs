//! CLI tool for generating Tenet traces
//!
//! Usage: trace [OPTIONS] <COMMAND>
//!
//! Examples:
//!   trace --start 0x140001000 --end 0x140001100 --backend emu "program.exe"
//!   trace --start 0x140001000 --limit 1000 --backend trap "program.exe arg1 arg2"

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::exit;

use clap::Parser;
use joybug2::protocol::{
    DebuggerRequest, DebuggerResponse, EmulationMode, TraceExitCondition,
};
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

#[derive(Parser, Debug)]
#[command(name = "trace")]
#[command(about = "Generate Tenet traces from executable programs")]
struct Args {
    /// Target command to execute (program and arguments)
    #[arg(required = true)]
    command: String,

    /// Trace start address (hex, e.g., 0x140001000)
    /// If not specified, tracing starts at initial breakpoint
    #[arg(short = 's', long, value_parser = parse_hex)]
    start: Option<u64>,

    /// Trace end address (hex, e.g., 0x140001100)
    /// Tracing stops when this address is reached
    #[arg(short = 'e', long, value_parser = parse_hex)]
    end: Option<u64>,

    /// Maximum number of instructions to trace
    #[arg(short = 'l', long, default_value = "10000")]
    limit: usize,

    /// Trace backend: "emu" (emulator) or "trap" (trap-flag)
    #[arg(short = 'b', long, default_value = "emu")]
    backend: String,

    /// Output file (default: stdout)
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Server address (default: auto-select port)
    #[arg(long)]
    server: Option<String>,
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("Invalid hex: {}", e))
}

/// State for the trace session
struct TraceState {
    start_address: Option<u64>,
    end_address: Option<u64>,
    max_instructions: usize,
    backend: String,
    trace_text: Option<String>,
    error: Option<String>,
    trace_complete: bool,
}

impl TraceState {
    fn new(args: &Args) -> Self {
        Self {
            start_address: args.start,
            end_address: args.end,
            max_instructions: args.limit,
            backend: args.backend.clone(),
            trace_text: None,
            error: None,
            trace_complete: false,
        }
    }
}

fn main() {
    let args = Args::parse();

    // Validate backend
    if args.backend != "emu" && args.backend != "trap" {
        eprintln!("Error: backend must be 'emu' or 'trap'");
        exit(1);
    }

    // Start server
    let server_addr = args.server.clone().unwrap_or_else(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port");
        let addr = listener.local_addr().unwrap().to_string();

        // Start server in background with tokio runtime
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                if let Err(e) = joybug2::server::run_server_with_std_listener(
                    listener,
                    std::future::pending::<()>(),
                ).await {
                    eprintln!("Server error: {}", e);
                }
            });
        });

        // Give server time to start
        std::thread::sleep(std::time::Duration::from_millis(100));
        addr
    });

    eprintln!("Trace CLI - Backend: {}", args.backend);
    eprintln!("Server: {}", server_addr);
    eprintln!("Command: {}", args.command);
    if let Some(start) = args.start {
        eprintln!("Start address: 0x{:X}", start);
    }
    if let Some(end) = args.end {
        eprintln!("End address: 0x{:X}", end);
    }
    eprintln!("Max instructions: {}", args.limit);
    eprintln!();

    // Run trace session
    let final_state = DebugSession::new(TraceState::new(&args), Some(&server_addr))
        .expect("Failed to connect to server")
        .on_initial_breakpoint(|session, pid, tid, address| {
            eprintln!("Initial breakpoint at 0x{:016X}", address);

            // Determine trace start point
            let trace_start = session.state.start_address.unwrap_or(address);

            // If start address is different from current, set breakpoint and continue
            if trace_start != address {
                eprintln!("Setting breakpoint at start address 0x{:016X}...", trace_start);
                session.set_breakpoint_at(pid, trace_start, None, |session, pid, tid, address| {
                    eprintln!("Reached trace start address 0x{:016X}", address);
                    run_trace(session, pid, tid)?;
                    Ok(BreakpointDecision::Remove)
                })?;
                return Ok(());
            }

            // Start tracing immediately
            run_trace(session, pid, tid)?;
            Ok(())
        })
        .on_event(|session, _event| {
            // Stop the session once trace is complete
            if session.state.trace_complete {
                Ok(false)
            } else {
                Ok(true)
            }
        })
        .on_process_exited(|_session, pid, exit_code| {
            eprintln!("Process {} exited with code {}", pid, exit_code);
            Ok(())
        })
        .launch(args.command.clone())
        .expect("Debug session failed");

    // Handle result
    if let Some(error) = final_state.error {
        eprintln!("Error: {}", error);
        exit(1);
    }

    if let Some(trace_text) = final_state.trace_text {
        // Output trace
        if let Some(output_path) = args.output {
            std::fs::write(&output_path, &trace_text)
                .expect("Failed to write output file");
            eprintln!("Trace written to: {}", output_path.display());
        } else {
            // Write to stdout
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(trace_text.as_bytes()).expect("Failed to write to stdout");
        }
    } else {
        eprintln!("No trace captured");
        exit(1);
    }
}

fn run_trace(
    session: &mut DebugSession<TraceState>,
    pid: u32,
    tid: u32,
) -> Result<(), anyhow::Error> {
    let exit_condition = if let Some(end_addr) = session.state.end_address {
        TraceExitCondition::ReachAddress(end_addr)
    } else {
        TraceExitCondition::InstructionLimit(session.state.max_instructions)
    };

    let max_instructions = session.state.max_instructions;
    let backend = session.state.backend.clone();

    eprintln!("Starting {} trace (max {} instructions)...", backend, max_instructions);

    let response = if backend == "emu" {
        // Use emulator backend
        let req = DebuggerRequest::EmulateInstructions {
            pid,
            tid,
            max_instructions,
            mode: EmulationMode::InstructionTrace,
            exit_condition: Some(exit_condition.clone()),
        };
        session.send_and_receive(&req)?
    } else {
        // Use trap-flag backend
        let req = DebuggerRequest::TraceInstructions {
            pid,
            tid,
            exit_condition,
            max_instructions,
        };
        session.send_and_receive(&req)?
    };

    match response {
        DebuggerResponse::TenetTrace {
            trace_text,
            stop_reason,
            trace_time_us,
        } => {
            let line_count = trace_text.lines().count();
            eprintln!(
                "Trace complete: {} lines, {} us, reason: {}",
                line_count, trace_time_us, stop_reason
            );
            session.state.trace_text = Some(trace_text);
            session.state.trace_complete = true;
        }
        DebuggerResponse::Error { message } => {
            session.state.error = Some(format!("Trace failed: {}", message));
            session.state.trace_complete = true;
        }
        other => {
            session.state.error = Some(format!("Unexpected response: {:?}", other));
            session.state.trace_complete = true;
        }
    }

    Ok(())
}
