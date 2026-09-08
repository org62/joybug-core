use crate::interfaces::{PlatformAPI, Stepper};
use crate::protocol::{DebuggerRequest, DebuggerResponse};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use std::future::{pending, Future};
use std::net::TcpListener as StdTcpListener;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

// Server-side timing stats
static SERVER_RECV_US: AtomicU64 = AtomicU64::new(0);
static SERVER_HANDLE_US: AtomicU64 = AtomicU64::new(0);
static SERVER_SEND_US: AtomicU64 = AtomicU64::new(0);
static SERVER_REQ_COUNT: AtomicUsize = AtomicUsize::new(0);

fn print_server_stats() {
    let count = SERVER_REQ_COUNT.load(Ordering::Relaxed);
    if count > 0 && count % 1000 == 0 {
        let recv = SERVER_RECV_US.load(Ordering::Relaxed) as f64 / 1000.0;
        let handle = SERVER_HANDLE_US.load(Ordering::Relaxed) as f64 / 1000.0;
        let send = SERVER_SEND_US.load(Ordering::Relaxed) as f64 / 1000.0;
        eprintln!("=== SERVER STATS after {} requests ===", count);
        eprintln!("  Receive:  {:>8.2} ms", recv);
        eprintln!("  Handle:   {:>8.2} ms", handle);
        eprintln!("  Send:     {:>8.2} ms", send);
        eprintln!("  Total:    {:>8.2} ms", recv + handle + send);
        eprintln!("======================================");
    }
}

use crate::framed_json_stream::FramedJsonStream;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9000";

fn handle_connection<P>(stream: std::net::TcpStream, platform: Arc<RwLock<P>>)
where
    P: PlatformAPI + Stepper + Send + Sync + 'static,
{
    let mut framed_stream = FramedJsonStream::new(stream);
    let mut scanner = crate::memory_scanner::MemoryScanner::new();
    let mut pointer_scanner = crate::pointer_scanner::PointerScanner::new();
    let mut string_scanner = crate::string_scanner::StringScanner::new();
    // Per-connection value freezes; dropped (which stops all threads) on disconnect.
    let mut freeze_manager = crate::freeze_manager::FreezeManager::new();
    loop {
        let recv_start = Instant::now();
        let req: DebuggerRequest = match framed_stream.receive() {
            Ok(req) => req,
            Err(e) => {
                if let Some(io_err) = e.root_cause().downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                        debug!("Client disconnected");
                        break;
                    }
                }
                error!(?e, "Failed to receive request from client");
                break;
            }
        };
        SERVER_RECV_US.fetch_add(recv_start.elapsed().as_micros() as u64, Ordering::Relaxed);
        debug!(?req, "Received request");
        let handle_start = Instant::now();

        let resp = match req {
            // ---------- Protocol handshake ----------
            DebuggerRequest::Hello { fingerprint, client } => {
                let ours = crate::protocol::PROTOCOL_FINGERPRINT;
                if fingerprint == ours {
                    info!(%client, "client handshake ok (protocol {ours:016x})");
                } else {
                    // Answer anyway so the client can print both sides; it will
                    // disconnect. Serving it would only produce decode errors.
                    warn!(%client, "client protocol fingerprint {fingerprint:016x} != ours {ours:016x}");
                }
                DebuggerResponse::Hello {
                    fingerprint: ours,
                    server: "joybug-core".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }
            }

            // ---------- Server-side dispatch hooks (platform-specific locking) ----------
            DebuggerRequest::Continue { pid, tid, pass_exception } => {
                match P::server_continue(&platform, pid, tid, pass_exception) {
                    Ok(Some(event)) => DebuggerResponse::Event { event },
                    Ok(None) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::TerminateProcess { pid } => {
                info!(pid, "TerminateProcess request received");
                match P::server_terminate(&platform, pid) {
                    Ok(()) => { info!(pid, "TerminateProcess executed successfully"); DebuggerResponse::Ack }
                    Err(e) => { error!(pid, error = %e, "TerminateProcess failed"); DebuggerResponse::Error { message: e.to_string() } }
                }
            }
            DebuggerRequest::FinalizeExitedProcess { pid, tid } => {
                match P::server_finalize_exited_process(&platform, pid, tid) {
                    Ok(()) => { debug!(pid, tid, "Finalized exited process"); DebuggerResponse::Ack }
                    Err(e) => { error!(pid, tid, error = %e, "FinalizeExitedProcess failed"); DebuggerResponse::Error { message: e.to_string() } }
                }
            }
            DebuggerRequest::BreakInto { pid } => {
                match P::server_break_into(&platform, pid) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }

            // ---------- Regular request dispatch ----------
            DebuggerRequest::Attach { pid } => {
                let mut p = platform.write().unwrap();
                match p.attach(pid) {
                    Ok(Some(event)) => DebuggerResponse::Event { event },
                    Ok(None) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::Detach { pid } => {
                let mut p = platform.write().unwrap();
                match p.detach(pid) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::OpenProcess { pid } => {
                let mut p = platform.write().unwrap();
                match p.open_process(pid) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::CloseProcess { pid } => {
                let mut p = platform.write().unwrap();
                match p.close_process(pid) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SetBreakpoint { pid, addr, tid } => {
                let mut p = platform.write().unwrap();
                match p.set_breakpoint(pid, addr, tid) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SetSingleShotBreakpoint { pid, addr } => {
                let mut p = platform.write().unwrap();
                match p.set_single_shot_breakpoint(pid, addr) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::RemoveBreakpoint { pid, addr } => {
                let mut p = platform.write().unwrap();
                match p.remove_breakpoint(pid, addr) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::StartCodeCoverage { pid, addrs, limit } => {
                let mut p = platform.write().unwrap();
                match p.start_code_coverage(pid, &addrs, limit) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetCodeCoverage { pid } => {
                let p = platform.read().unwrap();
                match p.get_code_coverage(pid) {
                    Ok(hits) => DebuggerResponse::CoverageResults { hits },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::StopCodeCoverage { pid } => {
                let mut p = platform.write().unwrap();
                match p.stop_code_coverage(pid) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::StartWatchpointTrace { pid, addr, bp_type, size } => {
                let mut p = platform.write().unwrap();
                match p.start_watchpoint_trace(pid, addr, bp_type, size) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetWatchpointAccesses { pid, addr } => {
                let p = platform.read().unwrap();
                match p.get_watchpoint_accesses(pid, addr) {
                    Ok(accesses) => DebuggerResponse::WatchpointAccesses { accesses },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::StopWatchpointTrace { pid, addr } => {
                let mut p = platform.write().unwrap();
                match p.stop_watchpoint_trace(pid, addr) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SetHardwareBreakpoint { pid, addr, bp_type, size } => {
                let mut p = platform.write().unwrap();
                match p.set_hardware_breakpoint(pid, addr, bp_type, size) {
                    Ok(dr_index) => DebuggerResponse::HardwareBreakpointSet { dr_index },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::RemoveHardwareBreakpoint { pid, addr } => {
                let mut p = platform.write().unwrap();
                match p.remove_hardware_breakpoint(pid, addr) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::Launch { command, debug_children, working_directory, environment } => {
                let mut p = platform.write().unwrap();
                match p.launch(&command, debug_children, working_directory.as_deref(), environment.as_deref()) {
                    Ok(Some(event)) => DebuggerResponse::Event { event },
                    Ok(None) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ReadMemory { pid, address, size } => {
                let p = platform.read().unwrap();
                match p.read_memory(pid, address, size) {
                    Ok(data) => DebuggerResponse::MemoryData { data },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::WriteMemory { pid, address, data } => {
                let p = platform.read().unwrap();
                match p.write_memory(pid, address, &data) {
                    Ok(_) => DebuggerResponse::WriteAck,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::AllocateMemory { pid, size, executable } => {
                let p = platform.read().unwrap();
                match p.allocate_memory(pid, size, executable) {
                    Ok(address) => DebuggerResponse::MemoryAllocated { address },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ReadWideString { pid, address, max_len } => {
                let p = platform.read().unwrap();
                match p.read_wide_string(pid, address, max_len) {
                    Ok(data) => DebuggerResponse::WideStringData { data },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetThreadContext { pid, tid } => {
                let p = platform.read().unwrap();
                match p.get_thread_context(pid, tid) {
                    Ok(context) => DebuggerResponse::ThreadContext { context },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SuspendThread { pid, tid } => {
                let p = platform.read().unwrap();
                match p.suspend_thread(pid, tid) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ResumeThread { pid, tid } => {
                let p = platform.read().unwrap();
                match p.resume_thread(pid, tid) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::TerminateThread { pid, tid, exit_code } => {
                let p = platform.read().unwrap();
                match p.terminate_thread(pid, tid, exit_code) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetFunctionArguments { pid, tid, count } => {
                let p = platform.read().unwrap();
                match p.get_function_arguments(pid, tid, count) {
                    Ok(arguments) => DebuggerResponse::FunctionArguments { arguments },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SetThreadContext { pid, tid, context } => {
                let p = platform.read().unwrap();
                match p.set_thread_context(pid, tid, context) {
                    Ok(_) => DebuggerResponse::SetContextAck,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ListModules { pid } => {
                let p = platform.read().unwrap();
                match p.list_modules(pid) {
                    Ok(modules) => DebuggerResponse::ModuleList { modules },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetProcessArchitecture { pid } => {
                let p = platform.read().unwrap();
                match p.process_architecture(pid) {
                    Ok(arch) => DebuggerResponse::ProcessArchitecture { arch },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ListThreads { pid } => {
                let p = platform.read().unwrap();
                match p.list_threads(pid) {
                    Ok(threads) => DebuggerResponse::ThreadList { threads },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ListProcessObjects { pid } => {
                let p = platform.read().unwrap();
                match p.list_process_objects(pid) {
                    Ok(objects) => DebuggerResponse::ProcessObjects { objects },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::CloseRemoteHandle { pid, handle } => {
                let p = platform.read().unwrap();
                match p.close_remote_handle(pid, handle) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SetPrivilege { pid, name, enable } => {
                let p = platform.read().unwrap();
                match p.set_privilege(pid, &name, enable) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SetWindowEnabled { pid, hwnd, enabled } => {
                let p = platform.read().unwrap();
                match p.set_window_enabled(pid, hwnd, enabled) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ListProcesses => {
                let p = platform.read().unwrap();
                match p.list_processes() {
                    Ok(processes) => DebuggerResponse::ProcessList { processes },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::FindSymbol { symbol_name, max_results } => {
                let p = platform.read().unwrap();
                match p.find_symbol(&symbol_name, max_results) {
                    Ok(symbols) => DebuggerResponse::ResolvedSymbolList { symbols },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetSymbolStatus { pid } => {
                let p = platform.read().unwrap();
                match p.get_symbol_status(pid) {
                    Ok(statuses) => DebuggerResponse::SymbolStatusList { statuses },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::LoadPdbFromPath { pid, module_base, pdb_path, force } => {
                let p = platform.read().unwrap();
                match p.load_pdb_from_path(pid, module_base, &pdb_path, force) {
                    Ok(crate::protocol::PdbLoadOutcome::Loaded { symbol_count }) => DebuggerResponse::PdbLoaded { symbol_count },
                    Ok(crate::protocol::PdbLoadOutcome::Mismatch(info)) => DebuggerResponse::PdbMismatch(info),
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::RetrySymbolLoad { pid, module_base } => {
                let p = platform.read().unwrap();
                match p.retry_symbol_load(pid, module_base) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::UnloadModuleSymbols { pid, module_base } => {
                let p = platform.read().unwrap();
                match p.unload_module_symbols(pid, module_base) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SetSymbolDenyList { modules } => {
                let p = platform.read().unwrap();
                match p.set_symbol_deny_list(modules) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::EnumerateCoverageTargets { pid, module_path, sources } => {
                let p = platform.read().unwrap();
                match p.enumerate_coverage_targets(pid, &module_path, &sources) {
                    Ok(targets) => DebuggerResponse::CoverageTargetList { targets },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ListSymbols { module_path } => {
                let p = platform.read().unwrap();
                match p.list_symbols(&module_path) {
                    Ok(symbols) => DebuggerResponse::SymbolList { symbols },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ResolveRvaToSymbol { module_path, rva } => {
                let p = platform.read().unwrap();
                match p.resolve_rva_to_symbol(&module_path, rva) {
                    Ok(symbol) => DebuggerResponse::Symbol { symbol },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ResolveAddressToSymbol { pid, address } => {
                let p = platform.read().unwrap();
                match p.resolve_address_to_symbol(pid, address) {
                    Ok(Some((module_path, symbol, offset))) => DebuggerResponse::AddressSymbol {
                        module_path: Some(module_path),
                        symbol: Some(symbol),
                        offset: Some(offset),
                    },
                    Ok(None) => DebuggerResponse::AddressSymbol {
                        module_path: None,
                        symbol: None,
                        offset: None,
                    },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::TryResolveAddressesToSymbols { pid, addresses } => {
                let p = platform.read().unwrap();
                match p.try_resolve_addresses_to_symbols(pid, &addresses) {
                    Ok(results) => DebuggerResponse::AddressSymbolBatch { results },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SymbolsInRange { pid, start, len, max_results } => {
                let p = platform.read().unwrap();
                match p.symbols_in_range(pid, start, len, max_results) {
                    Ok(symbols) => DebuggerResponse::ResolvedSymbolList { symbols },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ResolveAddressToLine { pid, address } => {
                let p = platform.read().unwrap();
                match p.resolve_address_to_line(pid, address) {
                    Ok(info) => DebuggerResponse::AddressLine { info },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetSourceFileLineMap { pid, module_base, file_path, start_line, end_line } => {
                let p = platform.read().unwrap();
                match p.get_source_file_line_map(pid, module_base, &file_path, start_line, end_line) {
                    Ok((file, entries)) => DebuggerResponse::SourceFileLineMap { file, entries },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ListSourceFiles { pid, module_base } => {
                let p = platform.read().unwrap();
                match p.list_source_files(pid, module_base) {
                    Ok(files) => DebuggerResponse::SourceFileList { files },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ListTypes { pid, module_base, filter, max_results } => {
                let p = platform.read().unwrap();
                match p.list_types(pid, module_base, filter.as_deref(), max_results) {
                    Ok(types) => DebuggerResponse::TypeList { types },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetType { pid, module_base, name } => {
                let p = platform.read().unwrap();
                match p.get_type(pid, module_base, &name) {
                    Ok(layout) => DebuggerResponse::TypeResult { layout },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetTypeByIndex { pid, module_base, index } => {
                let p = platform.read().unwrap();
                match p.get_type_by_index(pid, module_base, index) {
                    Ok(layout) => DebuggerResponse::TypeResult { layout },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetTebAddress { pid, tid } => {
                let p = platform.read().unwrap();
                match p.get_teb_address(pid, tid) {
                    Ok(address) => DebuggerResponse::TebAddress { address },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetPebAddress { pid } => {
                let p = platform.read().unwrap();
                match p.get_peb_address(pid) {
                    Ok(address) => DebuggerResponse::PebAddress { address },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::DisassembleMemory { pid, address, count, arch } => {
                let p = platform.read().unwrap();
                match p.disassemble_memory(pid, address, count, arch) {
                    Ok(instructions) => DebuggerResponse::Instructions { instructions },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetCallStack { pid, tid } => {
                let p = platform.read().unwrap();
                match p.get_call_stack(pid, tid) {
                    Ok(frames) => DebuggerResponse::CallStack { frames },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::GetModuleExtraInfo { pid, module_base } => {
                let p = platform.read().unwrap();
                match p.get_module_extra_info(pid, module_base) {
                    Ok(info) => DebuggerResponse::ModuleExtraInfo { info },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::QueryMemoryRegion { pid, address } => {
                let p = platform.read().unwrap();
                match p.query_memory_region(pid, address) {
                    Ok(info) => DebuggerResponse::MemoryRegionInfo { info },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::EnumerateMemoryRegions { pid } => {
                let p = platform.read().unwrap();
                match p.enumerate_memory_regions(pid) {
                    Ok(regions) => DebuggerResponse::MemoryRegionList { regions },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::Dereference { pid, address, count, reference_base, probe_start } => {
                let p = platform.read().unwrap();
                match p.dereference(pid, address, count, reference_base, probe_start) {
                    Ok(entries) => DebuggerResponse::DereferenceResult { entries },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::DereferenceBatch { pid, addresses, count, reference_base, probe_start } => {
                let p = platform.read().unwrap();
                match p.dereference_batch(pid, &addresses, count, reference_base, probe_start) {
                    Ok(results) => DebuggerResponse::DereferenceBatchResult { results },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::SearchMemory { pid, pattern, max_results } => {
                let p = platform.read().unwrap();
                match p.search_memory(pid, &pattern, max_results) {
                    Ok((addresses, capped)) => DebuggerResponse::MemorySearchResult { addresses, capped },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::WriteMinidump { pid, path, kind } => {
                let p = platform.read().unwrap();
                match p.write_minidump(pid, &path, kind) {
                    Ok(size_bytes) => DebuggerResponse::MinidumpWritten { size_bytes },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::DisassembleFunction { pid, address, max_instructions, arch } => {
                let p = platform.read().unwrap();
                match p.disassemble_function(pid, address, max_instructions, arch) {
                    Ok((instructions, function_start, function_end, function_name)) => {
                        DebuggerResponse::FunctionDisassembly {
                            instructions,
                            function_start,
                            function_end,
                            function_name,
                        }
                    }
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::DisassembleBackward { pid, target, count, arch } => {
                let p = platform.read().unwrap();
                match p.disassemble_backward(pid, target, count, arch) {
                    Ok(instructions) => DebuggerResponse::Instructions { instructions },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::Step { pid, tid, kind } => {
                let mut p = platform.write().unwrap();
                match p.step(pid, tid, kind) {
                    Ok(_) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Event { event: crate::protocol::DebugEvent::StepFailed {
                        pid,
                        tid,
                        kind,
                        message: e.to_string(),
                    }},
                }
            }
            DebuggerRequest::EmulateInstructions { pid, tid, max_instructions, mode, exit_condition, memory_reads } => {
                use crate::protocol::EmulationMode;
                let p = platform.read().unwrap();
                match p.emulate_with_mode(pid, tid, max_instructions, mode, exit_condition, &memory_reads) {
                    Ok(result) => {
                        if mode == EmulationMode::InstructionTrace {
                            let trace_text = crate::tenet_format::traces_to_tenet(
                                &result.register_trace,
                                &result.memory_trace,
                            );
                            DebuggerResponse::TenetTrace {
                                trace_text,
                                stop_reason: format!("{}", result.stop_reason),
                                trace_time_us: result.emulation_time_us,
                                stats_text: result.stats_text,
                                final_pc: Some(result.final_pc),
                                instructions_executed: result.instructions_executed,
                            }
                        } else {
                            DebuggerResponse::EmulationResult {
                                final_pc: result.final_pc,
                                instructions_executed: result.instructions_executed,
                                stop_reason: format!("{}", result.stop_reason),
                                emulation_time_us: result.emulation_time_us,
                                pages_loaded: result.pages_loaded,
                                basic_blocks: result.basic_blocks,
                                stats_text: result.stats_text,
                                memory_snapshots: result.memory_snapshots,
                            }
                        }
                    }
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::ScanMemoryStart { pid, value_type, compare_type, value, value2, alignment, float_tolerance, writable_only, thread_count } => {
                let p = platform.read().unwrap();
                match scanner.start_scan(&*p, pid, value_type, compare_type, value, value2, alignment, float_tolerance, writable_only.unwrap_or(true), thread_count) {
                    Ok((scan_id, match_count, scan_time_us)) => DebuggerResponse::ScanMemoryResult { scan_id, match_count, scan_time_us },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::ScanMemoryNext { scan_id, compare_type, value, value2, float_tolerance } => {
                let p = platform.read().unwrap();
                match scanner.next_scan(&*p, scan_id, compare_type, value, value2, float_tolerance) {
                    Ok((match_count, scan_time_us)) => DebuggerResponse::ScanMemoryResult { scan_id, match_count, scan_time_us },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::ScanMemoryGetResults { scan_id, offset, count } => {
                let p = platform.read().unwrap();
                match scanner.get_results(&*p, scan_id, offset, count) {
                    Ok((addresses, values, total_count)) => DebuggerResponse::ScanMemoryResults { addresses, values, total_count },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::ScanMemoryReset { scan_id } => {
                match scanner.reset_scan(scan_id) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::PointerScanStart { pid, target_address, max_offset, max_depth, alignment, max_results, modules, thread_count, writable_only } => {
                let p = platform.read().unwrap();
                match pointer_scanner.start_scan(&*p, pid, target_address, max_offset, max_depth, alignment, max_results, modules, thread_count, writable_only) {
                    Ok((results_path, match_count, scan_time_us)) => DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::PointerScanGetResults { pid, results_path, offset, count, offset_filter } => {
                let p = platform.read().unwrap();
                match pointer_scanner.get_results(&*p, pid, &results_path, offset, count, &offset_filter) {
                    Ok((paths, total_count)) => DebuggerResponse::PointerScanResults { paths, total_count },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::PointerScanReset { results_path } => {
                match pointer_scanner.reset_scan(&results_path) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::PointerScanApplyFilter { results_path, offset_filter } => {
                match pointer_scanner.apply_filter(&results_path, &offset_filter) {
                    Ok((results_path, match_count, scan_time_us)) => DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::PointerScanRescan { pid, results_path, target_address } => {
                let p = platform.read().unwrap();
                match pointer_scanner.rescan(&*p, pid, &results_path, target_address) {
                    Ok((results_path, match_count, scan_time_us)) => DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::StringScanStart { pid, start_address, size, min_length, max_results, thread_count, region_filter, encodings, contains } => {
                let p = platform.read().unwrap();
                match string_scanner.start_scan(&*p, pid, start_address, size, min_length, max_results, thread_count, region_filter, encodings, &contains) {
                    Ok((results_path, match_count, scan_time_us, capped)) => DebuggerResponse::StringScanResult { results_path, match_count, scan_time_us, capped },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::StringScanGetResults { results_path, offset, count, filter, sort, ascending } => {
                match string_scanner.get_results(&results_path, offset, count, &filter, sort, ascending) {
                    Ok((strings, total_count)) => DebuggerResponse::StringScanResults { strings, total_count },
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::StringScanReset { results_path } => {
                match string_scanner.reset_scan(&results_path) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::TraceInstructions { pid, tid, exit_condition, max_instructions } => {
                let mut p = platform.write().unwrap();
                match p.trace_instructions(pid, tid, exit_condition, max_instructions) {
                    Ok((entries, stop_reason, trace_time_us)) => {
                        let trace_data: Vec<_> = entries
                            .iter()
                            .map(|e| (e.registers.clone(), e.memory_accesses.clone()))
                            .collect();
                        let trace_text = crate::tenet_format::trace_to_tenet(&trace_data);
                        DebuggerResponse::TenetTrace {
                            trace_text,
                            stop_reason,
                            trace_time_us,
                            stats_text: String::new(),
                            final_pc: None,
                            instructions_executed: entries.len(),
                        }
                    }
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::HidePeb { pid, options } => {
                let p = platform.read().unwrap();
                match crate::anti_anti_debug::peb::hide_peb(&*p, pid, &options) {
                    Ok(report) => DebuggerResponse::PebHideResult { report },
                    Err(e) => DebuggerResponse::Error { message: e.to_string() },
                }
            }
            DebuggerRequest::FreezeValueStart { pid, address, data, interval_ms, offsets } => {
                let freeze_id = freeze_manager.start(platform.clone(), pid, address, data, interval_ms, offsets);
                DebuggerResponse::FreezeValueStarted { freeze_id }
            }
            DebuggerRequest::FreezeValueUpdate { freeze_id, data } => {
                match freeze_manager.update(freeze_id, data) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
            DebuggerRequest::FreezeValueStop { freeze_id } => {
                match freeze_manager.stop(freeze_id) {
                    Ok(()) => DebuggerResponse::Ack,
                    Err(e) => DebuggerResponse::Error { message: e },
                }
            }
        };
        SERVER_HANDLE_US.fetch_add(handle_start.elapsed().as_micros() as u64, Ordering::Relaxed);
        debug!(resp = %match &resp {
            DebuggerResponse::Event { event } => event.to_string(),
            DebuggerResponse::ThreadContext { context } => {
                format!("ThreadContext {{ pc: 0x{:016x} }}", context.get_pc())
            },
            DebuggerResponse::ModuleList { modules } => format!("ModuleList {{ modules: [..{} modules] }}", modules.len()),
            DebuggerResponse::ThreadList { threads } => format!("ThreadList {{ threads: [..{} threads] }}", threads.len()),
            DebuggerResponse::ProcessObjects { objects } => format!("ProcessObjects {{ handles: {}, windows: {}, tcp: {}, privileges: {} }}", objects.handles.len(), objects.windows.len(), objects.tcp_connections.len(), objects.privileges.len()),
            DebuggerResponse::ProcessList { processes } => format!("ProcessList {{ processes: [..{} processes] }}", processes.len()),
            DebuggerResponse::Instructions { instructions } => {
                format!(
                    "Instructions {{ instructions: [..{} instructions] }}",
                    instructions.len()
                )
            },
            DebuggerResponse::WideStringData { data } => format!("WideStringData {{ data: \"{}\" }}", data),
            DebuggerResponse::CoverageTargetList { targets } => format!("CoverageTargetList {{ targets: [..{} targets] }}", targets.len()),
            DebuggerResponse::SymbolList { symbols } => format!("SymbolList {{ symbols: [..{} symbols] }}", symbols.len()),
            DebuggerResponse::ResolvedSymbolList { symbols } => format!("ResolvedSymbolList {{ symbols: [..{} symbols] }}", symbols.len()),
            DebuggerResponse::CallStack { frames } => format!(
                "CallStack {{ frames: [..{} frames] }}",
                frames.len()
            ),
            DebuggerResponse::MemoryRegionList { regions } => format!(
                "MemoryRegionList {{ regions: [..{} regions] }}",
                regions.len()
            ),
            DebuggerResponse::DereferenceResult { entries } => format!(
                "DereferenceResult {{ entries: [..{} entries] }}",
                entries.len()
            ),
            DebuggerResponse::MemorySearchResult { addresses, capped } => format!(
                "MemorySearchResult ({} matches, capped={})", addresses.len(), capped
            ),
            _ => format!("{:?}", resp),
        }, "Sending response");
        let send_start = Instant::now();
        if let Err(e) = framed_stream.send(&resp) {
            error!(?e, "Failed to write response to socket");
            break;
        }
        SERVER_SEND_US.fetch_add(send_start.elapsed().as_micros() as u64, Ordering::Relaxed);
        SERVER_REQ_COUNT.fetch_add(1, Ordering::Relaxed);
        print_server_stats();
    }
}

pub async fn run_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind(DEFAULT_LISTEN_ADDR).await?;
    run_server_with_listener(listener, crate::PlatformImpl::new(), pending()).await
}

/// Bind `listen` and serve the debug protocol with the default platform until
/// the process is killed. The one owner of the server bootstrap (bind →
/// platform with `cfg` → serve forever), shared by core's own `main` and by
/// hosts that re-launch themselves as an in-guest server (the Joybug UI's guest
/// mode) — so the CLI and an embedded server can't drift apart.
pub async fn serve(listen: &str, cfg: crate::SymbolConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    run_server_with_listener(listener, crate::PlatformImpl::new_with_config(cfg), pending()).await
}

pub async fn run_server_with_shutdown<F>(shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind(DEFAULT_LISTEN_ADDR).await?;
    run_server_with_listener(listener, crate::PlatformImpl::new(), shutdown).await
}

pub async fn run_server_with_std_listener<F>(
    listener: StdTcpListener,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send,
{
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    run_server_with_listener(listener, crate::PlatformImpl::new(), shutdown).await
}

/// Run a server with any PlatformAPI implementation on a pre-bound tokio listener.
pub async fn run_server_with_listener<P, F>(
    listener: TcpListener,
    platform: P,
    shutdown: F,
) -> anyhow::Result<()>
where
    P: PlatformAPI + Stepper + Send + Sync + 'static,
    F: Future<Output = ()> + Send,
{
    let local_addr = listener.local_addr()?;
    info!(%local_addr, "Server listening");

    let shared_platform = Arc::new(RwLock::new(platform));
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutdown signal received; stopping server accept loop");
                break;
            }
            accept_result = listener.accept() => {
                let (socket, addr) = accept_result?;
                info!(%addr, "Accepted connection");
                let std_stream = socket.into_std()?;
                std_stream.set_nonblocking(false)?;
                // Disable Nagle: this is a small-message request/response protocol,
                // and Nagle + the client's delayed-ACK add ~40-200ms per exchange
                // over a real TCP link (e.g. host ↔ sandbox guest). Invisible on
                // loopback; ~150ms/round-trip to a VM without this.
                if let Err(e) = std_stream.set_nodelay(true) {
                    warn!(%addr, "Failed to set TCP_NODELAY on accepted socket: {}", e);
                }

                let platform = Arc::clone(&shared_platform);
                std::thread::spawn(move || {
                    handle_connection(std_stream, platform);
                });
            }
        }
    }

    Ok(())
}

/// Run a server with any PlatformAPI on a pre-bound std listener (used by LocalServer).
pub async fn run_server_with_platform<P, F>(
    listener: StdTcpListener,
    platform: P,
    shutdown: F,
) -> anyhow::Result<()>
where
    P: PlatformAPI + Stepper + Send + Sync + 'static,
    F: Future<Output = ()> + Send,
{
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    run_server_with_listener(listener, platform, shutdown).await
}
