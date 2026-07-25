#![cfg(windows)]

mod common;

use common::{module_file_name_matches, runtime_function_entry_vas, TestServer};
use joybug_core::protocol_io::DebugSession;
use std::path::Path;

/// Per-module breakpoint stats
struct ModuleStats {
    name: String,
    runtime_functions: usize,
    breakpoints_set: usize,
    breakpoints_failed: usize,
}

struct MassBreakpointState {
    /// (name, base) pairs captured from ProcessCreated / DllLoaded
    modules: Vec<(String, u64)>,
    module_stats: Vec<ModuleStats>,
    hits: Vec<(u64, String)>,
}

/// Module names we want to instrument (case-insensitive file name match)
const TARGET_MODULES: &[&str] = &["cmd.exe", "ntdll.dll", "kernel32.dll", "kernelbase.dll"];

fn is_target_module(image_name: &str) -> bool {
    TARGET_MODULES
        .iter()
        .any(|t| module_file_name_matches(image_name, t))
}

fn set_breakpoints_for_module(
    session: &mut DebugSession<MassBreakpointState>,
    pid: u32,
    module_name: &str,
    module_base: u64,
) {
    let entry_vas = runtime_function_entry_vas(session, pid, module_base);
    if entry_vas.is_empty() {
        return;
    }

    let mut stats = ModuleStats {
        name: module_name.to_string(),
        runtime_functions: entry_vas.len(),
        breakpoints_set: 0,
        breakpoints_failed: 0,
    };

    println!(
        "  {} @ 0x{:x}: {} unique valid entries",
        module_name,
        module_base,
        entry_vas.len()
    );

    for &va in &entry_vas {
        match session.set_single_shot_breakpoint_at(
            pid,
            va,
            move |session, pid, _tid, address| {
                let desc = match session.resolve_address_to_symbol(pid, address) {
                    Ok((module_path, symbol, offset)) => {
                        let module = module_path
                            .as_ref()
                            .and_then(|p| p.rsplit(['\\', '/']).next())
                            .unwrap_or("???");
                        let sym_name = symbol
                            .as_ref()
                            .map(|s| s.name.as_str())
                            .unwrap_or("???");
                        let off = offset.unwrap_or(0);
                        format!("{}!{}+0x{:x}", module, sym_name, off)
                    }
                    Err(_) => format!("<unresolved 0x{:x}>", address),
                };
                session.state.hits.push((address, desc));
                Ok(())
            },
        ) {
            Ok(()) => {
                stats.breakpoints_set += 1;
            }
            Err(_) => {
                stats.breakpoints_failed += 1;
            }
        }
    }

    println!(
        "    -> {} set, {} failed",
        stats.breakpoints_set, stats.breakpoints_failed
    );

    session.state.module_stats.push(stats);
}

#[test]
fn test_mass_breakpoint_cmd() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let state = MassBreakpointState {
        modules: Vec::new(),
        module_stats: Vec::new(),
        hits: Vec::new(),
    };

    let final_state = DebugSession::new(state, Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_process_created(|session, _pid, _tid, image_name, base_of_image| {
            if is_target_module(image_name) {
                let file_name = Path::new(image_name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(image_name);
                println!("{} loaded at base 0x{:x}", file_name, base_of_image);
                session
                    .state
                    .modules
                    .push((file_name.to_string(), base_of_image));
            }
            Ok(())
        })
        .on_dll_loaded(|session, _pid, _tid, dll_name, base_of_dll| {
            if is_target_module(dll_name) {
                let file_name = Path::new(dll_name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(dll_name);
                println!("{} loaded at base 0x{:x}", file_name, base_of_dll);
                session
                    .state
                    .modules
                    .push((file_name.to_string(), base_of_dll));
            }
            Ok(())
        })
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            println!(
                "\nSetting breakpoints on {} modules...",
                session.state.modules.len()
            );

            // Clone the list since set_breakpoints_for_module borrows session mutably
            let modules: Vec<_> = session.state.modules.clone();

            for (name, base) in &modules {
                set_breakpoints_for_module(session, pid, name, *base);
            }

            let total_set: usize = session.state.module_stats.iter().map(|s| s.breakpoints_set).sum();
            let total_failed: usize = session
                .state
                .module_stats
                .iter()
                .map(|s| s.breakpoints_failed)
                .sum();
            println!(
                "\nTotal breakpoints: {} set, {} failed across {} modules",
                total_set,
                total_failed,
                session.state.module_stats.len()
            );

            Ok(())
        })
        .on_process_exited(|session, _pid, exit_code| {
            println!("Process exited with code {}", exit_code);

            // Sort hits by address
            session.state.hits.sort_by_key(|(addr, _)| *addr);

            let total_rf: usize = session
                .state
                .module_stats
                .iter()
                .map(|s| s.runtime_functions)
                .sum();
            let total_set: usize = session
                .state
                .module_stats
                .iter()
                .map(|s| s.breakpoints_set)
                .sum();
            let total_failed: usize = session
                .state
                .module_stats
                .iter()
                .map(|s| s.breakpoints_failed)
                .sum();

            // Write log file
            let out_dir = std::env::var("OUT_DIR")
                .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
            let log_path = Path::new(&out_dir).join("mass_breakpoint_hits.txt");

            let mut log = String::new();
            log.push_str("Mass Breakpoint Test Results\n");
            log.push_str("============================\n\n");

            log.push_str("Per-module stats:\n");
            for s in &session.state.module_stats {
                log.push_str(&format!(
                    "  {:20} RUNTIME_FUNCTIONs: {:5}  set: {:5}  failed: {:3}\n",
                    s.name, s.runtime_functions, s.breakpoints_set, s.breakpoints_failed
                ));
            }

            log.push_str(&format!(
                "\nTotal RUNTIME_FUNCTION entries: {}\n",
                total_rf
            ));
            log.push_str(&format!("Total breakpoints set: {}\n", total_set));
            log.push_str(&format!("Total breakpoints failed: {}\n", total_failed));
            log.push_str(&format!("Functions hit: {}\n\n", session.state.hits.len()));
            log.push_str(&format!("{:<20} {}\n", "Address", "Symbol"));
            log.push_str(&format!("{}\n", "-".repeat(80)));
            for (addr, desc) in &session.state.hits {
                log.push_str(&format!("0x{:016x} {}\n", addr, desc));
            }

            std::fs::write(&log_path, &log).ok();
            println!("Log written to {}", log_path.display());
            println!("{}", log);

            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("Debug session failed");

    // Aggregate final stats
    let total_rf: usize = final_state
        .module_stats
        .iter()
        .map(|s| s.runtime_functions)
        .sum();
    let total_set: usize = final_state
        .module_stats
        .iter()
        .map(|s| s.breakpoints_set)
        .sum();
    let total_failed: usize = final_state
        .module_stats
        .iter()
        .map(|s| s.breakpoints_failed)
        .sum();

    println!("\n=== Assertions ===");
    println!("modules instrumented = {}", final_state.module_stats.len());
    println!("total_runtime_functions = {}", total_rf);
    println!("breakpoints_set = {}", total_set);
    println!("breakpoints_failed = {}", total_failed);
    println!("hits = {}", final_state.hits.len());

    // We should have instrumented all 4 target modules
    assert!(
        final_state.module_stats.len() >= 4,
        "Expected at least 4 modules instrumented, got {}",
        final_state.module_stats.len()
    );

    // ntdll + kernel32 + kernelbase + cmd.exe should have thousands of functions total
    assert!(
        total_rf >= 1000,
        "Expected at least 1000 total RUNTIME_FUNCTION entries, got {}",
        total_rf
    );

    let success_rate = total_set as f64 / total_rf as f64;
    assert!(
        success_rate > 0.90,
        "Breakpoint set success rate {:.1}% is below 90%",
        success_rate * 100.0
    );

    assert!(
        final_state.hits.len() >= 10,
        "Expected at least 10 functions hit during 'cmd /c echo test', got {}",
        final_state.hits.len()
    );

    assert!(
        final_state.hits.len() <= total_set,
        "More hits ({}) than breakpoints set ({}) - single-shot should fire at most once",
        final_state.hits.len(),
        total_set
    );
}
