#![cfg(windows)]

#[path = "common/mod.rs"]
mod common;
#[path = "emulator_test/helpers.rs"]
mod helpers;
#[path = "emulator_test/basic.rs"]
mod basic;
#[path = "emulator_test/basic_block.rs"]
mod basic_block;
#[path = "emulator_test/instruction_trace.rs"]
mod instruction_trace;
#[path = "emulator_test/instruction_trace_exit.rs"]
mod instruction_trace_exit;
#[path = "emulator_test/instruction_trace_syscall.rs"]
mod instruction_trace_syscall;
#[path = "emulator_test/module_transition.rs"]
mod module_transition;
#[path = "emulator_test/performance.rs"]
mod performance;
#[path = "emulator_test/syscall.rs"]
mod syscall;
#[path = "emulator_test/timeout.rs"]
mod timeout;

use common::{TestServer, find_symbol, find_module};
use helpers::{EmulatorTestState, get_xtea_test_path, get_emulator_test_path};
use joybug_core::interfaces::Architecture;
use joybug_core::protocol_io::{BreakpointDecision, DebugSession};

#[test]
fn test_emulator_integration() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let xtea_path = get_xtea_test_path();

    println!("=== Emulator Integration Test ===");
    println!("Test program: {}", xtea_path);
    println!("Server: {}", server_addr);

    let final_state = DebugSession::new(EmulatorTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, address| {
            println!("\n=== Initial breakpoint at 0x{:016X} ===", address);

            // Find the main module
            let main_module = find_module(session, pid, "xtea_test")?;
            println!("  Module: {} at 0x{:016X} (size: 0x{:X})",
                main_module.name, main_module.base, main_module.size.unwrap_or(0));

            // Find key symbols
            let encrypt_sym = find_symbol(session, "xtea_encrypt", "xtea_test")?;
            println!("  xtea_encrypt: 0x{:016X}", encrypt_sym.va);

            let end_marker_sym = find_symbol(session, "trace_end_marker", "xtea_test")?;
            println!("  trace_end_marker: 0x{:016X}", end_marker_sym.va);

            let syscall_marker_sym = find_symbol(session, "syscall_marker", "xtea_test")?;
            println!("  syscall_marker: 0x{:016X}", syscall_marker_sym.va);

            let entry_info = session.get_module_extra_info(pid, main_module.base)?;
            let entry_rva = entry_info.nt_headers.OptionalHeader.AddressOfEntryPoint;
            let entry_point = main_module.base + entry_rva as u64;
            println!("  Entry point: 0x{:016X}", entry_point);

            let encrypt_addr = encrypt_sym.va;
            let end_marker_addr = end_marker_sym.va;
            let syscall_marker_addr = syscall_marker_sym.va;

            // Breakpoint at syscall_marker: test Syscall and InstructionTrace+Syscall modes
            // syscall_marker calls CloseHandle(NULL) → kernel32 → ntdll!NtClose → SVC/SYSCALL
            session.set_breakpoint_at(pid, syscall_marker_addr, None, move |session, pid, tid, address| {
                println!("\n=== Hit syscall_marker at 0x{:016X} ===", address);

                session.remove_breakpoint(pid, address)?;
                let saved_context = session.get_thread_context(pid, tid)?;

                syscall::test_syscall(session, pid, tid)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                instruction_trace_syscall::test_instruction_trace_syscall(session, pid, tid)?;
                session.set_thread_context(pid, tid, saved_context)?;

                Ok(BreakpointDecision::Remove)
            })?;

            // Breakpoint at xtea_encrypt: test modes on known arithmetic code
            session.set_breakpoint_at(pid, encrypt_addr, None, move |session, pid, tid, address| {
                println!("\n=== Hit xtea_encrypt at 0x{:016X} ===", address);

                // Remove breakpoint so emulator sees original bytes
                session.remove_breakpoint(pid, address)?;

                // Save context for restoration between tests
                let saved_context = session.get_thread_context(pid, tid)?;
                let start_pc = saved_context.get_pc();

                // Disassemble first few instructions for context
                let arch = Architecture::from_native();
                let disasm = session.disassemble_memory(pid, start_pc, 5, arch)?;
                println!("  Disassembly:");
                for insn in &disasm {
                    println!("    0x{:016X}: {} {}", insn.address, insn.mnemonic, insn.op_str);
                }

                basic::test_basic(session, pid, tid, start_pc)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                basic_block::test_basic_block(session, pid, tid, start_pc)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                instruction_trace::test_instruction_trace(session, pid, tid, start_pc)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                instruction_trace_exit::test_instruction_trace_exit_condition(session, pid, tid, end_marker_addr)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                performance::test_performance(session, pid, tid, end_marker_addr)?;
                session.set_thread_context(pid, tid, saved_context.clone())?;

                Ok(BreakpointDecision::Remove)
            })?;

            // Breakpoint at entry point: test ModuleTransition
            session.set_breakpoint_at(pid, entry_point, None, move |session, pid, tid, address| {
                println!("\n=== Hit entry point at 0x{:016X} ===", address);

                session.remove_breakpoint(pid, address)?;
                let saved_context = session.get_thread_context(pid, tid)?;

                module_transition::test_module_transition(session, pid, tid)?;
                session.set_thread_context(pid, tid, saved_context)?;

                Ok(BreakpointDecision::Remove)
            })?;

            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("\nProcess {} exited with code {}", pid, exit_code);

            assert!(session.state.basic_tested, "Basic mode was not tested");
            assert!(session.state.basic_block_tested, "BasicBlock mode was not tested");
            assert!(session.state.instruction_trace_tested, "InstructionTrace mode was not tested");
            assert!(session.state.instruction_trace_exit_tested, "InstructionTrace exit condition was not tested");
            assert!(session.state.instruction_trace_syscall_tested, "InstructionTrace syscall was not tested");
            assert!(session.state.module_transition_tested, "ModuleTransition mode was not tested");
            assert!(session.state.syscall_tested, "Syscall mode was not tested");
            assert!(session.state.performance_tested, "Performance was not tested");

            println!("\nAll emulator tests passed!");
            Ok(())
        })
        .launch(xtea_path)
        .expect("Debug session failed");

    assert!(final_state.all_tested(), "Not all emulator features were tested");
}

/// Test emulation timeout using an infinite loop program.
/// Launches emulator_test.exe, breaks on infinite_increment(), sets g_do_infinite_loop
/// to force an infinite loop, then emulates in Basic mode until the 3s safety timeout fires.
/// Reads g_counter from emulated memory to verify the loop ran many iterations.
#[test]
fn test_emulator_timeout() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_emulator_test_path();

    println!("=== Emulator Timeout Test ===");
    println!("Test program: {}", test_exe);
    println!("Server: {}", server_addr);

    let final_state = DebugSession::new(EmulatorTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, address| {
            println!("\nInitial breakpoint at 0x{:016X}", address);

            let func_sym = find_symbol(session, "infinite_increment", "emulator_test")?;
            println!("  infinite_increment: 0x{:016X}", func_sym.va);

            let loop_flag_sym = find_symbol(session, "g_do_infinite_loop", "emulator_test")?;
            println!("  g_do_infinite_loop: 0x{:016X}", loop_flag_sym.va);

            let counter_sym = find_symbol(session, "g_counter", "emulator_test")?;
            println!("  g_counter: 0x{:016X}", counter_sym.va);

            let func_addr = func_sym.va;
            let loop_flag_addr = loop_flag_sym.va;
            let counter_addr = counter_sym.va;

            session.set_breakpoint_at(pid, func_addr, None, move |session, pid, tid, address| {
                println!("\n=== Hit infinite_increment at 0x{:016X} ===", address);
                session.remove_breakpoint(pid, address)?;

                // Force infinite loop: set g_do_infinite_loop = 1
                session.write_memory(pid, loop_flag_addr, 1u64.to_le_bytes().to_vec())?;

                let saved_context = session.get_thread_context(pid, tid)?;

                timeout::test_timeout(session, pid, tid, counter_addr)?;
                session.set_thread_context(pid, tid, saved_context)?;

                // Restore g_do_infinite_loop = 0 so the real process exits after resuming
                session.write_memory(pid, loop_flag_addr, 0u64.to_le_bytes().to_vec())?;

                Ok(BreakpointDecision::Remove)
            })?;

            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("\nProcess {} exited with code {}", pid, exit_code);
            assert!(session.state.timeout_tested, "Timeout was not tested");
            Ok(())
        })
        .launch(test_exe)
        .expect("Debug session failed");

    assert!(final_state.timeout_tested, "Timeout test was not completed");
}
