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

use common::TestServer;
use helpers::{EmulatorTestState, get_xtea_test_path};
use joybug2::interfaces::Architecture;
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

#[test]
fn test_emulator_integration() {
    joybug2::init_tracing();

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
            let modules = session.list_modules(pid)?;
            let main_module = modules.iter()
                .find(|m| m.name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find xtea_test module"))?;
            println!("  Module: {} at 0x{:016X} (size: 0x{:X})",
                main_module.name, main_module.base, main_module.size.unwrap_or(0));

            // Find key symbols
            let encrypt_sym = session.find_symbols("xtea_encrypt", 1)?
                .into_iter()
                .find(|s| s.module_name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find xtea_encrypt symbol"))?;
            println!("  xtea_encrypt: 0x{:016X}", encrypt_sym.va);

            let end_marker_sym = session.find_symbols("trace_end_marker", 1)?
                .into_iter()
                .find(|s| s.module_name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find trace_end_marker symbol"))?;
            println!("  trace_end_marker: 0x{:016X}", end_marker_sym.va);

            let syscall_marker_sym = session.find_symbols("syscall_marker", 1)?
                .into_iter()
                .find(|s| s.module_name.to_lowercase().contains("xtea_test"))
                .ok_or_else(|| anyhow::anyhow!("Could not find syscall_marker symbol"))?;
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
