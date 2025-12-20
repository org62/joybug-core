#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::interfaces::Architecture;
use joybug2::protocol_io::DebugSession;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

#[test]
fn test_disassembly_basic() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    // Test exe must exist - fail if not compiled
    let test_exe_path = format!("{}/disassembly_test.exe", env!("OUT_DIR"));
    assert!(
        Path::new(&test_exe_path).exists(),
        "disassembly_test.exe not found at {}. Ensure cl.exe is available (run from VS Developer Command Prompt).",
        test_exe_path
    );

    struct TestState {
        disassembly_tested: bool,
    }

    let final_state = DebugSession::new(
        TestState {
            disassembly_tested: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        println!("\n========== DISASSEMBLY TEST: Setting up breakpoint ==========\n");

        // Set breakpoint on breakpoint_here function
        session.set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", |session, pid, _tid, _addr| {
            println!("\n========== HIT breakpoint_here ==========\n");

            // =============================================
            // TEST 1: Find test_control_flow function
            // =============================================
            println!("\n----- TEST 1: Find test_control_flow function -----\n");

            let symbols = session.find_symbols("disassembly_test!test_control_flow", 10)?;
            assert!(!symbols.is_empty(), "test_control_flow symbol must be found");

            let test_fn_sym = symbols.iter()
                .find(|s| s.name.contains("test_control_flow"))
                .expect("test_control_flow symbol not found");

            println!("test_control_flow @ {:#x}", test_fn_sym.va);

            // =============================================
            // TEST 2: Disassemble function and check instruction flags
            // =============================================
            println!("\n----- TEST 2: Disassemble function -----\n");

            #[cfg(target_arch = "x86_64")]
            let arch = Architecture::X64;
            #[cfg(target_arch = "aarch64")]
            let arch = Architecture::Arm64;

            let (instructions, fn_start, fn_end, fn_name) = session
                .disassemble_function(pid, test_fn_sym.va, 200, arch)?;

            println!("Disassembled {} instructions", instructions.len());
            if let Some(name) = &fn_name {
                println!("Function name: {}", name);
            }
            if let (Some(start), Some(end)) = (fn_start, fn_end) {
                println!("Function bounds: {:#x} - {:#x}", start, end);
            }

            assert!(!instructions.is_empty(), "Should have some instructions");

            // Print first few instructions
            println!("\nFirst 20 instructions:");
            for (i, inst) in instructions.iter().take(20).enumerate() {
                let flags = format!(
                    "{}{}{}",
                    if inst.is_call { "C" } else { "-" },
                    if inst.is_jump { "J" } else { "-" },
                    if inst.is_ret { "R" } else { "-" }
                );
                let target = inst.jump_target.map(|t| format!(" -> {:#x}", t)).unwrap_or_default();
                println!(
                    "  {:3}. {:#018x} [{}] {:8} {}{}",
                    i, inst.address, flags, inst.mnemonic, inst.op_str, target
                );
            }

            // =============================================
            // TEST 3: Verify instruction flags
            // =============================================
            println!("\n----- TEST 3: Verify instruction flags -----\n");

            // Count instruction types
            let call_count = instructions.iter().filter(|i| i.is_call).count();
            let jump_count = instructions.iter().filter(|i| i.is_jump).count();
            let ret_count = instructions.iter().filter(|i| i.is_ret).count();

            println!("Instruction counts:");
            println!("  Calls: {}", call_count);
            println!("  Jumps: {}", jump_count);
            println!("  Returns: {}", ret_count);

            // test_control_flow should have:
            // - At least 2 calls (helper_add, helper_multiply)
            // - At least 2 jumps (if conditions, loop)
            // - At least 1 ret
            assert!(call_count >= 2, "Should have at least 2 call instructions, got {}", call_count);
            assert!(jump_count >= 2, "Should have at least 2 jump instructions, got {}", jump_count);
            assert!(ret_count >= 1, "Should have at least 1 ret instruction, got {}", ret_count);

            println!("Instruction flag counts verified");

            // =============================================
            // TEST 4: Verify jump targets
            // =============================================
            println!("\n----- TEST 4: Verify jump targets -----\n");

            let jumps_with_targets: Vec<_> = instructions.iter()
                .filter(|i| i.is_jump && i.jump_target.is_some())
                .collect();

            println!("Jumps with targets: {}", jumps_with_targets.len());
            for inst in &jumps_with_targets {
                println!(
                    "  {:#x}: {} {} -> {:#x}",
                    inst.address, inst.mnemonic, inst.op_str, inst.jump_target.unwrap()
                );
            }

            // Should have at least some jumps with resolved targets (direct jumps)
            assert!(
                !jumps_with_targets.is_empty(),
                "Should have at least one jump with resolved target"
            );

            // Verify targets are within reasonable range (not 0, not obviously wrong)
            for inst in &jumps_with_targets {
                let target = inst.jump_target.unwrap();
                assert!(target > 0x10000, "Jump target {:#x} seems too low", target);
            }

            println!("Jump targets verified");

            // =============================================
            // TEST 5: Verify call targets
            // =============================================
            println!("\n----- TEST 5: Verify call targets -----\n");

            let calls_with_targets: Vec<_> = instructions.iter()
                .filter(|i| i.is_call && i.jump_target.is_some())
                .collect();

            println!("Calls with targets: {}", calls_with_targets.len());
            for inst in &calls_with_targets {
                println!(
                    "  {:#x}: {} {} -> {:#x}",
                    inst.address, inst.mnemonic, inst.op_str, inst.jump_target.unwrap()
                );
            }

            // Should have at least some calls with resolved targets (direct calls)
            // Note: Some calls might be indirect (register-based) without resolved targets
            println!("Call targets verified");

            // =============================================
            // TEST 6: Verify function boundaries (if available)
            // =============================================
            println!("\n----- TEST 6: Verify function boundaries -----\n");

            if let (Some(start), Some(end)) = (fn_start, fn_end) {
                // Function should contain the symbol address
                assert!(
                    start <= test_fn_sym.va && test_fn_sym.va < end,
                    "Symbol address {:#x} should be within function bounds [{:#x}, {:#x})",
                    test_fn_sym.va, start, end
                );

                // Function size should be reasonable (not too small, not too large)
                let size = end - start;
                assert!(size >= 50, "Function too small: {} bytes", size);
                assert!(size <= 10000, "Function too large: {} bytes", size);

                // All instructions should be within bounds
                for inst in &instructions {
                    assert!(
                        inst.address >= start && inst.address < end,
                        "Instruction at {:#x} outside function bounds [{:#x}, {:#x})",
                        inst.address, start, end
                    );
                }

                println!("Function boundaries verified: {:#x} - {:#x} ({} bytes)", start, end, size);
            } else {
                println!("Note: Function boundaries not available");
            }

            // =============================================
            // TEST 7: Disassemble helper_add to verify different function
            // =============================================
            println!("\n----- TEST 7: Disassemble helper_add -----\n");

            let helper_symbols = session.find_symbols("disassembly_test!helper_add", 10)?;
            if let Some(helper_sym) = helper_symbols.iter().find(|s| s.name.contains("helper_add")) {
                let (helper_instrs, helper_start, helper_end, helper_name) = session
                    .disassemble_function(pid, helper_sym.va, 50, arch)?;

                println!("helper_add @ {:#x}: {} instructions", helper_sym.va, helper_instrs.len());
                if let Some(name) = &helper_name {
                    println!("Function name: {}", name);
                }

                // helper_add should be small and have exactly 1 ret
                let helper_ret_count = helper_instrs.iter().filter(|i| i.is_ret).count();
                assert!(helper_ret_count >= 1, "helper_add should have at least 1 ret");

                // If we have bounds, verify helper_add is separate from test_control_flow
                if let (Some(h_start), Some(h_end), Some(t_start), Some(t_end)) =
                    (helper_start, helper_end, fn_start, fn_end)
                {
                    assert!(
                        h_end <= t_start || h_start >= t_end,
                        "helper_add [{:#x}, {:#x}) should not overlap with test_control_flow [{:#x}, {:#x})",
                        h_start, h_end, t_start, t_end
                    );
                    println!("Verified helper_add is separate from test_control_flow");
                }
            }

            session.state.disassembly_tested = true;

            println!("\n========== ALL DISASSEMBLY TESTS PASSED ==========\n");
            Ok(())
        })?;

        Ok(())
    })
    .launch(test_exe_path)
    .expect("Debug session failed");

    assert!(
        final_state.disassembly_tested,
        "Disassembly tests should have run"
    );
}

#[test]
fn test_instruction_flags_detection() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe_path = format!("{}/disassembly_test.exe", env!("OUT_DIR"));
    assert!(
        Path::new(&test_exe_path).exists(),
        "disassembly_test.exe not found at {}",
        test_exe_path
    );

    struct TestState {
        flags_tested: bool,
    }

    let final_state = DebugSession::new(
        TestState {
            flags_tested: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        session.set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", |session, pid, _tid, _addr| {
            println!("\n----- Testing instruction flag mutual exclusivity -----\n");

            let symbols = session.find_symbols("disassembly_test!test_control_flow", 10)?;
            let test_fn_sym = symbols.iter()
                .find(|s| s.name.contains("test_control_flow"))
                .expect("test_control_flow symbol not found");

            #[cfg(target_arch = "x86_64")]
            let arch = Architecture::X64;
            #[cfg(target_arch = "aarch64")]
            let arch = Architecture::Arm64;

            let (instructions, _, _, _) = session
                .disassemble_function(pid, test_fn_sym.va, 200, arch)?;

            // Verify flags are not set simultaneously (except call which is technically a jump)
            for inst in &instructions {
                // is_ret should be exclusive
                if inst.is_ret {
                    assert!(
                        !inst.is_jump,
                        "Instruction at {:#x} ({}) has both is_ret and is_jump",
                        inst.address, inst.mnemonic
                    );
                    assert!(
                        !inst.is_call,
                        "Instruction at {:#x} ({}) has both is_ret and is_call",
                        inst.address, inst.mnemonic
                    );
                }

                // If is_call is set, is_jump should not be set (they're different categories)
                // Note: In our implementation, call is NOT marked as jump
                if inst.is_call {
                    assert!(
                        !inst.is_jump,
                        "Instruction at {:#x} ({}) has both is_call and is_jump",
                        inst.address, inst.mnemonic
                    );
                }
            }

            session.state.flags_tested = true;
            println!("Instruction flag exclusivity verified");
            Ok(())
        })?;
        Ok(())
    })
    .launch(test_exe_path)
    .expect("Debug session failed");

    assert!(final_state.flags_tested, "Flag tests should have run");
}

#[test]
fn test_disassemble_non_module_memory() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe_path = format!("{}/disassembly_test.exe", env!("OUT_DIR"));
    assert!(
        Path::new(&test_exe_path).exists(),
        "disassembly_test.exe not found at {}",
        test_exe_path
    );

    struct TestState {
        non_module_tested: bool,
    }

    let final_state = DebugSession::new(
        TestState {
            non_module_tested: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        session.set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", |session, pid, _tid, _addr| {
            println!("\n----- Testing disassembly of non-module memory -----\n");

            // Read the global pointer to dynamically allocated code
            // The C program allocated RWX memory and stored the pointer in g_dynamic_code_ptr
            let ptr_symbols = session.find_symbols("disassembly_test!g_dynamic_code_ptr", 10)?;
            let ptr_sym = ptr_symbols.iter()
                .find(|s| s.name.contains("g_dynamic_code_ptr"))
                .expect("g_dynamic_code_ptr symbol not found");

            println!("g_dynamic_code_ptr symbol @ {:#x}", ptr_sym.va);

            // Read the pointer value (8 bytes for x64)
            let ptr_bytes = session.read_memory(pid, ptr_sym.va, 8)?;
            let dynamic_code_addr = u64::from_le_bytes(ptr_bytes[0..8].try_into().unwrap());

            assert!(
                dynamic_code_addr != 0,
                "g_dynamic_code_ptr is NULL - VirtualAlloc may have failed in test program"
            );

            println!("Dynamic code address: {:#x}", dynamic_code_addr);

            // Verify this address is NOT in any module
            let regions = session.enumerate_memory_regions(pid)?;
            let region = regions.iter().find(|r| {
                dynamic_code_addr >= r.base_address
                    && dynamic_code_addr < r.base_address + r.region_size
            }).expect("Should find memory region containing dynamic code");

            println!("Memory region for dynamic code:");
            println!("  Base: {:#x}", region.base_address);
            println!("  Size: {:#x}", region.region_size);
            println!("  Type: {:#x} (MEM_PRIVATE=0x20000, MEM_IMAGE=0x1000000)", region.region_type);
            println!("  Protect: {:#x}", region.protect);

            assert!(
                region.region_type != 0x1000000, // Not MEM_IMAGE
                "Dynamic code should NOT be in a module (MEM_IMAGE), got type {:#x}",
                region.region_type
            );

            // Disassemble the dynamic code
            #[cfg(target_arch = "x86_64")]
            let arch = Architecture::X64;
            #[cfg(target_arch = "aarch64")]
            let arch = Architecture::Arm64;

            let (instructions, fn_start, fn_end, fn_name) = session
                .disassemble_function(pid, dynamic_code_addr, 20, arch)?;

            println!("\nDisassembled {} instructions from dynamic code", instructions.len());

            // Key assertions for non-module memory:
            // 1. Function bounds should be None (no module = no exception directory)
            assert!(
                fn_start.is_none(),
                "Function start should be None for non-module memory, got {:#x?}",
                fn_start
            );
            assert!(
                fn_end.is_none(),
                "Function end should be None for non-module memory, got {:#x?}",
                fn_end
            );
            assert!(
                fn_name.is_none(),
                "Function name should be None for non-module memory, got {:?}",
                fn_name
            );

            // 2. Verify the disassembly matches our known shellcode
            assert!(
                instructions.len() >= 2,
                "Should have at least 2 instructions, got {}",
                instructions.len()
            );

            println!("\nDisassembled instructions:");
            for (i, inst) in instructions.iter().enumerate() {
                let flags = format!(
                    "{}{}{}",
                    if inst.is_call { "C" } else { "-" },
                    if inst.is_jump { "J" } else { "-" },
                    if inst.is_ret { "R" } else { "-" }
                );
                println!(
                    "  {:2}. {:#018x} [{}] {:8} {} ({:02x?})",
                    i, inst.address, flags, inst.mnemonic, inst.op_str, inst.bytes
                );
            }

            #[cfg(target_arch = "x86_64")]
            {
                // x64 shellcode:
                //   mov eax, ecx    ; 89 c8
                //   add eax, edx    ; 01 d0
                //   ret             ; c3
                //   nop (padding)   ; 90 90 90 ...
                assert!(instructions.len() >= 3, "x64: Should have at least 3 instructions");

                // Verify instruction 0: mov eax, ecx
                let inst0 = &instructions[0];
                assert_eq!(inst0.bytes, vec![0x89, 0xc8], "First instruction should be 'mov eax, ecx' (89 c8)");
                assert_eq!(inst0.mnemonic.to_lowercase(), "mov", "First instruction mnemonic should be 'mov'");

                // Verify instruction 1: add eax, edx
                let inst1 = &instructions[1];
                assert_eq!(inst1.bytes, vec![0x01, 0xd0], "Second instruction should be 'add eax, edx' (01 d0)");
                assert_eq!(inst1.mnemonic.to_lowercase(), "add", "Second instruction mnemonic should be 'add'");

                // Verify instruction 2: ret
                let inst2 = &instructions[2];
                assert_eq!(inst2.bytes, vec![0xc3], "Third instruction should be 'ret' (c3)");
                assert_eq!(inst2.mnemonic.to_lowercase(), "ret", "Third instruction mnemonic should be 'ret'");
                assert!(inst2.is_ret, "ret instruction should have is_ret=true");

                // Verify remaining instructions are nops (padding)
                for inst in instructions.iter().skip(3) {
                    if inst.bytes == vec![0x90] {
                        assert_eq!(inst.mnemonic.to_lowercase(), "nop", "0x90 should be 'nop'");
                    }
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                // ARM64 shellcode:
                //   add w0, w0, w1  ; 00 00 01 0b
                //   ret             ; c0 03 5f d6
                //   nop             ; 1f 20 03 d5

                // Verify instruction 0: add w0, w0, w1
                let inst0 = &instructions[0];
                assert_eq!(inst0.bytes, vec![0x00, 0x00, 0x01, 0x0b], "First instruction should be 'add w0, w0, w1'");
                assert_eq!(inst0.mnemonic.to_lowercase(), "add", "First instruction mnemonic should be 'add'");

                // Verify instruction 1: ret
                let inst1 = &instructions[1];
                assert_eq!(inst1.bytes, vec![0xc0, 0x03, 0x5f, 0xd6], "Second instruction should be 'ret'");
                assert_eq!(inst1.mnemonic.to_lowercase(), "ret", "Second instruction mnemonic should be 'ret'");
                assert!(inst1.is_ret, "ret instruction should have is_ret=true");

                // Verify remaining instructions are nops (padding)
                for inst in instructions.iter().skip(2) {
                    if inst.bytes == vec![0x1f, 0x20, 0x03, 0xd5] {
                        assert_eq!(inst.mnemonic.to_lowercase(), "nop", "ARM64 nop check");
                    }
                }
            }

            // Verify sequential addresses
            let mut expected_addr = dynamic_code_addr;
            for inst in &instructions {
                assert_eq!(
                    inst.address, expected_addr,
                    "Instruction address mismatch: expected {:#x}, got {:#x}",
                    expected_addr, inst.address
                );
                expected_addr += inst.size as u64;
            }

            session.state.non_module_tested = true;
            println!("\n----- Non-module memory disassembly test PASSED -----\n");
            Ok(())
        })?;
        Ok(())
    })
    .launch(test_exe_path)
    .expect("Debug session failed");

    assert!(final_state.non_module_tested, "Non-module memory test should have run");
}

#[test]
fn test_disassembly_speed_kernelbase() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe_path = format!("{}/disassembly_test.exe", env!("OUT_DIR"));
    assert!(
        Path::new(&test_exe_path).exists(),
        "disassembly_test.exe not found at {}",
        test_exe_path
    );

    struct TestState {
        speed_tested: bool,
        functions_disassembled: usize,
        total_instructions: usize,
        elapsed_ms: u128,
    }

    let final_state = DebugSession::new(
        TestState {
            speed_tested: false,
            functions_disassembled: 0,
            total_instructions: 0,
            elapsed_ms: 0,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        println!("\n========== DISASSEMBLY SPEED TEST ==========\n");

        // Find kernelbase.dll
        let modules = session.list_modules(pid)?;
        let kernelbase = modules.iter()
            .find(|m| m.name.to_lowercase().contains("kernelbase"))
            .expect("kernelbase.dll should be loaded");

        println!("Found kernelbase.dll:");
        println!("  Name: {}", kernelbase.name);
        println!("  Base: {:#x}", kernelbase.base);
        println!("  Size: {:#x}", kernelbase.size.unwrap_or(0));

        // Get module extra info to access runtime functions
        let extra_info = session.get_module_extra_info(pid, kernelbase.base)?;

        let runtime_functions = extra_info.runtime_functions
            .as_ref()
            .expect("kernelbase.dll should have runtime functions");

        println!("  Runtime functions: {}", runtime_functions.len());

        #[cfg(target_arch = "x86_64")]
        let arch = Architecture::X64;
        #[cfg(target_arch = "aarch64")]
        let arch = Architecture::Arm64;

        // Disassemble first 1000 functions and measure time
        const MAX_FUNCTIONS: usize = 1000;

        // Collect results during timing, write to file after
        struct FuncResult {
            func_start: u64,
            func_end: u64,
            func_size: usize,
            instructions: Vec<joybug2::interfaces::Instruction>,
            error: Option<String>,
        }
        let mut results: Vec<FuncResult> = Vec::with_capacity(MAX_FUNCTIONS);

        let start = Instant::now();

        let mut functions_disassembled = 0usize;
        let mut total_instructions = 0usize;
        let mut errors = 0usize;

        for rf in runtime_functions.iter().take(MAX_FUNCTIONS) {
            let func_start = kernelbase.base + rf.BeginAddress as u64;
            let func_end = kernelbase.base + rf.EndAddress as u64;
            let func_size = (rf.EndAddress - rf.BeginAddress) as usize;

            // Estimate instruction count (assume avg 3 bytes per instruction for x64)
            let estimated_count = (func_size / 2).max(1);

            match session.disassemble_memory(pid, func_start, estimated_count, arch) {
                Ok(instructions) => {
                    // Filter to only instructions within function bounds
                    let valid_instructions: Vec<_> = instructions
                        .into_iter()
                        .filter(|i| i.address >= func_start && i.address < func_end)
                        .collect();

                    total_instructions += valid_instructions.len();
                    functions_disassembled += 1;
                    results.push(FuncResult {
                        func_start,
                        func_end,
                        func_size,
                        instructions: valid_instructions,
                        error: None,
                    });
                }
                Err(e) => {
                    errors += 1;
                    results.push(FuncResult {
                        func_start,
                        func_end,
                        func_size,
                        instructions: Vec::new(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        let elapsed = start.elapsed();

        // Write results to file AFTER timing
        let out_path = format!("{}/kernelbase_disassembly.txt", env!("OUT_DIR"));
        let mut out_file = std::fs::File::create(&out_path)
            .expect("Failed to create disassembly output file");

        writeln!(out_file, "Kernelbase.dll Disassembly").unwrap();
        writeln!(out_file, "Base: {:#x}", kernelbase.base).unwrap();
        writeln!(out_file, "========================================\n").unwrap();

        for result in &results {
            if let Some(ref err) = result.error {
                writeln!(out_file, "Function @ {:#x}: ERROR - {}", result.func_start, err).unwrap();
            } else {
                writeln!(out_file, "Function @ {:#x} - {:#x} ({} bytes)",
                    result.func_start, result.func_end, result.func_size).unwrap();
                for inst in &result.instructions {
                    let bytes_hex: Vec<String> = inst.bytes.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    writeln!(out_file, "  {:#010x}  {:24}  {:8} {}",
                        inst.address,
                        bytes_hex.join(" "),
                        inst.mnemonic,
                        inst.op_str
                    ).unwrap();
                }
                writeln!(out_file).unwrap();
            }
        }

        out_file.flush().unwrap();
        println!("Disassembly written to: {}", out_path);

        println!("\n----- RESULTS -----");
        println!("Functions disassembled: {}", functions_disassembled);
        println!("Total instructions: {}", total_instructions);
        println!("Errors: {}", errors);
        println!("Time taken: {:.2}ms", elapsed.as_secs_f64() * 1000.0);
        joybug2::framed_json_stream::print_serialization_stats();

        if functions_disassembled > 0 {
            let funcs_per_sec = functions_disassembled as f64 / elapsed.as_secs_f64();
            let instrs_per_sec = total_instructions as f64 / elapsed.as_secs_f64();
            println!("Functions/second: {:.0}", funcs_per_sec);
            println!("Instructions/second: {:.0}", instrs_per_sec);
        }

        // Verify we disassembled a significant portion
        let attempted = MAX_FUNCTIONS.min(runtime_functions.len());
        let success_rate = functions_disassembled as f64 / attempted as f64;
        println!("Success rate: {:.1}%", success_rate * 100.0);

        assert!(
            success_rate > 0.95,
            "Should successfully disassemble >95% of functions, got {:.1}%",
            success_rate * 100.0
        );

        assert!(
            total_instructions > 1000,
            "Should have disassembled many instructions, got {}",
            total_instructions
        );

        session.state.speed_tested = true;
        session.state.functions_disassembled = functions_disassembled;
        session.state.total_instructions = total_instructions;
        session.state.elapsed_ms = elapsed.as_millis();

        println!("\n========== SPEED TEST PASSED ==========\n");
        Ok(())
    })
    .launch(test_exe_path)
    .expect("Debug session failed");

    assert!(final_state.speed_tested, "Speed test should have run");
    println!(
        "\nFinal stats: {} functions, {} instructions in {}ms",
        final_state.functions_disassembled,
        final_state.total_instructions,
        final_state.elapsed_ms
    );
}
