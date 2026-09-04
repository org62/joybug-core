#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path, find_symbol};
use joybug_core::protocol::{DereferenceEntry, DereferenceValue};
use joybug_core::protocol_io::DebugSession;

/// Format a dereference entry in GEF-style output
fn format_entry(entry: &DereferenceEntry) -> String {
    let offset_str = if entry.offset >= 0 {
        format!("+{:#06x}", entry.offset)
    } else {
        format!("-{:#06x}", entry.offset.unsigned_abs())
    };

    let mut result = format!("{:#018x}|{}: ", entry.address, offset_str);

    for (i, value) in entry.chain.iter().enumerate() {
        if i > 0 {
            result.push_str(" -> ");
        }
        match value {
            DereferenceValue::Pointer(addr, symbol) => {
                if let Some(sym) = symbol {
                    result.push_str(&format!("{} ({:#018x})", sym, addr));
                } else {
                    result.push_str(&format!("{:#018x}", addr));
                }
            }
            DereferenceValue::Value(val) => {
                result.push_str(&format!("{:#018x}", val));
            }
            DereferenceValue::String(s) => {
                result.push_str(s);
            }
            DereferenceValue::Instruction(instr, _) => {
                result.push_str(&format!("<{}>", instr));
            }
            DereferenceValue::LoopDetected(addr) => {
                result.push_str(&format!("[loop @ {:#018x}]", addr));
            }
        }
    }

    result
}

#[test]
fn test_dereference_basic() {
    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe_path = get_test_program_path("dereference_test");

    struct TestState {
        dereference_tested: bool,
    }

    let final_state = DebugSession::new(
        TestState {
            dereference_tested: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        println!("\n========== DEREFERENCE TEST: Setting up breakpoint ==========\n");

        // Set breakpoint on breakpoint_here function in our test exe
        // This is called after globals are set up
        session.set_single_shot_breakpoint(pid, "dereference_test!breakpoint_here", |session, pid, tid, addr| {
            println!("\n========== HIT breakpoint_here at 0x{:x} ==========\n", addr);

            // List modules to show test exe is loaded
            let modules = session.list_modules(pid)?;
            println!("Loaded modules:");
            for m in &modules {
                if m.name.to_lowercase().contains("dereference_test") {
                    println!("  {} @ {:#x} (size: {:?})", m.name, m.base, m.size);
                }
            }

            // Try to find our global symbols using module-qualified names
            println!("\n----- Searching for global symbols -----\n");

            let symbols_to_find = ["dereference_test!g_string_ptr", "dereference_test!g_self_ptr", "dereference_test!g_list_head"];
            for sym_name in &symbols_to_find {
                let symbols = session.find_symbols(sym_name, 10)?;
                println!("Found {} symbols matching '{}':", symbols.len(), sym_name);
                for s in &symbols {
                    println!("  {}!{} @ {:#x}", s.module_name, s.name, s.va);
                }
            }

            // =============================================
            // TEST 1: g_string_ptr - should point to "Hello, Dereference!"
            // =============================================
            println!("\n----- TEST 1: g_string_ptr -----\n");

            let string_sym = find_symbol(session, "dereference_test!g_string_ptr", "dereference_test")?;
            println!("g_string_ptr symbol at 0x{:x}", string_sym.va);

            let entries = session.dereference(pid, string_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain: should be Pointer -> String
            assert!(
                entries[0].chain.len() >= 2,
                "g_string_ptr chain should have at least 2 elements (pointer + string)"
            );
            match &entries[0].chain[0] {
                DereferenceValue::Pointer(_, _) => {}
                other => panic!("First element should be Pointer, got {:?}", other),
            }
            match &entries[0].chain[1] {
                DereferenceValue::String(s) => {
                    assert!(
                        s.contains("Hello, Dereference!"),
                        "String should contain 'Hello, Dereference!', got: {}",
                        s
                    );
                    println!("✓ g_string_ptr correctly points to: {}", s);
                }
                other => panic!("Second element should be String, got {:?}", other),
            }

            // =============================================
            // TEST 1b: g_wide_string_ptr - should point to "Wide String Test!"
            // =============================================
            println!("\n----- TEST 1b: g_wide_string_ptr (UTF-16) -----\n");

            let wide_string_sym = find_symbol(session, "dereference_test!g_wide_string_ptr", "dereference_test")?;
            println!("g_wide_string_ptr symbol at 0x{:x}", wide_string_sym.va);

            let entries = session.dereference(pid, wide_string_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain: should be Pointer -> String (wide)
            assert!(
                entries[0].chain.len() >= 2,
                "g_wide_string_ptr chain should have at least 2 elements (pointer + string)"
            );
            match &entries[0].chain[0] {
                DereferenceValue::Pointer(_, _) => {}
                other => panic!("First element should be Pointer, got {:?}", other),
            }
            match &entries[0].chain[1] {
                DereferenceValue::String(s) => {
                    assert!(
                        s.contains("Wide String Test!"),
                        "Wide string should contain 'Wide String Test!', got: {}",
                        s
                    );
                    println!("✓ g_wide_string_ptr correctly points to: {}", s);
                }
                other => panic!("Second element should be String (wide), got {:?}", other),
            }

            // =============================================
            // TEST 2: g_loop_ptr1 - should detect loop with intermediate pointer
            // Chain: g_loop_ptr1 -> g_loop_ptr2 -> g_loop_ptr1 (loop)
            // This tests both loop detection AND symbol resolution in the chain
            // =============================================
            println!("\n----- TEST 2: g_loop_ptr1 (loop detection with chain) -----\n");

            let loop_sym = find_symbol(session, "dereference_test!g_loop_ptr1", "dereference_test")?;
            println!("g_loop_ptr1 symbol at 0x{:x}", loop_sym.va);

            let entries = session.dereference(pid, loop_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain structure: Pointer(g_loop_ptr2) -> Pointer(g_loop_ptr1) -> LoopDetected
            assert!(
                entries[0].chain.len() >= 3,
                "g_loop_ptr1 chain should have at least 3 elements, got: {:?}",
                entries[0].chain
            );

            // First element should be Pointer to g_loop_ptr2 with symbol
            match &entries[0].chain[0] {
                DereferenceValue::Pointer(_, Some(sym)) => {
                    assert!(
                        sym.contains("g_loop_ptr2"),
                        "First pointer should resolve to g_loop_ptr2, got: {}",
                        sym
                    );
                    println!("✓ First element correctly symbolized as: {}", sym);
                }
                DereferenceValue::Pointer(addr, None) => {
                    panic!("First pointer at {:#x} should have symbol g_loop_ptr2", addr);
                }
                other => panic!("First element should be Pointer, got {:?}", other),
            }

            // Second element should be Pointer back to g_loop_ptr1 with symbol
            match &entries[0].chain[1] {
                DereferenceValue::Pointer(_, Some(sym)) => {
                    assert!(
                        sym.contains("g_loop_ptr1"),
                        "Second pointer should resolve to g_loop_ptr1, got: {}",
                        sym
                    );
                    println!("✓ Second element correctly symbolized as: {}", sym);
                }
                DereferenceValue::Pointer(addr, None) => {
                    panic!("Second pointer at {:#x} should have symbol g_loop_ptr1", addr);
                }
                other => panic!("Second element should be Pointer, got {:?}", other),
            }

            // Third element should be LoopDetected
            match &entries[0].chain[2] {
                DereferenceValue::LoopDetected(addr) => {
                    println!("✓ Loop correctly detected at address: {:#x}", addr);
                }
                other => panic!("Third element should be LoopDetected, got {:?}", other),
            }

            println!("✓ g_loop_ptr1 correctly detected loop with symbolized chain");

            // =============================================
            // TEST 3: g_list_head - pointer to heap allocation
            // =============================================
            println!("\n----- TEST 3: g_list_head (heap pointer) -----\n");

            let list_sym = find_symbol(session, "dereference_test!g_list_head", "dereference_test")?;
            println!("g_list_head symbol at 0x{:x}", list_sym.va);

            let entries = session.dereference(pid, list_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify the chain starts with a valid pointer (to heap-allocated Node)
            // Note: We can't follow the linked list because the Node struct has
            // int value (4 bytes) first, so reading 8 bytes at the node address
            // gives us value + padding, not the next pointer.
            assert!(
                !entries[0].chain.is_empty(),
                "g_list_head chain should not be empty"
            );
            match &entries[0].chain[0] {
                DereferenceValue::Pointer(addr, _) => {
                    println!("✓ g_list_head correctly points to heap address: {:#x}", addr);
                }
                other => panic!("First element should be Pointer to heap Node, got {:?}", other),
            }

            // =============================================
            // TEST 4: g_main_ptr - function pointer to main
            // =============================================
            println!("\n----- TEST 4: g_main_ptr (function pointer) -----\n");

            let main_ptr_sym = find_symbol(session, "dereference_test!g_main_ptr", "dereference_test")?;
            println!("g_main_ptr symbol at 0x{:x}", main_ptr_sym.va);

            let entries = session.dereference(pid, main_ptr_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain: should be Pointer -> Instruction (disassembly of main)
            assert!(
                entries[0].chain.len() >= 2,
                "g_main_ptr chain should have at least 2 elements (pointer + instruction)"
            );
            match &entries[0].chain[0] {
                DereferenceValue::Pointer(addr, _) => {
                    println!("g_main_ptr points to address: {:#x}", addr);
                }
                other => panic!("First element should be Pointer, got {:?}", other),
            }
            match &entries[0].chain[1] {
                DereferenceValue::Instruction(instr, _) => {
                    println!("✓ g_main_ptr correctly dereferences to instruction: <{}>", instr);
                }
                other => panic!("Second element should be Instruction (disassembly of main), got {:?}", other),
            }

            // =============================================
            // TEST 5: g_null_ptr - NULL pointer (tests Value for invalid pointer)
            // =============================================
            println!("\n----- TEST 5: g_null_ptr (NULL pointer) -----\n");

            let null_ptr_sym = find_symbol(session, "dereference_test!g_null_ptr", "dereference_test")?;
            println!("g_null_ptr symbol at 0x{:x}", null_ptr_sym.va);

            let entries = session.dereference(pid, null_ptr_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain: should be Value(0) since NULL is not a valid pointer
            assert!(
                !entries[0].chain.is_empty(),
                "g_null_ptr chain should not be empty"
            );
            match &entries[0].chain[0] {
                DereferenceValue::Value(val) => {
                    assert_eq!(*val, 0, "NULL pointer should have value 0");
                    println!("✓ g_null_ptr correctly shows Value(0) for NULL");
                }
                other => panic!("NULL pointer should produce Value(0), got {:?}", other),
            }

            // =============================================
            // TEST 6: g_ptr_to_small_int - Pointer to small integer value
            // =============================================
            println!("\n----- TEST 6: g_ptr_to_small_int (pointer to small int) -----\n");

            let small_int_ptr_sym = find_symbol(session, "dereference_test!g_ptr_to_small_int", "dereference_test")?;
            println!("g_ptr_to_small_int symbol at 0x{:x}", small_int_ptr_sym.va);

            let entries = session.dereference(pid, small_int_ptr_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain: Pointer(g_small_int) -> Value(0x12345678...)
            // The pointer should resolve to g_small_int symbol
            assert!(
                entries[0].chain.len() >= 2,
                "g_ptr_to_small_int chain should have at least 2 elements"
            );
            match &entries[0].chain[0] {
                DereferenceValue::Pointer(_, Some(sym)) => {
                    assert!(
                        sym.contains("g_small_int"),
                        "Pointer should resolve to g_small_int, got: {}",
                        sym
                    );
                    println!("✓ Pointer correctly symbolized as: {}", sym);
                }
                DereferenceValue::Pointer(addr, None) => {
                    println!("Note: Pointer at {:#x} has no symbol (g_small_int)", addr);
                }
                other => panic!("First element should be Pointer, got {:?}", other),
            }
            // Second element should be Value (the small int value read as 8 bytes)
            match &entries[0].chain[1] {
                DereferenceValue::Value(val) => {
                    // Note: g_small_int is 4 bytes (0x12345678), but we read 8 bytes
                    // so the value includes whatever is after g_small_int in memory
                    let low_32 = (*val & 0xFFFFFFFF) as u32;
                    assert_eq!(low_32, 0x12345678, "Low 32 bits should be 0x12345678");
                    println!("✓ Value correctly shows small int: {:#x} (low 32 bits: {:#x})", val, low_32);
                }
                other => panic!("Second element should be Value, got {:?}", other),
            }

            // =============================================
            // TEST 7: g_invalid_ptr - Value that looks like pointer but can't be dereferenced
            // =============================================
            println!("\n----- TEST 7: g_invalid_ptr (non-dereferenceable value) -----\n");

            let invalid_ptr_sym = find_symbol(session, "dereference_test!g_invalid_ptr", "dereference_test")?;
            println!("g_invalid_ptr symbol at 0x{:x}", invalid_ptr_sym.va);

            let entries = session.dereference(pid, invalid_ptr_sym.va, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain: Value(0xDEAD0000BEEF0000)
            // The value looks like it could be a pointer but can't be dereferenced (unmapped)
            // So it's treated as a Value, not a Pointer
            assert_eq!(
                entries[0].chain.len(), 1,
                "g_invalid_ptr chain should have exactly 1 element (Value)"
            );
            match &entries[0].chain[0] {
                DereferenceValue::Value(val) => {
                    assert_eq!(*val, 0xDEAD0000BEEF0000u64, "Value should be 0xDEAD0000BEEF0000");
                    println!("✓ Correctly shows as Value (can't be dereferenced): {:#x}", val);
                }
                other => panic!("Element should be Value, got {:?}", other),
            }

            // =============================================
            // TEST 8: Stack pointer dereference
            // =============================================
            println!("\n----- TEST 8: Stack pointer dereference -----\n");

            let ctx = session.get_thread_context(pid, tid)?;
            let sp = ctx.sp();

            println!("Stack pointer: {:#018x}", sp);

            let entries = session.dereference(pid, sp, 10, None, true)?;
            assert_eq!(entries.len(), 10, "Should get exactly 10 entries");

            println!("Stack dereference ({} entries):", entries.len());
            for entry in &entries {
                println!("{}", format_entry(entry));
            }

            // Verify offsets are correct (8 bytes apart for 64-bit)
            for (i, entry) in entries.iter().enumerate() {
                let expected_offset = (i * 8) as i64;
                assert_eq!(
                    entry.offset, expected_offset,
                    "Entry {} should have offset {:#x}, got {:#x}",
                    i, expected_offset, entry.offset
                );
            }
            println!("✓ Stack pointer dereference offsets are correct");

            // =============================================
            // TEST 9: Custom reference base
            // =============================================
            println!("\n----- TEST 9: Custom reference base -----\n");

            let ref_base = sp + 0x20;
            let entries = session.dereference(pid, sp, 5, Some(ref_base), true)?;

            println!("Dereference with reference base {:#x}:", ref_base);
            for entry in &entries {
                println!("{}", format_entry(entry));
            }

            assert_eq!(entries[0].offset, -0x20, "First entry offset should be -0x20");
            assert_eq!(entries[4].offset, 0x00, "Fifth entry offset should be 0x00");
            println!("✓ Custom reference base offsets are correct");

            // =============================================
            // TEST 10: Direct string address dereference
            // Tests the fix for registers pointing directly to strings.
            // When dereferencing a string ADDRESS (not a pointer TO a string),
            // should return [String("...")] directly, not interpret string bytes as pointer.
            // =============================================
            println!("\n----- TEST 10: Direct string address dereference -----\n");

            // First, get the string address from g_string_ptr
            let string_sym = find_symbol(session, "dereference_test!g_string_ptr", "dereference_test")?;

            let ptr_entries = session.dereference(pid, string_sym.va, 1, None, true)?;
            let string_addr = match &ptr_entries[0].chain[0] {
                DereferenceValue::Pointer(addr, _) => *addr,
                other => panic!("Expected Pointer, got {:?}", other),
            };
            println!("String address (from g_string_ptr): {:#x}", string_addr);

            // Now dereference the string address DIRECTLY
            // This simulates a register containing a string address (like RBX = string_addr)
            let entries = session.dereference(pid, string_addr, 1, None, true)?;
            assert_eq!(entries.len(), 1);
            println!("{}", format_entry(&entries[0]));

            // Verify chain: should be just [String("Hello, Dereference!")]
            // NOT [Value(garbage)] which would happen if string bytes were read as pointer
            assert_eq!(
                entries[0].chain.len(), 1,
                "Direct string dereference should have exactly 1 element (String)"
            );
            match &entries[0].chain[0] {
                DereferenceValue::String(s) => {
                    assert!(
                        s.contains("Hello, Dereference!"),
                        "String should contain 'Hello, Dereference!', got: {}",
                        s
                    );
                    println!("✓ Direct string address correctly returns String: {}", s);
                }
                DereferenceValue::Value(val) => {
                    panic!(
                        "BUG: String bytes were interpreted as pointer value {:#x}. \
                        Expected String type for direct string address dereference.",
                        val
                    );
                }
                other => panic!("Expected String, got {:?}", other),
            }

            session.state.dereference_tested = true;

            println!("\n========== ALL DEREFERENCE TESTS PASSED ==========\n");
            Ok(())
        })?;

        Ok(())
    })
    .launch(test_exe_path)
    .expect("Debug session failed");

    assert!(
        final_state.dereference_tested,
        "Dereference tests should have run"
    );
}

