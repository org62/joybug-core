-- Test: Disassembly of non-module (dynamically allocated) memory
-- Ported from: disassembly_test.rs::test_disassemble_non_module_memory
-- Requires: disassembly_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", function(pid, tid, addr)
        -- Read the global pointer to dynamically allocated code
        local ptr_sym = dbg:find_symbol("disassembly_test!g_dynamic_code_ptr", 5)
        assert(#ptr_sym > 0, "Should find g_dynamic_code_ptr symbol")

        -- Read the pointer value (8 bytes for x64)
        local dynamic_code_addr = dbg:read_u64(pid, ptr_sym[1].va)
        assert(dynamic_code_addr ~= 0,
            "g_dynamic_code_ptr is NULL - VirtualAlloc may have failed")

        -- Verify this address is NOT in MEM_IMAGE type region
        local region = dbg:query_memory(pid, dynamic_code_addr)
        assert(region.region_type ~= 0x1000000,
            "Dynamic code should NOT be MEM_IMAGE, got type " .. hex(region.region_type))

        -- Disassemble the dynamic code
        local result = dbg:disassemble_function(pid, dynamic_code_addr, 20)
        local instrs = result.instructions
        assert(#instrs >= 2, "Should have at least 2 instructions, got " .. #instrs)

        -- Function bounds should be nil for non-module memory
        assert(result.start == nil, "Function start should be nil for non-module memory")
        assert(result["end"] == nil, "Function end should be nil for non-module memory")
        assert(result.name == nil, "Function name should be nil for non-module memory")

        -- Verify the disassembly matches known shellcode (x64)
        -- mov eax, ecx / add eax, edx / ret
        assert(instrs[1].mnemonic:lower() == "mov", "First instruction should be 'mov'")
        assert(instrs[2].mnemonic:lower() == "add", "Second instruction should be 'add'")
        assert(instrs[3].mnemonic:lower() == "ret", "Third instruction should be 'ret'")
        assert(instrs[3].is_ret, "ret instruction should have is_ret=true")
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
