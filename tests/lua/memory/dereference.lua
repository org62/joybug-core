-- Test: Pointer dereference chain resolution
-- Ported from: dereference_test.rs::test_dereference_basic
-- Requires: dereference_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "dereference_test!breakpoint_here", function(pid, tid, addr)
        -- TEST 1: g_string_ptr - should point to "Hello, Dereference!"
        local string_sym = dbg:find_symbol("dereference_test!g_string_ptr", 1)
        assert(#string_sym > 0, "Should find g_string_ptr symbol")
        local entries = dbg:dereference(pid, string_sym[1].va, 1)
        assert(#entries == 1, "Should get 1 entry")
        assert(#entries[1].chain >= 2, "g_string_ptr chain should have >= 2 elements")
        -- First element should be a pointer
        assert(entries[1].chain[1].type == "pointer", "First should be pointer")
        -- Second should be a string
        assert(entries[1].chain[2].type == "string", "Second should be string")
        assert(entries[1].chain[2].value:find("Hello, Dereference!"),
            "String should contain 'Hello, Dereference!'")

        -- TEST 2: g_null_ptr - NULL pointer
        local null_sym = dbg:find_symbol("dereference_test!g_null_ptr", 1)
        assert(#null_sym > 0, "Should find g_null_ptr symbol")
        local null_entries = dbg:dereference(pid, null_sym[1].va, 1)
        assert(#null_entries == 1, "Should get 1 entry")
        assert(null_entries[1].chain[1].type == "value", "NULL should produce value")
        assert(null_entries[1].chain[1].value == 0, "NULL pointer value should be 0")

        -- TEST 3: g_main_ptr - function pointer
        local main_sym = dbg:find_symbol("dereference_test!g_main_ptr", 1)
        assert(#main_sym > 0, "Should find g_main_ptr symbol")
        local main_entries = dbg:dereference(pid, main_sym[1].va, 1)
        assert(#main_entries == 1, "Should get 1 entry")
        assert(#main_entries[1].chain >= 2, "g_main_ptr chain should have >= 2 elements")
        assert(main_entries[1].chain[1].type == "pointer", "First should be pointer")
        assert(main_entries[1].chain[2].type == "instruction", "Second should be instruction")

        -- TEST 3b: probe_start. Telescoping the code address main() itself:
        -- as a *pointer* (register-style, the default) its target is described
        -- first, i.e. the instruction at main; as a memory *slot* (hex view,
        -- probe_start = false) only the stored value — the instruction bytes
        -- reinterpreted as a QWORD — is followed, and that must not be reported
        -- as "the instruction at this slot".
        local code_addr = main_entries[1].chain[1].address
        local as_pointer = dbg:dereference(pid, code_addr, 1)
        assert(as_pointer[1].chain[1].type == "instruction",
            "code address as pointer should describe the instruction it points at")
        local as_slot = dbg:dereference(pid, code_addr, 1, nil, false)
        assert(#as_slot == 1 and #as_slot[1].chain >= 1, "slot telescope should yield a chain")
        assert(as_slot[1].chain[1].type ~= "instruction",
            "code slot must not report the instruction at its own address, got instruction")
        assert(as_slot[1].chain[1].type ~= "string",
            "code slot must not report a string at its own address")
        -- The batch form takes the same flag.
        local batch_slot = dbg:dereference_batch(pid, { code_addr }, 1, nil, false)
        assert(batch_slot[1][1].chain[1].type == as_slot[1].chain[1].type,
            "dereference_batch must honour probe_start like dereference")

        -- TEST 4: Stack pointer dereference (multiple entries)
        local ctx = dbg:get_context(pid, tid)
        local stack_entries = dbg:dereference(pid, spof(ctx), 10)
        assert(#stack_entries == 10, "Should get exactly 10 entries")
        -- Verify offsets are correct (8 bytes apart for 64-bit)
        for i, entry in ipairs(stack_entries) do
            local expected_offset = (i - 1) * 8
            assert(entry.offset == expected_offset,
                "Entry " .. i .. " should have offset " .. expected_offset .. ", got " .. entry.offset)
        end

        -- TEST 5: Batch dereference — one entry list per address, in order,
        -- matching the single-address results (server walks regions once).
        local batch = dbg:dereference_batch(pid,
            { string_sym[1].va, null_sym[1].va, main_sym[1].va }, 1)
        assert(#batch == 3, "Batch should return one list per address")
        assert(#batch[1] == 1 and batch[1][1].chain[1].type == "pointer",
            "Batch g_string_ptr should match single dereference")
        assert(batch[1][1].chain[2].value:find("Hello, Dereference!"),
            "Batch string chain should contain 'Hello, Dereference!'")
        assert(batch[2][1].chain[1].type == "value" and batch[2][1].chain[1].value == 0,
            "Batch NULL should produce value 0")
        assert(batch[3][1].chain[2].type == "instruction",
            "Batch g_main_ptr should resolve to instruction")
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
