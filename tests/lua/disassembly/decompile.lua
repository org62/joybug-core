-- Test: decompile a function of a live process (from the module's file).
-- Requires: disassembly_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness
local checked = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", function(pid, tid, addr)
        local syms = dbg:find_symbol("disassembly_test!test_control_flow", 5)
        assert(#syms > 0, "Should find test_control_flow symbol")
        local listing = dbg:disassemble_function(pid, syms[1].va, 400)

        local fn = dbg:decompile(pid, syms[1].va)
        assert(fn.name == "test_control_flow", "named from the loaded symbols, got " .. tostring(fn.name))
        assert(fn.start == syms[1].va, "starts at the symbol's live address")
        assert(fn.code:find("helper_add", 1, true), "callees are named: " .. fn.code)

        -- The line map is in live addresses (the module's load base applied).
        assert(#fn.lines > 0, "lines carry addresses")
        for _, row in ipairs(fn.lines) do
            for _, va in ipairs(row.addresses) do
                assert(va >= listing.start and va < listing["end"], "address inside the function: " .. hex(va))
            end
        end

        -- The address we stopped at is inside its own function.
        local here = dbg:decompile(pid, addr)
        assert(here.name == "breakpoint_here", "the current function, got " .. tostring(here.name))

        local ok = pcall(function() return dbg:decompile(pid, 0x10) end)
        assert(not ok, "an address in no module fails")
        checked = true
    end)
end)

dbg:launch(test_exe)
dbg:run()
assert(checked, "the breakpoint handler ran")

return { passed = true }
