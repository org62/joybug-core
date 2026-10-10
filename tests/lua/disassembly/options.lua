-- Test: dbg:set_disasm_options - listings without symbols, and the naive linear decode
-- Requires: disassembly_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", function(pid, tid, addr)
        local syms = dbg:find_symbol("disassembly_test!test_control_flow", 5)
        assert(#syms > 0, "Should find test_control_flow symbol")
        local va = syms[1].va

        -- The default: a named function whose first row carries its symbol.
        local full = dbg:disassemble_function(pid, va, 200)
        assert(full.name, "the default listing names the function")
        assert(full.instructions[1].symbol, "the default listing names its rows")

        -- No symbols: the same instructions and bounds, nothing named.
        assert(dbg:set_disasm_options({ symbolize = false }), "set_disasm_options should ack")
        local plain = dbg:disassemble_function(pid, va, 200)
        assert(plain.name == nil, "no function name without symbols")
        assert(plain.start == full.start and plain["end"] == full["end"], "bounds do not need symbols")
        assert(#plain.instructions == #full.instructions, "same instructions without symbols")
        for i, inst in ipairs(plain.instructions) do
            assert(inst.symbol == nil, "row " .. i .. " should carry no symbol")
            assert(inst.address == full.instructions[i].address, "row " .. i .. " should not move")
        end
        local back = dbg:disassemble_backward(pid, va + 16, 4)
        for _, inst in ipairs(back) do
            assert(inst.symbol == nil, "backward rows carry no symbol either")
        end

        -- Naive: a linear decode from the address, no bounds at all.
        assert(dbg:set_disasm_options({ naive = true }))
        local naive = dbg:disassemble_function(pid, va, 20)
        assert(naive.start == nil and naive["end"] == nil and naive.name == nil, "naive has no function bounds")
        assert(#naive.instructions == 20, "naive decodes exactly what was asked, got " .. #naive.instructions)
        assert(naive.instructions[1].address == va, "naive starts at the requested address")
        assert(naive.instructions[1].symbol == nil, "naive rows carry no symbol")
        local linear = dbg:disassemble(pid, va, 5)
        assert(#linear == 5 and linear[1].symbol == nil, "naive applies to plain listings too")

        -- Back to the default.
        assert(dbg:set_disasm_options({}))
        local again = dbg:disassemble_function(pid, va, 200)
        assert(again.name == full.name, "an empty table restores the full listing")
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
