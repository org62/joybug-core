-- Test: disassemble_function honours an address INSIDE an instruction.
--
-- A function with .pdata bounds is decoded from its start and trimmed to the
-- function range, because that is the only way to get correct boundaries for
-- the whole listing. But `start <= address < end` is satisfied by a
-- mid-instruction address too, and the aligned decode that comes back then
-- contains no row at the address the caller asked for. Callers that hand a
-- byte offset to a decoder (overlapping code, an instruction hidden inside
-- another's immediate) must still get a listing anchored where they asked.
--
-- NOTE ON max_instructions: the whole-function decode is only chosen when the
-- function's estimated instruction count (size/2) fits the requested count.
-- Passing a small count silently takes the other branch, which is already
-- anchored at the requested address — and the test would pass without the fix.
-- So the counts below are derived from the function's own size.
--
-- Requires: disassembly_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", function(pid, tid, addr)
        local syms = dbg:find_symbol("disassembly_test!test_control_flow", 5)
        assert(#syms > 0, "Should find test_control_flow symbol")
        local fn_va = syms[1].va

        -- Learn the function's .pdata bounds first.
        local probe = dbg:disassemble_function(pid, fn_va, 4000)
        assert(probe.start and probe["end"], "test_control_flow should have .pdata bounds")
        assert(probe.start == fn_va, "Symbol should sit at the function start")
        local size = probe["end"] - probe.start
        -- size >= size/2 == the estimated instruction count, so this count always
        -- selects the whole-function (trim) branch.
        local count = math.max(size, 2)

        local aligned = dbg:disassemble_function(pid, fn_va, count).instructions
        assert(#aligned > 0, "Should have some instructions")
        assert(aligned[1].address == fn_va, "Aligned decode should start at the function")

        -- Any multi-byte instruction gives us an address that is inside it.
        local host = nil
        for _, inst in ipairs(aligned) do
            if inst.size >= 2 then host = inst break end
        end
        assert(host, "Expected at least one multi-byte instruction")
        local mid = host.address + 1
        assert(mid > probe.start and mid < probe["end"],
            "mid must stay inside the function bounds to exercise the trim branch")

        -- Precondition: that address is genuinely not a boundary of the
        -- function's own aligned listing.
        for _, inst in ipairs(aligned) do
            assert(inst.address ~= mid,
                "mid should not be an instruction boundary: " .. hex(mid))
        end

        -- ...and asking for it anyway must return a listing that starts there,
        -- not the aligned whole-function decode that omits it entirely.
        local unaligned = dbg:disassemble_function(pid, mid, count).instructions
        assert(#unaligned > 0, "Unaligned decode returned nothing at " .. hex(mid))
        assert(unaligned[1].address == mid,
            "Expected first instruction at " .. hex(mid) ..
            ", got " .. hex(unaligned[1].address))

        -- A real boundary still decodes the whole aligned function, unchanged.
        local again = dbg:disassemble_function(pid, fn_va, count).instructions
        assert(#again == #aligned, "Aligned decode changed: " .. #again .. " vs " .. #aligned)
        assert(again[1].address == aligned[1].address,
            "Aligned decode should still be anchored at the function start")
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
