-- Test: Backward disassembly (x64dbg-style self-resynchronizing decode)
-- Verifies disassemble_backward's boundaries match a forward decode from a
-- known-good function start.
-- Requires: disassembly_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", function(pid, tid, addr)
        local syms = dbg:find_symbol("disassembly_test!test_control_flow", 5)
        assert(#syms > 0, "Should find test_control_flow symbol")
        local func_va = syms[1].va

        -- Forward decode from the (known-good) function start.
        local fwd = dbg:disassemble(pid, func_va, 20)
        assert(#fwd >= 8, "Need enough instructions to test backward decode, got " .. #fwd)

        -- Pick an instruction well inside the function as the backward anchor.
        local anchor_index = 6
        local target = fwd[anchor_index].address

        -- Backward-disassemble the 4 instructions ending at `target`.
        local want = 4
        local back = dbg:disassemble_backward(pid, target, want)
        assert(#back == want,
            "Expected " .. want .. " backward instructions, got " .. #back)

        -- Every returned instruction must end at or before the anchor (never straddle it).
        for _, inst in ipairs(back) do
            assert(inst.address < target, "backward insn not before target at " .. hex(inst.address))
            assert(inst.address + inst.size <= target, "backward insn straddles target at " .. hex(inst.address))
        end

        -- The last backward instruction must end exactly at the anchor (self-sync landed).
        local last = back[#back]
        assert(last.address + last.size == target,
            "last backward insn should end exactly at target: " .. hex(last.address + last.size) .. " vs " .. hex(target))

        -- Boundaries must match the forward decode's predecessors of `target`.
        for i = 0, want - 1 do
            local fwd_inst = fwd[anchor_index - want + i]
            local back_inst = back[i + 1]
            assert(fwd_inst.address == back_inst.address,
                "boundary mismatch at " .. i .. ": fwd " .. hex(fwd_inst.address) .. " vs back " .. hex(back_inst.address))
        end
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
