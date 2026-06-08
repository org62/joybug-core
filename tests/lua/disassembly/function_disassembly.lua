-- Test: Function disassembly with instruction flags and boundaries
-- Ported from: disassembly_test.rs::test_disassembly_basic + test_instruction_flags_detection
-- Requires: disassembly_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "disassembly_test!breakpoint_here", function(pid, tid, addr)
        -- Find test_control_flow function
        local syms = dbg:find_symbol("disassembly_test!test_control_flow", 5)
        assert(#syms > 0, "Should find test_control_flow symbol")

        -- Disassemble function
        local result = dbg:disassemble_function(pid, syms[1].va, 200)
        local instrs = result.instructions
        assert(#instrs > 0, "Should have some instructions")

        -- Count instruction types
        local call_count = 0
        local jump_count = 0
        local ret_count = 0
        for _, inst in ipairs(instrs) do
            if inst.is_call then call_count = call_count + 1 end
            if inst.is_jump then jump_count = jump_count + 1 end
            if inst.is_ret then ret_count = ret_count + 1 end
        end

        -- test_control_flow should have: >= 2 calls, >= 2 jumps, >= 1 ret
        assert(call_count >= 2, "Should have at least 2 call instructions, got " .. call_count)
        assert(jump_count >= 2, "Should have at least 2 jump instructions, got " .. jump_count)
        assert(ret_count >= 1, "Should have at least 1 ret instruction, got " .. ret_count)

        -- Verify instruction flag mutual exclusivity
        for _, inst in ipairs(instrs) do
            if inst.is_ret then
                assert(not inst.is_jump, "ret should not also be jump at " .. hex(inst.address))
                assert(not inst.is_call, "ret should not also be call at " .. hex(inst.address))
            end
            if inst.is_call then
                assert(not inst.is_jump, "call should not also be jump at " .. hex(inst.address))
            end
        end

        -- Verify jump targets
        local jumps_with_targets = 0
        for _, inst in ipairs(instrs) do
            if inst.is_jump and inst.jump_target then
                jumps_with_targets = jumps_with_targets + 1
                assert(inst.jump_target > 0x10000,
                    "Jump target seems too low: " .. hex(inst.jump_target))
            end
        end
        assert(jumps_with_targets > 0, "Should have at least one jump with resolved target")

        -- Verify function boundaries (field names: "start", "end")
        if result.start and result["end"] then
            assert(result.start <= syms[1].va and syms[1].va < result["end"],
                "Symbol address should be within function bounds")
            local size = result["end"] - result.start
            assert(size >= 50, "Function too small: " .. size .. " bytes")
            assert(size <= 10000, "Function too large: " .. size .. " bytes")
        end

        -- Disassemble helper_add to verify different function
        local helper_syms = dbg:find_symbol("disassembly_test!helper_add", 5)
        if #helper_syms > 0 then
            local helper_result = dbg:disassemble_function(pid, helper_syms[1].va, 50)
            local helper_ret = 0
            for _, inst in ipairs(helper_result.instructions) do
                if inst.is_ret then helper_ret = helper_ret + 1 end
            end
            assert(helper_ret >= 1, "helper_add should have at least 1 ret")
        end
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
