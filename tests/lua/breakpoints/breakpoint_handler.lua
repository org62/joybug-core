-- Test: Breakpoints with handlers (set, hit, remove)
-- Ported from: scripting_test.rs::test_script_breakpoint_handler
-- Requires: disassembly_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness
local bp_hit_count = 0
local bp_pid, bp_rip, bp_frame_count

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Set breakpoint on test_control_flow (a function in disassembly_test.exe)
    local syms = dbg:find_symbol("test_control_flow", 5)
    assert(#syms > 0, "should find test_control_flow symbol")

    dbg:set_breakpoint(pid, syms[1].va, function(pid, tid, addr)
        bp_hit_count = bp_hit_count + 1
        bp_pid = pid

        -- Read registers at the breakpoint
        local ctx = dbg:get_context(pid, tid)
        bp_rip = ipof(ctx)

        -- Get call stack at breakpoint
        local frames = dbg:get_call_stack(pid, tid)
        bp_frame_count = #frames

        return "remove"  -- remove after first hit
    end)
end)

dbg:launch(test_exe)
dbg:run()

assert(bp_hit_count == 1,
    "breakpoint should be hit exactly once, got " .. bp_hit_count)
assert(bp_pid > 0, "breakpoint pid should be nonzero")
assert(bp_rip > 0, "rip at breakpoint should be nonzero")
assert(bp_frame_count >= 1, "should have at least 1 frame at breakpoint")

return { passed = true }
