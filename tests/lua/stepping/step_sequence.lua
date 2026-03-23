-- Test: Stepping sequence (Into, Over, Out)
-- Ported from: stepper_test.rs::test_stepper_test

local steps_taken = 0
local step_kinds = {"into", "into", "into", "over", "over", "out", "out"}
local step_idx = 1

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Execute the step sequence
    for i, kind in ipairs(step_kinds) do
        local new_addr
        if kind == "into" then
            new_addr = dbg:step_into(pid, tid)
        elseif kind == "over" then
            new_addr = dbg:step_over(pid, tid)
        elseif kind == "out" then
            new_addr = dbg:step_out(pid, tid)
        end
        steps_taken = steps_taken + 1
        assert(new_addr > 0, "Step " .. i .. " (" .. kind .. ") should produce nonzero address")
    end

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

assert(steps_taken == #step_kinds,
    "Should have taken " .. #step_kinds .. " steps, got " .. steps_taken)

return { passed = true }
