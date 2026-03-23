-- Test: Simple trap-flag tracer
-- Ported from: tracer_test.rs::test_trap_flag_tracer_simple

local traced = false
local trace_count = 0

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Trace just 10 instructions from initial breakpoint
    local result = dbg:trace(pid, tid, 10)
    traced = true
    trace_count = #result.trace:gmatch("[^\n]+")()  -- crude line count
    -- Actually just check that trace is non-empty
    assert(result.trace ~= "", "Trace output should not be empty")
    assert(result.time_us > 0, "Trace time should be positive")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

assert(traced, "Should have traced instructions")

return { passed = true }
