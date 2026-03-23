-- Test: Exception passed to application (SEH handler runs)
-- Ported from: exception_test.rs::test_exception_passed_to_application
-- Requires: exception_test.exe
--
-- When exception 0xE0000001 is passed to the application (DBG_EXCEPTION_NOT_HANDLED),
-- the SEH handler runs, g_caught = 1, process exits with code 0.

local test_exe = TEST_EXE -- injected by Rust test harness
local exit_code = nil

-- Pass exception 0xE0000001 to application on first chance
dbg:on_exception(function(pid, tid, code, address, first_chance)
    if code == 0xE0000001 and first_chance then
        return "pass"
    end
end)

dbg:on_process_exited(function(pid, code)
    exit_code = code
end)

dbg:launch(test_exe)
dbg:run()

assert(exit_code == 0,
    "Expected exit code 0 (exception passed to application), got " .. tostring(exit_code))

return { passed = true }
