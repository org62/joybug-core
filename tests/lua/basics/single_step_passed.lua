-- Test: Program-raised single-step exception passed to application (SEH handler runs)
-- Ported from: single_step_test.rs::test_single_step_passed_to_application
-- Requires: single_step_test.exe
--
-- The debuggee raises EXCEPTION_SINGLE_STEP (0x80000004) itself. When it is
-- passed to the application (DBG_EXCEPTION_NOT_HANDLED), the SEH handler runs,
-- g_caught = 1, process exits with code 0.

local test_exe = TEST_EXE -- injected by Rust test harness
local exit_code = nil

-- Pass the single-step exception to the application on first chance
dbg:on_exception(function(pid, tid, code, address, first_chance)
    if code == 0x80000004 and first_chance then
        return "pass"
    end
end)

dbg:on_process_exited(function(pid, code)
    exit_code = code
end)

dbg:launch(test_exe)
dbg:run()

assert(exit_code == 0,
    "Expected exit code 0 (single-step exception passed to application), got " .. tostring(exit_code))

return { passed = true }
