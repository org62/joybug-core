-- Test: Exception handled by debugger (swallowed, SEH handler does NOT run)
-- Ported from: exception_test.rs::test_exception_not_passed_to_application
-- Requires: exception_test.exe
--
-- When the debugger handles exception 0xE0000001 (DBG_CONTINUE),
-- the SEH handler never runs, g_caught stays 0, process exits with code 1.

local test_exe = TEST_EXE -- injected by Rust test harness
local exit_code = nil

-- No on_exception handler → default behavior is DBG_CONTINUE (handled by debugger)
-- The exception is swallowed.

dbg:on_process_exited(function(pid, code)
    exit_code = code
end)

dbg:launch(test_exe)
dbg:run()

assert(exit_code == 1,
    "Expected exit code 1 (exception swallowed by debugger), got " .. tostring(exit_code))

return { passed = true }
