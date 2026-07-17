-- Test: Program-raised single-step exception handled by debugger (swallowed)
-- Ported from: single_step_test.rs::test_single_step_handled_by_debugger
-- Requires: single_step_test.exe
--
-- The debuggee raises EXCEPTION_SINGLE_STEP (0x80000004) itself. When the
-- debugger handles it (DBG_CONTINUE), the SEH handler never runs, g_caught
-- stays 0, process exits with code 1.

local test_exe = TEST_EXE -- injected by Rust test harness
local exit_code = nil

-- Explicitly handle the single-step exception (swallow it) on first chance.
dbg:on_exception(function(pid, tid, code, address, first_chance)
    if code == 0x80000004 and first_chance then
        return "handled"
    end
end)

dbg:on_process_exited(function(pid, code)
    exit_code = code
end)

dbg:launch(test_exe)
dbg:run()

assert(exit_code == 1,
    "Expected exit code 1 (single-step exception swallowed by debugger), got " .. tostring(exit_code))

return { passed = true }
