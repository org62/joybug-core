-- Test: Stepping (step into from initial breakpoint)
-- Ported from: scripting_test.rs::test_script_stepping

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local ctx_before = dbg:get_context(pid, tid)
    local rip_before = ctx_before.rip

    -- Single step into
    local step_addr = dbg:step_into(pid, tid)
    assert(step_addr ~= rip_before, "should have moved to a different address after step_into")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo stepping_test"')
dbg:run()

return { passed = true }
