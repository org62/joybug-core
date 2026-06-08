-- Test: REPL-style stepping (multiple steps + register globals + resolve)
-- Ported from: scripting_test.rs::test_repl_stepping_and_register_globals

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Simulate REPL stepping
    local ctx1 = dbg:get_context(pid, tid)
    local rip1 = ctx1.rip

    -- Step (same call the REPL si command makes)
    local rip2 = dbg:step_into(pid, tid)

    -- Step again
    local rip3 = dbg:step_into(pid, tid)

    -- Read context after stepping
    local ctx3 = dbg:get_context(pid, tid)
    assert(rip3 == ctx3.rip, "rip after step should match context rip")

    -- Resolve address (same as format_address)
    local sym = dbg:resolve_address(pid, rip3)
    assert(sym.name ~= nil and sym.name ~= "", "should resolve stepped address to a symbol")

    assert(rip1 ~= rip2 and rip2 ~= rip3,
        string.format("each step should reach different address: rip1=%s, rip2=%s, rip3=%s",
            hex(rip1), hex(rip2), hex(rip3)))

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
