-- Test: Per-module symbol load status (dbg:symbol_status)

local handler_ran = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Every reported entry is well-formed
    local statuses = dbg:symbol_status(pid)
    assert(#statuses > 0, "symbol_status should report at least one module")
    for _, s in ipairs(statuses) do
        assert(s.state == "loaded" or s.state == "loading"
            or s.state == "failed" or s.state == "not_requested",
            "unexpected state: " .. tostring(s.state))
        assert(s.base > 0, "module base should be nonzero")
    end

    -- The test program's PDB sits next to the exe, so its symbols load quickly,
    -- but loading is async: wait until the main module reports "loaded".
    local main = wait_symbols(pid, "disassembly_test")
    assert(main, "main module should be in the status list")
    assert(main.state == "loaded",
        "main module symbols should load, got: " .. main.state .. " (" .. tostring(main.error) .. ")")
    assert(main.symbol_count > 0, "loaded module should report a symbol count")
    assert(main.pdb_path ~= nil, "loaded module should report the PDB path")
    handler_ran = true

    dbg:terminate(pid)
end)

dbg:launch(TEST_EXE)
dbg:run()

assert(handler_ran, "initial breakpoint handler should have run")
return { passed = true }
