-- Test: Unload module symbols (dbg:unload_symbols) and the symbol deny list
-- (dbg:set_symbol_deny_list)

local handler_ran = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Wait for the main module's symbols (PDB sits next to the exe)
    local main = wait_symbols(pid, "disassembly_test")
    assert(main, "main module should be in the status list")
    assert(main.state == "loaded", "main module symbols should load, got: " .. main.state)
    assert(main.symbol_count > 0, "loaded module should report a symbol count")

    -- Unload frees the server-side caches; status drops to not_requested
    assert(dbg:unload_symbols(pid, main.base), "unload_symbols should ack")
    local statuses = dbg:symbol_status(pid)
    local after
    for _, s in ipairs(statuses) do
        if s.base == main.base then after = s end
    end
    assert(after, "main module should still be in the status list after unload")
    assert(after.state == "not_requested",
        "unloaded module should report not_requested, got: " .. after.state)

    -- Explicit retry re-loads the symbols
    assert(dbg:retry_symbols(pid, main.base), "retry_symbols should ack")
    local reloaded = wait_symbols(pid, "disassembly_test")
    assert(reloaded and reloaded.state == "loaded",
        "retried module should reload, got: " .. tostring(reloaded and reloaded.state))
    assert(reloaded.symbol_count == main.symbol_count,
        "reloaded symbol count should match the original")

    -- Deny list: a denied module is marked failed instead of downloading.
    -- Unload first so the cached copy doesn't short-circuit the load path.
    assert(dbg:set_symbol_deny_list({ "disassembly_test.exe" }), "set_symbol_deny_list should ack")
    assert(dbg:unload_symbols(pid, main.base), "unload_symbols should ack")
    assert(dbg:retry_symbols(pid, main.base), "retry after deny should ack (retry lifts the deny)")
    local lifted = wait_symbols(pid, "disassembly_test")
    assert(lifted and lifted.state == "loaded",
        "retry should lift the deny and reload, got: " .. tostring(lifted and lifted.state))

    handler_ran = true
    dbg:terminate(pid)
end)

dbg:launch(TEST_EXE)
dbg:run()

assert(handler_ran, "initial breakpoint handler should have run")
return { passed = true }
