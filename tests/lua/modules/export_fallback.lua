-- Test: PE export fallback when a module's PDB is unavailable. A deny-listed
-- module skips the PDB download but still gets its export table loaded as
-- symbols (state "exports_only"), so disassembly/resolution aren't nameless.

local handler_ran = false

-- Deny ntdll before launch, like a client restoring a persisted deny list.
assert(dbg:set_symbol_deny_list({ "ntdll.dll" }), "set_symbol_deny_list should ack")

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local nt = wait_symbols(pid, "ntdll")
    assert(nt, "ntdll should be in the status list")
    assert(nt.state == "exports_only",
        "denied ntdll should fall back to exports, got: " .. tostring(nt.state)
        .. " (" .. tostring(nt.error) .. ")")
    assert(nt.symbol_count > 100,
        "ntdll exports hundreds of symbols, got: " .. tostring(nt.symbol_count))
    assert(nt.error ~= nil, "exports_only should carry the PDB failure reason")
    assert(nt.pdb_path == nil, "exports_only must not report a pdb_path")

    -- Export names resolve like regular symbols
    local syms = dbg:find_symbol("ntdll!NtClose", 10)
    assert(#syms > 0, "NtClose should be found among ntdll's exports")
    assert(syms[1].va > nt.base, "resolved export VA should be inside ntdll")

    -- And addresses resolve back to export names
    local back = dbg:resolve_address(pid, syms[1].va)
    assert(back and back.name and back.name:find("NtClose"),
        "address should resolve back to the export name, got: "
        .. tostring(back and back.name))

    -- Retry lifts the deny, evicts the export stub, and re-attempts the real
    -- PDB. The result depends on symbol-server availability: loaded, or
    -- exports_only again — but then with a real download error, not the
    -- "skipped" deny message (proof a download was actually attempted).
    assert(dbg:retry_symbols(pid, nt.base), "retry_symbols should ack")
    local after = wait_symbols(pid, "ntdll", 120)
    assert(after, "ntdll should settle after retry")
    assert(after.state == "loaded" or after.state == "exports_only",
        "retried ntdll should settle, got: " .. tostring(after.state))
    if after.state == "exports_only" then
        assert(not after.error:find("skipped"),
            "after retry the error should be a real download failure, got: " .. after.error)
    end

    handler_ran = true
    dbg:terminate(pid)
end)

dbg:launch(TEST_EXE)
dbg:run()

assert(handler_ran, "initial breakpoint handler should have run")
return { passed = true }
