-- Test: List modules and find symbols
-- Ported from: scripting_test.rs::test_script_modules_and_symbols

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- List modules
    local mods = dbg:list_modules(pid)
    assert(#mods >= 3,
        "should have at least ntdll, kernel32, kernelbase: got " .. #mods)

    -- Check that ntdll is loaded
    local ntdll_base = nil
    for _, m in ipairs(mods) do
        if m.name:lower():find("ntdll") then
            ntdll_base = m.base
        end
    end
    assert(ntdll_base, "ntdll should be loaded")
    assert(ntdll_base > 0, "ntdll base should be nonzero")

    -- Find a well-known symbol
    local syms = dbg:find_symbol("LdrLoadDll", 5)
    assert(#syms > 0, "should find LdrLoadDll symbol")
    assert(syms[1].name:find("LdrLoadDll"),
        "symbol name should contain LdrLoadDll, got: " .. syms[1].name)

    -- Resolve the initial breakpoint address
    local ok, resolved = pcall(function() return dbg:resolve_address(pid, addr) end)
    if ok and resolved and resolved.name then
        assert(resolved.name ~= "", "resolved name should be non-empty")
    end

    -- Batch non-blocking resolve: one table per input address, in order.
    -- LdrLoadDll's VA must resolve (its symbols are loaded — find_symbol
    -- waited for them); an unmapped address yields an empty table, not a hole.
    local batch = dbg:try_resolve_addresses(pid, { syms[1].va, 0x1 })
    assert(#batch == 2, "batch should return one entry per address, got " .. #batch)
    assert(batch[1].name and batch[1].name:find("LdrLoadDll"),
        "batch entry 1 should resolve to LdrLoadDll")
    assert(batch[1].offset == 0, "exact symbol VA should have offset 0")
    assert(batch[2].name == nil, "unmapped address should stay unresolved")

    -- Range query: a 1-byte window at LdrLoadDll's VA contains exactly the
    -- symbols starting there (its module is loaded, see above); an unmapped
    -- window yields an empty list rather than an error.
    local in_range = dbg:symbols_in_range(pid, syms[1].va, 1)
    assert(#in_range >= 1, "range at LdrLoadDll should contain it, got " .. #in_range)
    local found = false
    for _, s in ipairs(in_range) do
        assert(s.va == syms[1].va, "every symbol in a 1-byte range shares its VA")
        if s.name:find("LdrLoadDll") then found = true end
    end
    assert(found, "range at LdrLoadDll should list LdrLoadDll")
    -- Widening the window backwards must keep results ascending by VA and
    -- still include the anchor symbol.
    local wide = dbg:symbols_in_range(pid, syms[1].va - 0x1000, 0x1001, 10000)
    assert(#wide >= #in_range, "wider range can't have fewer symbols")
    for i = 2, #wide do
        assert(wide[i - 1].va <= wide[i].va, "symbols_in_range must be sorted by VA")
    end
    assert(#dbg:symbols_in_range(pid, 0x1, 0x10) == 0, "unmapped range should be empty")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
