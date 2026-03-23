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

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
