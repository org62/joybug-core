-- Test: multi-token symbol search
-- A query is split on whitespace and every token must appear (case-insensitively)
-- in the module name or the symbol name, in any order. So "LoadDll Ldr" and
-- "ntdll LdrLoad" both find ntdll!LdrLoadDll.

local function names(syms)
    local out = {}
    for _, s in ipairs(syms) do out[#out + 1] = s.name end
    return table.concat(out, ", ")
end

local function has_ldrloaddll(syms)
    for _, s in ipairs(syms) do
        if s.name:find("LdrLoadDll") then return true end
    end
    return false
end

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Baseline: a single token still behaves as a plain substring match.
    local single = dbg:find_symbol("LdrLoadDll", 10)
    assert(has_ldrloaddll(single), "single token should find LdrLoadDll, got: " .. names(single))

    -- Tokens match in any order.
    local reordered = dbg:find_symbol("LoadDll Ldr", 10)
    assert(has_ldrloaddll(reordered),
        "reordered tokens should find LdrLoadDll, got: " .. names(reordered))

    -- A token may match the module name instead of the symbol name.
    local by_module = dbg:find_symbol("ntdll LdrLoad", 10)
    assert(has_ldrloaddll(by_module),
        "module token + name token should find LdrLoadDll, got: " .. names(by_module))

    -- Every token must match: one bogus token kills the hit.
    local none = dbg:find_symbol("LdrLoadDll zzz_no_such_token", 10)
    assert(#none == 0, "an unmatchable token should exclude everything, got: " .. names(none))

    -- module!symbol syntax keeps working, with tokens inside the symbol part.
    local scoped = dbg:find_symbol("ntdll!LoadDll Ldr", 10)
    assert(has_ldrloaddll(scoped),
        "module-scoped tokens should find LdrLoadDll, got: " .. names(scoped))

    -- An exact module!symbol query still ranks the exact match first.
    local exact = dbg:find_symbol("ntdll!LdrLoadDll", 5)
    assert(#exact > 0, "exact module!symbol should resolve")
    assert(exact[1].name:find("LdrLoadDll"),
        "exact match should come first, got: " .. exact[1].name)

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
