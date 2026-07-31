-- Test: server-side coverage target enumeration + first-hit timestamps.
--
-- `enumerate_coverage_targets` unions a module's `.pdata` RUNTIME_FUNCTION
-- starts with its symbols, filtering symbols the PDB doesn't mark as functions
-- through a code-sanity check. It needs no PDBs: ntdll's exception directory
-- alone yields thousands of targets, which is what makes Code Explorer work on
-- stripped and obfuscated binaries.
--
-- Also asserts the invariant behind the timestamp column: ordering by
-- `first_hit_seq` and ordering by `first_hit_us` agree, since both are stamped
-- on the same 0 -> 1 hit transition.

local result = { targets = 0, pdata_only = 0, sources = {}, named = 0, outside = 0, hits = {} }

local function ntdll_module(pid)
    for _, m in ipairs(dbg:list_modules(pid)) do
        if m.name:lower():find("ntdll%.dll") then return m end
    end
    return nil
end

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local ntdll = ntdll_module(pid)
    assert(ntdll ~= nil, "ntdll.dll should be loaded")

    local targets = dbg:enumerate_coverage_targets(ntdll.name, pid)
    result.targets = #targets

    -- Restricting the sources must only ever narrow the set, and must return
    -- nothing from a tier that wasn't asked for. This is what lets a user opt
    -- out of the heuristic tier entirely.
    local pdata_only = dbg:enumerate_coverage_targets(ntdll.name, pid, { "pdata" })
    result.pdata_only = #pdata_only
    for _, t in ipairs(pdata_only) do
        assert(t.source == "pdata", "pdata-only returned a " .. t.source .. " target")
    end

    local addrs = {}
    for _, t in ipairs(targets) do
        result.sources[t.source] = (result.sources[t.source] or 0) + 1
        if t.symbol ~= nil then result.named = result.named + 1 end
        -- Every target must be inside the module it was enumerated for.
        if t.address < ntdll.base or (ntdll.size and t.address >= ntdll.base + ntdll.size) then
            result.outside = result.outside + 1
        end
        assert(t.address == ntdll.base + t.rva, "address must be base + rva")
        addrs[#addrs + 1] = t.address
    end

    dbg:start_coverage(pid, addrs, 1)
end)

dbg:on_process_exited(function(pid, exit_code)
    for _, h in ipairs(dbg:get_coverage(pid)) do
        result.hits[#result.hits + 1] = { seq = h.first_hit_seq, us = h.first_hit_us }
    end
end)

dbg:launch('cmd.exe /c "echo coverage targets"')
dbg:run()

-- ntdll's exception directory alone is thousands of functions.
assert(result.targets > 500, "expected many coverage targets, got " .. result.targets)
assert(result.outside == 0, result.outside .. " targets fell outside the module")
assert(result.pdata_only > 0, "expected .pdata-only targets")
assert(result.pdata_only <= result.targets,
    "restricting sources must not widen the set: " .. result.pdata_only .. " > " .. result.targets)
assert((result.sources["pdata"] or 0) > 0, "expected .pdata-sourced targets")
for source, _ in pairs(result.sources) do
    assert(source == "pdata" or source == "function_symbol" or source == "validated_symbol",
        "unexpected target source: " .. source)
end
-- Exports are loaded as a symbol fallback even with no PDB, so some targets are
-- named; a nameless one is legitimate (a .pdata function no symbol covers).
assert(result.named > 0, "expected at least some named targets")

-- The run executed something.
assert(#result.hits >= 10, "expected >=10 functions hit, got " .. #result.hits)

-- first_hit_seq and first_hit_us are stamped together, so sorting by execution
-- order must give non-decreasing timestamps. (Equal values are fine: two hits
-- inside the same microsecond.)
table.sort(result.hits, function(a, b) return a.seq < b.seq end)
local previous = 0
for i, h in ipairs(result.hits) do
    assert(h.us >= previous,
        "first_hit_us went backwards at seq " .. h.seq .. ": " .. h.us .. " < " .. previous)
    previous = h.us
    if i == 1 then
        assert(h.seq == 1, "lowest seq should be 1, got " .. h.seq)
    end
end

return { passed = true }
