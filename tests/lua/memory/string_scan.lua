-- Test: runtime string scan over a module's memory span.
-- Requires: memory_search_test.exe
--
-- memory_search_test.exe embeds the static ASCII literal "JOYBUG_SEARCH_MARKER".
-- We scan the main module's [base, base+size) range and assert:
--   1. The marker is found as an ASCII string.
--   2. A case-insensitive substring filter narrows the results to it.
--   3. Sorting by value returns strings in ascending order.
--   4. Sorting by length returns strings in non-descending length order.
--   5. An ascii-only scan yields only ascii entries.
--   6. A scan-time `contains` filter stores only matching strings.
--   7. A writable-filtered whole-address-space scan succeeds.

local test_exe = TEST_EXE -- injected by Rust test harness
local MARKER = "JOYBUG_SEARCH_MARKER"

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "memory_search_test!breakpoint_here", function(pid, tid, addr)
        -- Locate the main module (base + size) to bound the scan.
        local mod = nil
        for _, m in ipairs(dbg:list_modules(pid)) do
            if string.find(m.name:lower(), "memory_search_test", 1, true) then
                mod = m
                break
            end
        end
        assert(mod ~= nil, "should find the memory_search_test module")
        assert(mod.size ~= nil and mod.size > 0, "module should report a size")

        -- 1. Scan the module for strings >= 5 chars.
        local scan = dbg:string_scan_start(pid, mod.base, mod.size, 5)
        assert(scan.match_count >= 1, "string scan should find at least one string")

        -- 2. Filter to the marker; it must be present as an ASCII string whose
        --    address lies inside the module.
        local res = dbg:string_scan_results(scan.results_path, 0, 100, MARKER)
        assert(res.total_count >= 1, "filter should match the marker string")
        local found = false
        for _, s in ipairs(res.strings) do
            if s.text == MARKER then
                assert(s.encoding == "ascii", "marker should be detected as ASCII")
                assert(s.address >= mod.base and s.address < mod.base + mod.size,
                    "marker address should lie within the module span")
                found = true
            end
        end
        assert(found, "the marker string should appear in the filtered results")

        -- 3. Sort by value ascending: results are non-descending (case-insensitive).
        local sorted = dbg:string_scan_results(scan.results_path, 0, 50, "", "value", true)
        local prev = nil
        for _, s in ipairs(sorted.strings) do
            local cur = s.text:lower()
            if prev ~= nil then
                assert(prev <= cur, "value sort should be non-descending")
            end
            prev = cur
        end

        -- 4. Sort by length ascending: lengths are non-descending.
        local by_len = dbg:string_scan_results(scan.results_path, 0, 50, "", "length", true)
        local prev_len = nil
        for _, s in ipairs(by_len.strings) do
            if prev_len ~= nil then
                assert(prev_len <= s.length, "length sort should be non-descending")
            end
            prev_len = s.length
        end

        dbg:string_scan_reset(scan.results_path)

        -- 5. Ascii-only scan: every stored entry is ascii.
        local ascii_scan = dbg:string_scan_start(pid, mod.base, mod.size, 5, "readable", "ascii")
        assert(ascii_scan.match_count >= 1, "ascii-only scan should find strings")
        local ascii_res = dbg:string_scan_results(ascii_scan.results_path, 0, 200)
        for _, s in ipairs(ascii_res.strings) do
            assert(s.encoding == "ascii", "ascii-only scan should store only ascii strings")
        end
        dbg:string_scan_reset(ascii_scan.results_path)

        -- 6. Scan-time contains filter: only strings containing the marker are stored.
        local contains_scan = dbg:string_scan_start(pid, mod.base, mod.size, 5, "readable", "both", MARKER:lower())
        assert(contains_scan.match_count >= 1, "contains-scan should find the marker")
        local contains_res = dbg:string_scan_results(contains_scan.results_path, 0, 200)
        for _, s in ipairs(contains_res.strings) do
            assert(string.find(s.text:lower(), MARKER:lower(), 1, true) ~= nil,
                "contains-scan should store only strings containing the needle")
        end
        dbg:string_scan_reset(contains_scan.results_path)

        -- 7. Writable-filtered scan across the whole user address space succeeds
        --    (environment strings etc. live in writable memory).
        local writable_scan = dbg:string_scan_start(pid, 0, 0xFFFFFFFFFFFF, 5, "writable")
        assert(writable_scan.match_count >= 1, "writable scan should find strings")
        dbg:string_scan_reset(writable_scan.results_path)

        dbg:terminate(pid)
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
