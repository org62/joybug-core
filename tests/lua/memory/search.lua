-- Test: Memory pattern search
-- Ported from: memory_search_test.rs::memory_search
-- Requires: memory_search_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "breakpoint_here", function(pid, tid, addr)
        -- 1. String search
        local addrs1, capped1 = dbg:search_memory(pid, "JOYBUG_SEARCH_MARKER", 1000)
        assert(#addrs1 >= 3, "Expected >= 3 string matches, got " .. #addrs1)
        assert(not capped1, "Should not be capped with limit 1000")

        -- 2. Hex pattern search
        local addrs2, capped2 = dbg:search_memory(pid, "\xDE\xAD\xBE\xEF\xCA\xFE", 1000)
        assert(#addrs2 >= 3, "Expected >= 3 hex matches, got " .. #addrs2)
        assert(not capped2, "Should not be capped with limit 1000")

        -- 3. max_results capping
        local addrs3, capped3 = dbg:search_memory(pid, "JOYBUG_SEARCH_MARKER", 1)
        assert(#addrs3 == 1, "Expected exactly 1 match with max_results=1")
        assert(capped3, "Should be capped with max_results=1")

        -- 4. No match
        local addrs4, capped4 = dbg:search_memory(pid, "THIS_STRING_DEFINITELY_DOES_NOT_EXIST_ANYWHERE_IN_MEMORY_12345", 1000)
        assert(#addrs4 == 0, "Expected 0 matches for non-existent pattern")
        assert(not capped4, "Should not be capped when no matches found")
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
