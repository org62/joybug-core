-- Test: Memory scan (exact value narrowing for U32)
-- Ported from: memory_scan_test.rs::memory_scan_exact_value (U32 type only)
-- Requires: memory_scan_test.exe
-- Note: Lua scan_start only supports string values, so we test U32 exact narrowing

local test_exe = TEST_EXE -- injected by Rust test harness

local scan_id = nil
local iteration = 0
local match_counts = {}
local done = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "pause_here", function(pid, tid, addr)
        if done then return "remove" end

        if iteration == 0 then
            -- Start scan for U32 with initial value 0x12345678
            local result = dbg:scan_start(pid, "u32", "exact", "0x12345678")
            scan_id = result.scan_id
            table.insert(match_counts, result.match_count)
        else
            -- Refine with next expected value
            local expected = 0x12345678 + iteration
            local result = dbg:scan_next(scan_id, "exact", tostring(expected), "u32")
            table.insert(match_counts, result.match_count)

            if result.match_count <= 5 or iteration >= 15 then
                done = true
            end
        end

        iteration = iteration + 1

        if done then
            -- Verify results
            local results = dbg:scan_results(scan_id, 0, 10)
            assert(results.total_count >= 1,
                "Expected at least 1 final match, got " .. results.total_count)
            dbg:scan_reset(scan_id)
            return "remove"
        end
    end)
end)

dbg:launch(test_exe)
dbg:run()

-- Verify convergence
assert(#match_counts > 0, "No scan iterations recorded")
local first = match_counts[1]
local last = match_counts[#match_counts]
assert(last < first or first <= 5,
    "Match count did not decrease (first=" .. first .. ", last=" .. last .. ")")
assert(last >= 1, "Expected at least 1 final match, got " .. last)
assert(done, "Test did not complete")

return { passed = true }
