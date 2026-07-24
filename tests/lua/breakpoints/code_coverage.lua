-- Test: server-side code coverage (silent, auto-counted breakpoints).
--
-- Coverage breakpoints are counted inside the server and the debuggee
-- auto-continues without client events, so we arm every ntdll function at the
-- initial breakpoint, run the target (cmd.exe) to exit, and read the counts back
-- in on_process_exited (the process entry, and its coverage map, survive process
-- exit and are only dropped on detach). Functions are enumerated from ntdll's
-- RUNTIME_FUNCTION table (PE exception directory) so the test needs no PDBs.

local LIMIT = 3 -- keep counting up to 3 hits per function (exercises re-arm path)

local result = { armed = 0, hit_fns = 0, max_count = 0, seqs = {}, bad_tids = 0 }

-- Enumerate ntdll's function entry points (VA = base + RUNTIME_FUNCTION.begin).
local function ntdll_function_addrs(pid)
    local base = nil
    for _, m in ipairs(dbg:list_modules(pid)) do
        if m.name:lower():find("ntdll%.dll") then base = m.base end
    end
    assert(base ~= nil, "ntdll.dll should be loaded")

    local info = dbg:get_module_info(pid, base)
    assert(info.runtime_functions ~= nil, "ntdll should expose a RUNTIME_FUNCTION table")

    local seen, addrs = {}, {}
    for _, rf in ipairs(info.runtime_functions) do
        if rf.end_address > rf.begin_address then
            local va = base + rf.begin_address
            if not seen[va] then
                seen[va] = true
                addrs[#addrs + 1] = va
            end
        end
    end
    return addrs
end

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local addrs = ntdll_function_addrs(pid)
    result.armed = #addrs
    dbg:start_coverage(pid, addrs, LIMIT)
end)

dbg:on_process_exited(function(pid, exit_code)
    -- The process (and its coverage map) is still present in this handler.
    local hits = dbg:get_coverage(pid)
    for _, h in ipairs(hits) do
        if h.hit_count > 0 then
            result.hit_fns = result.hit_fns + 1
            if h.hit_count > result.max_count then result.max_count = h.hit_count end
        end
        result.seqs[#result.seqs + 1] = h.first_hit_seq
        if type(h.thread_ids) ~= "table" or #h.thread_ids < 1 then
            result.bad_tids = result.bad_tids + 1
        end
    end
end)

dbg:launch('cmd.exe /c "echo coverage"')
dbg:run()

-- Validate arming, silent counting, and the per-address cap.
assert(result.armed > 100, "expected many armed coverage breakpoints, got " .. result.armed)
assert(result.hit_fns >= 10, "expected >=10 ntdll functions hit, got " .. result.hit_fns)
assert(result.max_count >= 2, "limit=3 should count repeated hits; max was " .. result.max_count)
assert(result.max_count <= LIMIT, "limit=3 should cap counts at 3; max was " .. result.max_count)

-- First-hit sequence numbers are exactly the consecutive set 1..hit_fns (only
-- coverage first-hits advance the counter), and every hit records >=1 thread id.
table.sort(result.seqs)
assert(#result.seqs == result.hit_fns, "one seq per hit function")
for i, seq in ipairs(result.seqs) do
    assert(seq == i, "first_hit_seq should be consecutive 1..N; index " .. i .. " was " .. seq)
end
assert(result.bad_tids == 0, result.bad_tids .. " hits reported no thread ids")

return { passed = true }
