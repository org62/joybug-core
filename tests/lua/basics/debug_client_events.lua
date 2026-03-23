-- Test: Debug client event collection (process/thread/DLL events, breakpoints, stepping)
-- Ported from: debug_client_test.rs::test_debug_client_event_collection

local initial_bp_hit = false
local process_created = false
local dll_loads_count = 0
local ntclose_bp_hits = 0
local steps_completed = 0
local single_shot_hit = false

dbg:on_process_created(function(pid, tid, name, base)
    process_created = true
end)

dbg:on_dll_loaded(function(pid, tid, name, base)
    dll_loads_count = dll_loads_count + 1
end)

dbg:on_initial_breakpoint(function(pid, tid, addr)
    initial_bp_hit = true

    -- Set a persistent breakpoint on NtClose, track 3 hits then remove
    local ntclose_syms = dbg:find_symbol("ntdll!NtClose", 5)
    assert(#ntclose_syms > 0, "Should find NtClose")
    dbg:set_breakpoint(pid, ntclose_syms[1].va, function(pid, tid, addr)
        ntclose_bp_hits = ntclose_bp_hits + 1
        if ntclose_bp_hits >= 3 then
            return "remove"
        end
    end)

    -- Set single-shot breakpoint on CmdPutChars
    dbg:set_single_shot_breakpoint(pid, "cmd!CmdPutChars", function(pid, tid, addr)
        single_shot_hit = true

        -- Test stepping: 3 steps of step_into
        for i = 1, 3 do
            local new_addr = dbg:step_into(pid, tid)
            assert(new_addr > 0, "Step " .. i .. " should produce nonzero address")
            steps_completed = steps_completed + 1
        end
    end)
end)

dbg:launch('cmd.exe /c echo test')
dbg:run()

assert(process_created, "Should have received process created event")
assert(initial_bp_hit, "Should have hit initial breakpoint")
assert(single_shot_hit, "Single-shot breakpoint should have been hit")
assert(dll_loads_count >= 1, "Should have at least one DLL loaded event")
assert(steps_completed == 3,
    "Should have completed exactly 3 steps, got " .. steps_completed)
assert(ntclose_bp_hits == 3,
    "NtClose should be hit exactly 3 times, got " .. ntclose_bp_hits)

return { passed = true }
