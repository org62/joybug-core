-- Test: server-side value freeze.
-- Requires: freeze_value_test.exe
--
-- The victim keeps resetting a global `g_value` to 1000 in a loop. We freeze the
-- global to a sentinel; while the debuggee is stopped only the server-side freeze
-- thread can write memory, so after letting it tick the address must read the
-- sentinel. After unfreeze, the freeze no longer overwrites the address.

local test_exe = TEST_EXE -- injected by Rust test harness

local PROGRAM_VALUE = 1000
local SENTINEL = 0xAABBCCDD

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "freeze_value_test!pause_here", function(pid, tid, addr)
        -- Resolve &g_value.
        local syms = dbg:find_symbol("freeze_value_test!g_value", 10)
        assert(#syms >= 1, "should resolve g_value symbol")
        local value_addr = syms[1].va

        -- Program just set g_value = PROGRAM_VALUE before hitting pause_here.
        assert(dbg:read_u32(pid, value_addr) == PROGRAM_VALUE,
            "expected program value before freeze")

        -- Freeze to the sentinel (little-endian bytes).
        local data = string.char(0xDD, 0xCC, 0xBB, 0xAA)
        local freeze_id = dbg:freeze_value(pid, value_addr, data)

        -- While stopped, only the freeze thread writes. Let it tick, then verify.
        dbg:sleep(200)
        assert(dbg:read_u32(pid, value_addr) == SENTINEL,
            "freeze should hold the sentinel value while stopped")

        -- After unfreeze nothing overwrites the address while stopped.
        dbg:unfreeze_value(freeze_id)
        dbg:sleep(100)
        assert(dbg:read_u32(pid, value_addr) == SENTINEL,
            "value should be untouched right after unfreeze")

        dbg:terminate(pid)
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
