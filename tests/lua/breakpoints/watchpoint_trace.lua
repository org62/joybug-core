-- Test: Hardware access trace ("find what reads/writes an address")
-- Arms a silent ReadWrite watchpoint on g_rw_dword; the target runs freely while
-- the server records every accessing instruction (no HardwareBreakpoint event is
-- ever delivered to us — we register no hw handler). g_rw_dword is read once
-- (read_rw) and written once (write_rw) after breakpoint_here, so we expect two
-- distinct accessors, one hit each.
-- Requires: hardware_bp_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

local rw_va = nil
local collected_count = nil        -- distinct accessors seen at execute_target
local collected_total_hits = nil   -- sum of hit counts
local cleared_after_stop = nil     -- accessor count after stop_watchpoint_trace

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Arm the access trace when we reach breakpoint_here (before any access).
    dbg:set_breakpoint(pid, "breakpoint_here", function(pid, tid, addr)
        local syms = dbg:find_symbol("g_rw_dword", 5)
        assert(#syms > 0, "Should find g_rw_dword")
        rw_va = syms[1].va
        -- Silent: no handler, the target must NOT break on this.
        dbg:start_watchpoint_trace(pid, rw_va, "rw", "4")
        return "remove"
    end)

    -- execute_target() is the last call in main(), reached only after both
    -- g_rw_dword accesses have happened. Inspect the collected accessors here,
    -- while the process is still alive.
    dbg:set_breakpoint(pid, "execute_target", function(pid, tid, addr)
        local accesses = dbg:get_watchpoint_accesses(pid, rw_va)
        collected_count = #accesses
        local total = 0
        for _, a in ipairs(accesses) do
            total = total + a.hit_count
            assert(a.accessor_raw_rip ~= 0, "raw trap instruction pointer should be set")
            assert(a.accessor ~= 0, "attributed accessor should be set")
            -- x86 traps after the access: the attributed accessor back-steps
            -- from (or, if attribution failed, equals) the raw trap RIP.
            assert(a.accessor <= a.accessor_raw_rip, "accessor should not be past the trap RIP")
        end
        collected_total_hits = total

        -- Stopping the trace tears down the server-side state; the caller (UI)
        -- keeps whatever it already polled. Prove the teardown clears it.
        dbg:stop_watchpoint_trace(pid, rw_va)
        cleared_after_stop = #dbg:get_watchpoint_accesses(pid, rw_va)
        return "remove"
    end)
end)

dbg:launch(test_exe)
dbg:run()

assert(collected_count == 2,
    "expected 2 distinct accessors of g_rw_dword (read_rw + write_rw), got " .. tostring(collected_count))
assert(collected_total_hits == 2,
    "expected 2 total accesses (1 read + 1 write), got " .. tostring(collected_total_hits))
assert(cleared_after_stop == 0,
    "stop_watchpoint_trace should clear server-side accesses, got " .. tostring(cleared_after_stop))

return { passed = true }
