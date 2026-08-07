-- Test: Hardware breakpoints (all types: write, readwrite, execute)
-- Ported from: hardware_breakpoint_test.rs::hardware_breakpoint_all_types
-- Requires: hardware_bp_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

local write_dword_hit = false
local rw_dword_hits = 0
local write_byte_hit = false
local execute_hit = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Set a software breakpoint on breakpoint_here
    dbg:set_breakpoint(pid, "breakpoint_here", function(pid, tid, addr)
        -- DR0: Write(Byte4) on g_write_dword
        local g_write_dword_syms = dbg:find_symbol("g_write_dword", 5)
        assert(#g_write_dword_syms > 0, "Should find g_write_dword")
        dbg:set_hw_breakpoint(pid, g_write_dword_syms[1].va, "write", "4", function(pid, tid, addr)
            write_dword_hit = true
            return "remove"
        end)

        -- DR1: ReadWrite(Byte4) on g_rw_dword (expect 2 hits: read + write)
        local g_rw_dword_syms = dbg:find_symbol("g_rw_dword", 5)
        assert(#g_rw_dword_syms > 0, "Should find g_rw_dword")
        dbg:set_hw_breakpoint(pid, g_rw_dword_syms[1].va, "readwrite", "4", function(pid, tid, addr)
            rw_dword_hits = rw_dword_hits + 1
            if rw_dword_hits >= 2 then
                return "remove"
            end
        end)

        -- DR2: Write(Byte1) on g_write_byte
        local g_write_byte_syms = dbg:find_symbol("g_write_byte", 5)
        assert(#g_write_byte_syms > 0, "Should find g_write_byte")
        dbg:set_hw_breakpoint(pid, g_write_byte_syms[1].va, "write", "1", function(pid, tid, addr)
            write_byte_hit = true
            return "remove"
        end)

        -- DR3: Execute(Byte1) on execute_target
        local exec_syms = dbg:find_symbol("execute_target", 5)
        assert(#exec_syms > 0, "Should find execute_target")
        dbg:set_hw_breakpoint(pid, exec_syms[1].va, "execute", "1", function(pid, tid, addr)
            execute_hit = true
            return "remove"
        end)

        return "remove"
    end)
end)

dbg:launch(test_exe)
dbg:run()

-- Report every flag on failure: which subset fired distinguishes "DRs never
-- armed" from "armed late" (only the first target, write_dword, missed).
local state = string.format(
    " [write_dword=%s rw_hits=%d write_byte=%s execute=%s]",
    tostring(write_dword_hit), rw_dword_hits, tostring(write_byte_hit), tostring(execute_hit))

assert(write_dword_hit, "g_write_dword Write(Byte4) breakpoint should have been hit" .. state)
assert(rw_dword_hits == 2,
    "g_rw_dword ReadWrite(Byte4) should be hit 2 times, got " .. rw_dword_hits)
assert(write_byte_hit, "g_write_byte Write(Byte1) breakpoint should have been hit")
assert(execute_hit, "execute_target Execute(Byte1) breakpoint should have been hit")

return { passed = true }
