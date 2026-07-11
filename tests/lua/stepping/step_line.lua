-- Test: Source-line stepping (dbg:step_line)
-- Requires: xtea_test.exe (built /Od /Zi, so it has PDB line tables)

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "xtea_test!main", function(pid, tid, addr)
        -- Resolve the starting source line at main's entry.
        local start = dbg:resolve_line(pid, addr)
        assert(start ~= nil, "main should resolve to a source line")
        local start_line = start.line

        -- Step over one source line; PC must advance to a different line
        -- (or leave the mapped source), never staying on the same line.
        local new_addr = dbg:step_line("over")
        assert(new_addr ~= addr, "step_line should advance the PC")

        local after = dbg:resolve_line(pid, new_addr)
        if after ~= nil and after.file:lower() == start.file:lower() then
            assert(after.line ~= start_line,
                "step_line should leave the starting source line (" .. start_line .. ")")
        end

        dbg:terminate(pid)
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
