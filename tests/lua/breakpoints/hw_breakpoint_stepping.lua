-- Test: Stepping over a hardware execution breakpoint
-- Ported from: hardware_breakpoint_stepping_test.rs::hardware_breakpoint_step_over
-- Requires: hardware_bp_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

local hw_bp_hit_count = 0
local hw_bp_address = 0
local step_completed = false
local step_address = 0

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "breakpoint_here", function(pid, tid, addr)
        -- Set HW execute breakpoint on execute_target
        local exec_syms = dbg:find_symbol("execute_target", 5)
        assert(#exec_syms > 0, "Should find execute_target")

        dbg:set_hw_breakpoint(pid, exec_syms[1].va, "execute", "1", function(pid, tid, addr)
            hw_bp_hit_count = hw_bp_hit_count + 1
            hw_bp_address = addr

            if hw_bp_hit_count == 1 then
                -- First hit: step over the instruction
                step_address = dbg:step_over(pid, tid)
                step_completed = true
            elseif hw_bp_hit_count >= 3 then
                -- Bug: step was swallowed, remove BP to unblock
                return "remove"
            end
        end)

        return "remove"
    end)
end)

dbg:launch(test_exe)
dbg:run()

assert(step_completed,
    "Step over from hardware breakpoint never completed")
assert(step_address ~= hw_bp_address,
    "Step over landed back at same HW BP address " .. hex(hw_bp_address))
assert(hw_bp_hit_count == 1,
    "HW BP was hit " .. hw_bp_hit_count .. " times, expected 1")

return { passed = true }
