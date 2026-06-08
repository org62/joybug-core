-- Test: Tracer vs Emulator comparison
-- Ported from: tracer_test.rs::test_tracer_vs_emulator
-- Requires: xtea_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

local trap_done = false
local emu_done = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Find xtea_encrypt
    local syms = dbg:find_symbol("xtea_encrypt", 5)
    assert(#syms > 0, "Should find xtea_encrypt")
    local encrypt_addr = syms[1].va

    dbg:set_breakpoint(pid, encrypt_addr, function(pid, tid, addr)
        -- Remove breakpoint so emulator sees original bytes
        dbg:remove_breakpoint(pid, addr)

        -- Save context
        local ctx = dbg:get_context(pid, tid)
        local saved_rip = ctx.rip

        -- Step 1: Trap-flag trace for 100 instructions
        local trace_limit = 100
        local trap_result = dbg:trace(pid, tid, trace_limit)
        assert(trap_result.trace ~= "", "Trap trace should produce output")
        trap_done = true

        -- Count trace lines
        local trap_lines = 0
        for _ in trap_result.trace:gmatch("[^\n]+") do
            trap_lines = trap_lines + 1
        end

        -- Step 2: Restore context
        ctx.rip = saved_rip
        dbg:set_context(pid, tid, ctx)

        -- Step 3: Emulator trace for same number of instructions
        local emu_result = dbg:emulate(pid, tid, trap_lines, "trace")
        assert(emu_result.trace ~= nil and emu_result.trace ~= "",
            "Emulator trace should produce output")
        emu_done = true

        -- Count emulator trace lines
        local emu_lines = 0
        for _ in emu_result.trace:gmatch("[^\n]+") do
            emu_lines = emu_lines + 1
        end

        -- Both should have traced instructions
        assert(trap_lines > 0, "Trap trace should have lines")
        assert(emu_lines > 0, "Emulator trace should have lines")

        return "remove"
    end)
end)

dbg:launch(test_exe)
dbg:run()

assert(trap_done, "Trap-flag trace should have run")
assert(emu_done, "Emulator trace should have run")

return { passed = true }
