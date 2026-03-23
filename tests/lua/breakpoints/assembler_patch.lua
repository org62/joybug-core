-- Test: Assembler code patching
-- Ported from: assembler_test.rs::test_assembler_patch
-- Requires: assembler_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness
local exit_code = nil

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "breakpoint_here", function(pid, tid, addr)
        -- Patch get_value to return 2
        local get_value_syms = dbg:find_symbol("assembler_test!get_value", 5)
        assert(#get_value_syms > 0, "Should find get_value symbol")
        local get_value_va = get_value_syms[1].va

        local result = dbg:assemble("mov eax, 2\nret", get_value_va)
        dbg:write_memory(pid, get_value_va, result.bytes)

        -- Patch get_global to read g_value_b (x86-64 only, RIP-relative)
        local g_value_b_syms = dbg:find_symbol("assembler_test!g_value_b", 5)
        local get_global_syms = dbg:find_symbol("assembler_test!get_global", 5)
        if #g_value_b_syms > 0 and #get_global_syms > 0 then
            local asm_code = string.format("mov eax, [0x%x]\nret", g_value_b_syms[1].va)
            dbg:assemble_to(pid, get_global_syms[1].va, asm_code)
        end

        return "remove"
    end)
end)

dbg:on_process_exited(function(pid, code)
    exit_code = code
end)

dbg:launch(test_exe)
dbg:run()

assert(exit_code == 0,
    "Patched program should exit with code 0, got " .. tostring(exit_code))

return { passed = true }
