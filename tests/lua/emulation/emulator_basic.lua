-- Test: Basic emulator modes (basic, trace, block)
-- Ported from: emulator_test.rs (basic, basic_block, instruction_trace sub-tests)
-- Requires: xtea_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

local basic_tested = false
local trace_tested = false
local block_tested = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Find xtea_encrypt
    local syms = dbg:find_symbol("xtea_encrypt", 5)
    assert(#syms > 0, "Should find xtea_encrypt")
    local encrypt_addr = syms[1].va

    dbg:set_breakpoint(pid, encrypt_addr, function(pid, tid, addr)
        -- Remove breakpoint so emulator sees original bytes
        dbg:remove_breakpoint(pid, addr)

        -- Test 1: Basic mode
        local basic_result = dbg:emulate(pid, tid, 100, "basic")
        -- Check all possible fields to understand the response shape
        local has_instrs = basic_result.instructions_executed ~= nil and basic_result.instructions_executed > 0
        local has_trace = basic_result.trace ~= nil and basic_result.trace ~= ""
        local has_pc = basic_result.final_pc ~= nil and basic_result.final_pc > 0
        assert(has_instrs or has_trace or has_pc,
            "Basic: should have some result (instrs=" .. tostring(basic_result.instructions_executed)
            .. ", trace=" .. tostring(basic_result.trace ~= nil)
            .. ", pc=" .. tostring(basic_result.final_pc) .. ")")
        basic_tested = true

        -- Test 2: InstructionTrace mode
        local trace_result = dbg:emulate(pid, tid, 50, "trace")
        assert(trace_result.trace ~= nil and trace_result.trace ~= "",
            "Trace: should produce trace output")
        trace_tested = true

        -- Test 3: BasicBlock mode
        local block_result = dbg:emulate(pid, tid, 50, "block")
        local block_has_instrs = block_result.instructions_executed ~= nil and block_result.instructions_executed > 0
        local block_has_pc = block_result.final_pc ~= nil and block_result.final_pc > 0
        assert(block_has_instrs or block_has_pc,
            "Block: should have some result")
        block_tested = true

        return "remove"
    end)
end)

dbg:launch(test_exe)
dbg:run()

assert(basic_tested, "Basic mode was not tested")
assert(trace_tested, "InstructionTrace mode was not tested")
assert(block_tested, "BasicBlock mode was not tested")

return { passed = true }
