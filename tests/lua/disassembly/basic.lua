-- Test: Disassembly and call stack
-- Ported from: scripting_test.rs::test_script_disassembly_and_callstack

local result = {}

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Disassemble 5 instructions at the breakpoint
    local instrs = dbg:disassemble(pid, addr, 5)
    assert(#instrs == 5, "should disassemble 5 instructions, got " .. #instrs)
    assert(instrs[1].mnemonic == "int3",
        "first instruction at initial breakpoint should be int3, got " .. instrs[1].mnemonic)
    assert(instrs[1].address > 0, "instruction address should be nonzero")
    assert(instrs[1].symbol ~= nil, "first instruction should have symbol info")

    -- Get call stack
    local frames = dbg:get_call_stack(pid, tid)
    assert(#frames >= 2, "call stack should have at least 2 frames, got " .. #frames)
    assert(frames[1].symbol ~= nil, "top frame should have symbol info")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
