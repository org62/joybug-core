-- Test: Memory read/write operations
-- Ported from: scripting_test.rs::test_script_memory_operations

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Read the breakpoint instruction (should be int3 = 0xCC on x64)
    local byte = dbg:read_u8(pid, addr)
    assert(byte == 0xCC,
        "initial breakpoint should be int3 (0xCC), got " .. byte)

    -- Read 16 bytes of memory
    local data = dbg:read_memory(pid, addr, 16)
    assert(#data == 16, "should read 16 bytes")
    assert(string.byte(data, 1) == 0xCC, "first byte should also be 0xCC")

    -- Read stack pointer and read 8 bytes from the stack
    local ctx = dbg:get_context(pid, tid)
    local stack_data = dbg:read_memory(pid, ctx.rsp, 8)
    assert(#stack_data == 8, "should read 8 bytes from stack")

    -- Test read_u32 and read_u64 (value may be 0, just verify they return a number)
    assert(dbg:read_u32(pid, ctx.rsp) ~= nil, "read_u32 should return a value")
    assert(dbg:read_u64(pid, ctx.rsp) ~= nil, "read_u64 should return a value")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
