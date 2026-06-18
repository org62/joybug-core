-- Test: Memory read/write operations
-- Ported from: scripting_test.rs::test_script_memory_operations

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Read the breakpoint instruction. x86: int3 = 0xCC (1 byte).
    -- AArch64: BRK #0xF000 = 0xD43E0000 (little-endian: 00 00 3E D4).
    local data = dbg:read_memory(pid, addr, 16)
    assert(#data == 16, "should read 16 bytes")
    if ARCH == 'aarch64' then
        local b0, b1, b2, b3 = string.byte(data, 1, 4)
        local insn = b0 + b1 * 0x100 + b2 * 0x10000 + b3 * 0x1000000
        assert(insn == 0xD43E0000,
            string.format("initial breakpoint should be BRK #0xF000 (0xD43E0000), got 0x%08X", insn))
    else
        local byte = dbg:read_u8(pid, addr)
        assert(byte == 0xCC,
            "initial breakpoint should be int3 (0xCC), got " .. byte)
        assert(string.byte(data, 1) == 0xCC, "first byte should also be 0xCC")
    end

    -- Read stack pointer and read 8 bytes from the stack
    local ctx = dbg:get_context(pid, tid)
    local sp = spof(ctx)
    local stack_data = dbg:read_memory(pid, sp, 8)
    assert(#stack_data == 8, "should read 8 bytes from stack")

    -- Test read_u32 and read_u64 (value may be 0, just verify they return a number)
    assert(dbg:read_u32(pid, sp) ~= nil, "read_u32 should return a value")
    assert(dbg:read_u64(pid, sp) ~= nil, "read_u64 should return a value")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
