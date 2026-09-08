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

    -- Wide-string round trip (RETRO B1: read_string used to drop the last
    -- character). Write UTF-16LE "UnholyDragon-0.exe\0" onto the stack and read
    -- it back whole; a bounded read of 6 chars returns exactly "Unholy".
    local text = "UnholyDragon-0.exe"
    local wide = ""
    for i = 1, #text do wide = wide .. string.char(text:byte(i), 0) end
    wide = wide .. string.char(0, 0)  -- NUL terminator
    local scratch = sp + 0x40         -- writable stack space, away from live data
    dbg:write_memory(pid, scratch, wide)
    assert(dbg:read_string(pid, scratch) == text,
        "read_string should return the whole wide string, got: " .. tostring(dbg:read_string(pid, scratch)))
    assert(dbg:read_string(pid, scratch, 6) == "Unholy",
        "bounded read_string(6) should return exactly 6 chars, got: " .. tostring(dbg:read_string(pid, scratch, 6)))


    -- A fresh allocation is readable and writable; an executable one too.
    local buf = dbg:allocate_memory(pid, 0x1000)
    assert(buf and buf > 0, "allocate_memory should return an address")
    dbg:write_memory(pid, buf, "joybug")
    assert(dbg:read_memory(pid, buf, 6) == "joybug", "allocated memory should round-trip a write")
    local code = dbg:allocate_memory(pid, 0x1000, true)
    assert(code and code > 0 and code ~= buf, "an executable allocation is a distinct region")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
