-- Test: Launch process, hit initial breakpoint, read registers
-- Ported from: scripting_test.rs::test_script_launch_and_registers

local got_pid, got_tid, got_addr

dbg:on_initial_breakpoint(function(pid, tid, addr)
    got_pid = pid
    got_tid = tid
    got_addr = addr

    local ctx = dbg:get_context(pid, tid)
    assert(ipof(ctx) > 0, "instruction pointer should be nonzero")
    assert(spof(ctx) > 0, "stack pointer should be nonzero")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

assert(got_pid > 0, "pid should be nonzero")
assert(got_tid > 0, "tid should be nonzero")
assert(got_addr > 0, "initial breakpoint address should be nonzero")

return { passed = true }
