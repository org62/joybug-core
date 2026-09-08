-- Test: dbg:skip_call returns from the current function without running it
-- (RETRO F8). Break at the entry of helper_add (a leaf that returns a+b), skip
-- it with a forced return value, and confirm the thread is back at the return
-- address with the return register set — and that the process still finishes.
-- Uses disassembly_test.exe (helper_add is called from test_control_flow).

local RET = 0x1234
local skipped = false
local ret_reg_after = nil
local rip_after = nil

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local syms = dbg:find_symbol("helper_add", 5)
    assert(#syms > 0, "should find helper_add")
    dbg:set_breakpoint(pid, syms[1].va, function(p, t, a)
        -- At function entry the top of stack is the return address.
        local ret_addr = dbg:skip_call(p, t, { ret = RET, args = 2, conv = "cdecl" })
        skipped = true

        local ctx = dbg:get_context(p, t)
        rip_after = ipof(ctx)
        -- Return-value register: eax/rax on x86/x64, x0 on arm64.
        if ARCH == 'aarch64' then
            ret_reg_after = ctx.x[1]
        elseif ctx.rax ~= nil then
            ret_reg_after = ctx.rax
        else
            ret_reg_after = ctx.eax
        end

        assert(rip_after == ret_addr,
            string.format("after skip, ip should equal the return address 0x%X, got 0x%X",
                ret_addr, rip_after))
        return "remove"
    end)
end)

dbg:launch(TEST_EXE)
dbg:run()

assert(skipped, "the breakpoint on helper_add should have fired and skipped the call")
-- The low 32 bits carry the forced return value on every arch.
assert((ret_reg_after & 0xFFFFFFFF) == RET,
    string.format("return register should be 0x%X, got 0x%X", RET, ret_reg_after & 0xFFFFFFFF))

return { passed = true }
