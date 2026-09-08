-- Test: the debuggee's live import table and import hooks (RETRO F7).
-- `dbg:imports` lists the IAT with each slot's resolved target, and
-- `dbg:set_breakpoint_import` hooks an API through that slot: the slot is
-- redirected to a breakpoint-carrying stub, so only calls made through THIS
-- module's import fire it, and it is unambiguous under WOW64.
-- Uses disassembly_test.exe (an ordinary MSVC console program).

local hit = 0
local stub_addr, target_addr = nil, nil
local mods

local function slot_of(pid, name)
    for _, imp in ipairs(dbg:imports(pid)) do
        if imp.name == name then return imp end
    end
end

local function in_a_module(a)
    for _, m in ipairs(mods) do
        if m.size and a >= m.base and a < m.base + m.size then return true end
    end
    return false
end

-- The address the API would return to: on the stack for x86/x64, in lr on arm64.
local function return_address(pid, tid)
    local ctx = dbg:get_context(pid, tid)
    local arch = dbg:arch(pid)
    if arch == "arm64" then return ctx.lr end
    if arch == "x86" then return dbg:read_u32(pid, ctx.esp) end
    return dbg:read_u64(pid, ctx.rsp)
end

local function on_hit(p, t, a)
    hit = hit + 1
    assert(a == stub_addr, "the handler should see the stub address, got " .. hex(a))
    -- The stub jumps straight to the API: the return address is the caller's,
    -- inside the exe, exactly as at VirtualAlloc's entry.
    local exe = mods[1]
    for _, m in ipairs(mods) do if m.base < exe.base then exe = m end end
    local ret = return_address(p, t)
    assert(ret >= exe.base and ret < exe.base + exe.size,
        "return address should be inside the exe, got " .. hex(ret))
    return "remove"
end

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Wait for kernel32's symbols so we can sanity-check the resolved target.
    wait_symbols(pid, "kernel32")

    local imports = dbg:imports(pid)
    assert(#imports > 0, "the exe should import at least one API")
    mods = dbg:list_modules(pid)

    -- Every entry has a dll and an IAT slot VA; a by-name import resolves to a
    -- target that lands inside a loaded module.
    local saw_kernel32 = false
    for _, imp in ipairs(imports) do
        assert(imp.iat_va and imp.iat_va > 0, "each import should carry an IAT slot VA")
        if imp.dll and imp.dll:lower():find("kernel32") then
            saw_kernel32 = true
            if imp.name and imp.target then
                assert(in_a_module(imp.target),
                    "resolved import target should point inside a loaded module: " .. imp.name)
            end
        end
    end
    assert(saw_kernel32, "disassembly_test.exe should import from KERNEL32.dll")

    -- disassembly_test.exe explicitly calls VirtualAlloc (to stage shellcode in
    -- RWX memory), so a hook on that import must fire.
    local before = slot_of(pid, "VirtualAlloc")
    assert(before and before.target, "VirtualAlloc should be an imported, resolved slot")

    stub_addr, target_addr = dbg:set_breakpoint_import(pid, "kernel32!VirtualAlloc", on_hit)
    assert(stub_addr and stub_addr > 0, "import hook should return the stub address")
    assert(target_addr == before.target, "the second return value is the slot's original target")
    assert(not in_a_module(stub_addr), "the stub lives in a private allocation, not in a module")
    assert(slot_of(pid, "VirtualAlloc").target == stub_addr, "the IAT slot should be redirected to the stub")

    -- Hooking the same import again re-arms the same stub.
    local again, again_target = dbg:set_breakpoint_import(pid, "VirtualAlloc", on_hit)
    assert(again == stub_addr and again_target == target_addr, "re-hooking reuses the stub")

    -- Removing the breakpoint points the slot back at the API.
    dbg:remove_breakpoint(pid, stub_addr)
    assert(slot_of(pid, "VirtualAlloc").target == target_addr, "removing the hook should restore the IAT slot")

    -- Arm it for real (a fresh stub) and let the program run into it.
    stub_addr, target_addr = dbg:set_breakpoint_import(pid, "kernel32!VirtualAlloc", on_hit)
    assert(slot_of(pid, "VirtualAlloc").target == stub_addr)

    -- Also accept an explicit module base.
    local ok = pcall(function() dbg:imports(pid, mods[1].base) end)
    assert(ok, "dbg:imports should accept an explicit module base")
end)

dbg:launch(TEST_EXE)
dbg:run()

assert(hit == 1, "the import hook should be hit exactly once, got " .. hit)

return { passed = true }
