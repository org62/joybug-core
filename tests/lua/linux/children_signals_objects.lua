-- Linux: child debugging, signal policy, descriptors and core files from Lua.
-- Globals from the harness: FORKER, SIGNALS, FDS (test programs), TMP (a directory).

-- ---------------------------------------------------------------- children
local created, initial, exited = {}, {}, {}
dbg:on_process_created(function(pid, tid, name, base) table.insert(created, pid) end)
dbg:on_initial_breakpoint(function(pid, tid, addr) table.insert(initial, pid) end)
dbg:on_process_exited(function(pid, code) exited[pid] = code end)

dbg:launch(FORKER, true) -- debug_children
dbg:run()

assert(#created == 2, "parent and fork child are both announced, got " .. #created)
local parent, child = created[1], created[2]
assert(#initial == 2 and initial[1] == parent and initial[2] == child, "one initial breakpoint each")
assert(exited[child] == 7, "child exit code")
assert(exited[parent] == 41, "parent saw the child exit, got " .. tostring(exited[parent]))

-- ----------------------------------------------------------------- signals
local seen = {}
dbg:on_process_created(function() end)
dbg:on_initial_breakpoint(function() end)
dbg:on_exception(function(pid, tid, code, addr, first_chance)
    table.insert(seen, { code = code, first_chance = first_chance })
    return nil -- handled: the signal is dropped
end)
local exit_code
dbg:on_process_exited(function(pid, code) exit_code = code end)

dbg:set_reported_signals({ "SIGUSR1" })
dbg:launch(SIGNALS)
dbg:run()
assert(#seen == 1, "SIGUSR1 stopped once, got " .. #seen)
assert(seen[1].code == 0x4C53000A, string.format("signal exception code, got 0x%X", seen[1].code))
assert(seen[1].first_chance == true)
assert(exit_code == 11, "the dropped signal never reached the handler, got " .. tostring(exit_code))

-- Numbers work too, and an empty set turns reporting off again.
dbg:set_reported_signals({ 10, 12 })
dbg:set_reported_signals({})
seen = {}
dbg:launch(SIGNALS)
dbg:run()
assert(#seen == 0, "nothing reported with an empty policy")
assert(exit_code == 10, "the handler ran, got " .. tostring(exit_code))
assert(not pcall(function() dbg:set_reported_signals({ "SIGNOPE" }) end), "an unknown signal name is an error")

-- ------------------------------------------------- descriptors + core file
local checked = false
dbg:on_initial_breakpoint(function(pid, tid, addr)
    local objs = dbg:process_objects(pid)
    assert(#objs.warnings == 0, table.concat(objs.warnings, "; "))
    local stdio = 0
    for _, h in ipairs(objs.handles) do
        if h.handle <= 2 then stdio = stdio + 1 end
        assert(h.type_name ~= "", "every descriptor has a type")
    end
    assert(stdio == 3, "stdin/stdout/stderr are listed")
    assert(#objs.windows == 0)

    local path = TMP .. "/lua.core"
    local size = dbg:write_dump(pid, path, "mini")
    assert(size > 0, "core file size")
    local f = assert(io.open(path, "rb"))
    local magic = f:read(4)
    f:close()
    assert(magic == "\127ELF", "an ELF file")
    os.remove(path)
    assert(not pcall(function() dbg:write_dump(pid, path, "huge") end), "an unknown dump kind is an error")
    checked = true
end)
dbg:launch(FDS)
dbg:run()
assert(checked, "the initial breakpoint was reached")

return { passed = true }
