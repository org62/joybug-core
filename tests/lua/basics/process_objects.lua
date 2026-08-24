-- Test: process_objects lists the debuggee's handles and privileges, names
-- resolve for well-known object types, and a privilege can be toggled and a
-- handle closed through the same API.

local checked = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local objs = dbg:process_objects(pid)
    assert(#objs.warnings == 0, "no section should fail: " .. table.concat(objs.warnings, "; "))

    -- Every process holds at least a few handles at the loader breakpoint
    -- (its own section/event/key handles), all with a resolved type.
    assert(#objs.handles > 0, "expected some handles")
    local named_key = false
    for _, h in ipairs(objs.handles) do
        assert(h.handle > 0, "handle value")
        assert(h.type_name ~= "", "every handle should have a type name")
        -- The loader opens registry keys under \REGISTRY; at least one should name.
        if h.type_name == "Key" and h.name:find("^\\REGISTRY") then named_key = true end
    end
    assert(named_key, "a \\REGISTRY key handle should be named")

    -- cmd.exe has no windows at its loader breakpoint and no sockets.
    assert(type(objs.windows) == "table", "windows table")
    assert(type(objs.tcp_connections) == "table", "tcp table")
    assert(objs.desktop_window > 0, "desktop window handle")

    -- Privileges: SeChangeNotifyPrivilege is in every user token, enabled by default.
    local change_notify
    for _, p in ipairs(objs.privileges) do
        if p.name == "SeChangeNotifyPrivilege" then change_notify = p end
    end
    assert(change_notify, "SeChangeNotifyPrivilege should be listed")
    assert(change_notify.state == "enabled_by_default",
        "SeChangeNotifyPrivilege enabled by default, got " .. change_notify.state)

    -- Toggle it off and back on.
    dbg:set_privilege(pid, "SeChangeNotifyPrivilege", false)
    for _, p in ipairs(dbg:process_objects(pid).privileges) do
        if p.name == "SeChangeNotifyPrivilege" then
            assert(p.state == "disabled", "should be disabled now, got " .. p.state)
        end
    end
    dbg:set_privilege(pid, "SeChangeNotifyPrivilege", true)

    -- Close one of the target's Key handles; it must disappear from the list.
    local victim
    for _, h in ipairs(objs.handles) do
        if h.type_name == "Key" then victim = h.handle break end
    end
    assert(victim, "a Key handle to close")
    dbg:close_remote_handle(pid, victim)
    for _, h in ipairs(dbg:process_objects(pid).handles) do
        assert(h.handle ~= victim, "closed handle should be gone")
    end

    checked = true
    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()
assert(checked, "initial breakpoint handler should have run")
