-- Test: Windows suspend/resume nest on top of the debug-event freeze;
-- terminate_thread ends the thread with our exit code.

local killed_tid, killed_code

local function count_of(pid, tid)
    for _, t in ipairs(dbg:list_threads(pid)) do
        if t.tid == tid then return t.suspend_count end
    end
    error("thread not listed")
end

dbg:on_initial_breakpoint(function(pid, tid, addr)
    assert(count_of(pid, tid) == 1, "initial breakpoint contributes a debug freeze")
    dbg:suspend_thread(pid, tid)
    assert(count_of(pid, tid) == 2, "explicit suspension adds to the debug freeze")
    dbg:suspend_thread(pid, tid)
    assert(count_of(pid, tid) == 3, "suspend nests")
    dbg:resume_thread(pid, tid)
    assert(count_of(pid, tid) == 2, "one user suspension remains")
    dbg:resume_thread(pid, tid)
    assert(count_of(pid, tid) == 1, "user suspensions cleared; debug freeze remains")
    dbg:terminate_thread(pid, tid, 7)
    killed_tid = tid
end)

dbg:on_thread_exited(function(pid, tid, exit_code)
    if tid == killed_tid then
        killed_code = exit_code
        -- The loader worker thread is parked for good once the initial thread
        -- dies at the loader breakpoint; end the process ourselves.
        dbg:terminate(pid)
    end
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

assert(killed_code == 7, "killed thread exit code")

return { passed = true }
