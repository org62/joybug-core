-- Test: Parent-child process debugging
-- Ported from: parent_child_test.rs::test_parent_child_debugging
-- Requires: parent_child_test.exe

local test_exe = TEST_EXE -- injected by Rust test harness

local parent_pid = nil
local child_pid = nil
local initial_breakpoints = {}
local exited_pids = {}

dbg:on_process_created(function(pid, tid, name, base)
    -- CREATE_NEW_CONSOLE at launch puts conhost.exe inside the debugged tree;
    -- it is infrastructure, not the test child — skip it (see parent_child_test.rs).
    if string.lower(name):find("conhost%.exe$") then
        return
    end
    if parent_pid == nil then
        parent_pid = pid
    elseif child_pid == nil then
        child_pid = pid
    end
end)

dbg:on_initial_breakpoint(function(pid, tid, addr)
    table.insert(initial_breakpoints, pid)
end)

dbg:on_process_exited(function(pid, code)
    table.insert(exited_pids, pid)
end)

dbg:launch(test_exe, true) -- debug_children = true
dbg:run()

assert(parent_pid ~= nil, "Parent PID should be set")
assert(child_pid ~= nil, "Child PID should be set")
assert(parent_pid ~= child_pid, "Parent and child should have different PIDs")

-- Both should have hit initial breakpoints
local parent_bp = false
local child_bp = false
for _, pid in ipairs(initial_breakpoints) do
    if pid == parent_pid then parent_bp = true end
    if pid == child_pid then child_bp = true end
end
assert(parent_bp, "Parent should have hit initial breakpoint")
assert(child_bp, "Child should have hit initial breakpoint")

-- Both should have exited
local parent_exited = false
local child_exited = false
for _, pid in ipairs(exited_pids) do
    if pid == parent_pid then parent_exited = true end
    if pid == child_pid then child_exited = true end
end
assert(parent_exited, "Parent should have exited")
assert(child_exited, "Child should have exited")

return { passed = true }
