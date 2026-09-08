-- Test: on_child_ready fires at a CHILD's initial breakpoint (pid != the launch
-- root), never at the root's (RETRO F6). on_initial_breakpoint still fires for
-- every process. The place a tree-debugging script re-arms breakpoints in each
-- new process under debug_children = true.
--
-- Requires: parent_child_test.exe (parent spawns itself with --child). Note the
-- parent is launched with CREATE_NEW_CONSOLE, so a conhost.exe also joins the
-- debugged tree and legitimately fires on_child_ready too; the contract we check
-- is structural and does not assume how many children there are or their order.

local test_exe = TEST_EXE

local names = {}          -- pid -> image name (from on_process_created)
local initial = {}        -- set of pids that fired on_initial_breakpoint
local child_ready = {}    -- set of pids that fired on_child_ready

dbg:on_process_created(function(pid, tid, name, base)
    names[pid] = (name or ""):lower()
end)

dbg:on_initial_breakpoint(function(pid, tid, addr)
    initial[pid] = true
end)

dbg:on_child_ready(function(pid, tid, addr)
    child_ready[pid] = true
    assert(addr and addr > 0, "on_child_ready should carry a nonzero address")
    -- We are at the child's loader breakpoint: prove the per-child hook can drive
    -- a real query against the new process.
    local mods = dbg:list_modules(pid)
    assert(#mods > 0, "child should have modules loaded at its initial breakpoint")
end)

dbg:launch(test_exe, true) -- debug_children = true
dbg:run()

-- Count processes that hit an initial breakpoint, and how many of those also
-- fired on_child_ready.
local n_initial, n_root_only = 0, 0
local root_pid = nil
for pid in pairs(initial) do
    n_initial = n_initial + 1
    if not child_ready[pid] then
        n_root_only = n_root_only + 1
        root_pid = pid
    end
end

-- At least the parent and its --child hit an initial breakpoint (conhost may add
-- a third).
assert(n_initial >= 2, "expected at least 2 initial breakpoints, got " .. n_initial)

-- THE contract: exactly one process (the launch root) fires an initial
-- breakpoint without on_child_ready. Every other process is a child and did
-- fire it.
assert(n_root_only == 1,
    "exactly one process (the root) should fire an initial breakpoint but not on_child_ready, got " .. n_root_only)
assert(not child_ready[root_pid], "on_child_ready must not fire for the root process")

-- Every on_child_ready pid also hit an initial breakpoint (they are real,
-- tracked processes), and differs from the root.
for pid in pairs(child_ready) do
    assert(initial[pid], "an on_child_ready pid should also have an initial breakpoint")
    assert(pid ~= root_pid, "a child_ready pid must differ from the root")
end

-- The spawned parent_child_test child (same image as the root) is among them.
local real_child_ready = false
for pid in pairs(child_ready) do
    if (names[pid] or ""):find("parent_child") then real_child_ready = true end
end
assert(real_child_ready,
    "on_child_ready should fire for the spawned parent_child_test child")

return { passed = true }
