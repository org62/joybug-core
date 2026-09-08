-- Test: ETW follows the whole process TREE inside the sandbox, past the death
-- of every ancestor.
--
-- `spawn_chain.exe <n> <dir>` walks a chain in which each generation writes a
-- marker file, spawns its successor WITHOUT waiting, and exits. So by the time
-- generation k does anything, generations k+1..n are already gone. A tracer that
-- only waits for its root pid sees none of it -- and, because the tracer runs
-- inside a `wsb exec` job object that dies with it, would kill the survivors
-- outright. This test is what pins that behaviour down.
--
-- Requires: the `sandbox` feature and Windows 11 24H2 + the "Windows Sandbox"
-- optional feature. The guest binary is joybug-core.exe (path injected as
-- GUEST_EXE_PATH). Gated on JOYBUG_SANDBOX_LIVE at the Rust layer so a plain
-- `cargo test` never boots a VM; here we also self-skip when the sandbox isn't
-- actually available, so the script is safe to run anywhere.

local GENERATIONS = 4

local status = sbx.status()
if not (status.supported and status.wsb_present) then
    print("sandbox not available; skipping: " .. (status.reason or "unknown"))
    return { passed = true, skipped = true }
end

assert(GUEST_EXE_PATH and #GUEST_EXE_PATH > 0, "GUEST_EXE_PATH not injected by the harness")
local guest_dir, guest_exe = GUEST_EXE_PATH:match("^(.*)[\/]([^\/]+)$")
assert(guest_dir, "could not split GUEST_EXE_PATH: " .. tostring(GUEST_EXE_PATH))

assert(TEST_EXE and #TEST_EXE > 0, "TEST_EXE (spawn_chain.exe) was not injected")
local exe_dir = TEST_EXE:match("^(.*)[\\/][^\\/]+$")
assert(exe_dir, "could not derive a directory from TEST_EXE: " .. tostring(TEST_EXE))

-- Per-run I/O folder so markers/events from a previous run can't leak in. It is
-- shared read-write into the guest as C:\io, which is where the chain writes its
-- markers -- giving us host-visible proof the whole chain really ran.
local io_dir = (os.getenv("TEMP") or "C:\\Windows\\Temp")
    .. "\\joybug-sbx-tree-" .. tostring(os.time())

-- Only the leading exe token is rewritten to its guest path, so the literal
-- guest `C:\io` argument passes through untouched.
local launch = TEST_EXE .. " " .. GENERATIONS .. " C:\\io"

local ok, h, info = pcall(sbx.provision, {
    guest_bin_dir  = guest_dir,
    guest_exe      = guest_exe,
    io_dir         = io_dir,
    -- The chain exe is not guest-resident, so its folder has to be mapped in.
    mounts         = { { host_path = exe_dir, read_only = true } },
    launch_command = launch,
    debug          = false,   -- run-only: the tracer launches + observes the target
    collect_etw    = true,
    etw            = { ops = { "process.start", "process.stop", "file.create", "file.write" } },
})
assert(ok, "provision failed: " .. tostring(h))

-- Blocks until the tracer exits -- which, with tree following, means the LAST
-- generation has exited, not the first.
h:run_traced()

local evs = sbx.events(info.io_dir, info.etw_out_file)
h:stop()

print(string.format("collected %d ETW event(s) from the sandbox", #evs))

-- ---------------------------------------------------------------------------
-- Sort into what we need. `ts` is a raw ETW timestamp, good for ordering only.
--
-- NOTE the root (generation `GENERATIONS`) has NO process.start event: the
-- tracer spawns it itself and registers it as the tree root programmatically,
-- so there is no ETW ProcessStart to attribute. It surfaces only as the `ppid`
-- of generation GENERATIONS-1, and in its own process.stop. Nor can stops be
-- matched on the image name -- Kernel-Process reports a 14-character
-- ImageFileName there ("spawn_chain.ex"), so they are keyed by pid instead.
--
-- The tree also picks up the console host: the target is launched with
-- CREATE_NEW_CONSOLE (so a console app is visible on the sandbox desktop), which
-- puts a conhost.exe child in the tree that outlives the whole chain. It is
-- infrastructure, not a generation -- filtering starts on the image name skips
-- it, the same way parent_child_test does.
-- ---------------------------------------------------------------------------
local function ends_with(s, suffix)
    return type(s) == "string" and s:lower():sub(-#suffix) == suffix:lower()
end

local starts, stop_by_pid, files, timed_out = {}, {}, {}, false
for _, e in ipairs(evs) do
    if e.kind == "tracer" and e.op == "tree_timeout" then
        timed_out = true
    elseif e.kind == "process" and e.op == "start" and ends_with(e.image, "spawn_chain.exe") then
        starts[#starts + 1] = e
    elseif e.kind == "process" and e.op == "stop" and e.pid then
        stop_by_pid[e.pid] = e
    elseif e.kind == "file" and (e.op == "create" or e.op == "write") then
        files[#files + 1] = e
    end
end
table.sort(starts, function(a, b) return a.ts < b.ts end)

-- 1. Every generation below the root was seen.
local expected_starts = GENERATIONS - 1
assert(#starts >= expected_starts, string.format(
    "expected at least %d spawn_chain.exe process.start events (the root has none), got %d",
    expected_starts, #starts))

local root_pid = starts[1].ppid
print(string.format("  root (generation %d) pid=%s", GENERATIONS, tostring(root_pid)))
for i, e in ipairs(starts) do
    print(string.format("  generation %d: pid=%s ppid=%s",
        GENERATIONS - i, tostring(e.pid), tostring(e.ppid)))
end

-- 2. They form a chain: each generation's parent is the previous one. This is
--    the transitive tree-following, generation by generation.
for i = 1, expected_starts - 1 do
    assert(starts[i + 1].ppid == starts[i].pid, string.format(
        "generation %d (pid %s) should be parented by generation %d (pid %s), got ppid %s",
        GENERATIONS - i - 1, tostring(starts[i + 1].pid),
        GENERATIONS - i, tostring(starts[i].pid), tostring(starts[i + 1].ppid)))
end

-- 3. THE point of the test: a process started AFTER the root died was still
--    captured. Without tree following the tracer is already gone by here.
local root_stop = stop_by_pid[root_pid]
assert(root_stop, "no process.stop for the root pid " .. tostring(root_pid))
assert(root_stop.exit == GENERATIONS, string.format(
    "root should exit with %d (its generation number), got %s",
    GENERATIONS, tostring(root_stop.exit)))

local after_root_death = 0
for _, e in ipairs(starts) do
    if e.ts > root_stop.ts then
        after_root_death = after_root_death + 1
    end
end
print(string.format("  %d generation(s) started after the root (pid %s) exited",
    after_root_death, tostring(root_pid)))
assert(after_root_death > 0,
    "no process started after the root exited -- the tracer stopped at its root")

-- 4. Non-process events from an orphaned descendant are attributed too: the
--    deepest generation's marker write, long after its whole ancestry is gone.
local last = starts[expected_starts]
local deep_marker = false
for _, e in ipairs(files) do
    if ends_with(e.path, "gen-1.txt") and e.pid == last.pid then
        deep_marker = true
        break
    end
end
assert(deep_marker, string.format(
    "no file event for gen-1.txt from pid %s -- file events lose the orphaned tree",
    tostring(last.pid)))

-- 5. Host-side ground truth: the chain ran to completion rather than being
--    killed with the tracer's job object.
for n = 1, GENERATIONS do
    local path = io_dir .. "\\gen-" .. n .. ".txt"
    local f = io.open(path, "r")
    assert(f, "missing marker " .. path .. " -- the chain did not run to completion")
    f:close()
end

-- 6. The capture was not truncated by the tree-follow cap.
assert(not timed_out, "tracer reported tree_timeout -- the tree outlived --tree-timeout")

return { passed = true }
