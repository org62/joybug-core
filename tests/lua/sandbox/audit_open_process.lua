-- Test: cross-process memory access is visible in the sandbox, via the
-- Kernel-Audit-API-Calls provider.
--
-- `open_remote.exe` spawns a victim, opens it with
-- VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION (0x438), reads and writes the
-- victim's memory, then opens one of its threads with
-- SUSPEND_RESUME|GET_CONTEXT|SET_CONTEXT (0x1A).
--
-- What ETW can and cannot see here is the whole point of the test. The reads and
-- writes themselves are invisible to any provider we can consume -- NtRead/
-- WriteVirtualMemory live in Microsoft-Windows-Threat-Intelligence, which needs a
-- PPL/anti-malware ELAM consumer. What IS visible is the handle acquisition that
-- must precede them, with the rights requested. So we assert on the opens and
-- their access masks, and use the victim's own marker file as ground truth that
-- the (invisible) cross-process write really happened.
--
-- Requires: the `sandbox` feature and Windows 11 24H2 + the "Windows Sandbox"
-- optional feature. The guest binary is joybug-core.exe (path injected as
-- GUEST_EXE_PATH). Gated on JOYBUG_SANDBOX_LIVE at the Rust layer.

local status = sbx.status()
if not (status.supported and status.wsb_present) then
    print("sandbox not available; skipping: " .. (status.reason or "unknown"))
    return { passed = true, skipped = true }
end

assert(GUEST_EXE_PATH and #GUEST_EXE_PATH > 0, "GUEST_EXE_PATH not injected by the harness")
local guest_dir, guest_exe = GUEST_EXE_PATH:match("^(.*)[\/]([^\/]+)$")
assert(guest_dir, "could not split GUEST_EXE_PATH: " .. tostring(GUEST_EXE_PATH))

assert(TEST_EXE and #TEST_EXE > 0, "TEST_EXE (open_remote.exe) was not injected")
local exe_dir = TEST_EXE:match("^(.*)[\\/][^\\/]+$")
assert(exe_dir, "could not derive a directory from TEST_EXE: " .. tostring(TEST_EXE))

local io_dir = (os.getenv("TEMP") or "C:\\Windows\\Temp")
    .. "\\joybug-sbx-audit-" .. tostring(os.time())

local ok, h, info = pcall(sbx.provision, {
    guest_bin_dir  = guest_dir,
    guest_exe      = guest_exe,
    io_dir         = io_dir,
    mounts         = { { host_path = exe_dir, read_only = true } },
    launch_command = TEST_EXE .. " C:\\io",
    debug          = false,
    collect_etw    = true,
    -- The audit ops are NOT in the tracer's default set (OpenProcess is common
    -- enough to be noise), so they have to be asked for explicitly.
    etw            = { ops = { "process.start", "process.stop",
                               "audit.open_process", "audit.open_thread" } },
})
assert(ok, "provision failed: " .. tostring(h))

h:run_traced()
local evs = sbx.events(info.io_dir, info.etw_out_file)
h:stop()

print(string.format("collected %d ETW event(s) from the sandbox", #evs))

-- The victim is the only spawn_chain-unrelated child here: find the actor
-- (open_remote parent) and the target (victim) from the process events.
local opens, thread_opens = {}, {}
for _, e in ipairs(evs) do
    if e.kind == "audit" and e.op == "open_process" then
        opens[#opens + 1] = e
    elseif e.kind == "audit" and e.op == "open_thread" then
        thread_opens[#thread_opens + 1] = e
    end
end

assert(#opens > 0, "no audit.open_process events -- the provider produced nothing")
for _, e in ipairs(opens) do
    print(string.format("  open_process pid=%s -> target=%s access=%s status=%s",
        tostring(e.pid), tostring(e.target_pid), tostring(e.access), tostring(e.status)))
end
for _, e in ipairs(thread_opens) do
    print(string.format("  open_thread   pid=%s -> target=%s access=%s status=%s",
        tostring(e.pid), tostring(e.target_pid), tostring(e.access), tostring(e.status)))
end

-- 1. THE assertion: a REMOTE open (actor ~= target) carrying VM read+write.
--    This is the signature of one process reading/writing another's memory.
local vm_open
for _, e in ipairs(opens) do
    if e.target_pid and e.pid and e.target_pid ~= e.pid
        and e.access and e.access:find("VM_READ", 1, true)
        and e.access:find("VM_WRITE", 1, true) then
        vm_open = e
        break
    end
end
assert(vm_open, "no remote OpenProcess carrying VM_READ|VM_WRITE was captured")
assert(vm_open.access:find("VM_OPERATION", 1, true),
    "expected VM_OPERATION too, got: " .. vm_open.access)
assert(vm_open.status == 0,
    "the VM open should have succeeded, got status " .. tostring(vm_open.status))

-- 2. The thread open is captured too, decoded with the THREAD vocabulary (the
--    same low bits mean different rights for processes and threads).
local ctx_open
for _, e in ipairs(thread_opens) do
    if e.access and e.access:find("SET_CONTEXT", 1, true) then
        ctx_open = e
        break
    end
end
assert(ctx_open, "no audit.open_thread carrying SET_CONTEXT was captured")
assert(ctx_open.access:find("GET_CONTEXT", 1, true),
    "expected GET_CONTEXT too, got: " .. ctx_open.access)
assert(ctx_open.target_pid == vm_open.target_pid,
    "the opened thread should belong to the same victim process")

-- 3. Ground truth that the cross-process WRITE landed, even though no provider
--    we can consume reports the write itself: the victim wrote out whatever its
--    marker held when it woke up.
local f = assert(io.open(io_dir .. "\\victim.txt", "r"),
    "victim.txt missing -- the target did not run to completion")
local marker = f:read("*a")
f:close()
assert(marker == "written-across-processes", string.format(
    "victim marker should show the injected value, got %q", marker))

return { passed = true }
