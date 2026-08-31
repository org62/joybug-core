-- Test: sandbox + ETW together, end to end, from pure Lua.
--
-- Boots a real Windows Sandbox in run-only mode, launches a target under the
-- in-guest ETW tracer (no UAC — kernel ETW runs as the sandbox's built-in admin),
-- then enumerates the recorded events with `sbx.events`. This is the combination
-- the app performs, driven entirely through the `sbx`/`etw` Lua API.
--
-- Requires: the `sandbox` feature, Windows 11 24H2 + the "Windows Sandbox"
-- optional feature, and a folder holding `guest-tracer.exe` pointed at by
-- JOYBUG_SANDBOX_TEST_BINDIR. Gated on JOYBUG_SANDBOX_LIVE at the Rust layer so a
-- plain `cargo test` never boots a VM; here we also self-skip when the sandbox
-- isn't actually available so the test is safe to run anywhere.

local status = sbx.status()
if not (status.supported and status.wsb_present) then
    print("sandbox not available; skipping: " .. (status.reason or "unknown"))
    return { passed = true, skipped = true }
end

local bindir = os.getenv("JOYBUG_SANDBOX_TEST_BINDIR")
assert(bindir and #bindir > 0,
    "set JOYBUG_SANDBOX_TEST_BINDIR to a folder containing guest-tracer.exe")

-- Per-run I/O folder so a stale events file can't leak in.
local io_dir = (os.getenv("TEMP") or "C:\\Windows\\Temp")
    .. "\\joybug-sbx-etw-" .. tostring(os.time())

-- A target that reliably produces ETW activity: cmd spawns whoami (process
-- start/stop) and writes a file (file create/write) inside the guest.
local launch = 'cmd.exe /c "whoami & echo hi > %USERPROFILE%\\joybug-etw-test.txt"'

-- Provision run-only (debug = false): no in-guest server, no debugger — only the
-- static guest-tracer.exe is used, so no VC runtime needs staging in the guest.
local ok, h, info = pcall(sbx.provision, {
    guest_bin_dir  = bindir,
    io_dir         = io_dir,
    launch_command = launch,
    debug          = false,   -- run-only: the tracer launches + observes the target
    collect_etw    = true,
})
assert(ok, "provision failed: " .. tostring(h))

-- Launch the target under ETW and wait for it to finish (blocks ~seconds).
h:run_traced()

-- Enumerate the recorded events.
local evs = sbx.events(info.io_dir, info.etw_out_file)
print(string.format("collected %d ETW event(s) from the sandbox", #evs))
local kinds = {}
for _, e in ipairs(evs) do
    kinds[e.kind] = (kinds[e.kind] or 0) + 1
    if e.seq <= 8 then
        print(string.format("  seq=%d %s.%s pid=%s %s",
            e.seq, e.kind, e.op, tostring(e.pid), e.path or e.image or e.dest or ""))
    end
end

h:stop()

assert(#evs > 0, "expected at least one ETW event from the traced target")
-- The tracer always brackets the run with process events, so this must be present.
assert((kinds["process"] or 0) > 0, "expected process ETW events (start/stop)")

return { passed = true }
