-- Test: see the guest desktop from the host (RETRO F4). Provision run-only,
-- start Notepad in the interactive session, then enumerate windows, screenshot
-- the desktop, and read a window's text — all executed INSIDE the guest.
--
-- Requires: the `sandbox` feature and Windows 11 24H2 + the "Windows Sandbox"
-- optional feature. Guest binary is joybug-core.exe (path injected as
-- GUEST_EXE_PATH). Gated on JOYBUG_SANDBOX_LIVE at the Rust layer.

local status = sbx.status()
if not (status.supported and status.wsb_present) then
    print("sandbox not available; skipping: " .. (status.reason or "unknown"))
    return { passed = true, skipped = true }
end

assert(GUEST_EXE_PATH and #GUEST_EXE_PATH > 0, "GUEST_EXE_PATH not injected by the harness")
local guest_dir, guest_exe = GUEST_EXE_PATH:match("^(.*)[\\/]([^\\/]+)$")
assert(guest_dir, "could not split GUEST_EXE_PATH: " .. tostring(GUEST_EXE_PATH))

local io_dir = (os.getenv("TEMP") or "C:\\Windows\\Temp")
    .. "\\joybug-sbx-ui-" .. tostring(os.time())

-- Run-only, but with a trivial target: we only need the interactive session and
-- the guest running; the UI probes are separate `h:exec` calls.
local ok, h, info = pcall(sbx.provision, {
    guest_bin_dir  = guest_dir,
    guest_exe      = guest_exe,
    io_dir         = io_dir,
    launch_command = "cmd.exe /c ver",
    debug          = false,
    collect_etw    = true,
})
assert(ok, "provision failed: " .. tostring(h))

-- Start Notepad in the interactive session (not under the tracer).
local code = h:exec("start \"\" notepad.exe", { run_as = "user" })
print("launched notepad, exec code = " .. tostring(code))

-- Poll for a Notepad top-level window.
local notepad
for _ = 1, 40 do
    local wins = h:list_windows()
    for _, w in ipairs(wins) do
        if w.visible and (w.class == "Notepad" or w.title:lower():find("notepad")) then
            notepad = w
            break
        end
    end
    if notepad then break end
    -- No dbg:sleep in run-only mode; a 1-ping delay paces the poll.
    h:exec("cmd /c ping -n 2 127.0.0.1 > nul", { run_as = "user" })
end
assert(notepad, "Notepad window should appear in the guest window list")
print(string.format("found notepad hwnd=%d class=%s title=%q",
    notepad.hwnd, notepad.class, notepad.title))

-- Its title text is readable via WM_GETTEXT.
local title = h:window_text(notepad.hwnd)
assert(title and #title > 0, "the Notepad window should have readable title text")

-- A screenshot lands as a real PNG.
local shot = h:screenshot()
local f = assert(io.open(shot, "rb"), "screenshot file should exist")
local head = f:read(8)
local size = f:seek("end")
f:close()
assert(size > 1024, "screenshot should be a non-trivial image, got " .. tostring(size) .. " bytes")
assert(head:byte(1) == 0x89 and head:sub(2, 4) == "PNG", "screenshot should have a PNG signature")
os.remove(shot)

h:stop()
return { passed = true }
