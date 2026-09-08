-- Test: recover / reuse a running sandbox (RETRO B5). Provision one, then adopt
-- it a second time with sbx.attach(id) from the same script: the attached handle
-- reaches the same in-guest server (its server_url handshakes OK) and does NOT
-- own the VM, so letting it go leaves the VM up. The owning handle's stop is the
-- one that tears it down.
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
    .. "\\joybug-sbx-attach-" .. tostring(os.time())

-- Debug-mode provision with NO launch command: the server comes up, we do not
-- launch a target. That is enough to prove attach reaches the guest server.
local ok, h, info = pcall(sbx.provision, {
    guest_bin_dir  = guest_dir,
    guest_exe      = guest_exe,
    io_dir         = io_dir,
    debug          = true,
})
assert(ok, "provision failed: " .. tostring(h))

local id = info.id
assert(id and #id > 0, "provision info should carry the sandbox id")
assert(info.owned == true, "a provisioned handle owns the VM")
assert(info.server_url and #info.server_url > 0, "the in-guest server should be reachable")

-- It appears in the running list.
local function listed(want)
    for _, running_id in ipairs(sbx.list()) do
        if running_id == want then return true end
    end
    return false
end
assert(listed(id), "the provisioned sandbox should appear in sbx.list()")

-- Adopt the SAME VM by id. The attached handle does not own it, and its
-- server_url handshakes with the same joybug server.
local h2, info2 = sbx.attach(id, { io_dir = io_dir })
assert(info2.id == id, "attach should report the same id")
assert(info2.owned == false, "an attached handle does not own the VM")
assert(info2.server_url and #info2.server_url > 0,
    "attach should find the in-guest server (handshake ok)")

-- A dbg client connects through the attached handle's url.
local dbg2 = sbx.connect(info2.server_url)
local procs = dbg2:list_processes()
assert(#procs > 0, "the guest server should answer list_processes")

-- Drop the attached handle (it does not own the VM) and force a GC. The VM must
-- stay up: only the owning handle's teardown stops it.
h2 = nil
collectgarbage("collect")
assert(listed(id), "dropping a non-owning attached handle must leave the VM running")

-- Definitive teardown through the owning handle.
h:stop()
assert(not listed(id), "after the owner's stop the sandbox should no longer be listed")

return { passed = true }
