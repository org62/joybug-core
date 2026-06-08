-- Test: dbg:hide_peb zeroes PEB.BeingDebugged and friends.
--
-- Pure memory-level check — no behavioural anti-debug exe is required.

-- PEB field offsets (x64 native layout), hardcoded independently of the
-- implementation so a wrong offset is actually caught.
local PEB_BEING_DEBUGGED = 0x02
local PEB_NT_GLOBAL_FLAG  = 0xBC
local PEB_OS_BUILD_NUMBER = 0x120
local SPOOFED_OS_BUILD_NUMBER = 19045
local EXPECTED_TECHNIQUE_COUNT = 5

local hit = false
local report_peb = 0
local before_byte = nil
local after_byte = nil
local after_ntglobalflag = nil
local after_osbuild = nil
local applied_count = 0
local failure_count = 0

dbg:on_initial_breakpoint(function(pid, tid, addr)
    hit = true

    -- Probe (no options): retrieves PEB address without writing anything.
    local probe = dbg:hide_peb(pid, {})
    assert(probe.peb_address ~= 0, "PEB address must be non-zero")
    report_peb = probe.peb_address

    local b = dbg:read_memory(pid, probe.peb_address + PEB_BEING_DEBUGGED, 1)
    before_byte = string.byte(b, 1)

    -- Apply all techniques.
    local report = dbg:hide_peb(pid, { all = true })
    applied_count = #report.applied
    failure_count = #report.failures

    after_byte = string.byte(dbg:read_memory(pid, report.peb_address + PEB_BEING_DEBUGGED, 1), 1)

    local nb = dbg:read_memory(pid, report.peb_address + PEB_NT_GLOBAL_FLAG, 4)
    after_ntglobalflag = string.byte(nb, 1)
                       + string.byte(nb, 2) * 0x100
                       + string.byte(nb, 3) * 0x10000
                       + string.byte(nb, 4) * 0x1000000

    local ob = dbg:read_memory(pid, report.peb_address + PEB_OS_BUILD_NUMBER, 2)
    after_osbuild = string.byte(ob, 1) + string.byte(ob, 2) * 0x100
end)

dbg:launch('cmd.exe /c exit 0')
dbg:run()

assert(hit,                                "initial breakpoint should fire")
assert(report_peb ~= 0,                    "PEB address resolved")
assert(before_byte == 1,                   "BeingDebugged should be 1 before hide")
assert(applied_count == EXPECTED_TECHNIQUE_COUNT, "all techniques applied, got " .. applied_count)
assert(failure_count == 0,                 "no failures expected, got " .. failure_count)
assert(after_byte == 0,                    "BeingDebugged should be 0 after hide")
assert(after_ntglobalflag == 0,            "NtGlobalFlag should be 0 after hide")
assert(after_osbuild == SPOOFED_OS_BUILD_NUMBER, "OSBuildNumber should be spoofed, got " .. after_osbuild)

return { passed = true }
