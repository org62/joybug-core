-- Test: dbg:normalize_peb restores PEB.BeingDebugged and the process-heap flags
-- to their non-debugged state.
--
-- Pure memory-level check — no behavioural sample exe is required.

-- PEB field offsets (x64 native layout), hardcoded independently of the
-- implementation so a wrong offset is actually caught.
local PEB_BEING_DEBUGGED = 0x02
local PEB_PROCESS_HEAP    = 0x30
local HEAP_FLAGS          = 0x70
local HEAP_FORCE_FLAGS    = 0x74
local HEAP_GROWABLE       = 0x2
local EXPECTED_FIELD_COUNT = 2

local function read_u32(pid, addr)
    local b = dbg:read_memory(pid, addr, 4)
    return string.byte(b, 1)
         + string.byte(b, 2) * 0x100
         + string.byte(b, 3) * 0x10000
         + string.byte(b, 4) * 0x1000000
end

local function read_u64(pid, addr)
    local b = dbg:read_memory(pid, addr, 8)
    local lo = string.byte(b, 1) + string.byte(b, 2) * 0x100
             + string.byte(b, 3) * 0x10000 + string.byte(b, 4) * 0x1000000
    local hi = string.byte(b, 5) + string.byte(b, 6) * 0x100
             + string.byte(b, 7) * 0x10000 + string.byte(b, 8) * 0x1000000
    return lo + hi * 0x100000000
end

local hit = false
local report_peb = 0
local before_byte = nil
local after_byte = nil
local after_heap_flags = nil
local after_heap_force_flags = nil
local applied_count = 0
local failure_count = 0

dbg:on_initial_breakpoint(function(pid, tid, addr)
    hit = true

    -- Probe (no options): retrieves PEB address without writing anything.
    local probe = dbg:normalize_peb(pid, {})
    assert(probe.peb_address ~= 0, "PEB address must be non-zero")
    report_peb = probe.peb_address

    local b = dbg:read_memory(pid, probe.peb_address + PEB_BEING_DEBUGGED, 1)
    before_byte = string.byte(b, 1)

    -- Apply all fields.
    local report = dbg:normalize_peb(pid, { all = true })
    applied_count = #report.applied
    failure_count = #report.failures

    after_byte = string.byte(dbg:read_memory(pid, report.peb_address + PEB_BEING_DEBUGGED, 1), 1)

    local heap = read_u64(pid, report.peb_address + PEB_PROCESS_HEAP)
    after_heap_flags = read_u32(pid, heap + HEAP_FLAGS)
    after_heap_force_flags = read_u32(pid, heap + HEAP_FORCE_FLAGS)
end)

dbg:launch('cmd.exe /c exit 0')
dbg:run()

assert(hit,                                "initial breakpoint should fire")
assert(report_peb ~= 0,                    "PEB address resolved")
assert(before_byte == 1,                   "BeingDebugged should be 1 before normalize")
assert(applied_count == EXPECTED_FIELD_COUNT, "all fields applied, got " .. applied_count)
assert(failure_count == 0,                 "no failures expected, got " .. failure_count)
assert(after_byte == 0,                    "BeingDebugged should be 0 after normalize")
assert(after_heap_flags == HEAP_GROWABLE,  "HEAP.Flags should be HEAP_GROWABLE, got " .. after_heap_flags)
assert(after_heap_force_flags == 0,        "HEAP.ForceFlags should be 0, got " .. after_heap_force_flags)

return { passed = true }
