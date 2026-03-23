-- Test: Mass breakpoint setting on all runtime functions across target modules
-- Ported from: mass_breakpoint_test.rs::test_mass_breakpoint_cmd
--
-- Sets single-shot breakpoints on every RUNTIME_FUNCTION entry in
-- cmd.exe, ntdll.dll, kernel32.dll, and kernelbase.dll, then lets
-- the process run "cmd.exe /c echo test" and counts how many fire.

local TARGET_MODULES = { "cmd.exe", "ntdll.dll", "kernel32.dll", "kernelbase.dll" }

local function is_target_module(name)
    -- Extract file name from full path
    local file_name = name:match("([^/\\]+)$") or name
    for _, target in ipairs(TARGET_MODULES) do
        if file_name:lower() == target:lower() then
            return true, file_name
        end
    end
    return false, file_name
end

local modules = {} -- { {name, base}, ... }
local module_stats = {} -- { {name, rf_count, set, failed}, ... }
local hits = {} -- { addr, ... }

dbg:on_process_created(function(pid, tid, name, base)
    local is_target, file_name = is_target_module(name)
    if is_target then
        table.insert(modules, { name = file_name, base = base })
    end
end)

dbg:on_dll_loaded(function(pid, tid, name, base)
    local is_target, file_name = is_target_module(name)
    if is_target then
        table.insert(modules, { name = file_name, base = base })
    end
end)

dbg:on_initial_breakpoint(function(pid, tid, addr)
    for _, mod_info in ipairs(modules) do
        local info = dbg:get_module_info(pid, mod_info.base)
        local rfs = info.runtime_functions
        if rfs then
            -- Deduplicate by begin_address and filter invalid entries
            local seen = {}
            local unique = {}
            for _, rf in ipairs(rfs) do
                if rf.end_address > rf.begin_address and not seen[rf.begin_address] then
                    seen[rf.begin_address] = true
                    table.insert(unique, rf)
                end
            end

            local set_count = 0
            local fail_count = 0
            for _, rf in ipairs(unique) do
                local va = mod_info.base + rf.begin_address
                local ok = pcall(function()
                    dbg:set_single_shot_breakpoint(pid, va, function(pid, tid, addr)
                        table.insert(hits, addr)
                    end)
                end)
                if ok then
                    set_count = set_count + 1
                else
                    fail_count = fail_count + 1
                end
            end

            table.insert(module_stats, {
                name = mod_info.name,
                rf_count = #unique,
                set = set_count,
                failed = fail_count,
            })
        end
    end
end)

dbg:launch('cmd.exe /c echo test')
dbg:run()

-- Aggregate stats
local total_rf = 0
local total_set = 0
local total_failed = 0
for _, s in ipairs(module_stats) do
    total_rf = total_rf + s.rf_count
    total_set = total_set + s.set
    total_failed = total_failed + s.failed
end

-- Assertions
assert(#module_stats >= 4,
    "Expected at least 4 modules instrumented, got " .. #module_stats)

assert(total_rf >= 1000,
    "Expected at least 1000 total RUNTIME_FUNCTION entries, got " .. total_rf)

local success_rate = total_set / total_rf
assert(success_rate > 0.90,
    string.format("Breakpoint set success rate %.1f%% is below 90%%", success_rate * 100))

assert(#hits >= 10,
    "Expected at least 10 functions hit during 'cmd /c echo test', got " .. #hits)

assert(#hits <= total_set,
    "More hits (" .. #hits .. ") than breakpoints set (" .. total_set .. ")")

return { passed = true }
