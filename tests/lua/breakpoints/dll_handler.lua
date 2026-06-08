-- Test: DLL load handler and memory regions
-- Ported from: scripting_test.rs::test_script_dll_handler_and_regions

local dll_loads = {}

dbg:on_dll_loaded(function(pid, tid, name, base)
    table.insert(dll_loads, { name = name, base = base })
end)

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Enumerate memory regions
    local regions = dbg:enumerate_regions(pid)
    assert(#regions > 10, "should have many memory regions, got " .. #regions)

    -- Query a specific region (the initial breakpoint address)
    local region = dbg:query_memory(pid, addr)
    assert(region.base_address > 0, "region base should be nonzero")
    assert(region.region_size > 0, "region size should be nonzero")

    -- List threads
    local threads = dbg:list_threads(pid)
    assert(#threads >= 1, "should have at least 1 thread")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

assert(#dll_loads >= 3,
    "should have loaded at least 3 DLLs (ntdll, kernel32, kernelbase), got " .. #dll_loads)

return { passed = true }
