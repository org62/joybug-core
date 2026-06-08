-- Test: Memory regions enumeration and querying
-- Ported from: memory_region_test.rs::test_memory_regions

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- TEST 1: Enumerate all memory regions
    local regions = dbg:enumerate_regions(pid)
    assert(#regions > 0, "Should have at least one memory region")

    -- Count committed regions (state == 0x1000 = MEM_COMMIT)
    local committed = 0
    for _, r in ipairs(regions) do
        if r.state == 0x1000 then committed = committed + 1 end
    end
    assert(committed > 0, "Should have committed regions")

    -- Count image regions (type == 0x1000000 = MEM_IMAGE)
    local image = 0
    for _, r in ipairs(regions) do
        if r.region_type == 0x1000000 then image = image + 1 end
    end
    assert(image > 0, "Should have image regions (loaded modules)")

    -- TEST 2: Query memory region by address
    local region = dbg:query_memory(pid, addr)
    assert(region.base_address > 0, "Region base should be nonzero")
    assert(region.region_size > 0, "Region size should be nonzero")
    assert(region.state == 0x1000, "Module memory should be committed")

    -- TEST 3: List threads
    local threads = dbg:list_threads(pid)
    assert(#threads >= 1, "Should have at least 1 thread")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
