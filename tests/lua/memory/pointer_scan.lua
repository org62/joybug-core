-- Test: value-scan + pointer-scan, Cheat-Engine style.
-- Requires: pointer_scan_test.exe
--
-- The victim is a single static global `g_list_head` heading a linked list whose
-- LAST node holds the sentinel value. This test:
--   1. Finds the sentinel's address by scanning memory for its value
--      (0x1337C0DE00000000) -- NOT by walking the list forward.
--   2. Runs a reverse pointer scan from that address and asserts a path walks
--      back to the PE image memory holding the global pointer.
--
-- The real chain is g_list_head + [0, 0, ..., 0, 8] (one hop per node, tiny
-- offsets), so we scan with a small max_offset. A large window would surface
-- thousands of incidental static pointers from system DLLs.

local test_exe = TEST_EXE -- injected by Rust test harness
local NUM_STRUCTS = 4
local SENTINEL = 0x1337C0DE00000000
local MAX_OFFSET = 0x40
local MAX_DEPTH = NUM_STRUCTS -- one indirection per node back to the head

dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_single_shot_breakpoint(pid, "pointer_scan_test!breakpoint_here", function(pid, tid, addr)
        -- Locate the PE image (main module) so we can require the pointer path
        -- to be rooted back in it.
        local image_base = nil
        for _, m in ipairs(dbg:list_modules(pid)) do
            if string.find(m.name:lower(), "pointer_scan_test", 1, true) then
                image_base = m.base
                break
            end
        end
        assert(image_base ~= nil, "Should find the pointer_scan_test PE image module")

        -- 1. Find the sentinel's address by value.
        local sentinel_str = string.format("0x%X", SENTINEL)
        local vscan = dbg:scan_start(pid, "u64", "exact", sentinel_str)
        assert(vscan.match_count >= 1,
            string.format("value scan should find sentinel %s", sentinel_str))
        local vres = dbg:scan_results(vscan.scan_id, 0, 100)

        -- 2. Pointer-scan each candidate back to the PE image, restricting the
        --    static base to the image module so every result roots there.
        local found_image_path = false
        for _, target in ipairs(vres.addresses) do
            local pscan = dbg:ptr_scan_start(pid, target, MAX_OFFSET, MAX_DEPTH, { image_base })
            if pscan.match_count > 0 then
                local got = dbg:ptr_scan_results(pscan.scan_id, 0, pscan.match_count)
                for _, p in ipairs(got.paths) do
                    if p.resolved == target and p.module_base == image_base then
                        found_image_path = true
                        break
                    end
                end
            end
            dbg:ptr_scan_reset(pscan.scan_id)
            if found_image_path then break end
        end

        dbg:scan_reset(vscan.scan_id)
        assert(found_image_path,
            "sentinel should trace back to the PE image global pointer")

        dbg:terminate(pid)
    end)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
