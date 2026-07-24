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
                local got = dbg:ptr_scan_results(pid, pscan.results_path, 0, pscan.match_count)
                for _, p in ipairs(got.paths) do
                    if p.resolved == target and p.module_base == image_base then
                        found_image_path = true
                        break
                    end
                end
            end
            if found_image_path then
                -- Offset quick-filter: the chain's final hop reaches the node's
                -- `value` field at +8, so a {0x8} filter must keep at least one
                -- path, while a bogus offset must match nothing.
                local kept = dbg:ptr_scan_results(pid, pscan.results_path, 0, 100, { 0x8 })
                assert(kept.total_count >= 1, "offset filter {0x8} should keep the value-field path")
                local none = dbg:ptr_scan_results(pid, pscan.results_path, 0, 100, { 0xDEADBEEF })
                assert(none.total_count == 0, "a bogus offset filter should match nothing")

                -- Commit the {0x8} filter into a new, smaller file; the survivors
                -- equal the filtered count, and the file path changes.
                local committed = dbg:ptr_scan_apply_filter(pscan.results_path, { 0x8 })
                assert(committed.match_count == kept.total_count, "apply_filter should keep exactly the matches")
                assert(committed.results_path ~= pscan.results_path, "apply_filter writes a new file")
                local after = dbg:ptr_scan_results(pid, committed.results_path, 0, 100)
                assert(after.total_count == kept.total_count, "committed file holds only the matches")
                pscan.results_path = committed.results_path -- old file is gone; track the new one

                -- Rescan against the same target: the resolving path(s) must survive.
                local re = dbg:ptr_scan_rescan(pid, pscan.results_path, target)
                assert(re.match_count >= 1, "rescan with same target should keep resolving paths")
                dbg:ptr_scan_reset(re.results_path)
            end
            dbg:ptr_scan_reset(pscan.results_path)
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
