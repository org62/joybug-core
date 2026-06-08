-- Test: Module extra info (PE headers, sections)
-- Ported from: module_extra_info_test.rs::test_module_extra_info_print
-- Note: The Lua binding exposes a subset of fields (entry_point, image_base,
-- size_of_image, sections). The full Rust test validates imports/exports/runtime
-- functions which aren't exposed via Lua get_module_info yet.

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local mods = dbg:list_modules(pid)

    -- Find kernelbase.dll
    local kernelbase = nil
    for _, m in ipairs(mods) do
        local name = m.name:lower()
        if name:find("kernelbase%.dll") then
            kernelbase = m
            break
        end
    end
    assert(kernelbase, "kernelbase.dll not found in module list")

    local info = dbg:get_module_info(pid, kernelbase.base)

    -- Verify entry point is reasonable
    assert(info.entry_point > 0, "Entry point should be nonzero")

    -- Verify image base is reasonable (may differ from module base due to ASLR)
    assert(info.image_base > 0, "Image base should be nonzero")

    -- Verify size of image is reasonable
    assert(info.size_of_image > 0x10000,
        "Size of image should be reasonable, got " .. hex(info.size_of_image))

    -- Verify sections exist and .text is present
    assert(#info.sections > 0, "Should have sections")
    local has_text = false
    for _, sec in ipairs(info.sections) do
        if sec.name:lower() == ".text" then
            has_text = true
            break
        end
    end
    assert(has_text, ".text section not found")

    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

return { passed = true }
