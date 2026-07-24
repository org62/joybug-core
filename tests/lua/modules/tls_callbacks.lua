-- Test: TLS callback RVAs in module PE info (get_module_info().tls_callbacks)
-- Uses tls_test.exe, which registers one TLS callback via .CRT$XLB.

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local main
    for _, m in ipairs(dbg:list_modules(pid)) do
        if m.name:lower():find("tls_test") then main = m end
    end
    assert(main, "tls_test main module should be loaded")

    local info = dbg:get_module_info(pid, main.base)

    assert(type(info.tls_callbacks) == "table", "tls_callbacks should be a table")
    assert(#info.tls_callbacks > 0, "tls_test.exe should expose at least one TLS callback")

    -- Every callback RVA must be non-zero and land inside the image.
    for _, rva in ipairs(info.tls_callbacks) do
        assert(rva > 0, "TLS callback RVA should be non-zero")
        assert(rva < info.size_of_image,
            "TLS callback RVA " .. hex(rva) .. " outside image (size " .. hex(info.size_of_image) .. ")")
    end

    -- A module without a TLS directory reports an empty table (kernelbase has none).
    local kernelbase
    for _, m in ipairs(dbg:list_modules(pid)) do
        if m.name:lower():find("kernelbase%.dll") then kernelbase = m end
    end
    if kernelbase then
        local kb_info = dbg:get_module_info(pid, kernelbase.base)
        assert(type(kb_info.tls_callbacks) == "table", "tls_callbacks should always be a table")
    end

    dbg:terminate(pid)
end)

dbg:launch(TEST_EXE)
dbg:run()

return { passed = true }
