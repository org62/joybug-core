-- Test: PDB source line info (resolve_line, line_map, source_files)
-- Requires: xtea_test.exe (built with /Od /Zi, so its PDB has full line tables)

local test_exe = TEST_EXE -- injected by Rust test harness

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- find_symbol waits for symbol loading, so the PDB path is known before
    -- the first line request triggers the lazy line-table parse.
    local syms = dbg:find_symbol("xtea_test!main", 5)
    assert(#syms > 0, "Should find xtea_test!main")
    local main_va = syms[1].va

    -- Resolve main's entry to a source line
    local line = dbg:resolve_line(pid, main_va)
    assert(line ~= nil, "main should resolve to a source line")
    assert(line.file:lower():find("xtea_test%.c$") ~= nil,
        "Expected xtea_test.c, got " .. line.file)
    assert(line.line > 0, "Line number should be positive")
    assert(line.checksum_kind ~= "none", "MSVC PDBs record file checksums")

    -- Line map for the file: non-empty, sorted by line, contains main's line
    local entries = dbg:line_map(pid, line.module_base, line.file)
    assert(#entries > 0, "Line map should have entries")
    local found_main, prev = false, 0
    for _, e in ipairs(entries) do
        assert(e.line >= prev, "Entries should be sorted by line")
        prev = e.line
        if e.line == line.line and e.rva == line.rva then found_main = true end
    end
    assert(found_main, "main's line/rva should appear in the file line map")

    -- Source file list contains the .c file
    local files = dbg:source_files(pid, line.module_base)
    local found_file = false
    for _, f in ipairs(files) do
        if f.path:lower():find("xtea_test%.c$") then found_file = true end
    end
    assert(found_file, "Source file list should contain xtea_test.c")

    -- Unknown file yields an empty map, not an error
    local empty = dbg:line_map(pid, line.module_base, "Z:\\no\\such\\file.c")
    assert(#empty == 0, "Unknown file should yield an empty map")

    dbg:terminate(pid)
end)

dbg:launch(test_exe)
dbg:run()

return { passed = true }
