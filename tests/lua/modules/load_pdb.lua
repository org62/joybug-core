-- Test: Load a user-supplied PDB (dbg:load_pdb) with GUID/age validation

local handler_ran = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    local main
    for _, m in ipairs(dbg:list_modules(pid)) do
        if m.name:lower():find("disassembly_test") then main = m end
    end
    assert(main, "main module should be loaded")

    -- Build.rs places each test program's PDB next to its exe in OUT_DIR,
    -- so another program's PDB doubles as a guaranteed GUID/age mismatch.
    local own_pdb = TEST_EXE:gsub("%.exe$", ".pdb")
    local other_pdb = own_pdb:gsub("disassembly_test", "dereference_test")

    -- Matching PDB loads without force
    local result = dbg:load_pdb(pid, main.base, own_pdb)
    assert(result.loaded == true, "matching PDB should load")
    assert(result.symbol_count > 0, "loaded PDB should contain symbols")

    -- Status reflects the user-supplied PDB
    local status
    for _, s in ipairs(dbg:symbol_status(pid)) do
        if s.base == main.base then status = s end
    end
    assert(status and status.state == "loaded", "module should be loaded after load_pdb")
    assert(status.pdb_path == own_pdb, "status should report the user PDB path, got: " .. tostring(status.pdb_path))

    -- Mismatched PDB is rejected without force...
    local mismatch = dbg:load_pdb(pid, main.base, other_pdb)
    assert(mismatch.loaded == false, "mismatched PDB should not load without force")
    assert(mismatch.mismatch ~= nil, "mismatch details should be present")
    assert(mismatch.mismatch.pe_guid ~= mismatch.mismatch.pdb_guid
        or mismatch.mismatch.pe_age ~= mismatch.mismatch.pdb_age,
        "PE and PDB identities should differ in the mismatch details")

    -- ...and loads with force=true
    local forced = dbg:load_pdb(pid, main.base, other_pdb, true)
    assert(forced.loaded == true, "mismatched PDB should load with force=true")

    handler_ran = true
    dbg:terminate(pid)
end)

dbg:launch(TEST_EXE)
dbg:run()

assert(handler_ran, "initial breakpoint handler should have run")
return { passed = true }
