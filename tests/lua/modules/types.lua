-- Test: PDB type information (dbg:list_types / dbg:get_type / dbg:get_type_by_index)
--
-- The Windows OS structs _PEB, _TEB and _KUSER_SHARED_DATA live in ntdll's PDB.
-- Verify we can enumerate types, resolve a named struct to its member layout,
-- follow bitfields, and expand a nested member type by its TPI index.

local handler_ran = false

dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- ntdll symbols load asynchronously; wait for them (PDB download + parse).
    local ntdll = wait_symbols(pid, "ntdll")
    assert(ntdll, "ntdll should be in the module list")
    assert(ntdll.state == "loaded",
        "ntdll symbols should load, got: " .. ntdll.state .. " (" .. tostring(ntdll.error) .. ")")

    -- Resolve _PEB by name (searches all loaded modules).
    local peb = dbg:get_type("_PEB")
    assert(peb, "_PEB type should resolve from ntdll")
    assert(peb.kind == "struct", "_PEB should be a struct, got " .. tostring(peb.kind))
    assert(peb.size > 0, "_PEB should have a nonzero size")
    assert(#peb.members > 10, "_PEB should have many members, got " .. #peb.members)

    -- BeingDebugged is a well-known byte at offset 2.
    local being_debugged
    for _, m in ipairs(peb.members) do
        if m.name == "BeingDebugged" then being_debugged = m end
    end
    assert(being_debugged, "_PEB should have a BeingDebugged member")
    assert(being_debugged.offset == 2,
        "BeingDebugged should be at offset 2, got " .. being_debugged.offset)
    -- Reserved primitive indices (< 0x1000) must resolve to a real type name,
    -- not an opaque "t#NN".
    assert(being_debugged.type:find("char") ~= nil,
        "BeingDebugged should be a char type, got '" .. being_debugged.type .. "'")
    assert(being_debugged.kind == "uint" or being_debugged.kind == "char",
        "BeingDebugged should be a scalar, got kind '" .. tostring(being_debugged.kind) .. "'")

    -- _PEB has bitfields packed at offset 3 (ImageUsesLargePages, etc.).
    local found_bitfield = false
    for _, m in ipairs(peb.members) do
        if m.bit_length ~= nil then found_bitfield = true end
    end
    assert(found_bitfield, "_PEB should expose bitfield members")

    -- _TEB references _PEB via a pointer member (ProcessEnvironmentBlock);
    -- the pointer carries its pointee as a structured sub-table.
    local teb = dbg:get_type("_TEB")
    assert(teb, "_TEB type should resolve")
    local peb_ptr
    for _, m in ipairs(teb.members) do
        if m.name == "ProcessEnvironmentBlock" then peb_ptr = m end
    end
    assert(peb_ptr, "_TEB should have a ProcessEnvironmentBlock member")
    assert(peb_ptr.kind == "pointer", "ProcessEnvironmentBlock should be a pointer")
    assert(peb_ptr.pointee and peb_ptr.pointee.type == "_PEB",
        "pointer member should carry its pointee, got " .. tostring(peb_ptr.pointee and peb_ptr.pointee.type))

    -- _KUSER_SHARED_DATA is the fixed shared page struct.
    local kusd = dbg:get_type("_KUSER_SHARED_DATA")
    assert(kusd, "_KUSER_SHARED_DATA should resolve")
    assert(#kusd.members > 10, "_KUSER_SHARED_DATA should have many members")

    -- Nested expansion: find a member that is itself a UDT and expand it by the
    -- TPI index the member carries. NtTib (_NT_TIB) is the first member of _TEB.
    local nt_tib
    for _, m in ipairs(teb.members) do
        if m.name == "NtTib" then nt_tib = m end
    end
    assert(nt_tib, "_TEB should have an NtTib member")
    assert(nt_tib.kind == "udt", "NtTib should be a nested UDT, got " .. tostring(nt_tib.kind))
    assert(nt_tib.type_index and nt_tib.type_index > 0, "udt member should carry its TPI type_index")
    local nested = dbg:get_type_by_index(teb.module_base, nt_tib.type_index)
    assert(nested, "NtTib should expand via get_type_by_index")
    assert(nested.name == "_NT_TIB", "expanded NtTib should be _NT_TIB, got " .. tostring(nested.name))
    assert(#nested.members > 0, "_NT_TIB should have members")

    -- TEB/PEB anchor addresses for overlaying the structs.
    local peb_addr = dbg:get_peb_address(pid)
    assert(peb_addr and peb_addr > 0, "PEB address should resolve")
    local teb_addr = dbg:get_teb_address(tid, pid)
    assert(teb_addr and teb_addr > 0, "TEB address should resolve")

    -- list_types with a filter should surface these structs by substring.
    local matches = dbg:list_types("_KUSER_SHARED_DATA")
    local saw_kusd = false
    for _, t in ipairs(matches) do
        if t.name == "_KUSER_SHARED_DATA" then saw_kusd = true end
    end
    assert(saw_kusd, "list_types filter should find _KUSER_SHARED_DATA")

    handler_ran = true
    dbg:terminate(pid)
end)

dbg:launch('cmd.exe /c "echo test"')
dbg:run()

assert(handler_ran, "initial breakpoint handler should have run")
return { passed = true }
