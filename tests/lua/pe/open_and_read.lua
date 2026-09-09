-- Test: pe.open() — headers, sections, imports, addresses, raw reads.
-- No server, no process: the image is the compiled xtea_test.exe on disk.

local img = pe.open(TEST_EXE)

-- Architecture follows the image's machine field, which is the host's here.
local want_arch = (ARCH == "aarch64") and "arm64" or "x64"
assert(img:arch() == want_arch, "arch " .. img:arch() .. " != " .. want_arch)
assert(img:path() == TEST_EXE, "path round-trips")
assert(img:module_name() == "xtea_test", "module name is the file stem, got " .. img:module_name())

local base, size = img:base(), img:size()
assert(base > 0 and size > 0, "base/size populated")
local ep = img:entry_point()
assert(ep >= base and ep < base + size, "entry point inside the image")

-- Sections: a .text section that contains the entry point.
local sections = img:sections()
assert(#sections >= 2, "expected several sections, got " .. #sections)
local text
for _, s in ipairs(sections) do
    if s.name == ".text" then text = s end
end
assert(text, ".text section present")
assert(ep >= text.va and ep < text.va + text.vsize, "entry point lives in .text")

-- Imports: a C runtime program imports from kernel32 (directly or via api-ms-*).
local imports = img:imports()
assert(#imports > 0, "import table is non-empty")
local seen_kernel32 = false
for _, imp in ipairs(imports) do
    assert(imp.iat_va >= base and imp.iat_va < base + size, "IAT slot inside the image")
    if imp.dll:lower():find("kernel32") then seen_kernel32 = true end
end
assert(seen_kernel32, "kernel32 among the imported DLLs")
-- An import lookup resolves to one of those slots, case-insensitively.
local slot = img:import_slot("KERNEL32!GetCurrentProcess") or img:import_slot("kernel32!ExitProcess")
    or img:import_slot(imports[1].name)
assert(slot ~= nil and slot >= base, "import_slot resolves a known import")
assert(img:import_slot("nosuch!Nope") == nil, "unknown import resolves to nil")

-- Raw reads at the base: the DOS header.
assert(img:read(base, 2) == "MZ", "MZ at the base")
assert(img:read_u16(base) == 0x5A4D, "read_u16 little-endian")
assert(img:read_u32(base) == (0x5A4D | (img:read_u16(base + 2) << 16)), "read_u32 composes")
assert(img:va2off(base) == 0, "base maps to file offset 0")
assert(img:off2va(0) == base, "offset 0 maps to the base")
assert(img:va2off(text.va) == text.raw, ".text VA maps to its raw pointer")
assert(img:off2va(text.raw) == text.va, ".text raw pointer maps back to its VA")

-- find_bytes: the MZ header is the first hit; wildcards are honoured.
local hits = img:find_bytes("4d 5a", 4)
assert(hits[1] == base, "MZ pattern found at the base")
local wild = img:find_bytes("4d ?? 90", 1)
assert(#wild == 1 and wild[1] == base, "wildcard pattern matches the DOS header")
local ok, err = pcall(function() return img:find_bytes("?? ??") end)
assert(not ok and tostring(err):find("fixed byte"), "all-wildcard pattern is rejected")

-- Strings: the program's printf format strings live in the image (VA addressed).
-- (`contains` is case-insensitive, so plain "xtea" would also hit the PDB path
-- in the debug directory; the banner text is unambiguous.)
local strs = img:strings{ min = 8, encoding = "ascii", contains = "XTEA Test Program" }
assert(#strs > 0, "found the XTEA banner string")
assert(strs[1].address >= base and strs[1].address < base + size, "string hit is a VA")
local at = img:read_string(strs[1].address, 64)
assert(at:find("XTEA Test Program", 1, true), "read_string at the hit returns the text, got " .. at)
-- File-offset mode addresses the raw file instead.
local fstrs = img:strings{ min = 8, encoding = "ascii", contains = "XTEA Test Program", file = true }
assert(#fstrs == #strs and fstrs[1].address < img:file_size(), "file mode addresses are offsets")

return { passed = true }
