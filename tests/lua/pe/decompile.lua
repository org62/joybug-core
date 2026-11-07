-- Test: offline decompilation of a function to pseudocode.

local img = pe.open(TEST_EXE)
local enc = img:find_symbol("xtea_encrypt")
assert(enc ~= nil, "xtea_encrypt symbol found")

local fn = img:decompile(enc.va)
assert(fn.name == "xtea_encrypt", "named from the PDB, got " .. tostring(fn.name))
assert(fn.start == enc.va, "starts at the symbol")
assert(fn.code:find("xtea_encrypt", 1, true), "the text declares the function")
assert(fn.code:find("{", 1, true) and fn.code:find("}", 1, true), "C-like body")

-- Lines map to instruction addresses inside the function.
local bounds = img:disassemble_function(enc.va, 4000)
assert(#fn.lines > 0, "lines carry addresses")
for _, row in ipairs(fn.lines) do
    assert(row.line >= 1, "1-based line")
    for _, va in ipairs(row.addresses) do
        assert(va >= bounds.start and va < bounds["end"], "address inside the function: " .. hex(va))
    end
end

-- An inner address selects the same function.
local inner = fn.lines[#fn.lines].addresses[1]
assert(img:decompile(inner).start == enc.va, "inner address resolves to the function start")

-- Outside the image there is nothing to decompile.
local ok = pcall(function() return img:decompile(img:base() - 1) end)
assert(not ok, "an address outside the image fails")

return { passed = true }
