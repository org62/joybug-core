-- Test: offline disassembly (forward, backward, function) and PDB symbols.

local img = pe.open(TEST_EXE)
local ep = img:entry_point()

-- Forward decode from the entry point: contiguous, correctly sized rows.
local instrs = img:disassemble(ep, 8)
assert(#instrs == 8, "8 instructions requested, got " .. #instrs)
assert(instrs[1].address == ep, "first row is the entry point")
for i = 2, #instrs do
    assert(instrs[i].address == instrs[i - 1].address + instrs[i - 1].size,
        "rows are contiguous at " .. hex(instrs[i].address))
end

-- Backward decode ends exactly at the anchor.
local target = instrs[5].address
local prev = img:disassemble_backward(target, 4)
assert(#prev >= 1, "backward decode yields rows")
local last = prev[#prev]
assert(last.address + last.size == target, "last backward row ends at the target")

-- Symbols: build.rs compiles the test programs with /Zi, so the PDB sits next
-- to the exe and loads automatically (offline).
assert(img:has_symbols(), "PDB next to the exe loads on open")
local enc = img:find_symbol("xtea_encrypt")
assert(enc ~= nil, "xtea_encrypt symbol found")
assert(enc.va >= img:base(), "symbol VA is absolute")
assert(img:resolve_address(enc.va) == "xtea_test!xtea_encrypt", "resolve_address at the symbol start, got " .. tostring(img:resolve_address(enc.va)))
assert(img:resolve_address(enc.va + 1):find("xtea_encrypt%+0x1"), "resolve_address inside the symbol carries the offset")
local matches = img:symbols("xtea", 10)
assert(#matches >= 2, "token search finds xtea_encrypt and xtea_decrypt")

-- Function disassembly: bounded, symbolised, starts at the function.
local fn = img:disassemble_function(enc.va)
assert(fn.start == enc.va, "function start is the symbol")
assert(fn["end"] and fn["end"] > fn.start, "function end recovered")
assert(fn.name == "xtea_test!xtea_encrypt", "function name from symbols, got " .. tostring(fn.name))
assert(#fn.instructions > 10, "a 32-round loop is more than a handful of instructions")
assert(fn.instructions[1].address == enc.va, "listing starts at the function")
local has_ret = false
for _, i in ipairs(fn.instructions) do if i.is_ret then has_ret = true end end
assert(has_ret, "listing reaches the function's ret")

-- The listing is symbolised: the rows at the symbol carry it.
assert(fn.instructions[1].symbol == "xtea_test!xtea_encrypt", "row symbol, got " .. tostring(fn.instructions[1].symbol))

return { passed = true }
