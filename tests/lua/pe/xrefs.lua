-- Test: cross-references and function recovery.

local img = pe.open(TEST_EXE)
local base, size = img:base(), img:size()
local function in_image(a) return a >= base and a < base + size end

-- main() calls xtea_encrypt directly: a Call xref from inside main.
local enc = img:find_symbol("xtea_encrypt")
local main = img:find_symbol("main")
assert(enc and main, "symbols for xtea_encrypt and main")
local to_enc = img:xrefs_to(enc.va)
assert(#to_enc >= 1, "xtea_encrypt has at least one caller")
local main_fn = img:disassemble_function(main.va)
local function in_main(a) return a >= main_fn.start and a < main_fn["end"] end
-- Debug builds link incrementally, so main reaches xtea_encrypt through an
-- ILT `jmp` thunk: follow one level of jump xrefs back to the real caller.
local from_main, seen = false, {}
for _, x in ipairs(to_enc) do
    assert(x.to == enc.va, "xref target is the function")
    assert(in_image(x.from), "xref source is inside the image")
    assert(x.kind == "call" or x.kind == "jump" or x.kind == "imm", "code reference kind, got " .. x.kind)
    seen[#seen + 1] = x.kind .. "@" .. hex(x.from)
    if in_main(x.from) then from_main = true end
    if x.kind == "jump" then
        for _, y in ipairs(img:xrefs_to(x.from)) do
            seen[#seen + 1] = "  via " .. y.kind .. "@" .. hex(y.from)
            if in_main(y.from) then from_main = true end
        end
    end
end
assert(from_main, "one caller of xtea_encrypt is main " .. hex(main_fn.start) .. "-" .. hex(main_fn["end"])
    .. ": " .. table.concat(seen, ", "))

-- The reverse direction: the call site references the function.
local site = to_enc[1].from
local from_site = img:xrefs_from(site)
local points_back = false
for _, x in ipairs(from_site) do if x.to == enc.va then points_back = true end end
assert(points_back, "xrefs_from(call site) lists the callee")

-- Imports: at least one named import has a call/jmp through its IAT slot.
local found_import_xref = false
for _, imp in ipairs(img:imports()) do
    if imp.name then
        local xs = img:xrefs_to_import(imp.dll .. "!" .. imp.name)
        if #xs > 0 then
            found_import_xref = true
            -- The referencing instruction really is an indirect call/jmp/load
            -- through the slot.
            local row = img:disassemble(xs[1].from, 1)[1]
            assert(row.mem_ref == imp.iat_va or row.jump_target == imp.iat_va,
                "referencing instruction operand is the IAT slot: " .. row.mnemonic .. " " .. row.operands)
            break
        end
    end
end
assert(found_import_xref, "some import is referenced through its IAT slot")
local ok = pcall(function() return img:xrefs_to_import("nosuch!Nope") end)
assert(not ok, "unknown import is an error")

-- Function recovery: sorted, includes the entry point and the symbol functions.
local funcs = img:functions()
assert(#funcs > 5, "recovered several functions, got " .. #funcs)
local seen_entry, seen_enc = false, false
for i, f in ipairs(funcs) do
    assert(in_image(f.start), "function start inside the image")
    if i > 1 then assert(funcs[i - 1].start < f.start, "functions sorted by start") end
    if f.start == img:entry_point() then seen_entry = true end
    if f.start == enc.va then
        seen_enc = true
        assert(f.name == "xtea_encrypt", "recovered function carries its symbol name, got " .. tostring(f.name))
    end
end
assert(seen_entry, "entry point is a function")
assert(seen_enc, "xtea_encrypt is a function")

return { passed = true }
