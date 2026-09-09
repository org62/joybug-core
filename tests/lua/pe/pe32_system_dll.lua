-- Test: a real PE32 (32-bit kernel32.dll) — x86 decoding, `ff 15` IAT calls
-- as import xrefs, and wildcard search finding the same sites. Skips when
-- the host has no WOW64 layer.

local path = os.getenv("SystemRoot") .. [[\SysWOW64\kernel32.dll]]
local f = io.open(path, "rb")
if not f then
    print("skipping: no " .. path)
    return { passed = true }
end
f:close()

local img = pe.open(path)
assert(img:arch() == "x86", "SysWOW64 kernel32 is x86, got " .. img:arch())
assert(img:base() <= 0xFFFFFFFF, "32-bit image base")

-- 32-bit mode decode at the entry point: no 64-bit registers appear.
local rows = img:disassemble(img:entry_point(), 6)
assert(#rows == 6, "decoded the entry point")
for _, r in ipairs(rows) do
    assert(not r.operands:find("r[a-d]x") and not r.operands:find("rsp") and not r.operands:find("rip"),
        "x86 decode has no 64-bit registers: " .. r.mnemonic .. " " .. r.operands)
end

-- Exports of a DLL are functions.
local exports = img:exports()
assert(#exports > 100, "kernel32 exports many functions")
local create_file
for _, e in ipairs(exports) do if e.name == "CreateFileW" then create_file = e end end
assert(create_file and create_file.va, "CreateFileW exported")

-- Some import is called through its IAT slot with `ff 15 <slot>` (x86 absolute
-- call) — the xref index sees it as a call whose target is the slot.
local found
for _, imp in ipairs(img:imports()) do
    if imp.name then
        local xs = img:xrefs_to_import(imp.dll .. "!" .. imp.name)
        for _, x in ipairs(xs) do
            if x.kind == "call" then found = { imp = imp, x = x } break end
        end
    end
    if found then break end
end
assert(found, "an import is reached by an indirect call")
local row = img:disassemble(found.x.from, 1)[1]
assert(row.is_call and row.mem_ref == found.imp.iat_va, "call site operand is the slot: " .. row.mnemonic .. " " .. row.operands)

-- find_bytes reproduces the same site: ff 15 <slot little-endian>.
local slot = found.imp.iat_va
local pat = string.format("ff 15 %02x %02x %02x %02x", slot & 0xFF, (slot >> 8) & 0xFF, (slot >> 16) & 0xFF, (slot >> 24) & 0xFF)
local hits = img:find_bytes(pat)
local matched = false
for _, h in ipairs(hits) do if h == found.x.from then matched = true end end
assert(matched, "byte pattern search finds the call site " .. hex(found.x.from))

-- Process-less emulation of 32-bit code: the entry point's prologue runs on the
-- synthetic stack (esp must land in it — a Mode32 Unicorn ignores 64-bit
-- register ids, which once left esp at 0 and faulted the first push at
-- 0xFFFFFFFC).
local L = img:emu_layout()
local run = img:emulate(img:entry_point(), { mode = "trace", max = 5 })
assert(run.stop_reason == "InstructionLimit", "5 instructions of the entry run cleanly, got " .. run.stop_reason)
assert(run.instructions_executed == 5, "counted 5 instructions, got " .. run.instructions_executed)
assert(run.regs.esp ~= nil and run.regs.esp > L.stack_base and run.regs.esp < L.stack_top,
    "esp stays inside the synthetic stack: " .. hex(run.regs.esp or 0))
assert(run.regs.eip == run.final_pc, "final pc is reported as eip")

-- Function recovery on x86 uses exports, calls and prologue hits.
local funcs = img:functions()
assert(#funcs > 500, "many functions recovered in kernel32, got " .. #funcs)
local sources = {}
for _, fn in ipairs(funcs) do sources[fn.source] = true end
assert(sources.export and sources.call, "functions come from exports and call targets")

return { passed = true }
