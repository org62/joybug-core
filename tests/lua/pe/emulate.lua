-- Test: process-less emulation of xtea_encrypt straight from the file.
-- Inputs are planted in the synthetic stack, argument registers point at
-- them, and the routine runs to its return sentinel. The ciphertext read back
-- must match a Lua reimplementation of XTEA.

local img = pe.open(TEST_EXE)
local enc = img:find_symbol("xtea_encrypt")
assert(enc, "xtea_encrypt symbol")

local M = 0xFFFFFFFF
local function xtea_encrypt(v0, v1, key)
    local sum, delta = 0, 0x9E3779B9
    for _ = 1, 32 do
        local t = ((((v1 << 4) & M) ~ (v1 >> 5)) + v1) & M
        v0 = (v0 + (t ~ ((sum + key[(sum & 3) + 1]) & M))) & M
        sum = (sum + delta) & M
        local u = ((((v0 << 4) & M) ~ (v0 >> 5)) + v0) & M
        v1 = (v1 + (u ~ ((sum + key[((sum >> 11) & 3) + 1]) & M))) & M
    end
    return v0, v1
end

local function le32(...)
    local out = {}
    for _, w in ipairs({ ... }) do out[#out + 1] = string.pack("<I4", w) end
    return table.concat(out)
end

local data = { 0x12345678, 0x9ABCDEF0 }
local key = { 0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE }
local want0, want1 = xtea_encrypt(data[1], data[2], key)

-- Place the buffers below the default stack pointer.
local L = img:emu_layout()
assert(L.sp > L.stack_base and L.sp < L.stack_top, "default sp is inside the synthetic stack")
local v_addr, k_addr = L.sp - 0x200, L.sp - 0x100
local regs = (ARCH == "aarch64") and { x0 = v_addr, x1 = k_addr } or { rcx = v_addr, rdx = k_addr }

local r = img:emulate(enc.va, {
    max = 20000,
    regs = regs,
    mem_writes = { { v_addr, le32(data[1], data[2]) }, { k_addr, le32(table.unpack(key)) } },
    mem_reads = { { v_addr, 8 } },
})
assert(r.stop_reason == "ReturnedToCaller", "routine returns to the sentinel, stopped with " .. r.stop_reason)
assert(r.final_pc == L.sentinel, "final pc is the sentinel")
assert(r.regs ~= nil, "final registers reported")
local got0, got1 = string.unpack("<I4<I4", r.memory_snapshots[1].data)
assert(got0 == want0 and got1 == want1,
    string.format("ciphertext %08x %08x != expected %08x %08x", got0, got1, want0, want1))
-- Basic mode runs whole translation blocks and does not count instructions;
-- trace mode does.
local counted = img:emulate(enc.va, { max = 20000, mode = "trace", regs = regs,
    mem_writes = { { v_addr, le32(data[1], data[2]) }, { k_addr, le32(table.unpack(key)) } } })
assert(counted.stop_reason == "ReturnedToCaller", "trace mode also runs to the sentinel, got " .. counted.stop_reason)
assert(counted.instructions_executed > 100, "32 rounds take more than 100 instructions, got " .. counted.instructions_executed)

-- The function also stores its result to globals in .data; the emulator sees
-- the write in the image copy (the file on disk is untouched).
local g_v0 = img:find_symbol("g_v0")
if g_v0 then
    local r2 = img:emulate(enc.va, {
        regs = regs,
        mem_writes = { { v_addr, le32(data[1], data[2]) }, { k_addr, le32(table.unpack(key)) } },
        mem_reads = { { g_v0.va, 4 } },
    })
    assert(string.unpack("<I4", r2.memory_snapshots[1].data) == want0, "global written by the emulated code")
    assert(img:read_u32(g_v0.va) == 0, "the image itself is not modified by a run")
end

-- Instruction-trace mode produces a Tenet trace and per-step accounting.
local t = img:emulate(enc.va, { max = 50, mode = "trace", regs = regs,
    mem_writes = { { v_addr, le32(data[1], data[2]) }, { k_addr, le32(table.unpack(key)) } } })
assert(t.trace and #t.trace > 0, "trace text produced")
assert(t.instructions_executed == 50 and t.stop_reason == "InstructionLimit", "trace honours the instruction limit")

-- Import calls stop with the import's name: syscall_marker() calls
-- CloseHandle through the IAT.
local marker = img:find_symbol("syscall_marker")
assert(marker, "syscall_marker symbol")
local s = img:emulate(marker.va, { max = 1000 })
assert(s.stop_reason:find("^ImportCall%("), "stopped at an import, got " .. s.stop_reason)
assert(s.import and s.import:lower():find("closehandle"), "the import is CloseHandle, got " .. tostring(s.import))
assert(s.return_address >= marker.va and s.return_address < marker.va + 0x100, "return address is in the caller")

-- imports = "skip": the call returns 0 and the marker runs to its own return.
local sk = img:emulate(marker.va, { max = 1000, imports = "skip", ret = 0 })
assert(sk.stop_reason == "ReturnedToCaller", "skipping the import lets the routine finish, got " .. sk.stop_reason)

-- Start address outside the image is an error, not a crash.
local ok, err = pcall(function() return img:emulate(0x10, {}) end)
assert(not ok and tostring(err):find("outside the image"), "bad start address rejected")

return { passed = true }
