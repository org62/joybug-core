-- Test: Lua helper library (hex, u8/u16/u32/u64 readers, hexdump)
-- Ported from: scripting_test.rs::test_lua_helpers

-- hex() formatting
assert(hex(0xDEADBEEF) == "0xDEADBEEF", "hex(0xDEADBEEF) = " .. hex(0xDEADBEEF))
assert(hex(255) == "0xFF", "hex(255) = " .. hex(255))
assert(hex(0) == "0x0", "hex(0) = " .. hex(0))

-- u8/u16/u32/u64 readers on binary data
assert(u8("\x42") == 0x42, "u8 mismatch: " .. u8("\x42"))
assert(u16("\x01\x02") == 0x0201, "u16 mismatch: " .. u16("\x01\x02")) -- little-endian
assert(u32("\x01\x02\x03\x04") == 0x04030201, "u32 mismatch: " .. u32("\x01\x02\x03\x04"))

-- hexdump produces expected format
local hexdump_out = hexdump("\x41\x42\x43\x44", 0x1000)
assert(hexdump_out:find("0000000000001000"), "hexdump should show base address")
assert(hexdump_out:find("41 42 43 44"), "hexdump should show hex bytes")
assert(hexdump_out:find("ABCD"), "hexdump should show ASCII")

return { passed = true }
