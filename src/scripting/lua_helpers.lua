-- joybug-core Lua helper library
-- Loaded automatically at startup

-- ---- Color system ----
-- C.addr("text")  -> colored text if _jlua_color is true, plain otherwise
-- Uses ANSI escape codes. Controlled by _jlua_color global (set by --no-color flag).

C = {}
local function _make_color(code)
    return function(s)
        if _jlua_color then
            return "\27[" .. code .. "m" .. s .. "\27[0m"
        end
        return s
    end
end

C.addr    = _make_color("36")       -- cyan: addresses
C.sym     = _make_color("33")       -- yellow: symbol names
C.reg     = _make_color("32")       -- green: register names
C.val     = _make_color("37")       -- white: values
C.mnem    = _make_color("1;37")     -- bold white: mnemonics
C.op      = _make_color("37")       -- white: operands
C.str     = _make_color("32")       -- green: strings
C.comment = _make_color("90")       -- gray: comments/annotations
C.err     = _make_color("31")       -- red: errors
C.header  = _make_color("1;36")     -- bold cyan: headers
C.dim     = _make_color("90")       -- dim gray
C.arrow   = _make_color("90")       -- dim gray: arrows

--- Format a number as hexadecimal (e.g. 0x7FFA1234)
function hex(n)
    if type(n) ~= "number" then return tostring(n) end
    if n < 0 then
        return string.format("0x%X", n & 0xFFFFFFFFFFFFFFFF)
    end
    return string.format("0x%X", n)
end

--- Classic hex dump of binary data or memory address
--- hexdump()            -- 64 bytes at rsp
--- hexdump(addr)        -- 64 bytes at addr
--- hexdump(addr, size)  -- size bytes at addr
--- hexdump(data_string, base_addr)  -- raw binary data
function hexdump(data_or_addr, size_or_base)
    local data, base_addr, auto_print
    if type(data_or_addr) == "number" then
        if pid and data_or_addr > 0xFFFF then
            local addr = data_or_addr
            local size = size_or_base or 64
            base_addr = addr
            data = dbg:read_memory(pid, addr, size)
            auto_print = true
        else
            print(C.err("(hexdump: pass a binary string or memory address)"))
            return
        end
    elseif type(data_or_addr) == "string" then
        data = data_or_addr
        base_addr = size_or_base or 0
        auto_print = false
    elseif data_or_addr == nil then
        if not rsp then print(C.err("(no rsp)")); return end
        base_addr = rsp
        data = dbg:read_memory(pid, rsp, 64)
        auto_print = true
    else
        print(C.err("(invalid argument)"))
        return
    end

    local lines = {}
    for i = 1, #data, 16 do
        local hex_part = {}
        local ascii_part = {}
        for j = 0, 15 do
            local idx = i + j
            if idx <= #data then
                local byte = string.byte(data, idx)
                table.insert(hex_part, string.format("%02X", byte))
                if byte >= 32 and byte < 127 then
                    table.insert(ascii_part, string.char(byte))
                else
                    table.insert(ascii_part, ".")
                end
            else
                table.insert(hex_part, "  ")
                table.insert(ascii_part, " ")
            end
        end
        local hex_str = table.concat(hex_part, " ", 1, math.min(8, #hex_part))
        if #hex_part > 8 then
            hex_str = hex_str .. "  " .. table.concat(hex_part, " ", 9)
        end
        local addr_str = C.addr(string.format("%016X", base_addr + i - 1))
        local ascii_str = C.str(table.concat(ascii_part))
        table.insert(lines, string.format("  %s  %-49s  %s", addr_str, hex_str, ascii_str))
    end
    local result = table.concat(lines, "\n")
    if auto_print then
        print(result)
    else
        return result
    end
end

--- Read a little-endian u8 from binary string at offset (1-based)
function u8(data, offset)
    offset = offset or 1
    return string.byte(data, offset)
end

--- Read a little-endian u16 from binary string at offset (1-based)
function u16(data, offset)
    offset = offset or 1
    local b1, b2 = string.byte(data, offset, offset + 1)
    return b1 + b2 * 0x100
end

--- Read a little-endian u32 from binary string at offset (1-based)
function u32(data, offset)
    offset = offset or 1
    local b1, b2, b3, b4 = string.byte(data, offset, offset + 3)
    return b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
end

--- Read a little-endian u64 from binary string at offset (1-based)
function u64(data, offset)
    offset = offset or 1
    local lo = u32(data, offset)
    local hi = u32(data, offset + 4)
    return lo + hi * 0x100000000
end

--- Format a dereference chain for a single value
local function _deref_annotation(val)
    if not pid then return "" end
    if val == 0 then return "" end
    if val < 0x10000 then return "" end

    local ok, entries = pcall(function()
        return dbg:dereference(pid, val, 1)
    end)
    if not ok or not entries or #entries == 0 then return "" end

    local chain = entries[1].chain
    if not chain or #chain == 0 then return "" end

    local parts = {}
    for _, v in ipairs(chain) do
        if v.type == "pointer" then
            if v.symbol then
                table.insert(parts, C.sym(v.symbol))
            else
                table.insert(parts, C.addr(hex(v.address)))
            end
        elseif v.type == "string" then
            local s = v.value
            if #s > 40 then s = s:sub(1, 40) .. "..." end
            table.insert(parts, C.str(string.format("%q", s)))
        elseif v.type == "instruction" then
            if v.symbol then
                table.insert(parts, C.sym(v.symbol))
            else
                table.insert(parts, C.mnem(v.mnemonic))
            end
        elseif v.type == "value" then
            table.insert(parts, C.val(hex(v.value)))
        elseif v.type == "loop" then
            table.insert(parts, C.dim("-> loop"))
        end
    end
    if #parts == 0 then return "" end
    return C.arrow(" -> ") .. table.concat(parts, C.arrow(" -> "))
end

--- Pretty-print registers with dereferenced pointer annotations
--- regs()       -- print current registers (from ctx global)
--- regs(table)  -- print given register table
function regs(c)
    c = c or ctx
    if not c then
        print(C.err("(no context)"))
        return
    end
    if c.rax ~= nil then
        local names = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                       "r8","r9","r10","r11","r12","r13","r14","r15","rip","rflags"}
        for _, name in ipairs(names) do
            if c[name] then
                local annotation = ""
                if name ~= "rflags" then
                    annotation = _deref_annotation(c[name])
                end
                print(string.format("  %s %s %s%s",
                    C.reg(string.format("%-7s", name)),
                    C.dim("="),
                    C.addr(hex(c[name])),
                    annotation))
            end
        end
    elseif c.pc ~= nil then
        local arm_names = {"fp","lr","sp","pc"}
        if c.x then
            for i = 0, 28 do
                local val = c.x[i+1]
                print(string.format("  %s %s %s%s",
                    C.reg(string.format("x%-6d", i)),
                    C.dim("="),
                    C.addr(hex(val)),
                    _deref_annotation(val)))
            end
        end
        for _, name in ipairs(arm_names) do
            if c[name] then
                local annotation = ""
                if name ~= "cpsr" then annotation = _deref_annotation(c[name]) end
                print(string.format("  %s %s %s%s",
                    C.reg(string.format("%-7s", name)),
                    C.dim("="),
                    C.addr(hex(c[name])),
                    annotation))
            end
        end
        if c.cpsr then
            print(string.format("  %s %s %s",
                C.reg("cpsr   "), C.dim("="), C.addr(hex(c.cpsr))))
        end
    end
end

--- Disassemble instructions
--- disasm()          -- 10 instructions at rip
--- disasm(addr)      -- 10 instructions at addr
--- disasm(addr, n)   -- n instructions at addr
--- disasm(table)     -- print instruction table (from dbg:disassemble)
function disasm(addr_or_instrs, count)
    if type(addr_or_instrs) == "table" then
        for _, inst in ipairs(addr_or_instrs) do
            local sym = ""
            if inst.symbol then
                sym = C.comment(" ; " .. inst.symbol)
            end
            print(string.format("  %s  %s %s%s",
                C.addr(hex(inst.address)),
                C.mnem(string.format("%-8s", inst.mnemonic)),
                C.op(inst.operands or ""),
                sym))
        end
        return
    end

    local addr = addr_or_instrs
    if addr == nil then addr = rip end
    if not addr then
        print(C.err("(no address - use disasm(addr) or break first)"))
        return
    end
    if not pid then
        print(C.err("(no pid)"))
        return
    end
    local n = count or 10
    local instrs = dbg:disassemble(pid, addr, n)
    disasm(instrs)
end

--- Pretty-print a call stack
--- callstack()       -- current call stack
--- callstack(frames) -- given frames table
function callstack(frames)
    if frames == nil then
        if pid and tid then
            frames = dbg:get_call_stack(pid, tid)
        else
            print(C.err("(no pid/tid)"))
            return
        end
    end
    for i, frame in ipairs(frames) do
        local sym = frame.symbol and C.sym(frame.symbol) or ""
        print(string.format("  %s %s  %s",
            C.dim(string.format("#%-3d", i - 1)),
            C.addr(hex(frame.address)),
            sym))
    end
end

--- Pretty-print module list
--- modules()     -- list modules for current pid
--- modules(mods) -- print given module table
function modules(mods)
    if mods == nil then
        if pid then
            mods = dbg:list_modules(pid)
        else
            print(C.err("(no pid)"))
            return
        end
    end
    print(string.format("  %s  %s  %s",
        C.header(string.format("%-18s", "BASE")),
        C.header(string.format("%-12s", "SIZE")),
        C.header("NAME")))
    for _, m in ipairs(mods) do
        local size_str = m.size and string.format("0x%X", m.size) or "?"
        print(string.format("  %s  %-12s  %s",
            C.addr(string.format("%-18s", hex(m.base))),
            size_str,
            C.sym(m.name)))
    end
end

--- Dereference pointer chains at an address
--- deref()          -- dereference 8 values at rsp
--- deref(addr)      -- dereference 8 values at addr
--- deref(addr, n)   -- dereference n values at addr
function deref(addr, count)
    addr = addr or rsp
    if not addr then print(C.err("(no address)")); return end
    if not pid then print(C.err("(no pid)")); return end
    count = count or 8
    local entries = dbg:dereference(pid, addr, count)
    for _, entry in ipairs(entries) do
        local parts = {}
        for _, v in ipairs(entry.chain) do
            if v.type == "pointer" then
                local s = C.addr(hex(v.address))
                if v.symbol then s = s .. " " .. C.sym(v.symbol) end
                table.insert(parts, s)
            elseif v.type == "value" then
                table.insert(parts, C.val(hex(v.value)))
            elseif v.type == "string" then
                table.insert(parts, C.str(string.format("%q", v.value)))
            elseif v.type == "instruction" then
                local s = C.mnem(v.mnemonic)
                if v.symbol then s = s .. C.comment(" ; " .. v.symbol) end
                table.insert(parts, s)
            elseif v.type == "loop" then
                table.insert(parts, C.dim("-> loop " .. hex(v.address)))
            end
        end
        print(string.format("  %s  %s",
            C.addr(hex(entry.address)),
            table.concat(parts, C.arrow(" -> "))))
    end
end

--- Read memory as a string (wide) from the debuggee
--- str(addr)         -- read wide string at addr
--- str(addr, maxlen) -- read wide string with max length
function str(addr, maxlen)
    if not addr then print(C.err("(no address)")); return end
    if not pid then print(C.err("(no pid)")); return end
    return dbg:read_string(pid, addr, maxlen)
end

--- Search for a symbol by name
--- sym(name)      -- find symbol, return first match VA
--- sym(name, max) -- find up to max matches, print all
function sym(name, max)
    max = max or 10
    local syms = dbg:find_symbol(name, max)
    if #syms == 0 then
        print(C.err("(no matches)"))
        return nil
    end
    for _, s in ipairs(syms) do
        print(string.format("  %s  %s",
            C.addr(hex(s.va)),
            C.sym(s.module .. "!" .. s.name)))
    end
    return syms[1].va
end

--- Wait for a module's symbols to settle (loaded, exports_only or failed).
--- wait_symbols(pid, pattern)            -- 30s default timeout
--- wait_symbols(pid, pattern, timeout_s)
--- `pattern` is matched (Lua pattern, case-insensitive) against module paths.
--- Returns the module's status table ({module, base, state, symbol_count, error,
--- pdb_path}), or nil if no matching module settled before the timeout.
function wait_symbols(pid, pattern, timeout_s)
    -- os.time (wall clock), not os.clock (CPU time): this loop sleeps, so a
    -- CPU-time deadline is never reached and the timeout would not apply.
    local deadline = os.time() + (timeout_s or 30)
    repeat
        local found
        for _, s in ipairs(dbg:symbol_status(pid)) do
            if s.module:lower():find(pattern) then found = s end
        end
        if found and (found.state == "loaded" or found.state == "exports_only" or found.state == "failed") then
            return found
        end
        dbg:sleep(100)
    until os.time() >= deadline
    return nil
end

--- Set a breakpoint by symbol name or address
--- bp(addr_or_name)            -- set breakpoint, drop to REPL on hit
--- bp(addr_or_name, handler)   -- set breakpoint with Lua handler
function bp(addr_or_name, handler)
    if not pid then print(C.err("(no pid)")); return end
    if not handler then
        handler = function(p, t, a) dbg:repl() end
    end
    local addr = dbg:set_breakpoint(pid, addr_or_name, handler)
    local sym_str = dbg:resolve_address(pid, addr)
    local name = sym_str.name or hex(addr)
    print("Breakpoint set at " .. C.addr(hex(addr)) .. " (" .. C.sym(name) .. ")")
    return addr
end

--- Assemble instructions
--- asm("nop")              -- assemble at address 0
--- asm("mov eax, 1", addr) -- assemble at specific address
--- Returns table with .bytes, .hex, .count, .size
function asm(code, address)
    local result = dbg:assemble(code, address)
    print(string.format("  %s  %s",
        C.dim(string.format("%d bytes:", result.size)),
        C.addr(result.hex)))
    return result
end

--- Assemble and patch memory
--- patch(addr, "nop; nop; nop")       -- assemble and write to addr
--- patch("NtClose", "ret")            -- resolve symbol, assemble, write
function patch(addr_or_sym, code)
    if not pid then print(C.err("(no pid)")); return end
    local addr = addr_or_sym
    if type(addr_or_sym) == "string" and not code then
        print(C.err("(usage: patch(addr, code) or patch(\"symbol\", code))"))
        return
    end
    if type(addr_or_sym) == "string" then
        local syms = dbg:find_symbol(addr_or_sym, 1)
        if #syms == 0 then
            print(C.err("(symbol not found: " .. addr_or_sym .. ")"))
            return
        end
        addr = syms[1].va
    end
    local result = dbg:assemble_to(pid, addr, code)
    local sym_name = dbg:resolve_address(pid, addr)
    local name = sym_name.name or hex(addr)
    print(string.format("  Patched %s %s at %s",
        C.dim(string.format("%d bytes", result.size)),
        C.addr(hex(addr)),
        C.sym(name)))
    return result
end

--- Pretty-print memory regions
--- regions()     -- all regions for current pid
function regions()
    if not pid then print(C.err("(no pid)")); return end
    local regs = dbg:enumerate_regions(pid)
    print(string.format("  %s  %s  %s  %s  %s",
        C.header(string.format("%-18s", "BASE")),
        C.header(string.format("%-12s", "SIZE")),
        C.header(string.format("%-24s", "PROTECT")),
        C.header(string.format("%-12s", "STATE")),
        C.header("TYPE")))
    for _, r in ipairs(regs) do
        print(string.format("  %s  %-12s  %-24s  %-12s  %s",
            C.addr(string.format("%-18s", hex(r.base_address))),
            string.format("0x%X", r.region_size),
            mem_protect(r.protect),
            mem_state(r.state),
            mem_type(r.region_type)))
    end
end
