# jlua — Joybug2 Lua Scripting Debugger

`jlua` is an interactive Lua scripting interface for the joybug2 debugger. It lets you automate debugging tasks, set scripted breakpoints, inspect memory and registers, and interactively explore a paused process — all from Lua.

## Quick Start

```bash
# Interactive REPL — break at every debug event
jlua --command "myprogram.exe" --repl-on-break

# Run a Lua script
jlua --script trace_api.lua

# Launch and debug with a script
jlua --command "myprogram.exe arg1 arg2" --script setup.lua
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-s, --script <FILE>` | Lua script file to execute |
| `-c, --command <CMD>` | Launch a target program for debugging |
| `--server <ADDR>` | Connect to a remote joybug2 server (default: start local) |
| `--repl-on-break` | Drop into interactive REPL on any breakpoint/exception |
| `<SCRIPT>` | Positional script file (same as `--script`) |

## Interactive REPL

When paused at a breakpoint, you get an interactive prompt:

```
Initial breakpoint at 0x7FF8CDCACBC4 (pid=1234, tid=5678)
Paused. Type 'go' to continue, 'quit' to exit.
break 1234:5678 0x7FF8CDCACBC4> regs(dbg:get_context())
  rax     = 0x0
  rbx     = 0x7FF8CDD0C760
  ...
break 1234:5678 0x7FF8CDCACBC4> modules(dbg:list_modules(dbg:pid()))
  BASE                SIZE          NAME
  0x7FF8CDBD0000      0x218000      ntdll.dll
  ...
break 1234:5678 0x7FF8CDCACBC4> go
```

### REPL Commands

| Command | Action |
|---------|--------|
| `go` / `g` / `continue` / `c` | Resume execution |
| `si` / `step_into` | Step one instruction (into calls) |
| `so` / `step_over` | Step one instruction (over calls) |
| `sout` / `step_out` | Step out of current function |
| `quit` / `exit` | Terminate debuggee and exit |
| *anything else* | Evaluated as Lua expression/statement |

## Debugger API (`dbg`)

### Process Control

```lua
dbg:launch("program.exe arg1 arg2")   -- Launch a process
dbg:launch("program.exe", true)        -- Launch with child-process debugging
dbg:launch("program.exe", false, "C:\\work")  -- Launch in a specific working directory
dbg:attach(pid)                        -- Attach to a running process
dbg:run()                              -- Enter the event loop (processes events until exit)
dbg:terminate(pid)                     -- Terminate the debuggee
dbg:detach(pid)                        -- Detach from the process
```

### Current State

When paused at a breakpoint, `pid`/`tid` parameters are optional — they default to the current stopped thread:

```lua
dbg:pid()                              -- Current process ID
dbg:tid()                              -- Current thread ID
dbg:address()                          -- Current stopped address
```

### Event Handlers

Register Lua functions that are called when debug events occur. Set these **before** `dbg:run()`:

```lua
dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Called once when the process first stops (loader breakpoint)
end)

dbg:on_dll_loaded(function(pid, tid, name, base)
    print("Loaded: " .. name .. " at " .. hex(base))
end)

dbg:on_exception(function(pid, tid, code, addr, first_chance)
    -- Return "stop" to drop into REPL, "pass" to pass to app, nil to handle
    return "stop"
end)

dbg:on_process_exited(function(pid, exit_code)
    print("Process exited: " .. exit_code)
end)

dbg:on_process_created(function(pid, tid, name, base) end)
dbg:on_thread_created(function(pid, tid, start_addr) end)
dbg:on_thread_exited(function(pid, tid, exit_code) end)
dbg:on_dll_unloaded(function(pid, tid, base) end)
```

### Breakpoints

```lua
-- Set by address
dbg:set_breakpoint(pid, 0x7FF612340000, function(pid, tid, addr)
    print("Hit breakpoint at " .. hex(addr))
    -- Return "remove" to auto-remove, or nil/nothing to keep
end)

-- Set by symbol name (auto-resolves address)
dbg:set_breakpoint(pid, "CreateFileW", function(pid, tid, addr)
    local args = dbg:get_arguments(pid, tid, 2)
    local filename = dbg:read_string(pid, args[1])
    print("CreateFileW(" .. filename .. ")")
end)

-- Remove a breakpoint
dbg:remove_breakpoint(pid, addr)
```

### Hardware Breakpoints

```lua
-- Types: "execute"/"x", "write"/"w", "readwrite"/"rw"
-- Sizes: "1", "2", "4", "8"
dbg:set_hw_breakpoint(pid, addr, "write", "4", function(pid, tid, addr)
    print("Write to " .. hex(addr))
end)

dbg:remove_hw_breakpoint(pid, addr)
```

### Stepping

```lua
local new_addr = dbg:step_into()       -- Step one instruction into calls
local new_addr = dbg:step_over()       -- Step one instruction over calls
local new_addr = dbg:step_out()        -- Step out of the current function

-- Explicit pid/tid:
dbg:step_into(pid, tid)

-- Source-line stepping: single-steps until the PC leaves the current source
-- line (needs PDB line info; degrades to a single step without it).
local new_addr = dbg:step_line("over")  -- Step over one source line (default)
local new_addr = dbg:step_line("into")  -- Step into one source line
```

### Registers

```lua
local ctx = dbg:get_context()          -- Uses current pid/tid
local ctx = dbg:get_context(pid, tid)  -- Explicit

-- x64 registers: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,
--                r8-r15, rip, rflags
print(hex(ctx.rip))
print(hex(ctx.rsp))

-- Modify registers
ctx.rax = 0x42
dbg:set_context(pid, tid, ctx)
```

### Memory

```lua
-- Read raw bytes (returns Lua binary string)
local data = dbg:read_memory(pid, addr, size)

-- Convenience readers
local val = dbg:read_u8(pid, addr)
local val = dbg:read_u16(pid, addr)
local val = dbg:read_u32(pid, addr)
local val = dbg:read_u64(pid, addr)

-- Read a wide (UTF-16) string
local str = dbg:read_string(pid, addr)

-- Write memory
dbg:write_memory(pid, addr, "\x90\x90\x90")  -- Write NOPs

-- Search for a byte pattern in process memory
local addrs, capped = dbg:search_memory(pid, "PATTERN", 100)

-- Value freeze (Cheat-Engine style "lock"): a server-side thread continuously
-- writes the given bytes to `addr` until unfrozen, so the value stays put even
-- while the target runs. Returns a freeze id.
local freeze_id = dbg:freeze_value(pid, addr, "\xDD\xCC\xBB\xAA")  -- optional 4th arg: interval_ms
dbg:update_freeze_value(freeze_id, "\x01\x00\x00\x00")            -- change the frozen value
dbg:unfreeze_value(freeze_id)                                     -- stop freezing

-- Pointer-chain freeze: pass an offsets list as the 5th arg. `addr` is then the
-- static base and the freeze re-resolves `base -> offsets` every tick, so the lock
-- follows the value when the chain repoints (e.g. a level reload).
local fid = dbg:freeze_value(pid, base, "\xDD\xCC\xBB\xAA", nil, { 0x10, 0x8 })

-- Pause the script (milliseconds), e.g. to let a freeze thread tick
dbg:sleep(100)
```

### Symbols

```lua
-- Find symbols by name (across all modules)
local syms = dbg:find_symbol("CreateFileW", 10)
for _, s in ipairs(syms) do
    print(s.name, s.module, hex(s.va))
end

-- Resolve an address to its symbol
local info = dbg:resolve_address(pid, addr)
print(info.name, info.module, info.offset)

-- Per-module symbol load status. Each entry:
-- {module, base, state = "loaded"|"loading"|"failed"|"not_requested",
--  symbol_count?, error?, pdb_path?}
for _, s in ipairs(dbg:symbol_status(pid)) do
    print(s.module, s.state, s.symbol_count or "", s.error or "")
end

-- Load symbols from a user-supplied PDB file.
-- Returns {loaded=true, symbol_count=N}, or when the PDB's GUID/age doesn't
-- match the module: {loaded=false, mismatch={pe_guid, pe_age, pdb_guid, pdb_age}}
local r = dbg:load_pdb(pid, module_base, "C:\\syms\\app.pdb")
if not r.loaded then
    -- pass force=true to load a mismatched PDB anyway
    r = dbg:load_pdb(pid, module_base, "C:\\syms\\app.pdb", true)
end

-- Retry a failed symbol download for a module
dbg:retry_symbols(pid, module_base)
```

### Source Lines (PDB line tables)

The module's PDB line table is parsed lazily on the first source-line request
and cached; while the module's symbols are still downloading these return nil
or empty results rather than blocking.

```lua
-- Resolve an address to a source file/line. Returns nil when no line info
-- covers the address. checksum_kind is "md5"|"sha1"|"sha256"|"none".
local line = dbg:resolve_line(pid, addr)
if line then
    print(line.file .. ":" .. line.line, line.module, hex(line.rva))
end

-- All line->address entries for one source file of a module,
-- sorted by line. Each entry: {rva, length, line, line_end}
for _, e in ipairs(dbg:line_map(pid, module_base, line.file)) do
    print(e.line, hex(e.rva))
end

-- All source files referenced by a module's PDB.
-- Each entry: {path, checksum_kind, checksum}
for _, f in ipairs(dbg:source_files(pid, module_base)) do
    print(f.path)
end
```

### Disassembly

```lua
-- Disassemble N instructions from an address
local instrs = dbg:disassemble(pid, addr, 10)
for _, i in ipairs(instrs) do
    print(hex(i.address), i.mnemonic, i.operands, i.symbol or "")
end

-- Disassemble an entire function
local func = dbg:disassemble_function(pid, addr)
print("Function: " .. (func.name or "unknown"))
disasm(func.instructions)
```

### Call Stack

```lua
local frames = dbg:get_call_stack()    -- Uses current pid/tid
for i, f in ipairs(frames) do
    print(string.format("#%d  %s  %s", i-1, hex(f.address), f.symbol or ""))
end
```

### Module / Thread / Process Info

```lua
local mods = dbg:list_modules(pid)
local threads = dbg:list_threads(pid)
local procs = dbg:list_processes()

-- Module PE info (entry point, sections, etc.)
local info = dbg:get_module_info(pid, module_base)
print("Entry point: " .. hex(info.entry_point))
for _, s in ipairs(info.sections) do
    print(s.name, hex(s.virtual_address), hex(s.virtual_size))
end
```

### Memory Regions

```lua
-- Query a single address
local region = dbg:query_memory(pid, addr)
print(hex(region.base_address), hex(region.region_size), hex(region.protect))

-- Enumerate all committed regions
local regions = dbg:enumerate_regions(pid)
```

### Pointer Dereferencing

```lua
-- Follow pointer chains (useful for examining stack values)
local entries = dbg:dereference(pid, addr, 8)  -- 8 consecutive pointers
```

### Function Arguments

```lua
-- Read the first N calling-convention arguments
local args = dbg:get_arguments(pid, tid, 4)
-- args[1] = rcx, args[2] = rdx, args[3] = r8, args[4] = r9 (x64)
```

### Tracing & Emulation

Two ways to produce a [Tenet](https://github.com/gaasedelen/tenet)-compatible execution trace:

**Trap-flag trace** — single-steps the real CPU. The process state advances (registers/memory change). Accurate but slower and has side-effects.

```lua
local r = dbg:trace(pid, tid, 1000)                -- max 1000 instructions
local r = dbg:trace(pid, tid, nil, 0x1400010FF)    -- trace until address
```

**Emulator trace** — runs in the Unicorn CPU emulator. The real process state is unchanged, so you can peek ahead without side-effects. Faster for large traces.

```lua
local r = dbg:emulate(pid, tid, 1000, "trace")                -- max 1000 instructions
local r = dbg:emulate(pid, tid, 1000, "trace", 0x1400010FF)   -- stop at address
```

Both return a table with:

| Field | Description |
|-------|-------------|
| `r.trace` | Tenet-format trace text (one line per instruction) |
| `r.stop_reason` | Why tracing stopped (e.g. "instruction limit", "reached address") |
| `r.time_us` | Execution time in microseconds |

Save to a file for use with the Tenet IDA/Binja plugin:

```lua
local r = dbg:trace(pid, tid, 10000)
local f = io.open("trace.tenet", "w")
f:write(r.trace)
f:close()
```

**Other emulation modes** — `dbg:emulate` supports modes beyond trace generation:

| Mode | Description | Key return fields |
|------|-------------|-------------------|
| `"basic"` | Run and return final state | `final_pc`, `instructions_executed` |
| `"trace"` | Tenet instruction trace | `trace` (text) |
| `"block"` | Record basic block addresses | `basic_blocks` (address list), `instructions_executed` |
| `"module"` | Track module transitions | `trace` (text) |
| `"syscall"` | Stop on syscall instructions | `trace` (text) |

```lua
-- Basic emulation: run 1000 instructions, get final PC
local r = dbg:emulate(pid, tid, 1000, "basic")
print("Stopped at " .. hex(r.final_pc) .. " after " .. r.instructions_executed .. " instructions")

-- Basic block trace: get list of executed block entry addresses
local r = dbg:emulate(pid, tid, 5000, "block")
for _, addr in ipairs(r.basic_blocks) do print(hex(addr)) end
```

### Memory Scanning (Cheat-Engine style)

```lua
-- Initial scan: find all u32 values equal to 100
local scan = dbg:scan_start(pid, "u32", "exact", "100")
print("Found: " .. scan.match_count)

-- Refine: value changed
local scan2 = dbg:scan_next(scan.scan_id, "changed")
print("Narrowed to: " .. scan2.match_count)

-- Get results
local results = dbg:scan_results(scan.scan_id)
for _, addr in ipairs(results.addresses) do
    print(hex(addr))
end

-- Reset to start over
dbg:scan_reset(scan.scan_id)
```

### Pointer Scanning (Cheat-Engine style)

Find chains of pointers that start at a *static* module base and resolve to a
dynamic `target` address — useful for building stable pointers that survive
restarts/relocation.

Results are streamed to a fixed-record file on the server (no in-RAM cap, millions
of paths possible) and identified by its **path**, not a scan id. The server keeps
no per-connection state for it, so the path can be persisted and reused after a full
restart — `ptr_scan_results`/`ptr_scan_rescan` re-base each path through the
*current* module list (by `module_index`), handling ASLR.

```lua
-- target = a dynamic address (e.g. from a value scan)
local res = dbg:ptr_scan_start(pid, target, 0x1000, 5) -- max_offset, max_depth (optional)
print("Paths found: " .. res.match_count)
-- res.results_path is the on-disk results file; persist it to survive a restart.

local got = dbg:ptr_scan_results(pid, res.results_path, 0, 100) -- pid, path, offset, count (optional)
for _, p in ipairs(got.paths) do
    -- Resolve as: addr = p.module_base + p.base_offset
    --             for each off in p.offsets: addr = read_u64(addr) + off  (== p.resolved)
    local s = string.format("module[%d]+0x%x", p.module_index, p.base_offset)
    for _, off in ipairs(p.offsets) do s = s .. string.format(" -> +0x%x", off) end
    print(s .. string.format("  => 0x%x", p.resolved))
end

-- Quick offset filter: page only the paths whose offsets contain ALL listed
-- values (order-independent); total_count is the match count over the whole file.
local hits = dbg:ptr_scan_results(pid, res.results_path, 0, 100, { 0x10, 0x8 })

-- Commit that filter: write a new file with only the matches (old file deleted).
local kept = dbg:ptr_scan_apply_filter(res.results_path, { 0x10, 0x8 })
print("kept " .. kept.match_count .. " paths -> " .. kept.results_path)

-- Re-resolve and keep only paths that still hit target; returns a NEW file path.
local re = dbg:ptr_scan_rescan(pid, kept.results_path, target)
dbg:ptr_scan_reset(re.results_path)
```

### Anti-Anti-Debug

Defeat common anti-debug probes by patching well-known fields in the target's PEB.
Apply once on the initial breakpoint — the kernel doesn't re-write these fields, so
a single hide is enough for static checks.

```lua
-- Enable every technique (BeingDebugged, NtGlobalFlag, primary HEAP flags,
-- RTL_USER_PROCESS_PARAMETERS window fields, spoof OSBuildNumber=19045).
local report = dbg:hide_peb(pid)                    -- nil opts ≡ { all = true }
local report = dbg:hide_peb(pid, { all = true })

-- Or pick specific techniques (missing keys = false).
local report = dbg:hide_peb(pid, {
    being_debugged  = true,
    nt_global_flag  = true,
    heap_flags      = true,
    startup_info    = false,
    os_build_number = false,
})

-- Report shape:
--   report.peb_address    -- u64, target's PEB base (0 if WOW64 was skipped)
--   report.applied        -- list of technique names that were written
--   report.failures       -- list of { technique = "...", error = "..." }
--   report.wow64_skipped  -- true if the target is a 32-bit WOW64 process
```

WOW64 (32-bit on 64-bit Windows) targets are detected and skipped — the offsets in
this module target the 64-bit native PEB layout. Returns `wow64_skipped = true`
with no writes performed.

### Drop into REPL

From a handler, call `dbg:repl()` to pause and drop into an interactive REPL:

```lua
dbg:set_breakpoint(pid, "main", function(pid, tid, addr)
    print("Hit main!")
    dbg:repl()  -- interactive debugging here
end)
```

Or set `--repl-on-break` from the command line to auto-REPL on every unhandled breakpoint.

## Built-in Lua Helpers

These functions are available globally:

| Function | Description |
|----------|-------------|
| `hex(n)` | Format number as `0x...` hex string |
| `hexdump(data, base)` | Classic hex dump of binary data |
| `u8(data, offset)` | Read little-endian u8 from binary string (1-based offset) |
| `u16(data, offset)` | Read little-endian u16 |
| `u32(data, offset)` | Read little-endian u32 |
| `u64(data, offset)` | Read little-endian u64 |
| `regs(ctx)` | Pretty-print a register context table |
| `disasm(instrs)` | Pretty-print a list of instructions |
| `callstack(frames)` | Pretty-print a call stack |
| `modules(mods)` | Pretty-print a module list |
| `wait_symbols(pid, pattern, [timeout_s=30])` | Wait until symbols for the first module matching `pattern` settle (`loaded`/`failed`); returns its status table, or nil on timeout |

## Example Scripts

### API Call Tracing

```lua
-- Trace file operations
dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "CreateFileW", function(pid, tid, addr)
        local args = dbg:get_arguments(pid, tid, 2)
        local filename = dbg:read_string(pid, args[1])
        print(string.format("CreateFileW(%q, 0x%X)", filename, args[2]))
        local frames = dbg:get_call_stack(pid, tid)
        callstack(frames)
    end)
end)

dbg:launch("target.exe")
dbg:run()
```

### Memory Dump at Breakpoint

```lua
dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "main", function(pid, tid, addr)
        local ctx = dbg:get_context(pid, tid)
        -- Dump 256 bytes of stack
        local stack = dbg:read_memory(pid, ctx.rsp, 256)
        print("Stack at " .. hex(ctx.rsp) .. ":")
        print(hexdump(stack, ctx.rsp))
        dbg:repl()
    end)
end)

dbg:launch("target.exe")
dbg:run()
```

### Find and Patch Code

```lua
dbg:on_initial_breakpoint(function(pid, tid, addr)
    -- Find the check function
    local syms = dbg:find_symbol("is_licensed", 1)
    if #syms > 0 then
        local func_addr = syms[1].va
        -- Patch to always return 1: mov eax, 1; ret
        dbg:write_memory(pid, func_addr, "\xB8\x01\x00\x00\x00\xC3")
        print("Patched is_licensed at " .. hex(func_addr))
    end
end)

dbg:launch("target.exe")
dbg:run()
```

### Tenet Trace at a Function

```lua
dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "xtea_encrypt", function(pid, tid, addr)
        -- Remove BP so emulator sees original bytes
        dbg:remove_breakpoint(pid, addr)

        -- Emulator trace: real process state unchanged
        local r = dbg:emulate(pid, tid, 50000, "trace")
        local f = io.open("xtea_encrypt.tenet", "w")
        f:write(r.trace)
        f:close()
        print("Saved trace: " .. r.stop_reason .. " (" .. r.time_us .. " us)")

        return "remove"
    end)
end)

dbg:launch("xtea_test.exe")
dbg:run()
```

### Conditional Breakpoint

```lua
dbg:on_initial_breakpoint(function(pid, tid, addr)
    local count = 0
    dbg:set_breakpoint(pid, "process_request", function(pid, tid, addr)
        count = count + 1
        local args = dbg:get_arguments(pid, tid, 1)
        -- Only break when first argument > 1000
        if args[1] > 1000 then
            print(string.format("Hit #%d: arg=%d", count, args[1]))
            dbg:repl()
        end
    end)
end)

dbg:launch("server.exe")
dbg:run()
```

### In-Process Inline Hooks

Hook functions in the current process with Lua callbacks. The hook uses inline code patching (no INT3/exceptions) for fast interception.

```lua
-- Hook a function at a known address.
-- The callback receives a context table with all x64 registers.
local info = dbg:hook(address, function(ctx)
    -- Read arguments (Windows x64 fastcall: rcx, rdx, r8, r9)
    print("arg1:", hex(ctx.rcx))
    print("arg2:", hex(ctx.rdx))

    -- Modify arguments before the original function runs
    ctx.rcx = ctx.rcx * 2
end)
-- info.id         = hook ID
-- info.trampoline = address of the original function trampoline
-- info.address    = hooked address

-- Remove the hook, restoring the original function
dbg:unhook(address)
```

**Context fields:** `rax`, `rcx`, `rdx`, `rbx`, `rbp`, `rsi`, `rdi`, `r8`–`r15`, `rflags`

The original function always executes after the callback returns (via trampoline). To skip the original, modify `ctx` to adjust control flow.

### In-Process Memory Access (`mem`)

The `mem` table provides direct memory read/write for the current process. Available everywhere (hooks, scripts, REPL).

```lua
-- Read typed values
local val  = mem.read_u8(addr)
local val  = mem.read_u16(addr)
local val  = mem.read_u32(addr)
local ptr  = mem.read_u64(addr)

-- Read raw bytes (returns Lua string)
local data = mem.read(addr, 64)

-- Read strings
local s  = mem.read_str(addr)            -- null-terminated ASCII/UTF-8
local ws = mem.read_wstr(addr)           -- null-terminated UTF-16 (Windows wide string)
local s  = mem.read_str(addr, 256)       -- with max length

-- Write typed values
mem.write_u8(addr, 0x90)
mem.write_u16(addr, val)
mem.write_u32(addr, val)
mem.write_u64(addr, val)

-- Write raw bytes
mem.write(addr, "\x90\x90\x90")
mem.write(addr, data)
```

#### Hook + Memory Example: Logging CreateFileW

```lua
dbg:hook(CreateFileW_addr, function(ctx)
    -- RCX = LPCWSTR lpFileName (first arg, wide string pointer)
    local filename = mem.read_wstr(ctx.rcx)
    print("CreateFileW:", filename)

    -- Read the second argument (dwDesiredAccess) from RDX
    print("  access:", hex(ctx.rdx))
end)
```
