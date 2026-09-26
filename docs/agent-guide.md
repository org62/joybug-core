# Using jlua from an AI agent

This is the "start here" page for a model (or a person in a hurry) that has been pointed at
this repository and told to debug or analyse a Windows binary with it. It says what to
download, how to drive the tool without a terminal session, which surface to reach for, and
gives copy-paste recipes that were each run against the test programs in this repo. The full
API is in [`jlua-guide.md`](jlua-guide.md); the recipes link to the test scripts under
[`tests/lua/`](../tests/lua/) that exercise the same calls.

## 1. Get the binary

Everything is one portable executable, `jlua.exe`. No installer, no DLLs, nothing to configure.

| Host CPU | Permalink |
| --- | --- |
| x64 | https://github.com/org62/joybug-core/releases/latest/download/jlua-x64.exe |
| ARM64 | https://github.com/org62/joybug-core/releases/latest/download/jlua-aarch64.exe |

A `.sha256` sidecar sits next to each (`jlua-x64.exe.sha256`, `sha256sum` format).

```powershell
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x64' }
Invoke-WebRequest "https://github.com/org62/joybug-core/releases/latest/download/jlua-$arch.exe" -OutFile jlua.exe
.\jlua.exe --version
```

Pick the build for the **machine's** architecture, not the target's. A native 64-bit target
must match the host (an ARM64 jlua cannot debug an emulated x64 process, or vice versa);
32-bit x86 targets work on either host. Offline analysis (`pe`) of any architecture works on
any host.

## 2. Non-interactive contract

jlua has an interactive REPL, but an agent should never use it. Write a Lua script, run it,
read stdout:

```powershell
.\jlua.exe --no-color -s script.lua                              # script drives everything
.\jlua.exe --no-color --command "C:\target.exe arg" -s script.lua  # shortcut for dbg:launch
```

Rules that keep a run from hanging or lying:

- **Do not** pass `--repl-on-break` and do not call `dbg:repl()` from a script. Both wait
  for a human at a prompt; with no console they block forever.
- `print` goes to stdout. A Lua error exits with code 1 and the message on stderr. A script
  that ends normally exits 0.
- `dbg:run()` blocks until the debuggee **exits** (or is terminated). If the target does not
  exit on its own, end the run from a handler with `dbg:terminate(pid)`. Always wrap the
  jlua process in a timeout of your own.
- Handlers run to completion before the target resumes; a breakpoint handler that returns
  `"remove"` deletes the breakpoint, anything else keeps it.
- Symbols download from the Microsoft symbol server by default (`_NT_SYMBOL_PATH` is
  honoured; `--symbol-path` overrides it). Pass `--offline` to forbid downloads and get
  deterministic runs; names then come from a local cache, from PE exports, or from a PDB next
  to the binary. `wait_symbols(pid, "app%.exe")` blocks until a module's symbols settle.
- Output can be large (a coverage run returns thousands of rows). Aggregate in Lua and print
  what matters; page big tables with the `max_results` / `count` arguments the API offers.
- One `jlua` process = one debug session. Run scripts sequentially, not in parallel against
  the same target.

Pass parameters through environment variables (`os.getenv("TARGET")`); jlua does not forward
extra command-line arguments to the script.

## 3. Which surface

| Global | Use it when | Runs code? | Needs |
| --- | --- | --- | --- |
| `pe` | You have a file and want facts: headers, imports/exports, strings, disassembly, xrefs, function list, or to emulate one routine with chosen inputs | No (emulation only, in-process) | Nothing |
| `dbg` | You need real behaviour: breakpoints, API arguments, memory, registers, call stacks, coverage, watchpoints, value scans | Yes, on this machine | Debug privilege on the target |
| `sbx` | The target is untrusted and should run in a disposable VM, optionally with ETW recorded inside it | Yes, in Windows Sandbox | Win11 24H2+ with the Windows Sandbox feature, one VM per user |
| `etw` | You want a procmon-style file/registry/network/process trace of a process tree on the host | Yes, on this machine | Administrator (UAC prompt unless already elevated) |

Start with `pe` when the question can be answered statically; it is instant and has no side
effects. Use `dbg` on the same file when behaviour matters. Combine them: `pe` finds the
address, `dbg` breaks on it.

## 4. Recipes

Every recipe below was run with `jlua --no-color -s` against a test program from
[`tests/test_programs/`](../tests/test_programs/) (built by `cargo build`), with the target
path in `TARGET`. `hex`, `hexdump`, `regs`, `callstack`, `modules` are built-in helpers.

### 4.1 Static triage of a PE (no execution)

<!-- recipe: static_triage.lua -->
```lua
local img = pe.open(os.getenv("TARGET"))
print(img:module_name(), img:arch(), "base=" .. hex(img:base()), "entry=" .. hex(img:entry_point()),
      "size=" .. hex(img:size()), "symbols=" .. tostring(img:has_symbols()))
for _, s in ipairs(img:sections()) do
    print(string.format("  %-8s va=%s vsize=%s raw=%s", s.name, hex(s.va), hex(s.vsize), hex(s.rsize)))
end

local per_dll, imports = {}, img:imports()
for _, i in ipairs(imports) do per_dll[i.dll] = (per_dll[i.dll] or 0) + 1 end
for dll, n in pairs(per_dll) do print(string.format("  import %-40s %d", dll, n)) end

-- Who references an interesting import? (call/jmp through its IAT slot, or a load of the slot)
for _, imp in ipairs(imports) do
    if imp.name and imp.name:find("^GetCurrentProcess") then
        for _, x in ipairs(img:xrefs_to_import(imp.dll .. "!" .. imp.name)) do
            print(string.format("  %s!%s <- %s at %s", imp.dll, imp.name, x.kind,
                  img:resolve_address(x.from) or hex(x.from)))
        end
    end
end

for _, s in ipairs(img:strings{ min = 8, contains = "XTEA" }) do
    print(string.format("  string %s [%s] %s", hex(s.address), s.encoding, s.text))
end
print(#img:functions() .. " functions recovered")
```

Reference tests: [`tests/lua/pe/open_and_read.lua`](../tests/lua/pe/open_and_read.lua),
[`tests/lua/pe/xrefs.lua`](../tests/lua/pe/xrefs.lua).

### 4.2 Disassemble a function by name or address

<!-- recipe: static_disasm.lua -->
```lua
local img = pe.open(os.getenv("TARGET"))
local sym = img:find_symbol("xtea_encrypt")          -- needs a PDB; fall back to an address
local va = sym and sym.va or img:entry_point()
local fn = img:disassemble_function(va)               -- bounds from .pdata, or recovered
print((fn.name or "?") .. " " .. hex(fn.start) .. "-" .. hex(fn["end"] or 0) .. ", " .. #fn.instructions .. " instructions")
for i, ins in ipairs(fn.instructions) do
    if i > 12 then print("  ...") break end
    print(string.format("  %s  %-8s %s  %s", hex(ins.address), ins.mnemonic, ins.operands, ins.symbol or ""))
end
for _, x in ipairs(img:xrefs_to(va)) do            -- callers (a debug build calls via an @ILT thunk)
    print("  referenced by " .. x.kind .. " at " .. (img:resolve_address(x.from) or hex(x.from)))
end
```

Reference test: [`tests/lua/pe/disassembly.lua`](../tests/lua/pe/disassembly.lua).

### 4.3 Emulate a routine offline with chosen inputs

The file is mapped at its base with a synthetic stack; plant arguments, run to the return
sentinel, read results back. The file on disk is never touched.

<!-- recipe: static_emulate.lua -->
```lua
local img = pe.open(os.getenv("TARGET"))
local enc = img:find_symbol("xtea_encrypt")           -- void xtea_encrypt(uint32_t v[2], const uint32_t key[4])
local L = img:emu_layout()
local v, k = L.sp - 0x200, L.sp - 0x100                 -- scratch buffers on the synthetic stack
local regs = (img:arch() == "arm64") and { x0 = v, x1 = k } or { rcx = v, rdx = k }
local r = img:emulate(enc.va, {
    max = 20000,
    regs = regs,
    mem_writes = { { v, string.pack("<I4<I4", 0x12345678, 0x9ABCDEF0) },
                   { k, string.pack("<I4<I4<I4<I4", 0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE) } },
    mem_reads  = { { v, 8 } },
})
print("stop=" .. r.stop_reason, "pc=" .. hex(r.final_pc), "time_us=" .. r.time_us)
local c0, c1 = string.unpack("<I4<I4", r.memory_snapshots[1].data)
print(string.format("ciphertext %08x %08x", c0, c1))
-- imports = "stop" (default) halts at the first API call: r.import names it, r.return_address is the caller
```

Reference test: [`tests/lua/pe/emulate.lua`](../tests/lua/pe/emulate.lua).

### 4.4 Trace an API call with arguments and the call stack (live)

Exports resolve at the initial breakpoint, so a name works before any PDB loads. Break on the
DLL that actually **implements** the API: on modern Windows `kernel32!WriteFile` is only a
forwarder to `kernelbase!WriteFile`, and the CRT calls the KernelBase copy — a breakpoint on
the kernel32 entry never fires. When unsure, `dbg:find_symbol("WriteFile", 10)` shows which
modules export it. A plain breakpoint fires process-wide; to catch only calls a specific
module makes through its own import table, use
`dbg:set_breakpoint_import(pid, "kernelbase!WriteFile", ...)`.

<!-- recipe: live_api_trace.lua -->
```lua
local hits = 0
dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "kernelbase!WriteFile", function(pid, tid, addr)
        local a = dbg:get_arguments(pid, tid, 3)                 -- hFile, lpBuffer, nNumberOfBytesToWrite
        local data = dbg:read_memory(pid, a[2], math.min(a[3], 64))
        hits = hits + 1
        print(string.format("WriteFile(h=%s, %d bytes) %q", hex(a[1]), a[3], data))
        if hits == 1 then callstack(dbg:get_call_stack(pid, tid)) end
    end)
end)
dbg:on_process_exited(function(pid, code) print("exit code " .. code .. ", " .. hits .. " WriteFile calls") end)
dbg:launch(os.getenv("TARGET"))
dbg:run()
```

Reference test: [`tests/lua/breakpoints/breakpoint_handler.lua`](../tests/lua/breakpoints/breakpoint_handler.lua).

### 4.5 Break on a function in the target and dump its state

<!-- recipe: live_break_dump.lua -->
```lua
dbg:on_initial_breakpoint(function(pid, tid, addr)
    print("arch " .. dbg:arch(pid))
    modules(dbg:list_modules(pid))
    dbg:set_breakpoint(pid, "xtea_encrypt", function(pid, tid, addr)   -- symbol from the PDB next to the exe
        local ctx = dbg:get_context(pid, tid)
        regs(ctx)
        local a = dbg:get_arguments(pid, tid, 2)                      -- v[2], key[4]
        print("v   = " .. hexdump(dbg:read_memory(pid, a[1], 8), a[1]))
        print("key = " .. hexdump(dbg:read_memory(pid, a[2], 16), a[2]))
        callstack(dbg:get_call_stack(pid, tid))
        local sp = ctx.rsp or ctx.sp or ctx.esp
        print(hexdump(dbg:read_memory(pid, sp, 64), sp))
        disasm(dbg:disassemble(pid, addr, 6))
        dbg:terminate(pid)                                             -- seen enough: end the run
        return "remove"
    end)
end)
dbg:launch(os.getenv("TARGET"))
dbg:run()
```

Reference test: [`tests/lua/basics/launch_and_registers.lua`](../tests/lua/basics/launch_and_registers.lua).

### 4.6 Which functions of a module executed (coverage)

Silent server-side breakpoints on every function entry; the target runs freely.

<!-- recipe: live_coverage.lua -->
```lua
local target = os.getenv("TARGET")
local names = {}
dbg:on_initial_breakpoint(function(pid, tid, addr)
    local exe = target:match("([^\\/]+)$"):lower()
    local main_mod
    for _, m in ipairs(dbg:list_modules(pid)) do
        if m.name:lower():find(exe, 1, true) then main_mod = m.name end
    end
    local targets = dbg:enumerate_coverage_targets(main_mod, pid)      -- .pdata + validated symbols
    local addrs = {}
    for _, t in ipairs(targets) do addrs[#addrs + 1] = t.address; names[t.address] = t.symbol end
    dbg:start_coverage(pid, addrs, 1)                                    -- limit 1: count each once
    print(#addrs .. " functions armed in " .. main_mod)
end)
dbg:on_process_exited(function(pid, code)
    local hits = dbg:get_coverage(pid)
    table.sort(hits, function(a, b) return a.first_hit_seq < b.first_hit_seq end)
    print(#hits .. " executed, in first-hit order:")
    for i, h in ipairs(hits) do
        if i > 15 then print("  ...") break end
        print(string.format("  #%-3d %s  %s", h.first_hit_seq, hex(h.address), names[h.address] or ""))
    end
end)
dbg:launch(target)
dbg:run()
```

Reference test: [`tests/lua/breakpoints/code_coverage.lua`](../tests/lua/breakpoints/code_coverage.lua).

### 4.7 Instruction trace of a function (Tenet format) without disturbing the process

<!-- recipe: live_emulate_trace.lua -->
```lua
dbg:on_initial_breakpoint(function(pid, tid, addr)
    dbg:set_breakpoint(pid, "xtea_encrypt", function(pid, tid, addr)
        dbg:remove_breakpoint(pid, addr)                        -- the emulator must see original bytes
        local ctx = dbg:get_context(pid, tid)                   -- stop the trace when the function returns
        local ret = ctx.lr or dbg:read_u64(pid, ctx.rsp or ctx.sp)   -- return addr: lr (arm64) or [rsp]
        local r = dbg:emulate(pid, tid, 100000, "trace", ret)   -- real process state is unchanged
        local lines = select(2, r.trace:gsub("\n", "\n"))
        print("stop=" .. r.stop_reason .. ", " .. lines .. " trace lines, " .. r.time_us .. " us")
        local f = assert(io.open(os.getenv("TEMP") .. "\\xtea_encrypt.tenet", "w"))  -- load in Tenet
        f:write(r.trace); f:close()
        local blocks = dbg:emulate(pid, tid, 100000, "block", ret)   -- or just the basic blocks
        print(#blocks.basic_blocks .. " basic blocks")
        dbg:terminate(pid)
    end)
end)
dbg:launch(os.getenv("TARGET"))
dbg:run()
```

Reference tests: [`tests/lua/emulation/`](../tests/lua/emulation/).

### 4.8 Detonate in a sandbox and read the ETW trace

Run-only mode: no debugger in the guest, the guest exe is just the ETW collector. jlua stages
itself as the guest (`guest_bin_dir` is its own folder). Boot takes about a minute; only one
sandbox per user, so a crashed script leaves `sbx.stop_all()` as the fix.

<!-- recipe: sandbox_etw.lua -->
```lua
local s = sbx.status()
if not (s.supported and s.wsb_present) then print("no sandbox: " .. tostring(s.reason)) return end
local self_dir = os.getenv("JLUA_DIR")                       -- folder holding jlua.exe
local target = os.getenv("TARGET")                           -- the target's HOST path
local io_dir = os.getenv("TEMP") .. "\\joybug-sbx-" .. os.time()
local ok, h, info = pcall(sbx.provision, {
    guest_bin_dir = self_dir, guest_exe = "jlua.exe", io_dir = io_dir,
    -- Mount the folder holding the target; pass its HOST path as launch_command
    -- and provision rewrites it to the C:\mounts\<folder>\... path in the guest.
    mounts = { { host_path = target:match("^(.*)[\\/][^\\/]+$"), read_only = true } },
    launch_command = target,
    debug = false, collect_etw = true,
    etw = { ops = { "process.*", "file.create", "file.write", "network.connect" } },
})
if not ok then error(h) end
h:run_traced()                                              -- blocks until the whole process tree exits
local kinds = {}
for _, e in ipairs(sbx.events(info.io_dir, info.etw_out_file)) do
    kinds[e.kind .. "." .. e.op] = (kinds[e.kind .. "." .. e.op] or 0) + 1
    if e.kind == "file" or e.kind == "network" then print(e.time, e.kind .. "." .. e.op, e.pid, e.path or e.dest) end
end
for k, n in pairs(kinds) do print(string.format("%-24s %d", k, n)) end
h:stop()
```

To debug inside the VM instead, `jlua --sandbox --command "C:\mounts\dir\target.exe" --mount C:\dir -s script.lua`
runs the script with `dbg` already connected to the in-guest server.
Reference test: [`tests/lua/sandbox/etw_live.lua`](../tests/lua/sandbox/etw_live.lua).

## 5. Gotchas

- **Symbol timing.** At the initial breakpoint only ntdll/kernel32 exports are certain. The
  main module's PDB (next to the exe, or downloaded) may still be loading; `set_breakpoint`
  by name waits for it, `list_symbols` errors after a short wait. Call `wait_symbols(pid,
  "app%.exe", 120)` first for anything large, and read `dbg:symbol_status(pid)` when a name
  fails to resolve (`exports_only` means "no PDB, exports only").
- **32-bit targets.** `dbg:arch(pid)` returns `"x86"`; registers are `eax`/`eip`/`esp`,
  pointers 4 bytes, arguments on the stack (`get_arguments` handles it).
- **Import hooks vs API breakpoints.** `set_breakpoint(pid, "kernel32!CreateProcessW")` fires
  for every caller in the process, loader included. `set_breakpoint_import` hooks one
  module's IAT slot and is unambiguous under WOW64.
- **PEB normalization.** `dbg:normalize_peb(pid)` at the initial breakpoint restores the PEB
  fields Windows leaves in their "debugger attached" state (BeingDebugged, process-heap flags)
  so the target runs like a normally launched process — no debug-heap slowdown, and code that
  reads `IsDebuggerPresent` (crash reporters, exception handlers that would fire an `int3`) takes
  its normal path. Not evasion; it's about reproducing behavior as it happens without a debugger.
- **Handlers are Lua closures** — accumulate results in upvalues and print after `dbg:run()`
  returns, or print inside; both work.
- **Emulation stops at imports by default** (`ImportCall(...)`). Pass `imports = "skip"` with
  a `ret` to fake every API return, or stop there and inspect `r.import`.
- **Coverage writes `int3`s.** Only addresses that pass the code-sanity gate are armed
  (`enumerate_coverage_targets` does that); never arm raw symbol lists yourself.
- **Sandbox is one-per-user.** `sbx.list()` / `sbx.stop_all()` recover from an abandoned VM.
- **Elevation for host ETW.** `etw.start` / `etw.spawn` trigger a UAC prompt unless jlua is
  elevated; a cancelled prompt yields no error, only no events. Inside the sandbox no
  elevation is needed.

## 6. Full reference

- [`docs/jlua-guide.md`](jlua-guide.md) — every `dbg:*`, `pe`, `sbx`, `etw` call with
  argument and return shapes. Raw:
  `https://raw.githubusercontent.com/org62/joybug-core/main/docs/jlua-guide.md`
- [`tests/lua/`](../tests/lua/) — executable examples, grouped by topic, run in CI.
- [`src/protocol.rs`](../src/protocol.rs) — the framed-JSON wire protocol, for a client in
  another language (`jlua --listen 127.0.0.1:9000` is the server).
- [`docs/TENET_TRACE_FORMAT.md`](TENET_TRACE_FORMAT.md) — the trace text produced by
  `dbg:trace` / `dbg:emulate(..., "trace")`.
