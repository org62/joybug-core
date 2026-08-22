#![cfg(windows)]

mod common;

use common::TestServer;
use joybug_core::scripting;
use joybug_core::scripting::bindings::LuaDebugClient;
use joybug_core::scripting::debug_client::DebugClient;

/// Helper: create a Lua state connected to a test server, with `dbg` global registered.
fn setup_lua_with_server(server: &TestServer) -> mlua::Lua {
    let lua = scripting::create_lua().expect("create lua");
    let client = DebugClient::connect(server.address()).expect("connect");
    let lua_client = LuaDebugClient::new(client);
    lua.globals()
        .set("dbg", lua.create_userdata(lua_client).unwrap())
        .unwrap();
    set_arch_global(&lua);
    lua
}

/// Inject an `ARCH` global ("x86_64" or "aarch64") plus `ipof(ctx)`/`spof(ctx)`
/// helpers so Lua test scripts can stay arch-neutral (the instruction/stack
/// pointer is rip/rsp on x86 and pc/sp on AArch64).
fn set_arch_global(lua: &mlua::Lua) {
    #[cfg(target_arch = "x86_64")]
    lua.globals().set("ARCH", "x86_64").unwrap();
    #[cfg(target_arch = "aarch64")]
    lua.globals().set("ARCH", "aarch64").unwrap();
    lua.load(
        r#"
        function ipof(ctx) if ARCH == 'aarch64' then return ctx.pc else return ctx.rip end end
        function spof(ctx) if ARCH == 'aarch64' then return ctx.sp else return ctx.rsp end end
        "#,
    )
    .exec()
    .unwrap();
}

/// Helper: run a Lua test script from a file path.
/// If `test_exe` is provided, it's injected as the global `TEST_EXE`.
fn run_lua_test_file(lua_path: &str, test_exe: Option<&str>) {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    if let Some(exe) = test_exe {
        lua.globals().set("TEST_EXE", exe).unwrap();
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let full_path = format!("{}\\tests\\lua\\{}", manifest_dir, lua_path);
    let script = std::fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", full_path, e));

    let result: mlua::Value = lua.load(&script).set_name(&full_path).eval()
        .unwrap_or_else(|e| panic!("Lua test {} failed: {}", lua_path, e));

    // Verify the script returned { passed = true }
    if let mlua::Value::Table(t) = result {
        let passed: bool = t.get("passed").unwrap_or(false);
        assert!(passed, "Lua test {} did not return passed=true", lua_path);
    }
}

/// Helper: run a Lua test that only needs the helpers (no server connection).
fn run_lua_test_file_no_server(lua_path: &str) {
    let lua = scripting::create_lua().expect("create lua");
    set_arch_global(&lua);

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let full_path = format!("{}\\tests\\lua\\{}", manifest_dir, lua_path);
    let script = std::fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", full_path, e));

    let result: mlua::Value = lua.load(&script).set_name(&full_path).eval()
        .unwrap_or_else(|e| panic!("Lua test {} failed: {}", lua_path, e));

    if let mlua::Value::Table(t) = result {
        let passed: bool = t.get("passed").unwrap_or(false);
        assert!(passed, "Lua test {} did not return passed=true", lua_path);
    }
}

// ---------------------------------------------------------------------------
// 1. Lua helper library
// ---------------------------------------------------------------------------

#[test]
fn test_lua_helpers() {
    let lua = scripting::create_lua().expect("create lua");

    // hex() formatting
    let result: String = lua.load(r#"return hex(0xDEADBEEF)"#).eval().unwrap();
    assert_eq!(result, "0xDEADBEEF");

    let result: String = lua.load(r#"return hex(255)"#).eval().unwrap();
    assert_eq!(result, "0xFF");

    let result: String = lua.load(r#"return hex(0)"#).eval().unwrap();
    assert_eq!(result, "0x0");

    // u8/u16/u32/u64 readers on binary data
    let result: i64 = lua.load(r#"return u8("\x42")"#).eval().unwrap();
    assert_eq!(result, 0x42);

    let result: i64 = lua.load(r#"return u16("\x01\x02")"#).eval().unwrap();
    assert_eq!(result, 0x0201); // little-endian

    let result: i64 = lua.load(r#"return u32("\x01\x02\x03\x04")"#).eval().unwrap();
    assert_eq!(result, 0x04030201);

    // hexdump produces expected format
    let result: String = lua.load(r#"return hexdump("\x41\x42\x43\x44", 0x1000)"#).eval().unwrap();
    assert!(result.contains("0000000000001000"), "hexdump should show base address");
    assert!(result.contains("41 42 43 44"), "hexdump should show hex bytes");
    assert!(result.contains("ABCD"), "hexdump should show ASCII");
}

// ---------------------------------------------------------------------------
// 2. Launch process, hit initial breakpoint, read registers
// ---------------------------------------------------------------------------

#[test]
fn test_script_launch_and_registers() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    // Script: launch cmd.exe, read registers at initial breakpoint, terminate
    let script = r#"
        local result = {}

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            result.pid = pid
            result.tid = tid
            result.addr = addr

            local ctx = dbg:get_context(pid, tid)
            result.has_rip = (ipof(ctx) ~= nil)
            result.has_rsp = (spof(ctx) ~= nil)
            result.rip = ipof(ctx)
            result.rsp = spof(ctx)

            dbg:terminate(pid)
        end)

        dbg:launch('cmd.exe /c "echo test"')
        dbg:run()
        return result
    "#;

    let result: mlua::Table = lua.load(script).eval().unwrap();

    let pid: u32 = result.get("pid").unwrap();
    let tid: u32 = result.get("tid").unwrap();
    let addr: u64 = result.get("addr").unwrap();
    let has_rip: bool = result.get("has_rip").unwrap();
    let has_rsp: bool = result.get("has_rsp").unwrap();
    let rip: u64 = result.get("rip").unwrap();
    let rsp: u64 = result.get("rsp").unwrap();

    assert!(pid > 0, "pid should be nonzero");
    assert!(tid > 0, "tid should be nonzero");
    assert!(addr > 0, "initial breakpoint address should be nonzero");
    assert!(has_rip, "context should have rip");
    assert!(has_rsp, "context should have rsp");
    assert!(rip > 0, "rip should be nonzero");
    assert!(rsp > 0, "rsp should be nonzero");
}

// ---------------------------------------------------------------------------
// 3. List modules and find symbols
// ---------------------------------------------------------------------------

#[test]
fn test_script_modules_and_symbols() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    let script = r#"
        local result = {}

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            -- List modules
            local mods = dbg:list_modules(pid)
            result.module_count = #mods

            -- Check that ntdll is loaded
            result.has_ntdll = false
            for _, m in ipairs(mods) do
                if m.name:lower():find("ntdll") then
                    result.has_ntdll = true
                    result.ntdll_base = m.base
                end
            end

            -- Find a well-known symbol
            local syms = dbg:find_symbol("LdrLoadDll", 5)
            result.symbol_count = #syms
            if #syms > 0 then
                result.symbol_name = syms[1].name
                result.symbol_va = syms[1].va
            end

            -- Resolve the initial breakpoint address
            local ok, resolved = pcall(function() return dbg:resolve_address(pid, addr) end)
            if ok and resolved and resolved.name then
                result.resolved_name = resolved.name
            else
                result.resolved_name = "unknown"
            end

            dbg:terminate(pid)
        end)

        dbg:launch('cmd.exe /c "echo test"')
        dbg:run()
        return result
    "#;

    let result: mlua::Table = lua.load(script).eval().unwrap();

    let module_count: i64 = result.get("module_count").unwrap();
    assert!(module_count >= 3, "should have at least ntdll, kernel32, kernelbase: got {}", module_count);

    let has_ntdll: bool = result.get("has_ntdll").unwrap();
    assert!(has_ntdll, "ntdll should be loaded");

    let ntdll_base: u64 = result.get("ntdll_base").unwrap();
    assert!(ntdll_base > 0, "ntdll base should be nonzero");

    let symbol_count: i64 = result.get("symbol_count").unwrap();
    assert!(symbol_count > 0, "should find NtClose symbol");

    let symbol_name: String = result.get("symbol_name").unwrap();
    assert!(symbol_name.contains("LdrLoadDll"), "symbol name should contain LdrLoadDll, got: {}", symbol_name);

    let resolved_name: String = result.get("resolved_name").unwrap();
    // Initial breakpoint resolves to LdrpDoDebuggerBreak or similar
    assert!(!resolved_name.is_empty(), "resolved name should be non-empty, got: {}", resolved_name);
}

// ---------------------------------------------------------------------------
// 4. Memory read/write
// ---------------------------------------------------------------------------

#[test]
fn test_script_memory_operations() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    let script = r#"
        local result = {}

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            -- Read the breakpoint instruction. x86: int3 = 0xCC. AArch64: BRK
            -- #0xF000 = 0xD43E0000 (little-endian first byte 0x00).
            local data = dbg:read_memory(pid, addr, 16)
            result.memory_size = #data
            if ARCH == 'aarch64' then
                local b0, b1, b2, b3 = string.byte(data, 1, 4)
                result.bp_ok = (b0 + b1 * 0x100 + b2 * 0x10000 + b3 * 0x1000000) == 0xD43E0000
            else
                local byte = dbg:read_u8(pid, addr)
                result.bp_ok = (byte == 0xCC) and (string.byte(data, 1) == 0xCC)
            end

            -- Read stack pointer and read 8 bytes from the stack
            local ctx = dbg:get_context(pid, tid)
            local sp = spof(ctx)
            local stack_data = dbg:read_memory(pid, sp, 8)
            result.stack_read_ok = (#stack_data == 8)

            -- Test read_u32 and read_u64
            local val32 = dbg:read_u32(pid, sp)
            local val64 = dbg:read_u64(pid, sp)
            result.has_u32 = (val32 ~= nil)
            result.has_u64 = (val64 ~= nil)

            dbg:terminate(pid)
        end)

        dbg:launch('cmd.exe /c "echo test"')
        dbg:run()
        return result
    "#;

    let result: mlua::Table = lua.load(script).eval().unwrap();

    let bp_ok: bool = result.get("bp_ok").unwrap();
    assert!(bp_ok, "initial breakpoint instruction should match the arch's breakpoint encoding");

    let mem_size: i64 = result.get("memory_size").unwrap();
    assert_eq!(mem_size, 16, "should read 16 bytes");

    let stack_ok: bool = result.get("stack_read_ok").unwrap();
    assert!(stack_ok, "should read 8 bytes from stack");

    let has_u32: bool = result.get("has_u32").unwrap();
    let has_u64: bool = result.get("has_u64").unwrap();
    assert!(has_u32, "read_u32 should return a value");
    assert!(has_u64, "read_u64 should return a value");
}

// ---------------------------------------------------------------------------
// 5. Disassembly and call stack
// ---------------------------------------------------------------------------

#[test]
fn test_script_disassembly_and_callstack() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    let script = r#"
        local result = {}

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            -- Disassembly symbolization is non-blocking: wait for ntdll's symbols
            -- (the initial breakpoint lives there) before asserting on them.
            local ntdll = wait_symbols(pid, "ntdll")
            assert(ntdll and ntdll.state == "loaded",
                "ntdll symbols should load: " .. tostring(ntdll and ntdll.error))

            -- Disassemble 5 instructions at the breakpoint
            local instrs = dbg:disassemble(pid, addr, 5)
            result.instr_count = #instrs
            result.first_mnemonic = instrs[1].mnemonic
            result.first_addr = instrs[1].address
            result.has_symbol = (instrs[1].symbol ~= nil)

            -- Get call stack
            local frames = dbg:get_call_stack(pid, tid)
            result.frame_count = #frames
            result.top_frame_addr = frames[1].address
            result.has_frame_symbol = (frames[1].symbol ~= nil)

            dbg:terminate(pid)
        end)

        dbg:launch('cmd.exe /c "echo test"')
        dbg:run()
        return result
    "#;

    let result: mlua::Table = lua.load(script).eval().unwrap();

    let instr_count: i64 = result.get("instr_count").unwrap();
    assert_eq!(instr_count, 5, "should disassemble 5 instructions");

    let first_mnemonic: String = result.get("first_mnemonic").unwrap();
    // Initial breakpoint instruction: int3 on x86, brk on AArch64.
    #[cfg(target_arch = "x86_64")]
    assert_eq!(first_mnemonic, "int3", "first instruction at initial breakpoint should be int3");
    #[cfg(target_arch = "aarch64")]
    assert_eq!(first_mnemonic, "brk", "first instruction at initial breakpoint should be brk");

    let first_addr: u64 = result.get("first_addr").unwrap();
    assert!(first_addr > 0, "instruction address should be nonzero");

    let has_symbol: bool = result.get("has_symbol").unwrap();
    assert!(has_symbol, "first instruction should have symbol info");

    let frame_count: i64 = result.get("frame_count").unwrap();
    assert!(frame_count >= 2, "call stack should have at least 2 frames, got {}", frame_count);

    let has_frame_symbol: bool = result.get("has_frame_symbol").unwrap();
    assert!(has_frame_symbol, "top frame should have symbol info");
}

// ---------------------------------------------------------------------------
// 6. Breakpoints with handlers
// ---------------------------------------------------------------------------

#[test]
fn test_script_breakpoint_handler() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    // Use the disassembly_test program which has a known symbol (helper_add)
    let test_exe = common::get_test_program_path("disassembly_test");

    let script = format!(r#"
        local result = {{}}
        result.bp_hit_count = 0

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            -- Set breakpoint on test_control_flow (a function in disassembly_test.exe)
            local syms = dbg:find_symbol("test_control_flow", 5)
            if #syms > 0 then
                result.sym_found = true
                result.bp_addr = syms[1].va

                dbg:set_breakpoint(pid, syms[1].va, function(pid, tid, addr)
                    result.bp_hit_count = result.bp_hit_count + 1
                    result.bp_pid = pid
                    result.bp_tid = tid
                    result.bp_address = addr

                    -- Read registers at the breakpoint
                    local ctx = dbg:get_context(pid, tid)
                    result.bp_rip = ipof(ctx)

                    -- Get call stack at breakpoint
                    local frames = dbg:get_call_stack(pid, tid)
                    result.bp_frame_count = #frames

                    return "remove"  -- remove after first hit
                end)
            else
                result.sym_found = false
            end
        end)

        dbg:launch({:?})
        dbg:run()
        return result
    "#, test_exe);

    let result: mlua::Table = lua.load(&script).eval().unwrap();

    let sym_found: bool = result.get("sym_found").unwrap();
    assert!(sym_found, "should find test_control_flow symbol");

    let bp_hit_count: i64 = result.get("bp_hit_count").unwrap();
    assert_eq!(bp_hit_count, 1, "breakpoint should be hit exactly once (removed after first hit)");

    let bp_pid: u32 = result.get("bp_pid").unwrap();
    assert!(bp_pid > 0, "breakpoint pid should be nonzero");

    let bp_rip: u64 = result.get("bp_rip").unwrap();
    assert!(bp_rip > 0, "rip at breakpoint should be nonzero");

    let bp_frame_count: i64 = result.get("bp_frame_count").unwrap();
    assert!(bp_frame_count >= 1, "should have at least 1 frame at breakpoint");
}

// ---------------------------------------------------------------------------
// 7. DLL load handler and memory regions
// ---------------------------------------------------------------------------

#[test]
fn test_script_dll_handler_and_regions() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    let script = r#"
        local result = {}
        result.dll_loads = {}

        dbg:on_dll_loaded(function(pid, tid, name, base)
            table.insert(result.dll_loads, { name = name, base = base })
        end)

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            -- Enumerate memory regions
            local regions = dbg:enumerate_regions(pid)
            result.region_count = #regions

            -- Query a specific region (the initial breakpoint address)
            local region = dbg:query_memory(pid, addr)
            result.region_base = region.base_address
            result.region_size = region.region_size

            -- List threads
            local threads = dbg:list_threads(pid)
            result.thread_count = #threads

            dbg:terminate(pid)
        end)

        dbg:launch('cmd.exe /c "echo test"')
        dbg:run()
        return result
    "#;

    let result: mlua::Table = lua.load(script).eval().unwrap();

    let dll_loads: mlua::Table = result.get("dll_loads").unwrap();
    let dll_count = dll_loads.raw_len();
    assert!(dll_count >= 3, "should have loaded at least 3 DLLs (ntdll, kernel32, kernelbase), got {}", dll_count);

    let region_count: i64 = result.get("region_count").unwrap();
    assert!(region_count > 10, "should have many memory regions, got {}", region_count);

    let region_base: u64 = result.get("region_base").unwrap();
    assert!(region_base > 0, "region base should be nonzero");

    let region_size: u64 = result.get("region_size").unwrap();
    assert!(region_size > 0, "region size should be nonzero");

    let thread_count: i64 = result.get("thread_count").unwrap();
    assert!(thread_count >= 1, "should have at least 1 thread");
}

// ---------------------------------------------------------------------------
// 8. Stepping (step into from initial breakpoint)
// ---------------------------------------------------------------------------

#[test]
fn test_script_stepping() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    // Step from the initial breakpoint — a known safe location (LdrpDoDebuggerBreak)
    let script = r#"
        local result = {}

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            local ctx_before = dbg:get_context(pid, tid)
            result.rip_before = ipof(ctx_before)

            -- Single step into
            local new_addr = dbg:step_into(pid, tid)
            result.step_addr = new_addr
            result.stepped = (new_addr ~= ipof(ctx_before))

            dbg:terminate(pid)
        end)

        dbg:launch('cmd.exe /c "echo stepping_test"')
        dbg:run()
        return result
    "#;

    let result: mlua::Table = lua.load(script).eval().unwrap();

    let rip_before: u64 = result.get("rip_before").unwrap();
    let step_addr: u64 = result.get("step_addr").unwrap();
    let stepped: bool = result.get("stepped").unwrap();

    assert!(rip_before > 0, "rip before step should be nonzero");
    assert!(step_addr > 0, "step address should be nonzero");
    assert!(stepped, "should have moved to a different address after step_into");
}

// ---------------------------------------------------------------------------
// 9. REPL-style stepping (tests the RefCell borrow path in repl.rs)
//    This exercises step_and_wait + format_address + populate_register_globals
//    through the same code path as typing "si" in the break REPL.
// ---------------------------------------------------------------------------

#[test]
fn test_repl_stepping_and_register_globals() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = setup_lua_with_server(&server);

    // Use repl_on_break so the event loop auto-enters the break handler,
    // then step and read register globals — this is the REPL code path.
    let script = r#"
        local result = {}

        dbg:on_initial_breakpoint(function(pid, tid, addr)
            -- Simulate what the REPL does: step, then read register globals
            -- (the REPL calls step_and_wait, format_address, populate_register_globals)
            local ctx1 = dbg:get_context(pid, tid)
            result.rip1 = ipof(ctx1)

            -- Step (same call the REPL si command makes)
            local addr2 = dbg:step_into(pid, tid)
            result.rip2 = addr2

            -- Step again
            local addr3 = dbg:step_into(pid, tid)
            result.rip3 = addr3

            -- Read context after stepping
            local ctx3 = dbg:get_context(pid, tid)
            result.rip3_ctx = ipof(ctx3)

            -- Resolve address (same as format_address)
            local sym = dbg:resolve_address(pid, addr3)
            result.sym_name = sym.name or "unknown"

            result.all_different = (result.rip1 ~= result.rip2) and (result.rip2 ~= result.rip3)

            dbg:terminate(pid)
        end)

        dbg:launch('cmd.exe /c "echo test"')
        dbg:run()
        return result
    "#;

    let result: mlua::Table = lua.load(script).eval().unwrap();

    let rip1: u64 = result.get("rip1").unwrap();
    let rip2: u64 = result.get("rip2").unwrap();
    let rip3: u64 = result.get("rip3").unwrap();
    let rip3_ctx: u64 = result.get("rip3_ctx").unwrap();
    let all_different: bool = result.get("all_different").unwrap();
    let sym_name: String = result.get("sym_name").unwrap();

    assert!(rip1 > 0);
    assert!(rip2 > 0);
    assert!(rip3 > 0);
    assert!(all_different, "each step should reach a different address: rip1=0x{:X}, rip2=0x{:X}, rip3=0x{:X}", rip1, rip2, rip3);
    assert_eq!(rip3, rip3_ctx, "rip after step should match context rip");
    assert!(!sym_name.is_empty(), "should resolve stepped address to a symbol");
}

// ===========================================================================
// Lua file-based tests (ported from Rust integration tests)
// ===========================================================================

// --- basics ---

#[test]
fn test_lua_file_helpers() {
    run_lua_test_file_no_server("basics/helpers.lua");
}

#[test]
fn test_lua_file_launch_and_registers() {
    run_lua_test_file("basics/launch_and_registers.lua", None);
}

#[test]
fn test_lua_thread_control() {
    run_lua_test_file("basics/thread_control.lua", None);
}

#[test]
fn test_lua_file_debug_client_events() {
    run_lua_test_file("basics/debug_client_events.lua", None);
}

#[test]
fn test_lua_file_launch_working_directory() {
    run_lua_test_file("basics/launch_working_directory.lua", None);
}

#[test]
fn test_lua_file_parent_child() {
    let test_exe = common::get_test_program_path("parent_child_test");
    run_lua_test_file("basics/parent_child.lua", Some(&test_exe));
}

// --- modules ---

#[test]
fn test_lua_file_modules_and_symbols() {
    run_lua_test_file("modules/modules_and_symbols.lua", None);
}

#[test]
fn test_lua_file_symbol_token_search() {
    run_lua_test_file("modules/symbol_token_search.lua", None);
}

#[test]
fn test_lua_file_module_extra_info() {
    run_lua_test_file("modules/module_extra_info.lua", None);
}

#[test]
fn test_lua_file_tls_callbacks() {
    let test_exe = common::get_test_program_path("tls_test");
    run_lua_test_file("modules/tls_callbacks.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_symbol_status() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("modules/symbol_status.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_unload_symbols() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("modules/unload_symbols.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_export_fallback() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("modules/export_fallback.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_load_pdb() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("modules/load_pdb.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_source_lines() {
    let test_exe = common::get_test_program_path("xtea_test");
    run_lua_test_file("modules/source_lines.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_types() {
    run_lua_test_file("modules/types.lua", None);
}

// --- memory ---

#[test]
fn test_lua_file_memory_read_write() {
    run_lua_test_file("memory/read_write.lua", None);
}

#[test]
fn test_lua_file_memory_regions() {
    run_lua_test_file("memory/regions.lua", None);
}

#[test]
fn test_lua_file_memory_search() {
    let test_exe = common::get_test_program_path("memory_search_test");
    run_lua_test_file("memory/search.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_memory_dereference() {
    let test_exe = common::get_test_program_path("dereference_test");
    run_lua_test_file("memory/dereference.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_memory_scan() {
    let test_exe = common::get_test_program_path("memory_scan_test");
    run_lua_test_file("memory/memory_scan.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_pointer_scan() {
    let test_exe = common::get_test_program_path("pointer_scan_test");
    run_lua_test_file("memory/pointer_scan.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_string_scan() {
    let test_exe = common::get_test_program_path("memory_search_test");
    run_lua_test_file("memory/string_scan.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_freeze_value() {
    let test_exe = common::get_test_program_path("freeze_value_test");
    run_lua_test_file("memory/freeze_value.lua", Some(&test_exe));
}

// --- disassembly ---

#[test]
fn test_lua_file_disassembly_basic() {
    run_lua_test_file("disassembly/basic.lua", None);
}

#[test]
fn test_lua_file_disassembly_function() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("disassembly/function_disassembly.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_disassembly_non_module() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("disassembly/non_module_memory.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_disassembly_backward() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("disassembly/backward.lua", Some(&test_exe));
}

// --- breakpoints ---

#[test]
fn test_lua_file_breakpoint_handler() {
    let test_exe = common::get_test_program_path("disassembly_test");
    run_lua_test_file("breakpoints/breakpoint_handler.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_dll_handler() {
    run_lua_test_file("breakpoints/dll_handler.lua", None);
}

#[test]
fn test_lua_file_assembler_patch() {
    let test_exe = common::get_test_program_path("assembler_test");
    run_lua_test_file("breakpoints/assembler_patch.lua", Some(&test_exe));
}

#[test]
#[cfg(not(target_arch = "aarch64"))]
fn test_lua_file_hardware_breakpoints() {
    let test_exe = common::get_test_program_path("hardware_bp_test");
    run_lua_test_file("breakpoints/hardware_breakpoints.lua", Some(&test_exe));
}

#[test]
#[cfg(not(target_arch = "aarch64"))]
fn test_lua_file_hw_breakpoint_stepping() {
    let test_exe = common::get_test_program_path("hardware_bp_test");
    run_lua_test_file("breakpoints/hw_breakpoint_stepping.lua", Some(&test_exe));
}

#[test]
#[cfg(not(target_arch = "aarch64"))]
fn test_lua_file_watchpoint_trace() {
    let test_exe = common::get_test_program_path("hardware_bp_test");
    run_lua_test_file("breakpoints/watchpoint_trace.lua", Some(&test_exe));
}

// --- stepping ---

#[test]
fn test_lua_file_step_into() {
    run_lua_test_file("stepping/step_into.lua", None);
}

#[test]
fn test_lua_file_repl_stepping() {
    run_lua_test_file("stepping/repl_stepping.lua", None);
}

#[test]
fn test_lua_file_step_sequence() {
    run_lua_test_file("stepping/step_sequence.lua", None);
}

#[test]
fn test_lua_file_step_line() {
    let test_exe = common::get_test_program_path("xtea_test");
    run_lua_test_file("stepping/step_line.lua", Some(&test_exe));
}

// --- emulation ---

#[test]
fn test_lua_file_tracer_simple() {
    run_lua_test_file("emulation/tracer_simple.lua", None);
}

#[test]
fn test_lua_file_emulator_basic() {
    let test_exe = common::get_test_program_path("xtea_test");
    run_lua_test_file("emulation/emulator_basic.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_tracer_vs_emulator() {
    let test_exe = common::get_test_program_path("xtea_test");
    run_lua_test_file("emulation/tracer_vs_emulator.lua", Some(&test_exe));
}

// --- exceptions ---

#[test]
fn test_lua_file_exception_handled() {
    let test_exe = common::get_test_program_path("exception_test");
    run_lua_test_file("basics/exception_handled.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_exception_passed() {
    let test_exe = common::get_test_program_path("exception_test");
    run_lua_test_file("basics/exception_passed.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_single_step_handled() {
    let test_exe = common::get_test_program_path("single_step_test");
    run_lua_test_file("basics/single_step_handled.lua", Some(&test_exe));
}

#[test]
fn test_lua_file_single_step_passed() {
    let test_exe = common::get_test_program_path("single_step_test");
    run_lua_test_file("basics/single_step_passed.lua", Some(&test_exe));
}

// --- mass breakpoints ---

#[test]
fn test_lua_file_mass_breakpoints() {
    run_lua_test_file("breakpoints/mass_breakpoints.lua", None);
}

// --- code coverage ---

#[test]
fn test_lua_file_code_coverage() {
    run_lua_test_file("breakpoints/code_coverage.lua", None);
}

#[test]
fn test_lua_file_coverage_targets() {
    run_lua_test_file("breakpoints/coverage_targets.lua", None);
}

// --- anti-anti-debug ---

#[test]
fn test_lua_file_hide_peb() {
    run_lua_test_file("anti_anti_debug/hide_peb.lua", None);
}
