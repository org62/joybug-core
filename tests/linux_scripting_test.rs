#![cfg(target_os = "linux")]

//! The Linux-only debugger features through the Lua API (`dbg:*`).

mod common;

use common::{get_test_program_path, TestServer};
use joybug_core::scripting;
use joybug_core::scripting::bindings::LuaDebugClient;
use joybug_core::scripting::debug_client::DebugClient;

#[test]
fn lua_children_signals_and_objects() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let lua = scripting::create_lua().expect("create lua");
    let client = DebugClient::connect(server.address()).expect("connect");
    lua.globals().set("dbg", lua.create_userdata(LuaDebugClient::new(client)).unwrap()).unwrap();
    for (global, program) in [("FORKER", "forker"), ("SIGNALS", "signals"), ("FDS", "fds")] {
        lua.globals().set(global, get_test_program_path(program)).unwrap();
    }
    let tmp = std::env::temp_dir().join(format!("joybug-lua-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    lua.globals().set("TMP", tmp.to_str().unwrap()).unwrap();

    let path = format!("{}/tests/lua/linux/children_signals_objects.lua", env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let result: mlua::Value = lua.load(&script).set_name(&path).eval().unwrap_or_else(|e| panic!("Lua test failed: {e}"));
    let _ = std::fs::remove_dir_all(&tmp);
    let mlua::Value::Table(table) = result else { panic!("the script returns a table") };
    assert!(table.get::<bool>("passed").unwrap_or(false), "the script did not return passed = true");
}
