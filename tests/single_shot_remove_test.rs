#![cfg(windows)]

mod common;

use common::TestServer;
use joybug_core::protocol_io::DebugSession;

/// Regression test for single-shot breakpoint removal.
///
/// Single-shot breakpoints are stored in their own map, separate from persistent
/// ones. `remove_breakpoint` used to look only at the persistent map, so removing
/// a single-shot breakpoint was a silent no-op: the INT3 stayed written in the
/// debuggee and the client kept trapping on a breakpoint it believed it had
/// removed (visible in the UI as deleted "Module Entry" / "TLS Callbacks" rows
/// that still break).
///
/// This drives the whole round trip: arm a single-shot breakpoint on a symbol the
/// target definitely reaches, verify the breakpoint instruction really landed,
/// remove it, verify the original bytes are back, then run to completion and
/// assert the handler never fired.
struct TestState {
    /// Set by the single-shot handler. Must stay false: the breakpoint is removed
    /// before the process is allowed to reach it.
    removed_breakpoint_hit: bool,
    /// The symbol we armed and removed, for the failure message.
    target_address: u64,
}

#[test]
fn test_removed_single_shot_breakpoint_does_not_fire() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let final_state = DebugSession::new(
        TestState { removed_breakpoint_hit: false, target_address: 0 },
        Some(server_addr.as_str()),
    )
    .expect("Failed to connect to debug server")
    .on_initial_breakpoint(|session, pid, _tid, _address| {
        // `cmd!CmdPutChars` runs for `cmd.exe /c echo test` (see debug_client_test).
        let symbols = session.find_symbols("cmd!CmdPutChars", 1)?;
        let address = symbols
            .first()
            .expect("cmd!CmdPutChars should resolve")
            .va;
        session.state.target_address = address;
        println!("=== Target: cmd!CmdPutChars at 0x{:x} ===", address);

        // Raw ReadMemory is not breakpoint-masked (only the disassembly paths
        // are), so these reads see the real bytes in the debuggee.
        let original = session.read_memory(pid, address, 4)?;

        session.set_single_shot_breakpoint_at(pid, address, |session, _pid, _tid, addr| {
            println!("=== Removed single-shot breakpoint fired at 0x{:x} ===", addr);
            session.state.removed_breakpoint_hit = true;
            Ok(())
        })?;

        let armed = session.read_memory(pid, address, 4)?;
        assert_ne!(
            armed, original,
            "arming a single-shot breakpoint should have written the breakpoint instruction at 0x{:x}",
            address
        );

        session.remove_breakpoint(pid, address)?;

        let after_removal = session.read_memory(pid, address, 4)?;
        assert_eq!(
            after_removal, original,
            "removing a single-shot breakpoint must restore the original bytes at 0x{:x}",
            address
        );

        println!("Single-shot breakpoint armed and removed, continuing process...");
        Ok(())
    })
    .launch("cmd.exe /c echo test".to_string())
    .expect("Debug session failed");

    assert!(
        !final_state.removed_breakpoint_hit,
        "a single-shot breakpoint removed at 0x{:x} must not fire",
        final_state.target_address
    );
    println!("✅ Removed single-shot breakpoint never fired");
}
