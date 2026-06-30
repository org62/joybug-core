#![cfg(windows)]

mod common;

use std::thread::sleep;
use std::time::Duration;

use common::{find_symbol, get_test_program_path, TestServer};
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

const PROGRAM_VALUE: u32 = 1000;
const SENTINEL: u32 = 0xAABB_CCDD;
/// Time we leave the debuggee stopped so the server-side freeze thread can tick.
/// Comfortably above the default ~30ms freeze interval.
const SETTLE: Duration = Duration::from_millis(150);

struct FreezeState {
    value_addr: u64,
    freeze_id: Option<u64>,
    iteration: u32,
    frozen_observed: bool,
    unfrozen_observed: bool,
    done: bool,
}

impl FreezeState {
    fn new() -> Self {
        Self {
            value_addr: 0,
            freeze_id: None,
            iteration: 0,
            frozen_observed: false,
            unfrozen_observed: false,
            done: false,
        }
    }
}

fn read_u32(session: &mut DebugSession<FreezeState>, pid: u32, addr: u64) -> anyhow::Result<u32> {
    let bytes = session.read_memory(pid, addr, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Verifies a server-side value freeze: while the debuggee is stopped (so only the
/// freeze thread can mutate memory) the frozen address holds the sentinel; after
/// unfreeze the program's own writes take effect again.
#[test]
fn freeze_value_holds_and_releases() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe = get_test_program_path("freeze_value_test");
    println!("Using freeze_value_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(FreezeState::new(), Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            // Resolve &g_value once, up front.
            let sym = find_symbol(session, "freeze_value_test!g_value", "freeze_value_test")?;
            session.state.value_addr = sym.va;
            println!("g_value @ 0x{:X}", sym.va);

            session.set_breakpoint_by_symbol(pid, "freeze_value_test!pause_here", None, |session, pid, _tid, _addr| {
                let addr = session.state.value_addr;
                let iter = session.state.iteration;
                session.state.iteration += 1;

                match iter {
                    0 => {
                        // Program just set the value; sanity-check, then freeze to sentinel.
                        let v = read_u32(session, pid, addr)?;
                        println!("[iter 0] value before freeze = {}", v);
                        assert_eq!(v, PROGRAM_VALUE, "expected program value before freezing");
                        let id = session.freeze_value(pid, addr, SENTINEL.to_le_bytes().to_vec(), None, Vec::new())?;
                        session.state.freeze_id = Some(id);
                        println!("[iter 0] started freeze id={}", id);
                        Ok(BreakpointDecision::Keep)
                    }
                    1 => {
                        // Stopped at pause_here (program set PROGRAM_VALUE just before). While
                        // stopped, only the freeze thread writes — after settling it must read sentinel.
                        sleep(SETTLE);
                        let v = read_u32(session, pid, addr)?;
                        println!("[iter 1] value while frozen = 0x{:X}", v);
                        assert_eq!(v, SENTINEL, "freeze did not hold the value");
                        session.state.frozen_observed = true;

                        let id = session.state.freeze_id.take().expect("freeze id");
                        session.unfreeze_value(id)?;
                        println!("[iter 1] unfroze id={}", id);
                        Ok(BreakpointDecision::Keep)
                    }
                    _ => {
                        // Freeze is off; program set PROGRAM_VALUE before pause_here and nothing
                        // overwrites it while stopped.
                        sleep(SETTLE);
                        let v = read_u32(session, pid, addr)?;
                        println!("[iter {}] value after unfreeze = {}", iter, v);
                        assert_eq!(v, PROGRAM_VALUE, "value should follow the program after unfreeze");
                        session.state.unfrozen_observed = true;
                        session.state.done = true;
                        Ok(BreakpointDecision::Remove)
                    }
                }
            })?;
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("Process {} exited with code 0x{:X}", pid, exit_code);
            // Best-effort cleanup if the test bailed early.
            if let Some(id) = session.state.freeze_id.take() {
                let _ = session.unfreeze_value(id);
            }
            Ok(())
        })
        .launch(test_exe)
        .expect("Debug session failed");

    assert!(final_state.frozen_observed, "did not observe the frozen value");
    assert!(final_state.unfrozen_observed, "did not observe the released value");
    assert!(final_state.done, "freeze test did not complete");
    println!("\n=== freeze_value test PASSED ===");
}
