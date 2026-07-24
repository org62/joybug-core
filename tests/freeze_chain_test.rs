#![cfg(windows)]

//! Chain-following freeze test.
//!
//! Freezing a value reached through a pointer chain must keep holding the value
//! even after the chain repoints (e.g. a level reload moves the object). The
//! server resolves `base -> offsets` each tick, so the lock tracks the moving
//! target instead of writing to a stale address.

mod common;

use std::thread::sleep;
use std::time::Duration;

use common::{find_symbol, get_test_program_path, TestServer};
use joybug2::protocol_io::{BreakpointDecision, DebugSession};

const SENTINEL: u32 = 0xAABB_CCDD;
/// Leave the debuggee stopped long enough for the freeze thread to tick.
const SETTLE: Duration = Duration::from_millis(150);

struct State {
    ptr_addr: u64,   // &g_ptr (static base of the chain)
    cell_a: u64,     // &g_cell_a
    cell_b: u64,     // &g_cell_b
    freeze_id: Option<u64>,
    iteration: u32,
    held_a: bool,    // observed the freeze holding cell A (chain -> A)
    followed_b: bool, // observed the freeze holding cell B after the repoint
    done: bool,
}

impl State {
    fn new() -> Self {
        Self {
            ptr_addr: 0, cell_a: 0, cell_b: 0,
            freeze_id: None, iteration: 0, held_a: false, followed_b: false, done: false,
        }
    }
}

fn read_u32(session: &mut DebugSession<State>, pid: u32, addr: u64) -> anyhow::Result<u32> {
    let b = session.read_memory(pid, addr, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[test]
fn freeze_follows_pointer_chain_after_repoint() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("freeze_chain_test");
    println!("Using freeze_chain_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(State::new(), Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            session.state.ptr_addr = find_symbol(session, "freeze_chain_test!g_ptr", "freeze_chain_test")?.va;
            session.state.cell_a = find_symbol(session, "freeze_chain_test!g_cell_a", "freeze_chain_test")?.va;
            session.state.cell_b = find_symbol(session, "freeze_chain_test!g_cell_b", "freeze_chain_test")?.va;
            println!("g_ptr @ 0x{:X}  cell_a @ 0x{:X}  cell_b @ 0x{:X}",
                session.state.ptr_addr, session.state.cell_a, session.state.cell_b);

            session.set_breakpoint_by_symbol(pid, "freeze_chain_test!pause_here", None, |session, pid, _tid, _addr| {
                let iter = session.state.iteration;
                session.state.iteration += 1;

                match iter {
                    0 => {
                        // Register the chain freeze while g_ptr is NULL — the chain can't
                        // resolve yet (exactly the situation just after a process restart,
                        // before the target object exists). The server must accept it and
                        // start holding once the chain becomes valid.
                        let nullp = session.read_memory(pid, session.state.ptr_addr, 8)?;
                        assert_eq!(u64::from_le_bytes(nullp[..8].try_into().unwrap()), 0, "g_ptr should be null here");
                        let id = session.freeze_value(
                            pid, session.state.ptr_addr, SENTINEL.to_le_bytes().to_vec(), None, vec![0],
                        )?;
                        session.state.freeze_id = Some(id);
                        println!("[iter 0] froze chain *g_ptr -> sentinel while NULL (id {})", id);
                        Ok(BreakpointDecision::Keep)
                    }
                    1 => {
                        // g_ptr now points at cell A; the freeze registered while null must
                        // now hold cell A.
                        sleep(SETTLE);
                        let a = read_u32(session, pid, session.state.cell_a)?;
                        println!("[iter 1] cell_a while frozen (chain->A) = 0x{:X}", a);
                        assert_eq!(a, SENTINEL, "freeze did not start holding once the chain became valid");
                        session.state.held_a = true;
                        Ok(BreakpointDecision::Keep)
                    }
                    2 => Ok(BreakpointDecision::Keep), // second cell-A reset; nothing to check
                    3 => {
                        // The program just repointed g_ptr to cell B ("level reload").
                        let ptr = session.read_memory(pid, session.state.ptr_addr, 8)?;
                        let target = u64::from_le_bytes(ptr[..8].try_into().unwrap());
                        println!("[iter 3] g_ptr now -> 0x{:X} (cell_b @ 0x{:X})", target, session.state.cell_b);
                        assert_eq!(target, session.state.cell_b, "program should have repointed to cell B");
                        Ok(BreakpointDecision::Keep)
                    }
                    _ => {
                        // Phase 2: the chain points at cell B and the program keeps resetting
                        // it. A chain-following freeze must now hold cell B (the decisive check
                        // — a stale fixed-address freeze would still be hammering cell A).
                        sleep(SETTLE);
                        let b = read_u32(session, pid, session.state.cell_b)?;
                        println!("[iter {}] cell_b while frozen (chain->B) = 0x{:X}", iter, b);
                        assert_eq!(b, SENTINEL, "freeze did not follow the chain to cell B after repoint");
                        session.state.followed_b = true;

                        if let Some(id) = session.state.freeze_id.take() {
                            session.unfreeze_value(id)?;
                        }
                        session.state.done = true;
                        Ok(BreakpointDecision::Remove)
                    }
                }
            })?;
            Ok(())
        })
        .on_process_exited(|session, _pid, _code| {
            if let Some(id) = session.state.freeze_id.take() {
                let _ = session.unfreeze_value(id);
            }
            Ok(())
        })
        .launch(test_exe)
        .expect("Debug session failed");

    assert!(final_state.held_a, "did not observe the freeze holding cell A");
    assert!(final_state.followed_b, "did not observe the freeze follow the chain to cell B");
    assert!(final_state.done, "chain freeze test did not complete");
    println!("\n=== freeze_chain test PASSED ===");
}
