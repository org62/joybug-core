#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path};
use joybug_core::protocol_io::{
    BreakpointDecision, DebugSession, HardwareBreakpointSize,
    HardwareBreakpointType,
};

struct HwBpTestState {
    write_dword_hit: bool,
    rw_dword_hits: u32,
    write_byte_hit: bool,
    execute_hit: bool,
}

impl HwBpTestState {
    fn new() -> Self {
        Self {
            write_dword_hit: false,
            rw_dword_hits: 0,
            write_byte_hit: false,
            execute_hit: false,
        }
    }
}

/// ARM64 hardware breakpoints/watchpoints.
///
/// ARM64 has separate debug-register banks: Bvr/Bcr for execute breakpoints and
/// Wvr/Wcr for data watchpoints. The Windows ARM64 CONTEXT exposes up to 2
/// watchpoints, but the number actually honored is implementation-defined and
/// observed to be 1 on the CI hardware. So rather than arm several watchpoints
/// at once (as the x86 test does with its 4 shared DR slots), we chain them:
/// each watchpoint fully removes itself and arms its successor from within its
/// own hit callback, so only one watchpoint is live at a time. This exercises
/// every type and is robust regardless of how many watchpoints the hardware has:
///   Execute (execute_target) + Write(Byte4) → ReadWrite(Byte4) → Write(Byte1).
#[test]
#[cfg(target_arch = "aarch64")]
fn hardware_breakpoint_all_types() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("hardware_bp_test");
    println!("Using hardware_bp_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(HwBpTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            session.set_breakpoint_by_symbol(
                pid,
                "breakpoint_here",
                None,
                |session: &mut DebugSession<HwBpTestState>, pid, _tid, _addr| {
                    // Execute breakpoint (breakpoint bank — independent of watchpoints).
                    session.set_hardware_breakpoint_by_symbol(
                        pid,
                        "execute_target",
                        HardwareBreakpointType::Execute,
                        HardwareBreakpointSize::Byte1,
                        |session, _pid, _tid, addr| {
                            println!("  HW BP hit: Execute on execute_target at 0x{:X}", addr);
                            session.state.execute_hit = true;
                            Ok(BreakpointDecision::Remove)
                        },
                    )?;

                    // Watchpoint 1: Write(Byte4) on g_write_dword. We fully REMOVE
                    // each watchpoint before arming the next so they always reuse
                    // the same (slot 0) register.
                    session.set_hardware_breakpoint_by_symbol(
                        pid,
                        "g_write_dword",
                        HardwareBreakpointType::Write,
                        HardwareBreakpointSize::Byte4,
                        |session, pid, _tid, addr| {
                            println!("  HW WP hit: Write(Byte4) on g_write_dword at 0x{:X}", addr);
                            session.state.write_dword_hit = true;
                            session.remove_hardware_breakpoint(pid, addr)?;

                            // Arm watchpoint 2: ReadWrite(Byte4) on g_rw_dword.
                            session.set_hardware_breakpoint_by_symbol(
                                pid,
                                "g_rw_dword",
                                HardwareBreakpointType::ReadWrite,
                                HardwareBreakpointSize::Byte4,
                                |session, pid, _tid, addr| {
                                    session.state.rw_dword_hits += 1;
                                    let count = session.state.rw_dword_hits;
                                    println!(
                                        "  HW WP hit: ReadWrite(Byte4) on g_rw_dword at 0x{:X} (hit #{})",
                                        addr, count
                                    );
                                    if count >= 2 {
                                        session.remove_hardware_breakpoint(pid, addr)?;
                                        // Arm watchpoint 3: Write(Byte1) on g_write_byte.
                                        session.set_hardware_breakpoint_by_symbol(
                                            pid,
                                            "g_write_byte",
                                            HardwareBreakpointType::Write,
                                            HardwareBreakpointSize::Byte1,
                                            |session, _pid, _tid, addr| {
                                                println!("  HW WP hit: Write(Byte1) on g_write_byte at 0x{:X}", addr);
                                                session.state.write_byte_hit = true;
                                                Ok(BreakpointDecision::Remove)
                                            },
                                        )?;
                                        Ok(BreakpointDecision::Keep)
                                    } else {
                                        Ok(BreakpointDecision::Keep)
                                    }
                                },
                            )?;
                            Ok(BreakpointDecision::Keep)
                        },
                    )?;

                    Ok(BreakpointDecision::Remove)
                },
            )?;
            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("Process {} exited with code 0x{:X}", pid, exit_code);
            println!("\n=== ARM64 Hardware Breakpoint All-Types Results ===");
            println!("  write_dword_hit:  {}", session.state.write_dword_hit);
            println!("  rw_dword_hits:    {}", session.state.rw_dword_hits);
            println!("  write_byte_hit:   {}", session.state.write_byte_hit);
            println!("  execute_hit:      {}", session.state.execute_hit);
            Ok(())
        })
        .launch(test_exe)
        .expect("Debug session failed");

    assert!(final_state.write_dword_hit, "g_write_dword Write(Byte4) watchpoint should have been hit");
    assert_eq!(
        final_state.rw_dword_hits, 2,
        "g_rw_dword ReadWrite(Byte4) watchpoint should have been hit exactly 2 times (read + write), got {}",
        final_state.rw_dword_hits
    );
    assert!(final_state.write_byte_hit, "g_write_byte Write(Byte1) watchpoint should have been hit");
    assert!(final_state.execute_hit, "execute_target Execute breakpoint should have been hit");

    println!("\n=== ARM64 Hardware Breakpoint All-Types Test PASSED ===");
}

/// State for the ARM64 max-concurrent test: two execute breakpoints and one
/// watchpoint, all armed at the same time.
struct HwBpConcurrentState {
    exec_write_dword_hit: bool,
    exec_execute_target_hit: bool,
    write_byte_wp_hit: bool,
}

/// ARM64: prove all THREE hardware debug slots can be in use simultaneously.
///
/// This hardware (Snapdragon X / Oryon) honors **2 execute breakpoints + 1
/// watchpoint** in two independent register banks (Bvr/Bcr and Wvr/Wcr). The
/// `hardware_breakpoint_all_types` test only ever has 1 execute + 1 watchpoint
/// live at once; this test specifically arms BOTH execute slots plus the single
/// watchpoint together — from `breakpoint_here`, before any of them is hit — and
/// confirms every one fires. The three targets are distinct functions/globals
/// reached in order by `main` (write_dword → write_byte → execute_target), so all
/// three are concurrently armed for the whole run until each removes itself on hit.
#[test]
#[cfg(target_arch = "aarch64")]
fn hardware_breakpoint_max_concurrent() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();
    let test_exe = get_test_program_path("hardware_bp_test");
    println!("Using hardware_bp_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(
        HwBpConcurrentState {
            exec_write_dword_hit: false,
            exec_execute_target_hit: false,
            write_byte_wp_hit: false,
        },
        Some(server_addr.as_str()),
    )
    .expect("Failed to create debug session")
    .on_initial_breakpoint(|session, pid, _tid, _addr| {
        session.set_breakpoint_by_symbol(
            pid,
            "breakpoint_here",
            None,
            |session: &mut DebugSession<HwBpConcurrentState>, pid, _tid, _addr| {
                // Execute breakpoint #1 (breakpoint bank slot 0).
                session.set_hardware_breakpoint_by_symbol(
                    pid,
                    "write_dword",
                    HardwareBreakpointType::Execute,
                    HardwareBreakpointSize::Byte1,
                    |session, _pid, _tid, addr| {
                        println!("  HW BP hit: Execute on write_dword at 0x{:X}", addr);
                        session.state.exec_write_dword_hit = true;
                        Ok(BreakpointDecision::Remove)
                    },
                )?;

                // Execute breakpoint #2 (breakpoint bank slot 1) — live at the
                // same time as #1, which is the whole point of this test.
                session.set_hardware_breakpoint_by_symbol(
                    pid,
                    "execute_target",
                    HardwareBreakpointType::Execute,
                    HardwareBreakpointSize::Byte1,
                    |session, _pid, _tid, addr| {
                        println!("  HW BP hit: Execute on execute_target at 0x{:X}", addr);
                        session.state.exec_execute_target_hit = true;
                        Ok(BreakpointDecision::Remove)
                    },
                )?;

                // Watchpoint (watchpoint bank slot 0) — the third concurrent slot.
                session.set_hardware_breakpoint_by_symbol(
                    pid,
                    "g_write_byte",
                    HardwareBreakpointType::Write,
                    HardwareBreakpointSize::Byte1,
                    |session, _pid, _tid, addr| {
                        println!("  HW WP hit: Write(Byte1) on g_write_byte at 0x{:X}", addr);
                        session.state.write_byte_wp_hit = true;
                        Ok(BreakpointDecision::Remove)
                    },
                )?;

                Ok(BreakpointDecision::Remove)
            },
        )?;
        Ok(())
    })
    .on_process_exited(|session, pid, exit_code| {
        println!("Process {} exited with code 0x{:X}", pid, exit_code);
        println!("\n=== ARM64 Max-Concurrent (2 execute + 1 watchpoint) Results ===");
        println!("  exec_write_dword_hit:    {}", session.state.exec_write_dword_hit);
        println!("  exec_execute_target_hit: {}", session.state.exec_execute_target_hit);
        println!("  write_byte_wp_hit:       {}", session.state.write_byte_wp_hit);
        Ok(())
    })
    .launch(test_exe)
    .expect("Debug session failed");

    assert!(
        final_state.exec_write_dword_hit,
        "Execute breakpoint #1 (write_dword) should have been hit"
    );
    assert!(
        final_state.exec_execute_target_hit,
        "Execute breakpoint #2 (execute_target) should have been hit"
    );
    assert!(
        final_state.write_byte_wp_hit,
        "Watchpoint (g_write_byte Write) should have been hit while both execute breakpoints were armed"
    );

    println!("\n=== ARM64 Max-Concurrent Hardware Breakpoint Test PASSED ===");
}

#[test]
#[cfg(not(target_arch = "aarch64"))]
fn hardware_breakpoint_all_types() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let test_exe = get_test_program_path("hardware_bp_test");
    println!("Using hardware_bp_test.exe at: {}", test_exe);

    let final_state = DebugSession::new(HwBpTestState::new(), Some(server_addr.as_str()))
        .expect("Failed to create debug session")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            println!("Initial breakpoint hit, setting SW breakpoint on breakpoint_here...");

            // Set a software breakpoint on breakpoint_here — this is where we'll
            // set up all 4 hardware breakpoints once the test program is ready.
            session.set_breakpoint_by_symbol(
                pid,
                "breakpoint_here",
                None,
                |session: &mut DebugSession<HwBpTestState>, pid, _tid, addr| {
                    println!("  SW BP hit: breakpoint_here at 0x{:X}", addr);
                    println!("  Setting up 4 hardware breakpoints...");

                    // DR0: Write(Byte4) on g_write_dword
                    let g_write_dword_addr = session
                        .set_hardware_breakpoint_by_symbol(
                            pid,
                            "g_write_dword",
                            HardwareBreakpointType::Write,
                            HardwareBreakpointSize::Byte4,
                            |session, _pid, _tid, addr| {
                                println!("  HW BP hit: Write(Byte4) on g_write_dword at 0x{:X}", addr);
                                session.state.write_dword_hit = true;
                                Ok(BreakpointDecision::Remove)
                            },
                        )?;
                    println!("  DR0: Write(Byte4) on g_write_dword at 0x{:X}", g_write_dword_addr);

                    // DR1: ReadWrite(Byte4) on g_rw_dword — expect 2 hits (read + write)
                    let g_rw_dword_addr = session
                        .set_hardware_breakpoint_by_symbol(
                            pid,
                            "g_rw_dword",
                            HardwareBreakpointType::ReadWrite,
                            HardwareBreakpointSize::Byte4,
                            |session, _pid, _tid, addr| {
                                session.state.rw_dword_hits += 1;
                                let count = session.state.rw_dword_hits;
                                println!(
                                    "  HW BP hit: ReadWrite(Byte4) on g_rw_dword at 0x{:X} (hit #{})",
                                    addr, count
                                );
                                if count >= 2 {
                                    Ok(BreakpointDecision::Remove)
                                } else {
                                    Ok(BreakpointDecision::Keep)
                                }
                            },
                        )?;
                    println!("  DR1: ReadWrite(Byte4) on g_rw_dword at 0x{:X}", g_rw_dword_addr);

                    // DR2: Write(Byte1) on g_write_byte
                    let g_write_byte_addr = session
                        .set_hardware_breakpoint_by_symbol(
                            pid,
                            "g_write_byte",
                            HardwareBreakpointType::Write,
                            HardwareBreakpointSize::Byte1,
                            |session, _pid, _tid, addr| {
                                println!("  HW BP hit: Write(Byte1) on g_write_byte at 0x{:X}", addr);
                                session.state.write_byte_hit = true;
                                Ok(BreakpointDecision::Remove)
                            },
                        )?;
                    println!("  DR2: Write(Byte1) on g_write_byte at 0x{:X}", g_write_byte_addr);

                    // DR3: Execute(Byte1) on execute_target
                    let execute_target_addr = session
                        .set_hardware_breakpoint_by_symbol(
                            pid,
                            "execute_target",
                            HardwareBreakpointType::Execute,
                            HardwareBreakpointSize::Byte1,
                            |session, _pid, _tid, addr| {
                                println!("  HW BP hit: Execute(Byte1) on execute_target at 0x{:X}", addr);
                                session.state.execute_hit = true;
                                Ok(BreakpointDecision::Remove)
                            },
                        )?;
                    println!("  DR3: Execute(Byte1) on execute_target at 0x{:X}", execute_target_addr);

                    Ok(BreakpointDecision::Remove)
                },
            )?;

            Ok(())
        })
        .on_process_exited(|session, pid, exit_code| {
            println!("Process {} exited with code 0x{:X}", pid, exit_code);
            println!("\n=== Hardware Breakpoint All-Types Results ===");
            println!("  write_dword_hit:  {}", session.state.write_dword_hit);
            println!("  rw_dword_hits:    {}", session.state.rw_dword_hits);
            println!("  write_byte_hit:   {}", session.state.write_byte_hit);
            println!("  execute_hit:      {}", session.state.execute_hit);
            Ok(())
        })
        .launch(test_exe)
        .expect("Debug session failed");

    // Verify results
    assert!(
        final_state.write_dword_hit,
        "g_write_dword Write(Byte4) breakpoint should have been hit"
    );
    assert_eq!(
        final_state.rw_dword_hits, 2,
        "g_rw_dword ReadWrite(Byte4) breakpoint should have been hit exactly 2 times (read + write), got {}",
        final_state.rw_dword_hits
    );
    assert!(
        final_state.write_byte_hit,
        "g_write_byte Write(Byte1) breakpoint should have been hit"
    );
    assert!(
        final_state.execute_hit,
        "execute_target Execute(Byte1) breakpoint should have been hit"
    );

    println!("\n=== Hardware Breakpoint All-Types Test PASSED ===");
}
