#![cfg(windows)]

mod common;

use common::{TestServer, get_test_program_path};
use joybug2::protocol_io::{
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

/// On ARM64, hardware breakpoints use BCR/BVR registers (not x86 DR0-DR7).
/// This is not yet implemented — this test ensures it's not forgotten.
#[test]
#[cfg(target_arch = "aarch64")]
fn hardware_breakpoint_all_types() {
    panic!(
        "Hardware breakpoints are not implemented for ARM64. \
         Need to implement BCR/BVR (breakpoint) and WCR/WVR (watchpoint) \
         register support in windows_platform/hardware_breakpoints.rs"
    );
}

#[test]
#[cfg(not(target_arch = "aarch64"))]
fn hardware_breakpoint_all_types() {
    joybug2::init_tracing();

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
