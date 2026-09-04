// Debugging a 32-bit (WOW64) process end to end: architecture detection, the
// single 32-bit initial breakpoint, the WOW64 register file, module list,
// disassembly, stepping (into / over / out), a symbol breakpoint, the call
// stack and 4-byte pointer dereferencing.
//
// The debuggee (`wow64_test32.exe`) is cross-compiled by build.rs with the x86
// `cl.exe`; when that toolchain is missing the fixture is absent and every
// test here skips with a note instead of failing.
#![cfg(windows)]

mod common;

use common::{try_get_test_program_path, TestServer};
use joybug_core::interfaces::Architecture;
use joybug_core::anti_anti_debug::PebHideOptions;
use joybug_core::protocol::{EmulationMode, StepAction, StepKind, ThreadContext};
use joybug_core::protocol_io::{
    BreakpointDecision, DebugSession, EmulateResult, HardwareBreakpointSize, HardwareBreakpointType,
};
use std::collections::VecDeque;

fn fixture() -> Option<String> {
    let path = try_get_test_program_path("wow64_test32");
    if path.is_none() {
        println!("skipping: wow64_test32.exe was not built (no x86 cl.exe on this host)");
    }
    path
}

fn module_named<'a>(modules: &'a [joybug_core::protocol::ModuleInfo], suffix: &str) -> Option<&'a joybug_core::protocol::ModuleInfo> {
    let suffix = suffix.to_ascii_lowercase();
    modules.iter().find(|m| m.name.to_ascii_lowercase().ends_with(&suffix))
}

fn contains(m: &joybug_core::protocol::ModuleInfo, addr: u64) -> bool {
    addr >= m.base && addr < m.base + m.size.unwrap_or(0)
}

/// Launch: exactly one InitialBreakpoint, raised from the 32-bit ntdll with a
/// WOW64 context; both ntdlls are in the module list; 32-bit disassembly works.
#[test]
fn wow64_launch_stops_at_the_32bit_initial_breakpoint() {
    let Some(exe) = fixture() else { return };
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    #[derive(Default)]
    struct State {
        initial_hits: usize,
        exit_code: Option<u32>,
    }

    let state = DebugSession::new(State::default(), Some(addr.as_str()))
        .expect("connect")
        .on_initial_breakpoint(|session, pid, tid, address| {
            session.state.initial_hits += 1;

            assert_eq!(session.get_process_architecture(pid)?, Architecture::X86);

            let ctx = session.get_thread_context(pid, tid)?;
            assert!(matches!(ctx, ThreadContext::Wow64RawContext(_)), "expected a WOW64 context");
            assert_eq!(ctx.architecture(), Architecture::X86);
            assert_eq!(ctx.pointer_size(), 4);
            // The loader's own `int3`: eip already points past it (as rip does on x64).
            assert!(ctx.pc() == address || ctx.pc() == address + 1, "eip {:#x} vs break {:#x}", ctx.pc(), address);
            assert!(address < 0x1_0000_0000, "32-bit address expected, got {:#x}", address);
            assert!(ctx.sp() != 0 && ctx.sp() < 0x1_0000_0000);

            let modules = session.list_modules(pid)?;
            // On an x64 host the 32-bit ntdll comes from SysWOW64; on ARM64 the x86
            // emulation layer loads the CHPE build from SyChpe32 instead.
            let ntdll32 = module_named(&modules, r"\syswow64\ntdll.dll")
                .or_else(|| module_named(&modules, r"\sychpe32\ntdll.dll"))
                .expect("32-bit ntdll in the module list");
            assert!(module_named(&modules, r"\system32\ntdll.dll").is_some(), "64-bit ntdll in the module list");
            assert!(contains(ntdll32, address), "initial break {:#x} not inside {} {:#x}+{:#x?}", address, ntdll32.name, ntdll32.base, ntdll32.size);

            let insns = session.disassemble_memory(pid, address, 3, Architecture::X86)?;
            assert!(!insns.is_empty());
            println!("initial break at {:#x}: {} {}", address, insns[0].mnemonic, insns[0].op_str);

            session.terminate_process(pid)?;
            Ok(())
        })
        .on_process_exited(|session, _pid, exit_code| {
            session.state.exit_code = Some(exit_code);
            Ok(())
        })
        .launch(exe)
        .expect("debug session");

    assert_eq!(state.initial_hits, 1, "exactly one initial breakpoint (the 64-bit loader break is skipped)");
    assert!(state.exit_code.is_some(), "process exit observed");
}

/// Breakpoint on a function of the 32-bit image, then step into / over / out
/// from there, with a call stack that names the marker and main.
#[test]
fn wow64_breakpoint_callstack_and_stepping() {
    let Some(exe) = fixture() else { return };
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    #[derive(Default)]
    struct State {
        marker_hits: usize,
        steps: Vec<(StepKind, u64)>,
        pending: VecDeque<StepKind>,
        call_stack_ok: bool,
        deref_ok: bool,
        marker_va: u64,
        done: bool,
    }

    let state = DebugSession::new(
        State { pending: VecDeque::from([StepKind::Into, StepKind::Over, StepKind::Out]), ..Default::default() },
        Some(addr.as_str()),
    )
    .expect("connect")
    .on_initial_breakpoint(|session, pid, _tid, _address| {
        // The main image's PDB sits next to the exe; symbols resolve by name.
        let marker_va = session.set_breakpoint_by_symbol(pid, "wow64_test32!wow64_marker", None, |session, pid, tid, address| {
            session.state.marker_hits += 1;
            println!("wow64_marker hit at {:#x}", address);
            assert!(address < 0x1_0000_0000);
            let ctx = session.get_thread_context(pid, tid)?;
            assert_eq!(ctx.pc(), address);

            // Call stack: wow64_marker, then main (32-bit EBP chain under /Od).
            let frames = session.get_call_stack(pid, tid)?;
            let names: Vec<String> = frames.iter().map(|f| f.symbol.as_ref().map(|s| s.symbol_name.clone()).unwrap_or_else(|| format!("{:#x}", f.instruction_pointer))).collect();
            println!("call stack: {:?}", names);
            assert!(frames.len() >= 2, "expected >= 2 frames, got {:?}", names);
            assert!(frames.iter().all(|f| f.instruction_pointer < 0x1_0000_0000), "32-bit frames only: {:?}", names);
            assert!(names[0].contains("wow64_marker"), "top frame {:?}", names);
            assert!(names.iter().any(|n| n.contains("main")), "main frame in {:?}", names);
            session.state.call_stack_ok = true;

            // Dereference the stack: slots are 4 bytes apart for a 32-bit target.
            let entries = session.dereference(pid, ctx.sp(), 3, None, false)?;
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[1].address - entries[0].address, 4);
            assert_eq!(entries[2].address - entries[1].address, 4);
            // The first stack slot is the return address into main.
            assert!(!entries[0].chain.is_empty());
            session.state.deref_ok = true;

            // Step into (the prologue), over (a plain instruction or the call), out (back to main).
            let first = session.state.pending.pop_front().unwrap();
            session.step(pid, tid, first, |session, _pid, _tid, address, kind| {
                println!("step {:?} -> {:#x}", kind, address);
                assert!(address < 0x1_0000_0000, "step landed outside the 32-bit space: {:#x}", address);
                session.state.steps.push((kind, address));
                match session.state.pending.pop_front() {
                    Some(next) => Ok(StepAction::Continue(next)),
                    None => {
                        session.state.done = true;
                        Ok(StepAction::Stop)
                    }
                }
            })?;
            Ok(BreakpointDecision::Remove)
        })?;
        session.state.marker_va = marker_va;
        assert!(marker_va < 0x1_0000_0000, "wow64_marker VA {:#x}", marker_va);
        Ok(())
    })
    .on_process_exited(|_session, _pid, _exit_code| Ok(()))
    .launch(exe)
    .expect("debug session");

    assert!(state.marker_hits >= 1, "wow64_marker breakpoint never hit");
    assert!(state.call_stack_ok);
    assert!(state.deref_ok);
    assert_eq!(state.steps.len(), 3, "steps: {:?}", state.steps);
    assert_eq!(state.steps[0].0, StepKind::Into);
    assert_ne!(state.steps[0].1, state.marker_va, "step-into must move eip");
    assert_eq!(state.steps[1].0, StepKind::Over);
    assert!(state.steps[1].1 > state.steps[0].1, "step-over moves forward within the function");
    assert_eq!(state.steps[2].0, StepKind::Out);
    assert!(state.steps[2].1 != state.steps[1].1);
}

/// A hardware write watchpoint on a 32-bit global fires from the WOW64 debug
/// registers (Wow64Set/GetThreadContext), on x64 and ARM64 hosts alike.
#[test]
fn wow64_hardware_write_breakpoint() {
    let Some(exe) = fixture() else { return };
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    #[derive(Default)]
    struct State {
        target_va: u64,
        hw_hits: Vec<u64>,
    }

    let state = DebugSession::new(State::default(), Some(addr.as_str()))
        .expect("connect")
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "wow64_test32!wow64_marker", None, |session, pid, _tid, _address| {
                // `wow64_marker` writes `*g_value_ptr` (== g_value) on every call.
                let va = session.set_hardware_breakpoint_by_symbol(
                    pid,
                    "wow64_test32!g_value",
                    HardwareBreakpointType::Write,
                    HardwareBreakpointSize::Byte4,
                    |session, _pid, _tid, address| {
                        println!("HW write hit at {:#x}", address);
                        session.state.hw_hits.push(address);
                        Ok(BreakpointDecision::Remove)
                    },
                )?;
                session.state.target_va = va;
                assert!(va < 0x1_0000_0000, "g_value VA {:#x}", va);
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .on_process_exited(|_session, _pid, _exit_code| Ok(()))
        .launch(exe)
        .expect("debug session");

    assert!(state.target_va != 0, "g_value never resolved");
    assert_eq!(state.hw_hits, vec![state.target_va], "hardware write breakpoint hits");
}

/// Unicorn runs the 32-bit code in Mode32 from the WOW64 register file and
/// stays inside the 4 GB space.
#[test]
fn wow64_emulation_runs_32bit_code() {
    let Some(exe) = fixture() else { return };
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    #[derive(Default)]
    struct State {
        executed: usize,
        final_pc: u64,
        stop_reason: String,
    }

    let state = DebugSession::new(State::default(), Some(addr.as_str()))
        .expect("connect")
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "wow64_test32!wow64_marker", None, |session, pid, tid, _address| {
                match session.emulate_instructions(pid, tid, 40, EmulationMode::InstructionTrace, None, vec![])? {
                    EmulateResult::Emulation(r) => {
                        println!("emulated {} instructions, final pc {:#x}, stop {}", r.instructions_executed, r.final_pc, r.stop_reason);
                        session.state.executed = r.instructions_executed;
                        session.state.final_pc = r.final_pc;
                        session.state.stop_reason = r.stop_reason;
                    }
                    EmulateResult::Trace(t) => {
                        session.state.executed = t.instructions_executed;
                        session.state.final_pc = t.final_pc.unwrap_or(0);
                        session.state.stop_reason = t.stop_reason;
                    }
                }
                session.terminate_process(pid)?;
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .on_process_exited(|_session, _pid, _exit_code| Ok(()))
        .launch(exe)
        .expect("debug session");

    assert!(state.executed >= 10, "expected to emulate the marker prologue and its call, got {} ({})", state.executed, state.stop_reason);
    assert!(state.final_pc != 0 && state.final_pc < 0x1_0000_0000, "final pc {:#x}", state.final_pc);
}

/// Resolve one `module!symbol` to its VA (exact name match).
fn sym_va<S>(session: &mut DebugSession<S>, name: &str) -> u64 {
    let leaf = name.rsplit('!').next().unwrap();
    session
        .find_symbols(name, 8)
        .unwrap_or_default()
        .into_iter()
        .find(|s| s.name.rsplit('!').next() == Some(leaf))
        .unwrap_or_else(|| panic!("symbol {} not found", name))
        .va
}

/// Pointer scan on a 32-bit target: reads 4-byte slots and finds the static
/// `g_value_ptr -> g_value` chain (base in the main image, offset 0).
#[test]
fn wow64_pointer_scan_finds_static_chain() {
    let Some(exe) = fixture() else { return };
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    #[derive(Default)]
    struct State { paths: u64, done: bool }

    let state = DebugSession::new(State::default(), Some(addr.as_str()))
        .expect("connect")
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "wow64_test32!wow64_marker", None, |session, pid, _tid, _address| {
                let target = sym_va(session, "wow64_test32!g_value");
                let ptr_slot = sym_va(session, "wow64_test32!g_value_ptr");
                assert!(target < 0x1_0000_0000 && ptr_slot < 0x1_0000_0000);
                let main = session.list_modules(pid)?.into_iter()
                    .find(|m| m.name.to_ascii_lowercase().ends_with("hello_c32.exe") || m.name.to_ascii_lowercase().ends_with("wow64_test32.exe"))
                    .map(|m| m.base);
                // Restrict static roots to the main image so g_value_ptr is the base.
                let (results, count, _us) = session.pointer_scan_start(
                    pid, target, 0x40, 2, None, None, main.map(|b| vec![b]), None, false,
                )?;
                println!("pointer scan: {} paths", count);
                assert!(count >= 1, "expected the static g_value_ptr -> g_value chain");
                session.state.paths = count;
                session.state.done = true;
                let _ = session.pointer_scan_reset(results);
                session.terminate_process(pid)?;
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .on_process_exited(|_s, _p, _c| Ok(()))
        .launch(exe)
        .expect("debug session");
    assert!(state.done && state.paths >= 1);
}

/// Freezing through a 1-level 32-bit pointer chain resolves 4-byte pointers and
/// writes the target.
#[test]
fn wow64_freeze_through_pointer_chain() {
    let Some(exe) = fixture() else { return };
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    #[derive(Default)]
    struct State { ok: bool }

    let state = DebugSession::new(State::default(), Some(addr.as_str()))
        .expect("connect")
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "wow64_test32!wow64_marker", None, |session, pid, _tid, _address| {
                let ptr_slot = sym_va(session, "wow64_test32!g_value_ptr");
                let target = sym_va(session, "wow64_test32!g_value");
                const SENTINEL: u32 = 0x0BADF00D;
                // base = &g_value_ptr, offsets = [0] => *g_value_ptr == &g_value.
                let id = session.freeze_value(pid, ptr_slot, SENTINEL.to_le_bytes().to_vec(), Some(5), vec![0])?;
                // The freeze thread's first write needs the platform lock, so under
                // load it can land late: poll for the sentinel instead of sleeping.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                let got = loop {
                    let bytes = session.read_memory(pid, target, 4)?;
                    let v = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    if v == SENTINEL || std::time::Instant::now() >= deadline {
                        break v;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                };
                session.unfreeze_value(id)?;
                assert_eq!(got, SENTINEL, "freeze through 32-bit chain did not write g_value");
                session.state.ok = true;
                session.terminate_process(pid)?;
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .on_process_exited(|_s, _p, _c| Ok(()))
        .launch(exe)
        .expect("debug session");
    assert!(state.ok);
}

/// PEB hiding on a WOW64 target patches both the 32-bit and 64-bit PEBs.
#[test]
fn wow64_hide_peb_patches_both_pebs() {
    let Some(exe) = fixture() else { return };
    let server = TestServer::spawn();
    let addr = server.address().to_string();

    #[derive(Default)]
    struct State { applied: Vec<String>, being_debugged_after: Option<u8> }

    let state = DebugSession::new(State::default(), Some(addr.as_str()))
        .expect("connect")
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            let peb32 = session.get_peb_address(pid)?;
            assert!(peb32 < 0x1_0000_0000, "32-bit PEB {:#x} must be in the low 4 GB", peb32);
            let report = session.hide_peb(pid, PebHideOptions { being_debugged: true, nt_global_flag: true, ..Default::default() })?;
            println!("hide_peb applied: {:?}", report.applied);
            // BeingDebugged cleared in the 32-bit PEB the target's own code reads.
            let bd = session.read_memory(pid, peb32 + 0x02, 1)?[0];
            session.state.being_debugged_after = Some(bd);
            session.state.applied = report.applied;
            session.terminate_process(pid)?;
            Ok(())
        })
        .on_process_exited(|_s, _p, _c| Ok(()))
        .launch(exe)
        .expect("debug session");
    assert_eq!(state.being_debugged_after, Some(0), "32-bit PEB.BeingDebugged must be cleared");
    // Both passes ran: the report names the 32-bit and 64-bit techniques.
    assert!(state.applied.iter().any(|a| a == "being_debugged32"), "32-bit pass: {:?}", state.applied);
    assert!(state.applied.iter().any(|a| a == "being_debugged64"), "64-bit pass: {:?}", state.applied);
}
