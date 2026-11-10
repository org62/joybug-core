#![cfg(windows)]

mod common;
use common::{try_get_test_program_path, TestServer};
use joybug_core::interfaces::Architecture;
use joybug_core::protocol::{DebugEvent, DebuggerRequest, DebuggerResponse, ThreadInfo};
use joybug_core::protocol_io::{DebugSession, ExceptionAction};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, SYNCHRONIZATION_SYNCHRONIZE};

struct Event(HANDLE);
unsafe impl Send for Event {}
impl Drop for Event { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
impl Event {
    fn open(pid: u32, suffix: &str) -> Self {
        let name: Vec<u16> = format!("Local\\joybug-thread-info-{pid}-{suffix}\0").encode_utf16().collect();
        let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr()) };
        assert!(!handle.is_null(), "open fixture {suffix} event");
        Self(handle)
    }
    fn signal(&self) { assert_ne!(unsafe { SetEvent(self.0) }, 0); }
    fn wait(&self, timeout: u32) -> u32 { unsafe { WaitForSingleObject(self.0, timeout) } }
}

#[derive(Default)]
struct State {
    server_address: String,
    phase_address: u64,
    worker_address: u64,
    marker_address: u64,
    main_tid: u32,
    worker_tid: u32,
    arch: Option<Architecture>,
    phase: u32,
    exceptions: usize,
    pauses: usize,
    initial: usize,
    entries: HashMap<u32, u64>,
    creation: HashMap<u32, u64>,
    before_work: Option<ThreadInfo>,
    running: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
    breakin: bool,
    exit: Option<u32>,
}

fn value(session: &mut DebugSession<State>, pid: u32, address: u64) -> anyhow::Result<u32> {
    let bytes = session.read_memory(pid, address, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

fn assert_counters_monotonic(before: &ThreadInfo, after: &ThreadInfo) {
    assert_eq!(before.creation_time_filetime_100ns, after.creation_time_filetime_100ns);
    assert!(after.user_time_100ns.unwrap() >= before.user_time_100ns.unwrap());
    assert!(after.kernel_time_100ns.unwrap() >= before.kernel_time_100ns.unwrap());
    assert!(after.cpu_cycles.unwrap() > before.cpu_cycles.unwrap(), "cycles increase across controlled CPU work only");
}

fn marker(session: &mut DebugSession<State>, pid: u32, tid: u32, address: u64) -> anyhow::Result<()> {
    let phase_address = session.state.phase_address;
    let phase = value(session, pid, phase_address)?;
    assert_eq!(phase, session.state.phase + 1, "no skipped fixture checkpoint");
    session.state.phase = phase;
    assert_eq!(tid, session.state.main_tid);
    let worker_address = session.state.worker_address;
    let worker_tid = value(session, pid, worker_address)?;
    session.state.worker_tid = worker_tid;
    let threads = session.list_threads(pid)?;
    assert!(threads.iter().all(|row| row.tid != 0xFFFFFFFE), "unknown target never creates a phantom thread");
    let main = threads.iter().find(|row| row.tid == tid).expect("main thread");
    let arch = session.state.arch.unwrap();
    assert_eq!(main.suspend_count, Some(1), "native count includes the debug-event freeze");
    assert_eq!(main.last_error, Some(0x1234ABCD), "call-free marker preserves LastErrorValue");
    assert_eq!(main.teb_architecture, Some(arch));
    assert_eq!(main.instruction_pointer_architecture, Some(arch));
    assert_eq!(main.instruction_pointer, Some(session.get_thread_context(pid, tid)?.pc()));
    let teb = main.teb_address.expect("validated TEB");
    let self_offset = if arch == Architecture::X86 { 0x18 } else { 0x30 };
    let self_bytes = session.read_memory(pid, teb + self_offset, if arch == Architecture::X86 { 4 } else { 8 })?;
    let self_address = if arch == Architecture::X86 { u32::from_le_bytes(self_bytes.try_into().unwrap()) as u64 } else { u64::from_le_bytes(self_bytes.try_into().unwrap()) };
    assert_eq!(self_address, teb, "NT_TIB.Self validates actual layout");
    if arch == Architecture::X86 { assert!(teb <= u32::MAX as u64); }
    for row in &threads {
        if let Some(&entry) = session.state.entries.get(&row.tid) {
            if entry != 0 { assert_eq!(row.start_address, entry, "preserve actual debug-event Entry"); }
        }
        if row.tid == tid || row.tid == worker_tid {
            let creation = row.creation_time_filetime_100ns.expect("creation FILETIME available");
            if let Some(previous) = session.state.creation.insert(row.tid, creation) { assert_eq!(previous, creation); }
            assert!(row.user_time_100ns.is_some() && row.kernel_time_100ns.is_some() && row.cpu_cycles.is_some());
        }
    }
    let expected_name = match phase {
        1 => Some(" legacy main "), 2 => Some("renamed main"), 3 => Some("edge"),
        4 => None, // ACP depends on the machine's configured Windows code page.
        5 => Some("modern main λ"), 6 | 7 => Some("modern renamed 🐞"),
        8 => Some("latest legacy"), 9 => None, 15 => Some("running rename Δ"),
        _ => Some("native four"),
    };
    if phase == 4 { assert!(main.name.as_ref().is_some_and(|name| !name.is_empty())); }
    else { assert_eq!(main.name.as_deref(), expected_name, "phase {phase}"); }
    if phase < 15 {
        let worker = threads.iter().find(|row| row.tid == worker_tid).expect("worker");
        assert_eq!(worker.name.as_deref(), Some(if phase < 5 { "legacy worker" } else { "现代 worker Ω" }));
        assert_eq!(worker.priority, Some(-1));
        assert_eq!(worker.teb_architecture, Some(arch));
        assert_eq!(worker.suspend_count, Some(1), "debug freeze also covers the worker");
        if phase == 12 {
            session.state.before_work = Some(worker.clone());
            session.suspend_thread(pid, worker_tid)?;
            assert_eq!(session.list_threads(pid)?.into_iter().find(|row| row.tid == worker_tid).unwrap().suspend_count, Some(2));
            session.suspend_thread(pid, worker_tid)?;
            let row = session.list_threads(pid)?.into_iter().find(|row| row.tid == worker_tid).unwrap();
            assert_eq!(row.suspend_count, Some(3), "nested suspensions add to the debug freeze");
            session.resume_thread(pid, worker_tid)?;
            assert_eq!(session.list_threads(pid)?.into_iter().find(|row| row.tid == worker_tid).unwrap().suspend_count, Some(2));
            session.resume_thread(pid, worker_tid)?;
            assert_eq!(session.list_threads(pid)?.into_iter().find(|row| row.tid == worker_tid).unwrap().suspend_count, Some(1), "user resumes leave the debug freeze");
        }
        if phase == 13 { assert_counters_monotonic(session.state.before_work.as_ref().unwrap(), worker); }
    }
    if phase == 11 { assert_eq!(session.state.exceptions, 7, "every invalid notification reaches ordinary exception policy"); }
    if phase == 14 {
        let running_event = Event::open(pid, "running");
        let release_event = Event::open(pid, "release");
        let address = session.state.running.take();
        assert!(address.is_none());
        // The helper's first operation is an event wait. The marker callback can
        // return and the debug loop continues normally while this OOB client polls.
        let server_address = session.state.server_address.clone();
        let main_tid = tid;
        session.state.running = Some(std::thread::spawn(move || {
            struct Release(Option<Event>);
            impl Drop for Release { fn drop(&mut self) { if let Some(event) = &self.0 { event.signal(); } } }
            let mut release_on_failure = Release(Some(release_event));
            assert_eq!(running_event.wait(30000), 0, "fixture entered real running phase");
            let mut oob = DebugSession::new((), Some(&server_address))?;
            oob.set_read_timeout(Some(Duration::from_secs(15)))?;
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let rows = oob.list_threads(pid)?;
                let worker = rows.iter().find(|row| row.tid == worker_tid).expect("live worker");
                let main = rows.iter().find(|row| row.tid == main_tid).expect("live main");
                if worker.thread_state == Some(5) && main.thread_state == Some(5) && worker.instruction_pointer.is_none() && main.instruction_pointer.is_none() {
                    assert!(matches!(worker.wait_reason, Some(6) | Some(13)), "event wait has a native UserRequest/WrUserRequest reason");
                    assert_eq!(worker.suspend_count, Some(0));
                    assert_eq!(main.suspend_count, Some(0));
                    assert_eq!(worker.instruction_pointer_architecture, None);
                    assert_eq!(main.instruction_pointer_architecture, None);
                    break;
                }
                assert!(Instant::now() < deadline, "waiting threads become observable without a debug freeze");
                std::thread::yield_now();
            }
            // A modern description-only rename while Running must appear on the
            // next ordinary ListThreads snapshot, without another debug event.
            use windows_sys::Win32::System::Threading::{OpenThread, SetThreadDescription, THREAD_SET_LIMITED_INFORMATION};
            let thread = unsafe { OpenThread(THREAD_SET_LIMITED_INFORMATION, 0, main_tid) };
            assert!(!thread.is_null());
            let name: Vec<u16> = "running rename Δ\0".encode_utf16().collect();
            let status = unsafe { SetThreadDescription(thread, name.as_ptr()) };
            unsafe { CloseHandle(thread); }
            assert!(status >= 0);
            assert_eq!(oob.list_threads(pid)?.into_iter().find(|row| row.tid == main_tid).unwrap().name.as_deref(), Some("running rename Δ"));
            match oob.send_and_receive(&DebuggerRequest::BreakInto { pid })? {
                DebuggerResponse::Error { message } => anyhow::bail!("pause: {message}"),
                _ => {}
            }
            // The breakpoint callback releases both fixture threads only after
            // verifying the injected native break-in thread. Do not signal early.
            drop(release_on_failure.0.take());
            Ok(())
        }));
    }
    // ARM64 BRK leaves PC on the trap; the fixture's intrinsic is known to us.
    if arch == Architecture::Arm64 {
        let mut context = session.get_thread_context(pid, tid)?;
        context.set_pc(address + 4);
        session.set_thread_context(pid, tid, context)?;
    }
    Ok(())
}

fn run(name: &str) {
    let Some(exe) = try_get_test_program_path(name) else {
        if name.ends_with("32") { println!("skipping: {name} requires the x86 MSVC fixture toolchain"); return; }
        panic!("native thread-information fixture must be built");
    };
    let server = TestServer::spawn();
    let address = server.address().to_string();
    let mut state = State::default();
    state.server_address = address.clone();
    let module = name.to_owned();
    let final_state = DebugSession::new(state, Some(&address)).expect("connect")
        .on_thread_created(|session, _pid, tid, entry| { session.state.entries.insert(tid, entry); Ok(()) })
        .on_initial_breakpoint(move |session, pid, tid, _| {
            session.state.initial += 1;
            session.state.main_tid = tid;
            session.state.arch = Some(session.get_process_architecture(pid)?);
            session.state.phase_address = session.find_symbols(&format!("{module}!g_phase"), 1)?[0].va;
            session.state.worker_address = session.find_symbols(&format!("{module}!g_worker_tid"), 1)?[0].va;
            let marker = session.find_symbols(&format!("{module}!thread_info_marker"), 1)?[0].va;
            session.state.marker_address = session.disassemble_memory(pid, marker, 24, session.state.arch.unwrap())?
                .into_iter().find(|instruction| matches!(instruction.mnemonic.as_str(), "int3" | "brk"))
                .expect("call-free intrinsic trap marker").address;
            Ok(())
        })
        .on_exception(|session, _pid, _tid, code, _address, first_chance, _params| {
            assert_eq!(code, 0x406D1388, "no unrelated fixture exception");
            assert!(first_chance);
            assert_eq!(session.state.phase, 10, "valid names never reach exception policy");
            session.state.exceptions += 1;
            Ok(ExceptionAction::PassToApplication)
        })
        .on_event(|session, event| {
            if let DebugEvent::ProcessCreated { tid, start_address, .. } = event {
                session.state.entries.insert(*tid, *start_address);
            }
            if let DebugEvent::Breakpoint { pid, tid, address } = event {
                session.state.pauses += 1;
                if *address == session.state.marker_address {
                    marker(session, *pid, *tid, *address)?;
                } else {
                    assert_eq!(session.state.phase, 14, "no extra user-visible stops from naming notifications");
                    let rows = session.list_threads(*pid)?;
                    let row = rows.iter().find(|row| row.tid == *tid).expect("native break-in row");
                    assert!(row.start_address > u32::MAX as u64);
                    assert_eq!(session.state.entries.get(tid), Some(&row.start_address));
                    assert_ne!(row.teb_architecture, Some(Architecture::X86));
                    let teb = row.teb_address.expect("native break-in TEB");
                    let self_bytes = session.read_memory(*pid, teb + 0x30, 8)?;
                    assert_eq!(u64::from_le_bytes(self_bytes.try_into().unwrap()), teb);
                    assert!(row.instruction_pointer.expect("native break-in CONTROL sample") > u32::MAX as u64);
                    assert_eq!(row.instruction_pointer_architecture, row.teb_architecture);
                    assert_eq!(row.suspend_count, Some(1), "native break-in thread includes the debug freeze");
                    session.state.breakin = true;
                    session.state.running.take().expect("OOB helper").join().expect("helper panic")?;
                    Event::open(*pid, "release").signal();
                }
            }
            Ok(true)
        })
        .on_process_exited(|session, _pid, code| { session.state.exit = Some(code); Ok(()) })
        .launch(format!("\"{exe}\""))
        .expect("real debug session");
    if let Some(helper) = final_state.running { helper.join().expect("helper panic").expect("OOB helper"); }
    assert_eq!(final_state.initial, 1);
    assert_eq!(final_state.phase, 15);
    assert_eq!(final_state.exceptions, 7);
    assert_eq!(final_state.pauses, 16, "15 markers plus one explicitly requested native break-in");
    assert!(final_state.breakin);
    assert_eq!(final_state.exit, Some(0));
}

#[test]
fn native_thread_names_and_metadata() { run("thread_info_test"); }
#[test]
fn wow64_thread_names_and_metadata() { run("thread_info_test32"); }
