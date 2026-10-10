#![cfg(target_os = "linux")]

//! The Handles window's data on Linux (file descriptors, sockets,
//! capabilities), closing a descriptor in the target, and core files.

mod common;

use common::{get_test_program_path, TestServer};
use joybug_core::protocol::{DebugEvent, MinidumpKind};
use joybug_core::protocol_io::{BreakpointDecision, DebugSession, ExceptionAction};
use object::read::elf::{FileHeader, ProgramHeader};
use object::{elf, Endianness};

#[derive(Default)]
struct State {
    exit_code: Option<u32>,
    checked: bool,
}

fn session(server: &TestServer) -> DebugSession<State> {
    DebugSession::new(State::default(), Some(server.address())).expect("connect").on_event(|session, event| {
        if let DebugEvent::ProcessExited { exit_code, .. } = event {
            session.state.exit_code = Some(*exit_code);
        }
        Ok(true)
    })
}

#[test]
fn descriptors_are_listed_and_one_can_be_closed() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let state = session(&server)
        .on_initial_breakpoint(|session, pid, _tid, _address| {
            session.set_breakpoint_by_symbol(pid, "fds!checkpoint", None, |session, pid, tid, _address| {
                let args = session.get_arguments(pid, tid, 2)?;
                let (file, sock) = (args[0], args[1]);
                let objects = session.list_process_objects(pid)?;
                assert!(objects.warnings.is_empty(), "{:?}", objects.warnings);
                assert!(objects.windows.is_empty());

                let row = |fd: u64| objects.handles.iter().find(|h| h.handle == fd).unwrap_or_else(|| panic!("fd {fd} listed: {:?}", objects.handles));
                assert!(objects.handles.windows(2).all(|w| w[0].handle < w[1].handle), "sorted by descriptor");
                for std_fd in 0..3 {
                    row(std_fd);
                }
                assert_eq!(row(file).type_name, "File");
                assert_eq!(row(file).name, format!("/proc/{pid}/maps"));
                assert_eq!(row(file).granted_access & 3, 0, "O_RDONLY");
                assert_eq!(row(file).attributes & 2, 2, "opened without O_CLOEXEC: inherited across exec");

                assert_eq!(row(sock).type_name, "Socket");
                assert!(row(sock).name.starts_with("TCP 127.0.0.1:") && row(sock).name.ends_with("(LISTEN)"), "{}", row(sock).name);
                let listener = objects.tcp_connections.iter().find(|c| c.state == "LISTEN").expect("the listening socket");
                assert_eq!(listener.local_address, "127.0.0.1");
                assert_ne!(listener.local_port, 0, "the kernel picked a port");

                assert_eq!(objects.handles.iter().filter(|h| h.type_name == "Pipe").count() >= 2, true, "both pipe ends: {:?}", objects.handles);

                // close(file) inside the target; the program checks for it.
                session.close_remote_handle(pid, file)?;
                let after = session.list_process_objects(pid)?;
                assert!(after.handles.iter().all(|h| h.handle != file), "closed");
                assert!(session.close_remote_handle(pid, file).is_err(), "closing it again is EBADF");
                // The injected call left the thread's registers alone.
                assert_eq!(session.get_arguments(pid, tid, 2)?, vec![file, sock]);
                session.state.checked = true;
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .launch(get_test_program_path("fds"))
        .expect("launch");
    assert!(state.checked, "the checkpoint was reached");
    assert_eq!(state.exit_code, Some(21), "the program found its descriptor closed");
}

/// The PT_LOAD of `core` that holds `address`, as `(file offset, bytes in the file)`.
fn load_segment_for(core: &[u8], address: u64) -> Option<(u64, u64)> {
    let header = elf::FileHeader64::<Endianness>::parse(core).ok()?;
    let endian = header.endian().ok()?;
    header.program_headers(endian, core).ok()?.iter().find_map(|ph| {
        let (start, size) = (ph.p_vaddr(endian), ph.p_filesz(endian));
        (ph.p_type(endian) == elf::PT_LOAD && address >= start && address < start + size).then(|| (ph.p_offset(endian) + (address - start), start + size - address))
    })
}

/// The descriptor of the first note of type `wanted` in `core`'s PT_NOTE.
fn core_note(core: &[u8], wanted: u32) -> Option<Vec<u8>> {
    let header = elf::FileHeader64::<Endianness>::parse(core).ok()?;
    let endian = header.endian().ok()?;
    let notes = header.program_headers(endian, core).ok()?.iter().find(|ph| ph.p_type(endian) == elf::PT_NOTE)?;
    let notes = &core[notes.p_offset(endian) as usize..(notes.p_offset(endian) + notes.p_filesz(endian)) as usize];
    let u32_at = |at: usize| u32::from_le_bytes(notes[at..at + 4].try_into().unwrap()) as usize;
    let mut at = 0;
    while at + 12 <= notes.len() {
        let (name_size, desc_size, kind) = (u32_at(at), u32_at(at + 4), u32_at(at + 8) as u32);
        let desc = at + 12 + name_size.next_multiple_of(4);
        if kind == wanted {
            return Some(notes[desc..desc + desc_size].to_vec());
        }
        at = desc + desc_size.next_multiple_of(4);
    }
    None
}

const NT_SIGINFO: u32 = 0x5349_4749;

/// A core written while stopped on a fault carries its `siginfo_t`: the
/// signal, its `si_code` and the address that faulted (gdb's `$_siginfo`).
#[test]
fn a_core_file_at_a_fault_records_its_siginfo() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let dir = std::env::temp_dir().join(format!("joybug-core-siginfo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("segv.core");
    let core_path = path.clone();

    let state = session(&server)
        .on_exception(move |session, pid, _tid, code, _address, first_chance, _params| {
            if first_chance {
                assert_eq!(code, 0xC000_0005);
                session.write_minidump(pid, core_path.to_str().unwrap(), MinidumpKind::Mini)?;
                session.state.checked = true;
            }
            // Delivered: nobody handles it, so the target dies of it.
            Ok(ExceptionAction::PassToApplication)
        })
        .launch(get_test_program_path("segv"))
        .expect("launch");
    assert!(state.checked, "the fault was reported");

    let core = std::fs::read(&path).unwrap();
    let info = core_note(&core, NT_SIGINFO).expect("NT_SIGINFO");
    assert_eq!(info.len(), 128, "a whole siginfo_t");
    let i32_at = |at: usize| i32::from_le_bytes(info[at..at + 4].try_into().unwrap());
    assert_eq!(i32_at(0), 11, "si_signo: SIGSEGV");
    assert_eq!(i32_at(8), 1, "si_code: SEGV_MAPERR, nothing mapped at NULL");
    assert_eq!(u64::from_le_bytes(info[16..24].try_into().unwrap()), 0, "si_addr: the NULL write");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_core_file_holds_the_stack_and_opens_in_gdb() {
    joybug_core::init_tracing();
    let server = TestServer::spawn();
    let dir = std::env::temp_dir().join(format!("joybug-core-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (full_path, mini_path) = (dir.join("hello.full.core"), dir.join("hello.mini.core"));
    let (full, mini) = (full_path.clone(), mini_path.clone());
    let hello = get_test_program_path("hello");

    let state = session(&server)
        .on_initial_breakpoint(move |session, pid, _tid, _address| {
            let (full, mini) = (full.clone(), mini.clone());
            session.set_breakpoint_by_symbol(pid, "hello!compute", None, move |session, pid, tid, address| {
                let full_size = session.write_minidump(pid, full.to_str().unwrap(), MinidumpKind::Full)?;
                let mini_size = session.write_minidump(pid, mini.to_str().unwrap(), MinidumpKind::Mini)?;
                assert_eq!(full_size, std::fs::metadata(&full)?.len());
                assert!(mini_size < full_size, "mini {mini_size} < full {full_size}");

                let ctx = session.get_thread_context(pid, tid)?;
                let stack = session.read_memory(pid, ctx.sp(), 64)?;
                for path in [&full, &mini] {
                    let core = std::fs::read(path)?;
                    let header = elf::FileHeader64::<Endianness>::parse(&*core).expect("an ELF64 file");
                    let endian = header.endian().unwrap();
                    assert_eq!(header.e_type(endian), elf::ET_CORE);
                    assert_eq!(header.e_machine(endian), elf::EM_X86_64);
                    // The stack is in both kinds, byte for byte.
                    let (offset, available) = load_segment_for(&core, ctx.sp()).expect("the stack is saved");
                    assert!(available >= 64);
                    assert_eq!(&core[offset as usize..offset as usize + 64], &stack[..]);
                    // The registers are in the notes: the PC appears in NT_PRSTATUS.
                    let notes = header
                        .program_headers(endian, &*core)
                        .unwrap()
                        .iter()
                        .find(|ph| ph.p_type(endian) == elf::PT_NOTE)
                        .map(|ph| &core[ph.p_offset(endian) as usize..(ph.p_offset(endian) + ph.p_filesz(endian)) as usize])
                        .expect("PT_NOTE");
                    assert!(notes.windows(8).any(|w| w == address.to_le_bytes()), "the breakpoint address is the saved PC");
                    // A breakpoint is the debugger's stop, not a signal the target got.
                    assert!(core_note(&core, NT_SIGINFO).is_none(), "no siginfo at a breakpoint stop");
                }
                // Code: saved in the full dump with the breakpoint byte taken
                // out, left to the binary on disk in the mini one.
                let core = std::fs::read(&full)?;
                let (offset, _) = load_segment_for(&core, address).expect("code is in the full dump");
                assert_ne!(core[offset as usize], 0xCC, "the debugger's breakpoint is not in the dump");
                assert!(load_segment_for(&std::fs::read(&mini)?, address).is_none(), "code is not in the mini dump");
                session.state.checked = true;
                Ok(BreakpointDecision::Remove)
            })?;
            Ok(())
        })
        .launch(hello.clone())
        .expect("launch");
    assert!(state.checked);
    assert_eq!(state.exit_code, Some(42), "the target ran on after the dump");

    // A real consumer: gdb unwinds both from the saved registers and stack.
    if std::path::Path::new("/usr/bin/gdb").exists() {
        for path in [&full_path, &mini_path] {
            let out = std::process::Command::new("/usr/bin/gdb")
                .args(["-nx", "-batch", "-ex", "bt", &hello, path.to_str().unwrap()])
                .output()
                .expect("run gdb");
            let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            for frame in ["compute", "hello_marker", "main"] {
                assert!(text.contains(frame), "gdb's backtrace of {} names {frame}:\n{text}", path.display());
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
