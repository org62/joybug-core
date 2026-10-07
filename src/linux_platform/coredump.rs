//! `write_minidump` on Linux: an ELF core file of the stopped target, in the
//! layout the kernel writes (`fs/binfmt_elf.c`) so gdb, lldb and `eu-stack`
//! open it like any other core.
//!
//! ```text
//! ELF header (ET_CORE)
//! program headers: PT_NOTE, then one PT_LOAD per mapping
//! notes:  per thread NT_PRSTATUS + NT_FPREGSET (the thread that faulted
//!         first: debuggers show the first one as the crashing thread),
//!         NT_PRPSINFO, NT_AUXV, NT_FILE (which file backs which range)
//! memory: page-aligned, in mapping order
//! ```
//!
//! `MinidumpKind::Full` saves every readable mapping. `Mini` is the kernel's
//! default `coredump_filter`: what the process could have written (anonymous
//! and writable mappings: stacks, heap, data) plus the first page of each
//! file mapping (its ELF header, so a debugger can match the file by build
//! id) - code comes back from the binaries on disk.
//!
//! The debugger's own breakpoint bytes are taken out of the saved memory.

use std::fs::{self, File};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use tracing::{debug, info};

use super::maps::{self, Mapping};
use super::regs::RegisterImage;
use super::{procfs, LinuxPlatform, LinuxProcess};
use crate::debugger_core::ops::ProcessOps;
use crate::interfaces::PlatformError;
use crate::protocol::MinidumpKind;

const PAGE: u64 = 4096;
const EHDR_SIZE: u64 = 64;
const PHDR_SIZE: u64 = 56;
const SHDR_SIZE: u64 = 64;

const ET_CORE: u16 = 4;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
/// `e_phnum` when the real count lives in section header 0's `sh_info`.
const PN_XNUM: u16 = 0xFFFF;

const NT_PRSTATUS: u32 = 1;
const NT_FPREGSET: u32 = 2;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x4649_4C45;

const PRSTATUS_SIZE: usize = 336;
const PRSTATUS_PID: usize = 32;
const PRSTATUS_REGS: usize = 112;
const PRSTATUS_FPVALID: usize = 328;
const PRPSINFO_SIZE: usize = 136;

const _: () = assert!(std::mem::size_of::<libc::user_regs_struct>() == 27 * 8);
const _: () = assert!(PRSTATUS_REGS + 27 * 8 == PRSTATUS_FPVALID);

/// One PT_LOAD: a mapping and how much of it goes into the file.
struct Segment {
    map: Mapping,
    file_size: u64,
}

pub fn write_core(platform: &LinuxPlatform, pid: u32, path: &Path, kind: MinidumpKind) -> Result<u64, PlatformError> {
    let process = platform.process(pid)?;
    if process.open_only {
        return Err(PlatformError::Other("a core file needs the thread registers: attach to the process first".into()));
    }
    let threads = thread_images(process, pid)?;
    let mappings = maps::read_maps(pid).map_err(|e| PlatformError::OsError(format!("/proc/{pid}/maps: {e}")))?;
    let notes = build_notes(process, pid, &threads, &mappings);
    let segments: Vec<Segment> = mappings.into_iter().map(|map| Segment { file_size: dumped_size(&map, kind), map }).collect();
    info!(pid, path = %path.display(), ?kind, threads = threads.len(), segments = segments.len(), "writing core file");

    let file = File::create(path).map_err(|e| PlatformError::OsError(format!("create {}: {e}", path.display())))?;
    let result = write_file(process, pid, file, &notes, &segments);
    match result {
        Ok(size) => Ok(size),
        Err(e) => {
            let _ = fs::remove_file(path);
            Err(PlatformError::OsError(format!("write {}: {e}", path.display())))
        }
    }
}

/// Registers of every thread, the thread with a pending fault first.
fn thread_images(process: &LinuxProcess, pid: u32) -> Result<Vec<(u32, RegisterImage, i32)>, PlatformError> {
    let mut tids = process.os.live_threads(pid);
    tids.sort_unstable();
    // Faulting thread first, then the main thread, then the rest.
    tids.sort_by_key(|tid| (!process.last_fault.contains_key(tid), *tid != pid));
    let mut out = Vec::with_capacity(tids.len());
    for tid in tids {
        match process.os.image(tid) {
            Ok(image) => out.push((tid, image, process.last_fault.get(&tid).map(|p| p.signo).unwrap_or(0))),
            // Exiting under us is fine; a running thread is not a snapshot.
            Err(e) => debug!(pid, tid, error = %e, "thread left out of the core file"),
        }
    }
    if out.is_empty() {
        return Err(PlatformError::Other("no stopped thread to take registers from: pause the target first".into()));
    }
    Ok(out)
}

/// How many bytes of a mapping are saved.
fn dumped_size(map: &Mapping, kind: MinidumpKind) -> u64 {
    let size = map.end - map.start;
    // Not ours to read: the kernel's own pages, and inaccessible ranges.
    if !map.read || map.path == "[vvar]" || map.path == "[vvar_vclock]" || map.path == "[vsyscall]" {
        return 0;
    }
    match kind {
        MinidumpKind::Full => size,
        MinidumpKind::Mini => {
            if !map.is_file_backed() || map.write {
                size
            } else if map.offset == 0 {
                size.min(PAGE)
            } else {
                0
            }
        }
    }
}

fn write_file(process: &LinuxProcess, pid: u32, file: File, notes: &[u8], segments: &[Segment]) -> std::io::Result<u64> {
    let phnum = segments.len() as u64 + 1;
    let extended = phnum >= PN_XNUM as u64;
    let phoff = EHDR_SIZE;
    let notes_offset = phoff + phnum * PHDR_SIZE;
    let shoff = if extended { align_up(notes_offset + notes.len() as u64, 8) } else { 0 };
    let headers_end = if extended { shoff + SHDR_SIZE } else { notes_offset + notes.len() as u64 };
    let data_offset = align_up(headers_end, PAGE);

    let mut out = BufWriter::with_capacity(1 << 20, file);

    // ---- ELF header
    let mut ehdr = Vec::with_capacity(EHDR_SIZE as usize);
    ehdr.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2 /* 64-bit */, 1 /* little endian */, 1 /* EV_CURRENT */, 0 /* SysV */]);
    ehdr.extend_from_slice(&[0; 8]);
    ehdr.extend_from_slice(&ET_CORE.to_le_bytes());
    ehdr.extend_from_slice(&EM_X86_64.to_le_bytes());
    ehdr.extend_from_slice(&1u32.to_le_bytes()); // e_version
    ehdr.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    ehdr.extend_from_slice(&phoff.to_le_bytes());
    ehdr.extend_from_slice(&shoff.to_le_bytes());
    ehdr.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    ehdr.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
    ehdr.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
    ehdr.extend_from_slice(&(if extended { PN_XNUM } else { phnum as u16 }).to_le_bytes());
    ehdr.extend_from_slice(&(if extended { SHDR_SIZE as u16 } else { 0 }).to_le_bytes()); // e_shentsize
    ehdr.extend_from_slice(&(if extended { 1u16 } else { 0 }).to_le_bytes()); // e_shnum
    ehdr.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    out.write_all(&ehdr)?;

    // ---- program headers
    out.write_all(&phdr(PT_NOTE, 0, notes_offset, 0, notes.len() as u64, 0, 4))?;
    let mut offset = data_offset;
    for seg in segments {
        let flags = (seg.map.exec as u32) | (seg.map.write as u32) << 1 | (seg.map.read as u32) << 2;
        out.write_all(&phdr(PT_LOAD, flags, offset, seg.map.start, seg.file_size, seg.map.end - seg.map.start, PAGE))?;
        offset += seg.file_size;
    }
    let total = offset;

    out.write_all(notes)?;
    if extended {
        pad_to(&mut out, notes_offset + notes.len() as u64, shoff)?;
        // Section header 0: sh_info carries the real program header count.
        let mut shdr = [0u8; SHDR_SIZE as usize];
        shdr[44..48].copy_from_slice(&(phnum as u32).to_le_bytes());
        out.write_all(&shdr)?;
    }
    pad_to(&mut out, headers_end, data_offset)?;

    // ---- memory. Pages that cannot be read (a guard page inside a mapping,
    // a mapping truncated under us) are left as holes: zeros, and no disk.
    const CHUNK: u64 = 1 << 20;
    for seg in segments {
        let mut at = seg.map.start;
        let end = seg.map.start + seg.file_size;
        while at < end {
            let len = (end - at).min(CHUNK);
            let mut data = process.os.read(pid, at, len as usize).unwrap_or_default();
            process.book.bps.patch_breakpoint_bytes(at, &mut data);
            out.write_all(&data)?;
            let got = data.len() as u64;
            if got < len {
                // Skip to the next page boundary past the unreadable byte.
                let skip = (align_up(at + got + 1, PAGE).min(at + len)) - (at + got);
                out.seek(SeekFrom::Current(skip as i64))?;
                at += got + skip;
            } else {
                at += len;
            }
        }
    }
    out.flush()?;
    let file = out.into_inner().map_err(|e| e.into_error())?;
    // A trailing hole is not part of the file until its length says so.
    file.set_len(total)?;
    Ok(total)
}

fn align_up(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

fn pad_to(out: &mut impl Write, from: u64, to: u64) -> std::io::Result<()> {
    out.write_all(&vec![0u8; (to - from) as usize])
}

fn phdr(p_type: u32, flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64, align: u64) -> [u8; PHDR_SIZE as usize] {
    let mut h = [0u8; PHDR_SIZE as usize];
    h[0..4].copy_from_slice(&p_type.to_le_bytes());
    h[4..8].copy_from_slice(&flags.to_le_bytes());
    h[8..16].copy_from_slice(&offset.to_le_bytes());
    h[16..24].copy_from_slice(&vaddr.to_le_bytes());
    // p_paddr stays 0.
    h[32..40].copy_from_slice(&filesz.to_le_bytes());
    h[40..48].copy_from_slice(&memsz.to_le_bytes());
    h[48..56].copy_from_slice(&align.to_le_bytes());
    h
}

// ============================================================================
// Notes
// ============================================================================

fn push_note(out: &mut Vec<u8>, note_type: u32, desc: &[u8]) {
    const NAME: &[u8] = b"CORE\0";
    out.extend_from_slice(&(NAME.len() as u32).to_le_bytes());
    out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    out.extend_from_slice(&note_type.to_le_bytes());
    out.extend_from_slice(NAME);
    out.resize(out.len().next_multiple_of(4), 0);
    out.extend_from_slice(desc);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// Plain-old-data as bytes.
fn pod_bytes<T: Copy>(value: &T) -> &[u8] {
    // SAFETY: `T` is a C register struct with no padding-dependent meaning;
    // reading its bytes is always defined for the lifetime of the borrow.
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
}

/// `/proc/pid/stat` fields after the command name: state, ppid, pgrp, session.
fn stat_fields(pid: u32) -> (u8, u32, u32, u32) {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    // The command name is parenthesised and may itself contain ") ".
    let rest = stat.rsplit_once(") ").map(|(_, r)| r).unwrap_or("");
    let mut fields = rest.split(' ');
    let state = fields.next().and_then(|s| s.bytes().next()).unwrap_or(b'T');
    let mut number = || fields.next().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) as u32;
    (state, number(), number(), number())
}

fn status_ids(pid: u32, key: &str) -> u32 {
    procfs::status(pid)
        .and_then(|s| procfs::status_field(&s, key)?.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

fn build_notes(process: &LinuxProcess, pid: u32, threads: &[(u32, RegisterImage, i32)], mappings: &[Mapping]) -> Vec<u8> {
    let (state, ppid, pgrp, sid) = stat_fields(pid);
    let mut notes = Vec::new();
    for (index, (tid, image, signo)) in threads.iter().enumerate() {
        let mut prstatus = [0u8; PRSTATUS_SIZE];
        prstatus[0..4].copy_from_slice(&signo.to_le_bytes()); // pr_info.si_signo
        prstatus[12..14].copy_from_slice(&(*signo as i16).to_le_bytes()); // pr_cursig
        for (i, value) in [*tid, ppid, pgrp, sid].into_iter().enumerate() {
            prstatus[PRSTATUS_PID + i * 4..PRSTATUS_PID + i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        prstatus[PRSTATUS_REGS..PRSTATUS_FPVALID].copy_from_slice(pod_bytes(&image.regs));
        prstatus[PRSTATUS_FPVALID..PRSTATUS_FPVALID + 4].copy_from_slice(&1u32.to_le_bytes());
        push_note(&mut notes, NT_PRSTATUS, &prstatus);
        if index == 0 {
            push_note(&mut notes, NT_PRPSINFO, &prpsinfo(process, pid, state, ppid, pgrp, sid));
            if let Ok(auxv) = fs::read(format!("/proc/{pid}/auxv")) {
                push_note(&mut notes, NT_AUXV, &auxv);
            }
            if let Some(files) = file_note(mappings) {
                push_note(&mut notes, NT_FILE, &files);
            }
        }
        push_note(&mut notes, NT_FPREGSET, pod_bytes(&image.fpregs));
    }
    notes
}

fn prpsinfo(process: &LinuxProcess, pid: u32, state: u8, ppid: u32, pgrp: u32, sid: u32) -> [u8; PRPSINFO_SIZE] {
    let mut info = [0u8; PRPSINFO_SIZE];
    // pr_state is the index of pr_sname in "RSDTZW".
    info[0] = b"RSDTZW".iter().position(|c| *c == state).unwrap_or(0) as u8;
    info[1] = state;
    info[2] = (state == b'Z') as u8;
    info[16..20].copy_from_slice(&status_ids(pid, "Uid:").to_le_bytes());
    info[20..24].copy_from_slice(&status_ids(pid, "Gid:").to_le_bytes());
    for (i, value) in [pid, ppid, pgrp, sid].into_iter().enumerate() {
        info[24 + i * 4..28 + i * 4].copy_from_slice(&value.to_le_bytes());
    }
    let fname = process.exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    copy_truncated(&mut info[40..56], fname.as_bytes());
    let mut args = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    while args.last() == Some(&0) {
        args.pop();
    }
    for b in &mut args {
        if *b == 0 {
            *b = b' ';
        }
    }
    copy_truncated(&mut info[56..136], &args);
    info
}

/// Copy into a fixed, NUL-terminated field.
fn copy_truncated(field: &mut [u8], value: &[u8]) {
    let n = value.len().min(field.len() - 1);
    field[..n].copy_from_slice(&value[..n]);
}

/// NT_FILE: `count, page_size, (start, end, file offset in pages)*, names`.
fn file_note(mappings: &[Mapping]) -> Option<Vec<u8>> {
    let files: Vec<&Mapping> = mappings.iter().filter(|m| m.is_file_backed()).collect();
    if files.is_empty() {
        return None;
    }
    let mut note = Vec::new();
    note.extend_from_slice(&(files.len() as u64).to_le_bytes());
    note.extend_from_slice(&PAGE.to_le_bytes());
    for m in &files {
        note.extend_from_slice(&m.start.to_le_bytes());
        note.extend_from_slice(&m.end.to_le_bytes());
        note.extend_from_slice(&(m.offset / PAGE).to_le_bytes());
    }
    for m in &files {
        note.extend_from_slice(procfs::clean_map_path(&m.path).as_os_str().as_encoded_bytes());
        note.push(0);
    }
    Some(note)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(path: &str, write: bool, offset: u64, pages: u64) -> Mapping {
        Mapping { start: 0x1000, end: 0x1000 + pages * PAGE, read: true, write, exec: false, shared: false, offset, path: path.to_string() }
    }

    #[test]
    fn mini_keeps_what_the_process_could_write() {
        assert_eq!(dumped_size(&mapping("[stack]", true, 0, 8), MinidumpKind::Mini), 8 * PAGE);
        assert_eq!(dumped_size(&mapping("", false, 0, 3), MinidumpKind::Mini), 3 * PAGE, "anonymous");
        assert_eq!(dumped_size(&mapping("/usr/lib/libc.so.6", true, 0x1000, 2), MinidumpKind::Mini), 2 * PAGE, "writable data");
        assert_eq!(dumped_size(&mapping("/usr/lib/libc.so.6", false, 0, 40), MinidumpKind::Mini), PAGE, "the ELF header page");
        assert_eq!(dumped_size(&mapping("/usr/lib/libc.so.6", false, 0x28000, 40), MinidumpKind::Mini), 0, "code is on disk");
        assert_eq!(dumped_size(&mapping("/usr/lib/libc.so.6", false, 0x28000, 40), MinidumpKind::Full), 40 * PAGE);
        assert_eq!(dumped_size(&mapping("[vvar]", false, 0, 4), MinidumpKind::Full), 0);
        let mut unreadable = mapping("", false, 0, 4);
        unreadable.read = false;
        assert_eq!(dumped_size(&unreadable, MinidumpKind::Full), 0);
    }

    #[test]
    fn notes_are_four_byte_aligned() {
        let mut notes = Vec::new();
        push_note(&mut notes, NT_AUXV, &[1, 2, 3]);
        // 12-byte header, "CORE\0" padded to 8, 3 bytes padded to 4.
        assert_eq!(notes.len(), 12 + 8 + 4);
        assert_eq!(&notes[12..17], b"CORE\0");
        assert_eq!(u32::from_le_bytes(notes[4..8].try_into().unwrap()), 3);
    }

    #[test]
    fn file_note_lists_backing_files() {
        let maps = [mapping("/bin/true", false, 0x2000, 1), mapping("[heap]", true, 0, 1)];
        let note = file_note(&maps).unwrap();
        assert_eq!(u64::from_le_bytes(note[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(note[32..40].try_into().unwrap()), 2, "offset in pages");
        assert!(note.ends_with(b"/bin/true\0"));
        assert!(file_note(&maps[1..]).is_none());
    }
}
