//! `/proc` readers: process listing, threads, auxv, exe path, maps.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::protocol::ProcessInfo;

/// Every process visible in `/proc`, named by its executable's file name
/// (falling back to `comm` when the exe link is unreadable). Kernel threads
/// (no exe, empty cmdline) are skipped.
pub fn list_processes() -> io::Result<Vec<ProcessInfo>> {
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let dir = entry.path();
        let name = match fs::read_link(dir.join("exe")) {
            Ok(exe) => exe.file_name().map(|n| n.to_string_lossy().into_owned()),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // Someone else's process: comm is still readable, and cmdline
                // tells a kernel thread (empty) from a user process.
                let cmdline = fs::read(dir.join("cmdline")).unwrap_or_default();
                if cmdline.is_empty() {
                    None
                } else {
                    fs::read_to_string(dir.join("comm")).ok().map(|c| c.trim_end().to_string())
                }
            }
            Err(_) => None,
        };
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            out.push(ProcessInfo { pid, name });
        }
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

/// The thread ids of `pid`, from `/proc/pid/task`.
pub fn thread_ids(pid: u32) -> io::Result<Vec<u32>> {
    let mut tids: Vec<u32> = fs::read_dir(format!("/proc/{pid}/task"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
        .collect();
    tids.sort_unstable();
    Ok(tids)
}

/// The thread-group id a tid belongs to.
pub fn tgid_of(tid: u32) -> Option<u32> {
    status_field(&status(tid)?, "Tgid:")?.parse().ok()
}

/// `/proc/pid/status`.
pub fn status(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/status")).ok()
}

/// The (trimmed) value of a `Key:` line of `/proc/pid/status`.
pub fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|l| l.strip_prefix(key)).map(str::trim)
}

/// A hexadecimal mask field of `/proc/pid/status` (`SigCgt:`, `CapEff:`, ...).
pub fn status_hex_mask(status: &str, key: &str) -> Option<u64> {
    u64::from_str_radix(status_field(status, key)?, 16).ok()
}

/// `(ignored, caught)` signal masks of a process (`SigIgn` / `SigCgt` in
/// `/proc/pid/status`; bit `n - 1` is signal `n`).
pub fn signal_dispositions(pid: u32) -> Option<(u64, u64)> {
    let status = status(pid)?;
    Some((status_hex_mask(&status, "SigIgn:")?, status_hex_mask(&status, "SigCgt:")?))
}

pub fn exe_path(pid: u32) -> io::Result<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe"))
}

/// The process's auxiliary vector as `(type, value)` pairs.
pub fn auxv(pid: u32) -> io::Result<Vec<(u64, u64)>> {
    let mut bytes = Vec::new();
    fs::File::open(format!("/proc/{pid}/auxv"))?.read_to_end(&mut bytes)?;
    Ok(bytes
        .chunks_exact(16)
        .map(|c| (u64::from_ne_bytes(c[..8].try_into().unwrap()), u64::from_ne_bytes(c[8..].try_into().unwrap())))
        .take_while(|&(t, _)| t != libc::AT_NULL as u64)
        .collect())
}

pub fn auxv_value(auxv: &[(u64, u64)], key: u64) -> Option<u64> {
    auxv.iter().find(|&&(t, _)| t == key).map(|&(_, v)| v)
}

/// `kernel.yama.ptrace_scope`, when Yama is present.
pub fn yama_ptrace_scope() -> Option<u32> {
    fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").ok()?.trim().parse().ok()
}

/// A readable path for a module as the kernel reports it in `maps`:
/// `(deleted)` suffixes stripped.
pub fn clean_map_path(path: &str) -> &Path {
    Path::new(path.strip_suffix(" (deleted)").unwrap_or(path))
}
