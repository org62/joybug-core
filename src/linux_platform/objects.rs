//! The Handles window on Linux: a process's file descriptors, its TCP
//! sockets and its capabilities, all from `/proc` (so it works for a running
//! target and for a non-invasive Open session too).
//!
//! The protocol's records are the Windows ones; the fields carry the nearest
//! Linux fact:
//!
//! | `HandleInfo`      | here                                                     |
//! |-------------------|----------------------------------------------------------|
//! | `handle`          | the descriptor number                                    |
//! | `type_name`       | `File`, `Directory`, `Pipe`, `Socket`, `eventfd`, ...     |
//! | `granted_access`  | the open flags (`O_*`, from `fdinfo`)                    |
//! | `attributes`      | `0x2` (inherit) when the descriptor survives an `exec`   |
//! | `name`            | the path, or what the socket is bound/connected to       |
//!
//! Privileges are the capability sets: `Enabled` when effective, `Disabled`
//! when only permitted.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::FileTypeExt;

use super::procfs;
use crate::protocol::{HandleInfo, PrivilegeInfo, PrivilegeState, ProcessObjects, TcpConnectionInfo};

/// `OBJ_INHERIT`: the descriptor is not close-on-exec.
const ATTR_INHERIT: u32 = 0x2;

/// What a socket inode is, from the `/proc/pid/net/*` tables.
#[derive(Debug, Clone)]
struct SocketInfo {
    /// `TCP`, `UDP`, `TCP6`, `UDP6`, `UNIX`.
    protocol: &'static str,
    local: (String, u16),
    remote: (String, u16),
    state: String,
    /// Bound path of a UNIX socket (`@name` for the abstract namespace).
    path: String,
}

impl SocketInfo {
    fn describe(&self) -> String {
        if self.protocol == "UNIX" {
            return if self.path.is_empty() { "UNIX".to_string() } else { format!("UNIX {}", self.path) };
        }
        let endpoint = |(addr, port): &(String, u16)| if addr.contains(':') { format!("[{addr}]:{port}") } else { format!("{addr}:{port}") };
        let unconnected = self.remote.1 == 0;
        let mut text = format!("{} {}", self.protocol, endpoint(&self.local));
        if !unconnected {
            text.push_str(&format!(" -> {}", endpoint(&self.remote)));
        }
        if !self.state.is_empty() {
            text.push_str(&format!(" ({})", self.state));
        }
        text
    }
}

pub fn list_process_objects(pid: u32) -> ProcessObjects {
    let mut objects = ProcessObjects::default();
    let sockets = socket_table(pid);

    match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let Some(fd) = entry.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) else { continue };
                // The descriptor can close between the listing and the readlink.
                let Ok(target) = fs::read_link(entry.path()) else { continue };
                let target = target.to_string_lossy().into_owned();
                let flags = fd_flags(pid, fd).unwrap_or(0);
                let socket = inode_of(&target, "socket:").and_then(|inode| sockets.get(&inode));
                let (type_name, name) = describe_fd(&entry.path(), &target, socket);
                if let Some(s) = socket.filter(|s| s.protocol.starts_with("TCP")) {
                    objects.tcp_connections.push(TcpConnectionInfo {
                        local_address: s.local.0.clone(),
                        local_port: s.local.1,
                        remote_address: s.remote.0.clone(),
                        remote_port: s.remote.1,
                        state: s.state.clone(),
                    });
                }
                objects.handles.push(HandleInfo {
                    handle: fd,
                    type_index: 0,
                    type_name,
                    granted_access: flags,
                    attributes: if flags & libc::O_CLOEXEC as u32 == 0 { ATTR_INHERIT } else { 0 },
                    name,
                });
            }
            objects.handles.sort_by_key(|h| h.handle);
        }
        Err(e) => objects.warnings.push(format!("File descriptors: /proc/{pid}/fd: {e}")),
    }

    match capabilities(pid) {
        Some(caps) => objects.privileges = caps,
        None => objects.warnings.push(format!("Capabilities: /proc/{pid}/status is unreadable")),
    }
    objects
}

/// `(type, name)` for one descriptor. `link` is `/proc/pid/fd/N`, `target`
/// what it points at.
fn describe_fd(link: &std::path::Path, target: &str, socket: Option<&SocketInfo>) -> (String, String) {
    if target.starts_with("socket:") {
        return ("Socket".to_string(), socket.map(SocketInfo::describe).unwrap_or_else(|| target.to_string()));
    }
    if target.starts_with("pipe:") {
        return ("Pipe".to_string(), target.to_string());
    }
    if let Some(kind) = target.strip_prefix("anon_inode:") {
        // `[eventfd]`, `[eventpoll]`, `[timerfd]`, `inotify`, `[pidfd]`, ...
        return (kind.trim_matches(|c| c == '[' || c == ']').to_string(), String::new());
    }
    if target.starts_with("/memfd:") {
        return ("memfd".to_string(), target.trim_start_matches('/').to_string());
    }
    // A real path: the link follows through to the open file, deleted or not.
    let type_name = match fs::metadata(link).map(|m| m.file_type()) {
        Ok(t) if t.is_dir() => "Directory",
        Ok(t) if t.is_char_device() => "Device",
        Ok(t) if t.is_block_device() => "BlockDevice",
        Ok(t) if t.is_fifo() => "Fifo",
        Ok(t) if t.is_socket() => "Socket",
        _ => "File",
    };
    (type_name.to_string(), target.to_string())
}

/// `socket:[1234]` -> 1234.
fn inode_of(target: &str, prefix: &str) -> Option<u64> {
    target.strip_prefix(prefix)?.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

/// The `flags:` line of `/proc/pid/fdinfo/N` (octal).
fn fd_flags(pid: u32, fd: u64) -> Option<u32> {
    let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok()?;
    let flags = info.lines().find_map(|l| l.strip_prefix("flags:"))?;
    u32::from_str_radix(flags.trim(), 8).ok()
}

/// Every socket of the process's network namespace, by inode.
fn socket_table(pid: u32) -> HashMap<u64, SocketInfo> {
    let mut table = HashMap::new();
    for (file, protocol, v6) in [("tcp", "TCP", false), ("tcp6", "TCP6", true), ("udp", "UDP", false), ("udp6", "UDP6", true)] {
        let Ok(text) = fs::read_to_string(format!("/proc/{pid}/net/{file}")) else { continue };
        for line in text.lines().skip(1) {
            if let Some((inode, info)) = parse_inet_line(line, protocol, v6) {
                table.insert(inode, info);
            }
        }
    }
    if let Ok(text) = fs::read_to_string(format!("/proc/{pid}/net/unix")) {
        for line in text.lines().skip(1) {
            if let Some((inode, info)) = parse_unix_line(line) {
                table.insert(inode, info);
            }
        }
    }
    table
}

/// One row of `/proc/net/{tcp,udp}[6]`:
/// `sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ...`
fn parse_inet_line(line: &str, protocol: &'static str, v6: bool) -> Option<(u64, SocketInfo)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let local = parse_endpoint(fields[1], v6)?;
    let remote = parse_endpoint(fields[2], v6)?;
    let state = u8::from_str_radix(fields[3], 16).ok()?;
    let inode: u64 = fields[9].parse().ok()?;
    if inode == 0 {
        return None; // a socket nobody holds a descriptor for (time-wait, orphaned)
    }
    let state = if protocol.starts_with("TCP") { tcp_state(state).to_string() } else { String::new() };
    Some((inode, SocketInfo { protocol, local, remote, state, path: String::new() }))
}

/// `0100007F:1F90` / `00000000000000000000000001000000:1F90` -> (address, port).
/// The kernel prints each 32-bit word of the address in host byte order.
fn parse_endpoint(text: &str, v6: bool) -> Option<(String, u16)> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok().map(u32::swap_bytes);
    let address = if v6 {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word(i)?.to_be_bytes());
        }
        let ip = Ipv6Addr::from(bytes);
        match ip.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => ip.to_string(),
        }
    } else {
        Ipv4Addr::from(word(0)?.to_be_bytes()).to_string()
    };
    Some((address, port))
}

fn tcp_state(state: u8) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// One row of `/proc/net/unix`: `Num RefCount Protocol Flags Type St Inode Path`.
fn parse_unix_line(line: &str) -> Option<(u64, SocketInfo)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 7 {
        return None;
    }
    let inode: u64 = fields[6].parse().ok()?;
    let path = fields.get(7).copied().unwrap_or_default().to_string();
    Some((inode, SocketInfo { protocol: "UNIX", local: (String::new(), 0), remote: (String::new(), 0), state: String::new(), path }))
}

const CAPABILITY_NAMES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// The permitted capabilities of the process, `Enabled` when effective.
fn capabilities(pid: u32) -> Option<Vec<PrivilegeInfo>> {
    let status = procfs::status(pid)?;
    Some(capabilities_from_masks(procfs::status_hex_mask(&status, "CapPrm:")?, procfs::status_hex_mask(&status, "CapEff:")?))
}

fn capabilities_from_masks(permitted: u64, effective: u64) -> Vec<PrivilegeInfo> {
    (0..64u32)
        .filter(|bit| (permitted | effective) & (1u64 << bit) != 0)
        .map(|bit| PrivilegeInfo {
            name: CAPABILITY_NAMES.get(bit as usize).map(|n| n.to_string()).unwrap_or_else(|| format!("CAP_{bit}")),
            state: if effective & (1u64 << bit) != 0 { PrivilegeState::Enabled } else { PrivilegeState::Disabled },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_rows_parse_in_host_word_order() {
        let line = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0";
        let (inode, s) = parse_inet_line(line, "TCP", false).unwrap();
        assert_eq!(inode, 4242);
        assert_eq!(s.local, ("127.0.0.1".to_string(), 8080));
        assert_eq!(s.state, "LISTEN");
        assert_eq!(s.describe(), "TCP 127.0.0.1:8080 (LISTEN)");

        let line6 = "   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1 0000000000000000 100 0 0 10 0";
        let (_, s6) = parse_inet_line(line6, "TCP6", true).unwrap();
        assert_eq!(s6.local, ("::1".to_string(), 80));
        assert_eq!(s6.describe(), "TCP6 [::1]:80 (LISTEN)");
    }

    #[test]
    fn unix_rows_keep_the_path() {
        let (inode, s) = parse_unix_line("0000000000000000: 00000002 00000000 00010000 0001 01 9001 /run/x.sock").unwrap();
        assert_eq!(inode, 9001);
        assert_eq!(s.describe(), "UNIX /run/x.sock");
        let (_, anon) = parse_unix_line("0000000000000000: 00000002 00000000 00000000 0001 03 9002").unwrap();
        assert_eq!(anon.describe(), "UNIX");
    }

    #[test]
    fn capabilities_follow_the_masks() {
        let caps = capabilities_from_masks(1 << 19 | 1 << 21, 1 << 19);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].name, "CAP_SYS_PTRACE");
        assert_eq!(caps[0].state, PrivilegeState::Enabled);
        assert_eq!(caps[1].name, "CAP_SYS_ADMIN");
        assert_eq!(caps[1].state, PrivilegeState::Disabled);
        assert!(capabilities_from_masks(0, 0).is_empty());
    }

    #[test]
    fn own_descriptors_are_listed() {
        let file = fs::File::open("/proc/self/status").unwrap();
        let objects = list_process_objects(std::process::id());
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd() as u64;
        let row = objects.handles.iter().find(|h| h.handle == fd).expect("our own descriptor");
        assert_eq!(row.type_name, "File");
        assert!(row.name.ends_with("/status"), "{}", row.name);
        // Rust opens files close-on-exec.
        assert_eq!(row.attributes & ATTR_INHERIT, 0);
        assert!(objects.warnings.is_empty(), "{:?}", objects.warnings);
    }
}
