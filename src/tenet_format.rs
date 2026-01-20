//! Tenet trace format conversion utilities
//!
//! Converts execution traces to the Tenet format for use with the
//! [Tenet](https://github.com/gaasedelen/tenet) trace explorer for IDA Pro.
//!
//! Each line represents one execution delta:
//! ```text
//! rip=0x...,reg=value,...,mr=addr:hexbytes,mw=addr:hexbytes
//! ```
//!
//! - RIP is always output first on every line
//! - Only output other registers that changed (delta-based)
//! - Full register state is dumped on the first line
//! - Memory reads: `mr=addr:hexbytes`
//! - Memory writes: `mw=addr:hexbytes`
//! - Memory read+write: `mrw=addr:hexbytes`

use crate::protocol::{MemoryAccess, MemoryAccessType, RegisterSnapshot};

/// Compute the register delta between two snapshots.
/// Returns a vector of (register_name, new_value) pairs for registers that changed.
pub fn compute_register_delta(
    prev: &RegisterSnapshot,
    curr: &RegisterSnapshot,
) -> Vec<(&'static str, u64)> {
    let mut delta = Vec::new();

    // Compare each register and record changes
    // Note: RIP is handled separately and always output first
    if prev.rax != curr.rax { delta.push(("rax", curr.rax)); }
    if prev.rbx != curr.rbx { delta.push(("rbx", curr.rbx)); }
    if prev.rcx != curr.rcx { delta.push(("rcx", curr.rcx)); }
    if prev.rdx != curr.rdx { delta.push(("rdx", curr.rdx)); }
    if prev.rsi != curr.rsi { delta.push(("rsi", curr.rsi)); }
    if prev.rdi != curr.rdi { delta.push(("rdi", curr.rdi)); }
    if prev.rbp != curr.rbp { delta.push(("rbp", curr.rbp)); }
    if prev.rsp != curr.rsp { delta.push(("rsp", curr.rsp)); }
    if prev.r8 != curr.r8 { delta.push(("r8", curr.r8)); }
    if prev.r9 != curr.r9 { delta.push(("r9", curr.r9)); }
    if prev.r10 != curr.r10 { delta.push(("r10", curr.r10)); }
    if prev.r11 != curr.r11 { delta.push(("r11", curr.r11)); }
    if prev.r12 != curr.r12 { delta.push(("r12", curr.r12)); }
    if prev.r13 != curr.r13 { delta.push(("r13", curr.r13)); }
    if prev.r14 != curr.r14 { delta.push(("r14", curr.r14)); }
    if prev.r15 != curr.r15 { delta.push(("r15", curr.r15)); }
    // Note: rflags changes are not typically included in Tenet traces
    // as they are not considered GPRs, but can be added if needed

    delta
}

/// Format a single memory access for Tenet output.
/// Returns a string like "mr=0x1234:aabbccdd" or "mw=0x1234:aabbccdd"
pub fn format_memory_access(access: &MemoryAccess) -> String {
    let prefix = match access.access_type {
        MemoryAccessType::Read => "mr",
        MemoryAccessType::Write => "mw",
        MemoryAccessType::ReadWrite => "mrw",
    };

    // Convert data to hex string (no spaces or separators)
    let hex_data: String = access.data.iter().map(|b| format!("{:02x}", b)).collect();

    format!("{}=0x{:x}:{}", prefix, access.address, hex_data)
}

/// Format a single Tenet trace line.
///
/// # Arguments
/// * `prev` - Previous register state (None for first line)
/// * `curr` - Current register state
/// * `mem` - Memory accesses for this instruction
///
/// # Returns
/// A Tenet format line with RIP first, then changed registers, then memory accesses
pub fn format_tenet_line(
    prev: Option<&RegisterSnapshot>,
    curr: &RegisterSnapshot,
    mem: &[MemoryAccess],
) -> String {
    let mut parts: Vec<String> = Vec::new();

    // RIP is always first
    parts.push(format!("rip=0x{:x}", curr.rip));

    match prev {
        None => {
            // First line: dump all registers
            parts.push(format!("rax=0x{:x}", curr.rax));
            parts.push(format!("rbx=0x{:x}", curr.rbx));
            parts.push(format!("rcx=0x{:x}", curr.rcx));
            parts.push(format!("rdx=0x{:x}", curr.rdx));
            parts.push(format!("rsi=0x{:x}", curr.rsi));
            parts.push(format!("rdi=0x{:x}", curr.rdi));
            parts.push(format!("rbp=0x{:x}", curr.rbp));
            parts.push(format!("rsp=0x{:x}", curr.rsp));
            parts.push(format!("r8=0x{:x}", curr.r8));
            parts.push(format!("r9=0x{:x}", curr.r9));
            parts.push(format!("r10=0x{:x}", curr.r10));
            parts.push(format!("r11=0x{:x}", curr.r11));
            parts.push(format!("r12=0x{:x}", curr.r12));
            parts.push(format!("r13=0x{:x}", curr.r13));
            parts.push(format!("r14=0x{:x}", curr.r14));
            parts.push(format!("r15=0x{:x}", curr.r15));
        }
        Some(prev_regs) => {
            // Delta: only output changed registers
            for (name, value) in compute_register_delta(prev_regs, curr) {
                parts.push(format!("{}=0x{:x}", name, value));
            }
        }
    }

    // Add memory accesses
    for access in mem {
        parts.push(format_memory_access(access));
    }

    parts.join(",")
}

/// Convert a full trace to Tenet format.
///
/// # Arguments
/// * `entries` - Vector of (RegisterSnapshot, Vec<MemoryAccess>) pairs
///
/// # Returns
/// A complete Tenet trace as a multi-line string
pub fn trace_to_tenet(entries: &[(RegisterSnapshot, Vec<MemoryAccess>)]) -> String {
    if entries.is_empty() {
        return String::new();
    }

    let mut lines: Vec<String> = Vec::with_capacity(entries.len());

    // First entry: full register dump
    let (first_regs, first_mem) = &entries[0];
    lines.push(format_tenet_line(None, first_regs, first_mem));

    // Subsequent entries: delta encoding
    for i in 1..entries.len() {
        let (prev_regs, _) = &entries[i - 1];
        let (curr_regs, curr_mem) = &entries[i];
        lines.push(format_tenet_line(Some(prev_regs), curr_regs, curr_mem));
    }

    lines.join("\n")
}

/// Convert register trace and memory trace to Tenet format.
/// This is a convenience function that combines separate register and memory traces.
///
/// # Arguments
/// * `register_trace` - Vector of RegisterSnapshot
/// * `memory_trace` - Vector of Vec<MemoryAccess>, one per instruction
///
/// # Returns
/// A complete Tenet trace as a multi-line string
pub fn traces_to_tenet(
    register_trace: &[RegisterSnapshot],
    memory_trace: &[Vec<MemoryAccess>],
) -> String {
    if register_trace.is_empty() {
        return String::new();
    }

    let mut lines: Vec<String> = Vec::with_capacity(register_trace.len());

    // First entry: full register dump
    let first_mem = memory_trace.first().map(|v| v.as_slice()).unwrap_or(&[]);
    lines.push(format_tenet_line(None, &register_trace[0], first_mem));

    // Subsequent entries: delta encoding
    for i in 1..register_trace.len() {
        let mem = memory_trace.get(i).map(|v| v.as_slice()).unwrap_or(&[]);
        lines.push(format_tenet_line(Some(&register_trace[i - 1]), &register_trace[i], mem));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regs(rip: u64, rax: u64, rsp: u64) -> RegisterSnapshot {
        RegisterSnapshot {
            rax,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip,
            rflags: 0x246,
        }
    }

    #[test]
    fn test_compute_register_delta() {
        let prev = make_regs(0x1000, 0x100, 0x7FFF0000);
        let curr = make_regs(0x1005, 0x200, 0x7FFF0000); // RAX changed, RSP same

        let delta = compute_register_delta(&prev, &curr);

        // Should only contain RAX (RIP is handled separately)
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0], ("rax", 0x200));
    }

    #[test]
    fn test_format_memory_access_read() {
        let access = MemoryAccess {
            access_type: MemoryAccessType::Read,
            address: 0x7FFF0000,
            data: vec![0x12, 0x34, 0x56, 0x78],
        };

        let formatted = format_memory_access(&access);
        assert_eq!(formatted, "mr=0x7fff0000:12345678");
    }

    #[test]
    fn test_format_memory_access_write() {
        let access = MemoryAccess {
            access_type: MemoryAccessType::Write,
            address: 0x1000,
            data: vec![0xAB, 0xCD],
        };

        let formatted = format_memory_access(&access);
        assert_eq!(formatted, "mw=0x1000:abcd");
    }

    #[test]
    fn test_format_tenet_line_first() {
        let regs = make_regs(0x140001000, 0x1234, 0x7FFF0000);
        let mem = vec![
            MemoryAccess {
                access_type: MemoryAccessType::Read,
                address: 0x7FFF0000,
                data: vec![0x12, 0x34],
            },
        ];

        let line = format_tenet_line(None, &regs, &mem);

        // Should have rip first, then all registers, then memory
        assert!(line.starts_with("rip=0x140001000,"));
        assert!(line.contains("rax=0x1234"));
        assert!(line.contains("rsp=0x7fff0000"));
        assert!(line.ends_with("mr=0x7fff0000:1234"));
    }

    #[test]
    fn test_format_tenet_line_delta() {
        let prev = make_regs(0x140001000, 0x100, 0x7FFF0000);
        let curr = make_regs(0x140001005, 0x200, 0x7FFEF000); // RAX and RSP changed

        let line = format_tenet_line(Some(&prev), &curr, &[]);

        // Should have rip, then only changed registers
        assert!(line.starts_with("rip=0x140001005,"));
        assert!(line.contains("rax=0x200"));
        assert!(line.contains("rsp=0x7ffef000"));
        // Should NOT contain unchanged registers
        assert!(!line.contains("rbx="));
    }

    #[test]
    fn test_trace_to_tenet() {
        let entries = vec![
            (
                make_regs(0x1000, 0x100, 0x7FFF0000),
                vec![],
            ),
            (
                make_regs(0x1005, 0x200, 0x7FFF0000),
                vec![MemoryAccess {
                    access_type: MemoryAccessType::Write,
                    address: 0x2000,
                    data: vec![0x11, 0x22],
                }],
            ),
        ];

        let tenet = trace_to_tenet(&entries);
        let lines: Vec<&str> = tenet.lines().collect();

        assert_eq!(lines.len(), 2);
        // First line should have full register dump
        assert!(lines[0].contains("rax=0x100"));
        // Second line should have delta (rax changed) and memory write
        assert!(lines[1].contains("rax=0x200"));
        assert!(lines[1].contains("mw=0x2000:1122"));
    }
}
