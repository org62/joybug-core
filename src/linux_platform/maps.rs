//! `/proc/pid/maps` parsing and its translation into the Win32-valued
//! `MemoryRegionInfo` the rest of the debugger (scanners, emulator, UI) reads.

use std::fs;
use std::io;

use crate::protocol::MemoryRegionInfo;

// The protocol's region vocabulary is Win32's; every consumer (dereference,
// scanners, the UI's "committed" filter) tests these exact values.
pub use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};
pub const PAGE_EXECUTABLE_MASK: u32 = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// One line of `/proc/pid/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub shared: bool,
    pub offset: u64,
    /// The backing file (`(deleted)` suffix kept), or the pseudo path such as
    /// `[heap]`, `[stack]`, `[vdso]`; empty for anonymous memory.
    pub path: String,
}

impl Mapping {
    pub fn is_file_backed(&self) -> bool {
        self.path.starts_with('/')
    }

    pub fn protect(&self) -> u32 {
        match (self.read, self.write, self.exec) {
            (false, false, false) => PAGE_NOACCESS,
            (_, false, false) => PAGE_READONLY,
            (_, true, false) => PAGE_READWRITE,
            (false, false, true) => PAGE_EXECUTE,
            (_, false, true) => PAGE_EXECUTE_READ,
            (_, true, true) => PAGE_EXECUTE_READWRITE,
        }
    }
}

pub fn parse_maps(text: &str) -> Vec<Mapping> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Mapping> {
    let mut fields = line.splitn(6, ' ');
    let range = fields.next()?;
    let perms = fields.next()?;
    let offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.next().unwrap_or("").trim_start().to_string();
    let (start, end) = range.split_once('-')?;
    let perms = perms.as_bytes();
    Some(Mapping {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        read: perms.first() == Some(&b'r'),
        write: perms.get(1) == Some(&b'w'),
        exec: perms.get(2) == Some(&b'x'),
        shared: perms.get(3) == Some(&b's'),
        offset: u64::from_str_radix(offset, 16).ok()?,
        path,
    })
}

/// The vdso's `(base, size)`.
pub fn vdso_range(maps: &[Mapping]) -> Option<(u64, u64)> {
    maps.iter().find(|m| m.path == "[vdso]").map(|m| (m.start, m.end - m.start))
}

pub fn read_maps(pid: u32) -> io::Result<Vec<Mapping>> {
    Ok(parse_maps(&fs::read_to_string(format!("/proc/{pid}/maps"))?))
}

/// Turn the mappings into the protocol's regions. `module_base_of` maps a
/// file path to the base of the loaded module it belongs to (so its mappings
/// become `MEM_IMAGE` with that `allocation_base`).
pub fn regions_from_maps(maps: &[Mapping], module_base_of: impl Fn(&str) -> Option<u64>) -> Vec<MemoryRegionInfo> {
    maps.iter()
        .map(|m| {
            let protect = m.protect();
            let (region_type, allocation_base) = if m.path == "[vdso]" {
                (MEM_IMAGE, module_base_of(&m.path).unwrap_or(m.start))
            } else if m.is_file_backed() {
                match module_base_of(&m.path) {
                    Some(base) => (MEM_IMAGE, base),
                    None => (MEM_MAPPED, m.start),
                }
            } else if m.shared {
                (MEM_MAPPED, m.start)
            } else {
                (MEM_PRIVATE, m.start)
            };
            MemoryRegionInfo {
                base_address: m.start,
                allocation_base,
                allocation_protect: protect,
                region_size: m.end - m.start,
                state: MEM_COMMIT,
                protect,
                region_type,
            }
        })
        .collect()
}

/// The region containing `address`, or a synthetic `MEM_FREE` gap region
/// spanning up to the next mapping, so callers that clamp to a region (the
/// backward disassembler, the telescoping) see an honest extent.
pub fn region_at(regions: &[MemoryRegionInfo], address: u64) -> MemoryRegionInfo {
    let idx = regions.partition_point(|r| r.base_address <= address);
    if idx > 0 {
        let r = &regions[idx - 1];
        if address < r.base_address + r.region_size {
            return r.clone();
        }
    }
    let gap_start = if idx > 0 { regions[idx - 1].base_address + regions[idx - 1].region_size } else { 0 };
    let gap_end = regions.get(idx).map(|r| r.base_address).unwrap_or(crate::interfaces::MAX_USER_ADDRESS + 1);
    MemoryRegionInfo {
        base_address: gap_start,
        allocation_base: 0,
        allocation_protect: 0,
        region_size: gap_end.saturating_sub(gap_start),
        state: MEM_FREE,
        protect: PAGE_NOACCESS,
        region_type: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
5555_5555_4000-5555_5555_5000 r--p 00000000 08:01 1234 /usr/bin/hello
555555555000-555555556000 r-xp 00001000 08:01 1234 /usr/bin/hello
7ffff7d80000-7ffff7da8000 rw-p 00000000 00:00 0
7ffff7fc1000-7ffff7fc3000 r-xp 00000000 00:00 0 [vdso]
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]
";

    #[test]
    fn parses_permissions_paths_and_pseudo_mappings() {
        let maps = parse_maps(&SAMPLE.replace('_', ""));
        assert_eq!(maps.len(), 5);
        assert_eq!(maps[1].path, "/usr/bin/hello");
        assert!(maps[1].exec && maps[1].read && !maps[1].write);
        assert_eq!(maps[1].offset, 0x1000);
        assert_eq!(maps[2].path, "");
        assert_eq!(maps[3].path, "[vdso]");
        assert_eq!(maps[4].path, "[stack]");
    }

    #[test]
    fn regions_carry_win32_values() {
        let maps = parse_maps(&SAMPLE.replace('_', ""));
        let regions = regions_from_maps(&maps, |p| (p == "/usr/bin/hello").then_some(0x5555_5555_4000));
        assert!(regions.iter().all(|r| r.state == MEM_COMMIT));
        assert_eq!(regions[0].protect, PAGE_READONLY);
        assert_eq!(regions[1].protect, PAGE_EXECUTE_READ);
        assert_eq!(regions[1].region_type, MEM_IMAGE);
        assert_eq!(regions[1].allocation_base, 0x5555_5555_4000);
        assert_eq!(regions[2].region_type, MEM_PRIVATE);
        assert_eq!(regions[4].protect, PAGE_READWRITE);
        let gap = region_at(&regions, 0x6000_0000_0000);
        assert_eq!(gap.state, MEM_FREE);
        assert_eq!(gap.base_address, regions[1].base_address + regions[1].region_size);
        assert_eq!(region_at(&regions, 0x5555_5555_4010).base_address, regions[0].base_address);
    }
}
