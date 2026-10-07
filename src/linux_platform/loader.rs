//! Module tracking through the dynamic loader's debugger interface
//! (`r_debug`/`link_map`): an internal breakpoint on `_dl_debug_state` fires
//! on every library load/unload, and the chain is diffed against what we
//! know. Plus the entry-point hook that becomes the `InitialBreakpoint`.

use std::collections::HashMap;
use std::path::Path;

use crate::interfaces::PlatformError;
use crate::protocol::ModuleInfo;

use super::memory::ProcessMemory;

pub const HOOK_LOADER: u32 = 1;
pub const HOOK_ENTRY: u32 = 2;

/// `r_debug.r_state`: the chain is consistent.
const RT_CONSISTENT: i32 = 0;

#[derive(Debug, Default)]
pub struct LoaderState {
    /// Runtime address of ld.so's `_r_debug`, once known.
    pub r_debug: Option<u64>,
    /// Modules reported so far, by link-map `l_addr` (0 for the executable).
    pub known: HashMap<u64, ModuleInfo>,
}

/// One `link_map` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMapEntry {
    pub l_addr: u64,
    pub name: String,
}

fn read_u64(mem: &ProcessMemory, addr: u64) -> Result<u64, PlatformError> {
    mem.try_read_pointer(addr).ok_or_else(|| PlatformError::Other(format!("short read at {addr:#x}")))
}

fn read_cstring(mem: &ProcessMemory, addr: u64) -> Result<String, PlatformError> {
    let mut out = Vec::new();
    let mut at = addr;
    loop {
        let chunk = mem.read(at, 64)?;
        if chunk.is_empty() {
            break;
        }
        if let Some(nul) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul]);
            break;
        }
        out.extend_from_slice(&chunk);
        at += chunk.len() as u64;
        if out.len() > 4096 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// `r_debug.r_state`.
pub fn r_state(mem: &ProcessMemory, r_debug: u64) -> Result<i32, PlatformError> {
    let b = mem.read(r_debug + 24, 4)?;
    Ok(i32::from_le_bytes(b[..4].try_into().map_err(|_| PlatformError::Other("short r_state read".into()))?))
}

pub fn is_consistent(mem: &ProcessMemory, r_debug: u64) -> bool {
    r_state(mem, r_debug).map(|s| s == RT_CONSISTENT).unwrap_or(false)
}

/// Walk `r_debug.r_map`. x86_64 glibc layout: `r_debug { r_version @0,
/// r_map @8, r_brk @16, r_state @24, r_ldbase @32 }`, `link_map { l_addr @0,
/// l_name @8, l_ld @16, l_next @24, l_prev @32 }`.
pub fn read_link_map(mem: &ProcessMemory, r_debug: u64) -> Result<Vec<LinkMapEntry>, PlatformError> {
    let mut out = Vec::new();
    let mut lm = read_u64(mem, r_debug + 8)?;
    let mut guard = 0;
    while lm != 0 && guard < 4096 {
        let l_addr = read_u64(mem, lm)?;
        let name_ptr = read_u64(mem, lm + 8)?;
        let name = if name_ptr != 0 { read_cstring(mem, name_ptr)? } else { String::new() };
        out.push(LinkMapEntry { l_addr, name });
        lm = read_u64(mem, lm + 24)?;
        guard += 1;
    }
    Ok(out)
}

/// The module a link-map entry describes, or `None` for the executable
/// itself (already reported as `ProcessCreated`) and unreadable files.
/// `vdso` supplies the vdso's base and size (it has no file).
pub fn module_for_entry(entry: &LinkMapEntry, vdso: Option<(u64, u64)>) -> Option<ModuleInfo> {
    if entry.name.is_empty() {
        return None;
    }
    if entry.name.starts_with("linux-vdso") || entry.name.starts_with("linux-gate") {
        let (base, size) = vdso?;
        return Some(ModuleInfo { name: "[vdso]".to_string(), base, size: Some(size) });
    }
    let path = Path::new(&entry.name);
    let layout = crate::elf::layout::read_layout(path).ok()?;
    let canonical = std::fs::canonicalize(path).map(|p| p.display().to_string()).unwrap_or_else(|_| entry.name.clone());
    Some(ModuleInfo { name: canonical, base: entry.l_addr + layout.min_vaddr, size: Some(layout.size) })
}
