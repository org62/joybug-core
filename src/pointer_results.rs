//! Disk-backed pointer-scan results.
//!
//! A scan can produce millions of paths, so results are streamed to a file of
//! fixed-size records (no in-RAM cap) and read back via a read-only mmap for
//! paging. The file is identified by its path — joybug2 keeps no per-connection
//! state — so results survive a target restart.
//!
//! Crucially, a path's static base must be re-identified across runs by something
//! *stable*. `module_index` alone is not: it is a position into the live module
//! list, whose order comes from a `HashMap` and is reseeded every process launch.
//! So the file embeds a **module-name table** captured at scan time; each path's
//! `module_index` indexes into that table, and `ResultReader` maps it back to a
//! name. The caller resolves that name against the *current* module list to get
//! the live base (handling both ASLR and module-set/order changes across runs).

use crate::formatting::module_basename_lower as basename_lower;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use memmap2::{Mmap, MmapOptions};

use crate::protocol::PointerPath;

const MAGIC: u64 = 0x4A42_5054_5253_4332; // "JBPTRSC2" (v2: + module table)
const HEADER_BYTES: usize = 16; // magic(u64) + max_offsets(u32) + module_count(u32)

/// Bytes per record for a file holding chains of up to `max_offsets` offsets:
/// module_index(i32) + num_offsets(u32) + base_offset(u64) + resolved(u64) + offsets.
fn record_bytes(max_offsets: usize) -> usize {
    4 + 4 + 8 + 8 + max_offsets * 8
}

/// Streams pointer paths to a fixed-record results file, preceded by a table of
/// the module names that paths may reference (indexed by `module_index`).
pub struct ResultWriter {
    w: BufWriter<File>,
    max_offsets: usize,
    rec: Vec<u8>,
    count: u64,
}

impl ResultWriter {
    /// `module_names[i]` is the name of the module at live index `i` at scan time;
    /// paths emitted with `module_index == i` resolve against this name later.
    pub fn create(path: &Path, max_offsets: usize, module_names: &[String]) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);
        w.write_all(&MAGIC.to_le_bytes())?;
        w.write_all(&(max_offsets as u32).to_le_bytes())?;
        w.write_all(&(module_names.len() as u32).to_le_bytes())?;
        // Module table: each entry is name_len(u16) + name bytes (UTF-8).
        for name in module_names {
            let bytes = name.as_bytes();
            let len = bytes.len().min(u16::MAX as usize);
            w.write_all(&(len as u16).to_le_bytes())?;
            w.write_all(&bytes[..len])?;
        }
        Ok(Self { w, max_offsets, rec: vec![0u8; record_bytes(max_offsets)], count: 0 })
    }

    pub fn push(&mut self, p: &PointerPath) -> std::io::Result<()> {
        let n = p.offsets.len().min(self.max_offsets);
        for b in self.rec.iter_mut() {
            *b = 0;
        }
        self.rec[0..4].copy_from_slice(&p.module_index.to_le_bytes());
        self.rec[4..8].copy_from_slice(&(n as u32).to_le_bytes());
        self.rec[8..16].copy_from_slice(&p.base_offset.to_le_bytes());
        self.rec[16..24].copy_from_slice(&p.resolved.to_le_bytes());
        for (i, off) in p.offsets.iter().take(n).enumerate() {
            let b = 24 + i * 8;
            self.rec[b..b + 8].copy_from_slice(&off.to_le_bytes());
        }
        self.w.write_all(&self.rec)?;
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn finish(mut self) -> std::io::Result<u64> {
        self.w.flush()?;
        Ok(self.count)
    }
}

/// Reads a results file via mmap. `module_base` is not stored — callers re-derive
/// it by resolving each path's module *name* against the current process.
pub struct ResultReader {
    mmap: Mmap,
    max_offsets: usize,
    /// Module names captured at scan time, indexed by `PointerPath::module_index`.
    module_names: Vec<String>,
    /// Byte offset where the fixed-size records begin (after header + module table).
    data_start: usize,
    count: usize,
}

impl ResultReader {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open results file: {}", e))?;
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| format!("Failed to mmap results file: {}", e))?;
        if mmap.len() < HEADER_BYTES {
            return Err("Results file truncated".to_string());
        }
        let magic = u64::from_le_bytes(mmap[0..8].try_into().unwrap());
        if magic != MAGIC {
            return Err("Not a pointer-scan results file (or incompatible version)".to_string());
        }
        let max_offsets = u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as usize;
        let module_count = u32::from_le_bytes(mmap[12..16].try_into().unwrap()) as usize;

        // Parse the module-name table that follows the header.
        let mut module_names = Vec::with_capacity(module_count);
        let mut pos = HEADER_BYTES;
        for _ in 0..module_count {
            if pos + 2 > mmap.len() {
                return Err("Results file module table truncated".to_string());
            }
            let len = u16::from_le_bytes(mmap[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > mmap.len() {
                return Err("Results file module table truncated".to_string());
            }
            module_names.push(String::from_utf8_lossy(&mmap[pos..pos + len]).into_owned());
            pos += len;
        }

        let data_start = pos;
        let rec = record_bytes(max_offsets).max(1);
        let count = mmap.len().saturating_sub(data_start) / rec;
        Ok(Self { mmap, max_offsets, module_names, data_start, count })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn max_offsets(&self) -> usize {
        self.max_offsets
    }

    /// The module-name table captured at scan time (index = `module_index`).
    pub fn module_names(&self) -> &[String] {
        &self.module_names
    }

    /// Name of the module a path's `module_index` refers to, if in range.
    pub fn module_name(&self, module_index: i32) -> Option<&str> {
        if module_index < 0 {
            return None;
        }
        self.module_names.get(module_index as usize).map(|s| s.as_str())
    }

    /// Page over records, keeping only those whose chain offsets contain *every*
    /// value in `filter` (order-independent; empty filter = all records). Returns
    /// the requested page `[offset, offset+count)` of matches plus the total number
    /// of matches across the **whole file**. `module_base` is left 0 on each path
    /// (the caller re-derives it from the module name).
    pub fn page_filtered(&self, filter: &[u64], offset: usize, count: usize) -> (Vec<PointerPath>, u64) {
        if filter.is_empty() {
            let begin = offset.min(self.count);
            let end = (offset.saturating_add(count)).min(self.count);
            let mut out = Vec::with_capacity(end - begin);
            for i in begin..end {
                if let Some(p) = self.get(i) {
                    out.push(p);
                }
            }
            return (out, self.count as u64);
        }
        let end = offset.saturating_add(count);
        let mut matched: u64 = 0;
        let mut out = Vec::new();
        for i in 0..self.count {
            let Some(p) = self.get(i) else { continue };
            if !filter.iter().all(|f| p.offsets.contains(f)) {
                continue;
            }
            let idx = matched as usize;
            if idx >= offset && idx < end {
                out.push(p);
            }
            matched += 1;
        }
        (out, matched)
    }

    /// Read record `i`. `module_base` is left 0 (re-derived by the caller from the
    /// module name; see [`Self::module_name`]).
    pub fn get(&self, i: usize) -> Option<PointerPath> {
        if i >= self.count {
            return None;
        }
        let rec = record_bytes(self.max_offsets);
        let base = self.data_start + i * rec;
        let m = &self.mmap;
        let module_index = i32::from_le_bytes(m[base..base + 4].try_into().unwrap());
        let num = (u32::from_le_bytes(m[base + 4..base + 8].try_into().unwrap()) as usize).min(self.max_offsets);
        let base_offset = u64::from_le_bytes(m[base + 8..base + 16].try_into().unwrap());
        let resolved = u64::from_le_bytes(m[base + 16..base + 24].try_into().unwrap());
        let mut offsets = Vec::with_capacity(num);
        for k in 0..num {
            let b = base + 24 + k * 8;
            offsets.push(u64::from_le_bytes(m[b..b + 8].try_into().unwrap()));
        }
        Some(PointerPath { module_index, module_base: 0, base_offset, offsets, resolved })
    }
}

/// Build a lookup from module name to live base address for the *current* process,
/// used to re-base stored paths. Keyed by both the full stored name and its
/// case-insensitive basename, so a path resolves even if the loader reports a
/// different path form across runs.
pub fn module_base_index(modules: &[crate::protocol::ModuleInfo]) -> HashMap<String, u64> {
    let mut map = HashMap::with_capacity(modules.len() * 2);
    for m in modules {
        map.insert(m.name.clone(), m.base);
        map.insert(basename_lower(&m.name), m.base);
    }
    map
}

/// Resolve a stored module name to a live base via [`module_base_index`].
pub fn resolve_module_base(index: &HashMap<String, u64>, name: &str) -> Option<u64> {
    index
        .get(name)
        .copied()
        .or_else(|| index.get(&basename_lower(name)).copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ModuleInfo, PointerPath};

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("joybug_ptrresults_unit_{}_{}.bin", tag, std::process::id()))
    }

    fn mi(name: &str, base: u64) -> ModuleInfo {
        ModuleInfo { name: name.to_string(), base, size: Some(0x10000) }
    }

    /// The decisive property: a path stored against run 1's module list re-bases
    /// correctly against run 2 even though (a) the live module *order* differs and
    /// (b) the module's base address has changed (ASLR). This is what
    /// `module_index`-based re-basing got wrong.
    #[test]
    fn rebases_by_name_across_reordered_relocated_modules() {
        let path = tmp_path("rebase");
        // Run 1: game.exe at index 1, base 0x1000.
        let run1_names = vec!["ntdll.dll".to_string(), "game.exe".to_string()];
        {
            let mut w = ResultWriter::create(&path, 4, &run1_names).unwrap();
            w.push(&PointerPath {
                module_index: 1, // -> "game.exe"
                module_base: 0x1000,
                base_offset: 0x40,
                offsets: vec![0x8, 0x10],
                resolved: 0x9999,
            })
            .unwrap();
            assert_eq!(w.finish().unwrap(), 1);
        }

        let reader = ResultReader::open(&path).unwrap();
        assert_eq!(reader.len(), 1);
        assert_eq!(reader.module_name(1), Some("game.exe"));

        // Run 2: DIFFERENT order (game.exe now first) and a DIFFERENT base (ASLR
        // relocated it to 0x7FF000000000). A stale index would pick the wrong
        // module; the name must still resolve to the new base.
        let live = [mi("game.exe", 0x7FF0_0000_0000), mi("ntdll.dll", 0x2000)];
        let index = module_base_index(&live);

        let p = reader.get(0).unwrap();
        let base = resolve_module_base(&index, reader.module_name(p.module_index).unwrap()).unwrap();
        assert_eq!(base, 0x7FF0_0000_0000, "must re-base game.exe to its current base");
        assert_eq!(p.base_offset, 0x40);
        assert_eq!(p.offsets, vec![0x8, 0x10]);

        let _ = std::fs::remove_file(&path);
    }

    /// The filter scans the ENTIRE file (not just one page): matches are seeded at
    /// the very first and very last record and spread throughout, and the reported
    /// total must count all of them while the returned page is the requested slice.
    #[test]
    fn filter_scans_whole_file_and_paginates_matches() {
        let path = tmp_path("filter");
        let n = 1000usize;
        {
            let mut w = ResultWriter::create(&path, 4, &["m.exe".to_string()]).unwrap();
            // Use a high, non-colliding range for the per-record "id" offset so it
            // can never equal the 0x88 marker.
            let id = |i: usize| 0x1_0000_0000u64 + i as u64;
            for i in 0..n {
                // Every 10th record (incl. index 0 and 990) carries offset 0x88;
                // give each a unique id offset/resolved so we can identify the page.
                let offsets = if i % 10 == 0 { vec![0x88, id(i)] } else { vec![id(i)] };
                w.push(&PointerPath {
                    module_index: 0,
                    module_base: 0,
                    base_offset: 0,
                    offsets,
                    resolved: id(i),
                })
                .unwrap();
            }
            assert_eq!(w.finish().unwrap(), n as u64);
        }
        let reader = ResultReader::open(&path).unwrap();
        assert_eq!(reader.len(), n);

        let id = |i: usize| 0x1_0000_0000u64 + i as u64;

        // 100 records match 0x88 across the whole file (indices 0,10,...,990).
        let (page0, total) = reader.page_filtered(&[0x88], 0, 30);
        assert_eq!(total, 100, "must count matches across the entire file");
        assert_eq!(page0.len(), 30, "first page returns the requested slice of matches");
        assert_eq!(page0[0].resolved, id(0), "first match is the very first record");
        assert_eq!(page0[1].resolved, id(10));

        // A later page reaches matches near the end of the file (record 990).
        let (last_page, total2) = reader.page_filtered(&[0x88], 90, 30);
        assert_eq!(total2, 100);
        assert_eq!(last_page.len(), 10, "only 10 matches remain after offset 90");
        assert_eq!(last_page.last().unwrap().resolved, id(990), "scan reached the final record");

        // Two-offset filter (AND): only the record carrying both 0x88 and id(500)
        // — i.e. exactly record 500 — matches.
        let (both, total3) = reader.page_filtered(&[0x88, id(500)], 0, 100);
        assert_eq!(total3, 1);
        assert_eq!(both[0].resolved, id(500));

        let _ = std::fs::remove_file(&path);
    }

    /// A stored full path still resolves when the loader reports only a basename
    /// (or a different path form / casing) on the second run.
    #[test]
    fn rebases_by_basename_when_path_form_differs() {
        let path = tmp_path("basename");
        let names = vec!["C:\\Games\\App\\game.exe".to_string()];
        {
            let mut w = ResultWriter::create(&path, 2, &names).unwrap();
            w.push(&PointerPath {
                module_index: 0,
                module_base: 0,
                base_offset: 0x4,
                offsets: vec![],
                resolved: 0x1,
            })
            .unwrap();
            w.finish().unwrap();
        }
        let reader = ResultReader::open(&path).unwrap();
        // Live process reports a bare, differently-cased name.
        let live = [mi("GAME.EXE", 0xABC0000)];
        let index = module_base_index(&live);
        let base = resolve_module_base(&index, reader.module_name(0).unwrap());
        assert_eq!(base, Some(0xABC0000));
        let _ = std::fs::remove_file(&path);
    }
}
