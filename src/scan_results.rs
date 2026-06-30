//! Disk-backed memory-scan results.
//!
//! A memory scan can match tens of millions of addresses (and an
//! `UnknownInitialValue` scan snapshots whole regions), so keeping every match
//! resident in the server process bloats RAM. Mirroring [`crate::pointer_results`],
//! matches are streamed to a file of fixed-size records and read back through a
//! read-only `memmap2::Mmap` for paging. Read-only pages evict cleanly (no
//! write-back), so the store can exceed physical RAM without thrashing, and the
//! per-session RAM cost drops to a small index plus the OS page cache.
//!
//! Unlike pointer scan, memory-scan addresses are produced in ascending order per
//! region, so results never need sorting — only ordered concatenation.

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use memmap2::{Mmap, MmapOptions};

use crate::protocol::ScanValueType;

const MAGIC: u64 = 0x4A42_5343_414E_5231; // "JBSCANR1"
/// magic(u64) + value_type(u32) + reserved(u32). 16 bytes keeps records aligned.
const HEADER_BYTES: usize = 16;
/// address(u64) + value([u8;8]).
const RECORD_BYTES: usize = 16;

fn vt_to_u32(vt: ScanValueType) -> u32 {
    match vt {
        ScanValueType::U8 => 0,
        ScanValueType::U16 => 1,
        ScanValueType::U32 => 2,
        ScanValueType::U64 => 3,
        ScanValueType::F32 => 4,
        ScanValueType::F64 => 5,
    }
}

fn vt_from_u32(v: u32) -> Option<ScanValueType> {
    Some(match v {
        0 => ScanValueType::U8,
        1 => ScanValueType::U16,
        2 => ScanValueType::U32,
        3 => ScanValueType::U64,
        4 => ScanValueType::F32,
        5 => ScanValueType::F64,
        _ => return None,
    })
}

/// A file path deleted when this guard drops. Backs scan result files, region
/// snapshots, and per-region build segments so they are unlinked on reset or
/// session end. Declare it *before* any `Mmap` of the same file so the mapping
/// drops first; the unlink is then immediate (and, while a mapping is still
/// live elsewhere, deferred by Windows share-delete semantics).
pub struct TempPath {
    path: PathBuf,
}

impl TempPath {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Streams memory-scan matches to a fixed-record results file.
pub struct ScanResultWriter {
    w: BufWriter<File>,
    rec: [u8; RECORD_BYTES],
    count: u64,
}

impl ScanResultWriter {
    pub fn create(path: &Path, value_type: ScanValueType) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);
        w.write_all(&MAGIC.to_le_bytes())?;
        w.write_all(&vt_to_u32(value_type).to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?; // reserved
        Ok(Self { w, rec: [0u8; RECORD_BYTES], count: 0 })
    }

    pub fn push(&mut self, address: u64, value: &[u8; 8]) -> std::io::Result<()> {
        self.rec[0..8].copy_from_slice(&address.to_le_bytes());
        self.rec[8..16].copy_from_slice(value);
        self.w.write_all(&self.rec)?;
        self.count += 1;
        Ok(())
    }

    /// Append every record from another results file by copying its raw record
    /// bytes — segment files share this exact little-endian record layout, so no
    /// decode/re-encode is needed. The source header is skipped. The source must
    /// have the same `value_type` (callers create segments with it).
    pub fn append_records_file(&mut self, path: &Path) -> std::io::Result<()> {
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        if len <= HEADER_BYTES as u64 {
            return Ok(()); // header-only (zero records)
        }
        f.seek(SeekFrom::Start(HEADER_BYTES as u64))?;
        let copied = std::io::copy(&mut f, &mut self.w)?;
        self.count += copied / RECORD_BYTES as u64;
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<u64> {
        self.w.flush()?;
        Ok(self.count)
    }
}

/// Reads a results file via read-only mmap. The header always occupies 16 bytes,
/// so a zero-match file is 16 bytes long — never zero-length (which `memmap2`
/// cannot map).
pub struct ScanResultReader {
    mmap: Mmap,
    value_type: ScanValueType,
    count: usize,
}

impl ScanResultReader {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open scan results file: {}", e))?;
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| format!("Failed to mmap scan results file: {}", e))?;
        if mmap.len() < HEADER_BYTES {
            return Err("Scan results file truncated".to_string());
        }
        let magic = u64::from_le_bytes(mmap[0..8].try_into().unwrap());
        if magic != MAGIC {
            return Err("Not a scan results file (or incompatible version)".to_string());
        }
        let vt_raw = u32::from_le_bytes(mmap[8..12].try_into().unwrap());
        let value_type = vt_from_u32(vt_raw).ok_or("Invalid value type in scan results file")?;
        let count = mmap.len().saturating_sub(HEADER_BYTES) / RECORD_BYTES;
        Ok(Self { mmap, value_type, count })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn value_type(&self) -> ScanValueType {
        self.value_type
    }

    /// Address of record `i`, if in range.
    pub fn address(&self, i: usize) -> Option<u64> {
        if i >= self.count {
            return None;
        }
        let base = HEADER_BYTES + i * RECORD_BYTES;
        Some(u64::from_le_bytes(self.mmap[base..base + 8].try_into().unwrap()))
    }

    /// Address + stored value of record `i`, if in range.
    pub fn record(&self, i: usize) -> Option<(u64, [u8; 8])> {
        if i >= self.count {
            return None;
        }
        let base = HEADER_BYTES + i * RECORD_BYTES;
        let address = u64::from_le_bytes(self.mmap[base..base + 8].try_into().unwrap());
        let mut value = [0u8; 8];
        value.copy_from_slice(&self.mmap[base + 8..base + 16]);
        Some((address, value))
    }

    /// Addresses for the page `[offset, offset+count)` (clamped to range).
    pub fn page_addresses(&self, offset: usize, count: usize) -> Vec<u64> {
        let begin = offset.min(self.count);
        let end = offset.saturating_add(count).min(self.count);
        let mut out = Vec::with_capacity(end - begin);
        for i in begin..end {
            out.push(self.address(i).unwrap());
        }
        out
    }

    /// Records for the half-open batch `[start, end)` (clamped to range). Used to
    /// stream the previous scan generation through a next-scan transform.
    pub fn batch(&self, start: usize, end: usize) -> Vec<(u64, [u8; 8])> {
        let begin = start.min(self.count);
        let stop = end.min(self.count);
        let mut out = Vec::with_capacity(stop.saturating_sub(begin));
        for i in begin..stop {
            out.push(self.record(i).unwrap());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("joybug_scanresults_unit_{}_{}.bin", tag, std::process::id()))
    }

    fn v(n: u64) -> [u8; 8] {
        n.to_le_bytes()
    }

    #[test]
    fn round_trips_records_and_paginates() {
        let path = tmp_path("roundtrip");
        let _guard = TempPath::new(path.clone());
        let n = 1000usize;
        {
            let mut w = ScanResultWriter::create(&path, ScanValueType::U32).unwrap();
            for i in 0..n {
                w.push(0x1_0000_0000u64 + (i as u64) * 4, &v(i as u64)).unwrap();
            }
            assert_eq!(w.finish().unwrap(), n as u64);
        }

        let r = ScanResultReader::open(&path).unwrap();
        assert_eq!(r.len(), n);
        assert_eq!(r.value_type(), ScanValueType::U32);

        // Random-ish access.
        assert_eq!(r.address(0), Some(0x1_0000_0000));
        assert_eq!(r.address(999), Some(0x1_0000_0000 + 999 * 4));
        assert_eq!(r.address(1000), None);
        assert_eq!(r.record(500), Some((0x1_0000_0000 + 500 * 4, v(500))));

        // Paging.
        let page = r.page_addresses(10, 5);
        assert_eq!(page, vec![
            0x1_0000_0000 + 10 * 4,
            0x1_0000_0000 + 11 * 4,
            0x1_0000_0000 + 12 * 4,
            0x1_0000_0000 + 13 * 4,
            0x1_0000_0000 + 14 * 4,
        ]);
        // Page past the end clamps.
        assert_eq!(r.page_addresses(998, 10).len(), 2);
        assert_eq!(r.page_addresses(5000, 10).len(), 0);

        // Batch.
        let b = r.batch(0, 3);
        assert_eq!(b, vec![
            (0x1_0000_0000, v(0)),
            (0x1_0000_0004, v(1)),
            (0x1_0000_0008, v(2)),
        ]);
        assert_eq!(r.batch(995, 10_000).len(), 5);
    }

    #[test]
    fn empty_file_has_header_and_zero_records() {
        let path = tmp_path("empty");
        let _guard = TempPath::new(path.clone());
        {
            let w = ScanResultWriter::create(&path, ScanValueType::F64).unwrap();
            assert_eq!(w.finish().unwrap(), 0);
        }
        // 16-byte header file maps fine and reports zero records.
        let r = ScanResultReader::open(&path).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.value_type(), ScanValueType::F64);
        assert_eq!(r.address(0), None);
        assert_eq!(r.page_addresses(0, 10).len(), 0);
    }

    #[test]
    fn value_type_round_trips_for_all_types() {
        for vt in [
            ScanValueType::U8,
            ScanValueType::U16,
            ScanValueType::U32,
            ScanValueType::U64,
            ScanValueType::F32,
            ScanValueType::F64,
        ] {
            let path = tmp_path(&format!("vt_{:?}", vt));
            let _guard = TempPath::new(path.clone());
            {
                let mut w = ScanResultWriter::create(&path, vt).unwrap();
                w.push(0xDEAD_BEEF, &v(7)).unwrap();
                w.finish().unwrap();
            }
            let r = ScanResultReader::open(&path).unwrap();
            assert_eq!(r.value_type(), vt);
            assert_eq!(r.record(0), Some((0xDEAD_BEEF, v(7))));
        }
    }

    #[test]
    fn rejects_non_scan_file() {
        let path = tmp_path("bogus");
        let _guard = TempPath::new(path.clone());
        std::fs::write(&path, b"not a scan results file at all").unwrap();
        assert!(ScanResultReader::open(&path).is_err());
    }
}
