use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use memmap2::{Mmap, MmapOptions};
use rayon::prelude::*;

use crate::interfaces::PlatformAPI;
use crate::protocol::{ScanCompareType, ScanValue, ScanValueType};
use crate::scan_results::{ScanResultReader, ScanResultWriter, TempPath};

/// Batch size for streaming the previous scan generation through a next-scan
/// transform — bounds peak RAM to one batch of records, not the whole result set.
const NEXT_SCAN_BATCH: usize = 64 * 1024;

/// Work-unit size for the parallel snapshot next-scan: regions are split into
/// chunks of about this size so a single huge region is shared across cores
/// (instead of pinning one thread) and peak RAM stays bounded to roughly
/// `threads × this` regardless of region size. Mirrors the pointer scanner's
/// `PARALLEL_CHUNK_BYTES`.
const SNAPSHOT_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Process-global counter for unique temp-file names. Combined with pid + a
/// timestamp so concurrent scans (and parallel build segments) never collide.
static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(prefix: &str, pid: u32) -> PathBuf {
    let id = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("joybug_{}_{}_{}_{}.bin", prefix, pid, id, nanos))
}

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;
const MEM_COMMIT: u32 = 0x1000;
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

pub struct MemoryScanner {
    scans: HashMap<u64, ScanState>,
    next_id: u64,
}

struct ScanState {
    pid: u32,
    value_type: ScanValueType,
    alignment: usize,
    float_tolerance: f64,
    /// Number of threads to use for scanning. `None` or `Some(0)` means the
    /// global rayon pool (all cores); `Some(n)` uses a scoped pool of `n` threads.
    thread_count: Option<usize>,
    storage: ScanStorage,
}

/// Runs `f` on a scoped rayon thread pool of `thread_count` threads, or on the
/// global pool (all cores) when `thread_count` is `None`/`Some(0)` or the scoped
/// pool fails to build.
pub(crate) fn install_pool<T: Send>(thread_count: Option<usize>, f: impl FnOnce() -> T + Send) -> T {
    match thread_count {
        Some(n) if n > 0 => match rayon::ThreadPoolBuilder::new().num_threads(n).build() {
            Ok(pool) => pool.install(f),
            Err(_) => f(),
        },
        _ => f(),
    }
}

/// Per-scan storage. Both variants are disk-backed (read-only mmap) so a scan's
/// RAM cost is a small index plus the OS page cache, regardless of match count
/// or snapshot size. See [`crate::scan_results`] for the result-file format.
enum ScanStorage {
    /// `UnknownInitialValue` first scan: every scanned region's bytes streamed to
    /// one mmap'd file, compared live on the next scan. Replaces the old
    /// `Vec<(u64, Vec<u8>)>` that held a full copy of committed memory in RAM.
    Snapshot(SnapshotStore),
    /// A concrete candidate set: 16-byte records (address + value) in an mmap'd
    /// results file. Replaces the old uncapped `Vec<ScanEntry>`.
    Filtered(FilteredResults),
}

/// A disk-backed results file plus its cleanup guard. `reader` (the mmap) is
/// declared before `_temp` so the mapping is released first; `_temp` then
/// unlinks the file (struct fields drop in declaration order).
struct FilteredResults {
    reader: ScanResultReader,
    _temp: TempPath,
}

/// Region snapshots for an `UnknownInitialValue` scan: every region's raw bytes
/// concatenated in one read-only mmap'd file, with an index of where each
/// region lives. `mmap` is declared before `_temp` so the mapping drops first.
struct SnapshotStore {
    /// `None` when no region was readable (the file would be zero-length, which
    /// `memmap2` cannot map).
    mmap: Option<Mmap>,
    /// `(region_base, file_offset, len)` for each non-empty region, ascending.
    index: Vec<(u64, usize, usize)>,
    _temp: TempPath,
}

impl SnapshotStore {
    /// Stored bytes of region `i`.
    fn region_bytes(&self, i: usize) -> &[u8] {
        match &self.mmap {
            Some(m) => {
                let (_, off, len) = self.index[i];
                &m[off..off + len]
            }
            None => &[],
        }
    }

    /// `(region_base, file_offset, len)` for every stored region, ascending.
    fn regions(&self) -> &[(u64, usize, usize)] {
        &self.index
    }
}

impl MemoryScanner {
    pub fn new() -> Self {
        Self {
            scans: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn start_scan(
        &mut self,
        platform: &dyn PlatformAPI,
        pid: u32,
        value_type: ScanValueType,
        compare_type: ScanCompareType,
        value: Option<ScanValue>,
        value2: Option<ScanValue>,
        alignment: Option<usize>,
        float_tolerance: Option<f64>,
        writable_only: bool,
        thread_count: Option<usize>,
    ) -> Result<(u64, u64, u64), String> {
        // Validation
        validate_first_scan(compare_type, value_type, &value, &value2)?;

        let alignment = alignment.unwrap_or(value_type.size()).max(1);
        let float_tolerance = float_tolerance.unwrap_or(1e-6);
        let val_size = value_type.size();

        let start = Instant::now();
        let regions = enumerate_scannable_regions(platform, pid, writable_only)?;

        let (storage, match_count) = if compare_type == ScanCompareType::UnknownInitialValue {
            // Snapshot every region's bytes to a disk-backed mmap file instead of
            // holding a full RAM copy of committed memory. The match count is the
            // number of aligned positions across all non-empty regions.
            let store = build_snapshot_store(platform, pid, &regions, thread_count)?;
            let mut total = 0u64;
            for &(_, _, len) in store.regions() {
                total += (len.saturating_sub(val_size - 1) / alignment) as u64;
            }
            (ScanStorage::Snapshot(store), total)
        } else {
            let value = value.unwrap(); // validated above
            // Scan each region in parallel, streaming matches to per-region segment
            // files, then concatenate them in ascending address order into one
            // results file — no full match set is ever held in RAM.
            let results = build_filtered_first(
                platform, pid, &regions, value_type, alignment,
                compare_type, value, value2, float_tolerance, thread_count,
            )?;
            let count = results.reader.len() as u64;
            (ScanStorage::Filtered(results), count)
        };

        let scan_id = self.next_id;
        self.next_id += 1;
        let scan_time_us = start.elapsed().as_micros() as u64;

        self.scans.insert(scan_id, ScanState {
            pid,
            value_type,
            alignment,
            float_tolerance,
            thread_count,
            storage,
        });

        Ok((scan_id, match_count, scan_time_us))
    }

    pub fn next_scan(
        &mut self,
        platform: &dyn PlatformAPI,
        scan_id: u64,
        compare_type: ScanCompareType,
        value: Option<ScanValue>,
        value2: Option<ScanValue>,
    ) -> Result<(u64, u64), String> {
        let state = self.scans.get_mut(&scan_id)
            .ok_or_else(|| format!("Scan ID {} not found", scan_id))?;

        validate_next_scan(compare_type, state.value_type, &value, &value2)?;

        let start = Instant::now();
        let pid = state.pid;
        let value_type = state.value_type;
        let alignment = state.alignment;
        let float_tolerance = state.float_tolerance;
        let thread_count = state.thread_count;
        let val_size = value_type.size();

        // Stream the previous generation through the comparison into a NEW results
        // file, then swap. Peak RAM is one batch (plus the live reads for it), not
        // two full result sets. The old storage is dropped on swap, unlinking its
        // temp file(s).
        let new_path = unique_temp_path("scanres", pid);
        let new_temp = TempPath::new(new_path.clone());

        let mut writer = ScanResultWriter::create(&new_path, value_type)
            .map_err(|e| format!("Failed to create scan results file: {}", e))?;

        let result: Result<(), String> = install_pool(thread_count, || match &state.storage {
            ScanStorage::Snapshot(store) => next_from_snapshot(
                platform, pid, store, value_type, alignment,
                compare_type, value, value2, float_tolerance, &mut writer,
            ),
            ScanStorage::Filtered(fr) => next_from_filtered(
                platform, pid, &fr.reader, value_type, val_size,
                compare_type, value, value2, float_tolerance, &mut writer,
            ),
        });
        result?;

        let match_count = writer.finish()
            .map_err(|e| format!("Failed to finalize scan results file: {}", e))?;

        let reader = ScanResultReader::open(&new_path)?;
        state.storage = ScanStorage::Filtered(FilteredResults { _temp: new_temp, reader });
        let scan_time_us = start.elapsed().as_micros() as u64;

        Ok((match_count, scan_time_us))
    }

    pub fn get_results(
        &self,
        platform: &dyn PlatformAPI,
        scan_id: u64,
        offset: u64,
        count: u64,
    ) -> Result<(Vec<u64>, Vec<ScanValue>, u64), String> {
        let state = self.scans.get(&scan_id)
            .ok_or_else(|| format!("Scan ID {} not found", scan_id))?;

        match &state.storage {
            ScanStorage::Snapshot(_) => {
                Err("Cannot get individual results from unknown initial value scan; run a next scan first".into())
            }
            ScanStorage::Filtered(fr) => {
                let total_count = fr.reader.len() as u64;
                let addresses = fr.reader.page_addresses(offset as usize, count as usize);

                let mut values = Vec::with_capacity(addresses.len());
                for (k, &address) in addresses.iter().enumerate() {
                    // Re-read current value from process memory; fall back to the
                    // stored value if the address is no longer readable.
                    let val = read_current_value(platform, state.pid, address, state.value_type)
                        .unwrap_or_else(|| {
                            let (_, stored) = fr.reader.record(offset as usize + k).unwrap();
                            bytes_to_scan_value(&stored, state.value_type)
                        });
                    values.push(val);
                }

                Ok((addresses, values, total_count))
            }
        }
    }

    pub fn reset_scan(&mut self, scan_id: u64) -> Result<(), String> {
        self.scans.remove(&scan_id)
            .map(|_| ())
            .ok_or_else(|| format!("Scan ID {} not found", scan_id))
    }
}

// --- Validation ---

fn validate_first_scan(
    compare_type: ScanCompareType,
    value_type: ScanValueType,
    value: &Option<ScanValue>,
    value2: &Option<ScanValue>,
) -> Result<(), String> {
    use ScanCompareType::*;
    match compare_type {
        IncreasedValue | DecreasedValue | Changed | Unchanged
        | IncreasedValueBy | DecreasedValueBy => {
            return Err(format!("{:?} cannot be used for first scan (no previous values)", compare_type));
        }
        _ => {}
    }
    validate_value_requirements(compare_type, value_type, value, value2)
}

fn validate_next_scan(
    compare_type: ScanCompareType,
    value_type: ScanValueType,
    value: &Option<ScanValue>,
    value2: &Option<ScanValue>,
) -> Result<(), String> {
    if compare_type == ScanCompareType::UnknownInitialValue {
        return Err("UnknownInitialValue cannot be used for next scan".into());
    }
    validate_value_requirements(compare_type, value_type, value, value2)
}

fn validate_value_requirements(
    compare_type: ScanCompareType,
    value_type: ScanValueType,
    value: &Option<ScanValue>,
    value2: &Option<ScanValue>,
) -> Result<(), String> {
    use ScanCompareType::*;
    match compare_type {
        ExactValue | BiggerThan | SmallerThan | IncreasedValueBy | DecreasedValueBy => {
            let v = value.as_ref().ok_or(format!("{:?} requires a value", compare_type))?;
            validate_type_match(value_type, v)?;
        }
        ValueBetween => {
            let v = value.as_ref().ok_or("ValueBetween requires value")?;
            let v2 = value2.as_ref().ok_or("ValueBetween requires value2")?;
            validate_type_match(value_type, v)?;
            validate_type_match(value_type, v2)?;
        }
        UnknownInitialValue | IncreasedValue | DecreasedValue | Changed | Unchanged => {}
    }
    Ok(())
}

fn validate_type_match(value_type: ScanValueType, value: &ScanValue) -> Result<(), String> {
    let matches = match (value_type, value) {
        (ScanValueType::U8, ScanValue::U8(_)) => true,
        (ScanValueType::U16, ScanValue::U16(_)) => true,
        (ScanValueType::U32, ScanValue::U32(_)) => true,
        (ScanValueType::U64, ScanValue::U64(_)) => true,
        (ScanValueType::F32, ScanValue::F32(_)) => true,
        (ScanValueType::F64, ScanValue::F64(_)) => true,
        _ => false,
    };
    if !matches {
        return Err(format!("ScanValue variant does not match ScanValueType {:?}", value_type));
    }
    Ok(())
}

// --- Region enumeration ---

/// Writable protection mask: PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
const PAGE_WRITABLE_MASK: u32 = 0x04 | 0x08 | 0x40 | 0x80;

pub(crate) fn enumerate_scannable_regions(platform: &dyn PlatformAPI, pid: u32, writable_only: bool) -> Result<Vec<(u64, usize)>, String> {
    let regions = platform.enumerate_memory_regions(pid)
        .map_err(|e| format!("Failed to enumerate memory regions: {}", e))?;

    Ok(regions.iter()
        .filter(|r| {
            r.state == MEM_COMMIT
            && r.protect != 0
            && (r.protect & PAGE_NOACCESS) == 0
            && (r.protect & PAGE_GUARD) == 0
            && (!writable_only || (r.protect & PAGE_WRITABLE_MASK) != 0)
        })
        .map(|r| (r.base_address, r.region_size as usize))
        .collect())
}

/// Read `[base, base+size)` in `CHUNK_SIZE` pieces, invoking `f(chunk_addr, &chunk)`
/// for each successfully read chunk. Stops after a short read (region boundary).
/// On a read error, `skip_on_error` chooses whether to skip the failed chunk and
/// continue (used by the value scan, so a single bad page doesn't truncate the
/// region) or stop (used when streaming raw bytes, where a gap can't be tolerated).
/// `f` returns `false` to stop early (e.g. on a downstream write error).
fn for_each_region_chunk(
    platform: &dyn PlatformAPI,
    pid: u32,
    base: u64,
    size: usize,
    skip_on_error: bool,
    mut f: impl FnMut(u64, &[u8]) -> bool,
) {
    let mut offset = 0usize;
    while offset < size {
        let read_size = CHUNK_SIZE.min(size - offset);
        match platform.read_memory(pid, base + offset as u64, read_size) {
            Ok(data) => {
                let n = data.len();
                let cont = f(base + offset as u64, &data);
                offset += n;
                if !cont || n < read_size {
                    break;
                }
            }
            Err(_) => {
                if skip_on_error {
                    offset += read_size;
                } else {
                    break;
                }
            }
        }
    }
}

pub(crate) fn read_region_chunked(platform: &dyn PlatformAPI, pid: u32, base: u64, size: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(size);
    for_each_region_chunk(platform, pid, base, size, false, |_, data| {
        result.extend_from_slice(data);
        true
    });
    result
}

// --- Disk-backed build helpers ---

/// Concatenate result segments (each a valid scan-results file) in order into a
/// single results file at `final_path`, streaming records in bounded batches.
fn concat_result_segments(
    final_path: &Path,
    value_type: ScanValueType,
    segments: &[TempPath],
) -> Result<(), String> {
    let mut writer = ScanResultWriter::create(final_path, value_type)
        .map_err(|e| format!("Failed to create scan results file: {}", e))?;
    for seg in segments {
        append_segment_records(&mut writer, seg)?;
    }
    writer.finish()
        .map_err(|e| format!("Failed to finalize scan results file: {}", e))?;
    Ok(())
}

/// Append every record from a segment file (itself a valid results file) into an
/// open writer by raw byte copy — no per-record decode/re-encode.
fn append_segment_records(writer: &mut ScanResultWriter, seg: &TempPath) -> Result<(), String> {
    writer.append_records_file(seg.path())
        .map_err(|e| format!("Failed to append scan results segment: {}", e))
}

/// A results segment created lazily on the first pushed record, so a producer that
/// finds no matches costs no file. Wraps the `Option<(writer, temp)>` + create-on-
/// first-push + finish-or-`None` dance shared by the first-scan and snapshot-next
/// producers.
struct LazySegment {
    inner: Option<(ScanResultWriter, TempPath)>,
    value_type: ScanValueType,
    pid: u32,
    prefix: &'static str,
}

impl LazySegment {
    fn new(value_type: ScanValueType, pid: u32, prefix: &'static str) -> Self {
        Self { inner: None, value_type, pid, prefix }
    }

    fn push(&mut self, address: u64, value: &[u8; 8]) -> Result<(), String> {
        if self.inner.is_none() {
            let path = unique_temp_path(self.prefix, self.pid);
            let w = ScanResultWriter::create(&path, self.value_type)
                .map_err(|e| format!("Failed to create scan results file: {}", e))?;
            self.inner = Some((w, TempPath::new(path)));
        }
        self.inner.as_mut().unwrap().0.push(address, value)
            .map_err(|e| format!("Failed to write scan results file: {}", e))
    }

    /// Finalize the segment, returning its guard, or `None` if nothing was pushed.
    fn finish(self) -> Result<Option<TempPath>, String> {
        match self.inner {
            Some((w, temp)) => {
                w.finish().map_err(|e| format!("Failed to finalize scan results file: {}", e))?;
                Ok(Some(temp))
            }
            None => Ok(None),
        }
    }
}

// --- First scan ---

/// First scan with a concrete predicate: scan each region in parallel, streaming
/// matches to per-region segment files, then concatenate them in ascending base
/// order. No full match set is ever materialized in RAM.
#[allow(clippy::too_many_arguments)]
fn build_filtered_first(
    platform: &dyn PlatformAPI,
    pid: u32,
    regions: &[(u64, usize)],
    value_type: ScanValueType,
    alignment: usize,
    compare_type: ScanCompareType,
    value: ScanValue,
    value2: Option<ScanValue>,
    float_tolerance: f64,
    thread_count: Option<usize>,
) -> Result<FilteredResults, String> {
    // Regions are ascending; `filter_map().collect()` preserves that order, so the
    // concatenated file is globally ascending (required by the next-scan batching).
    let segments: Vec<TempPath> = install_pool(thread_count, || {
        regions
            .par_iter()
            .filter_map(|(base, size)| {
                scan_region_first_to_segment(
                    platform, pid, *base, *size, value_type, alignment,
                    compare_type, value, value2, float_tolerance,
                )
            })
            .collect()
    });

    let final_path = unique_temp_path("scanres", pid);
    let temp = TempPath::new(final_path.clone());
    concat_result_segments(&final_path, value_type, &segments)?;
    // `segments` (and their temp files) drop at function return.
    let reader = ScanResultReader::open(&final_path)?;
    Ok(FilteredResults { _temp: temp, reader })
}

/// Scan one region for a concrete predicate, streaming matches to a fresh segment
/// file. Returns the segment guard, or `None` if the region had no matches (its
/// file is created lazily on the first match, so no-match regions cost no file).
#[allow(clippy::too_many_arguments)]
fn scan_region_first_to_segment(
    platform: &dyn PlatformAPI,
    pid: u32,
    base: u64,
    size: usize,
    value_type: ScanValueType,
    alignment: usize,
    compare_type: ScanCompareType,
    value: ScanValue,
    value2: Option<ScanValue>,
    float_tolerance: f64,
) -> Option<TempPath> {
    let val_size = value_type.size();
    let mut seg = LazySegment::new(value_type, pid, "scanseg");
    let mut failed = false;
    for_each_region_chunk(platform, pid, base, size, true, |chunk_addr, data| {
        if data.len() < val_size {
            return true;
        }
        let mut pos = 0usize;
        while pos + val_size <= data.len() {
            let bytes = &data[pos..pos + val_size];
            if compare_value_first(bytes, value_type, compare_type, value, value2, float_tolerance) {
                let mut stored = [0u8; 8];
                stored[..val_size].copy_from_slice(bytes);
                if seg.push(chunk_addr + pos as u64, &stored).is_err() {
                    failed = true;
                    return false;
                }
            }
            pos += alignment;
        }
        true
    });
    if failed {
        return None;
    }
    seg.finish().ok().flatten()
}

// --- Snapshot build (UnknownInitialValue first scan) ---

/// Read every region's bytes (in parallel) into per-region segment files, then
/// concatenate them in ascending base order into one read-only mmap'd snapshot
/// file. Peak RAM is bounded to per-thread chunk buffers plus the OS page cache.
fn build_snapshot_store(
    platform: &dyn PlatformAPI,
    pid: u32,
    regions: &[(u64, usize)],
    thread_count: Option<usize>,
) -> Result<SnapshotStore, String> {
    // (base, segment, actual_len) for each non-empty region, in ascending order.
    let segments: Vec<(u64, TempPath, usize)> = install_pool(thread_count, || {
        regions
            .par_iter()
            .filter_map(|(base, size)| write_region_segment(platform, pid, *base, *size))
            .collect()
    });

    let final_path = unique_temp_path("scansnap", pid);
    let temp = TempPath::new(final_path.clone());
    let mut index = Vec::with_capacity(segments.len());
    let mut total = 0usize;
    {
        let file = File::create(&final_path)
            .map_err(|e| format!("Failed to create snapshot file: {}", e))?;
        let mut w = BufWriter::new(file);
        for (base, seg, len) in &segments {
            let mut sf = File::open(seg.path())
                .map_err(|e| format!("Failed to open snapshot segment: {}", e))?;
            std::io::copy(&mut sf, &mut w)
                .map_err(|e| format!("Failed to copy snapshot segment: {}", e))?;
            index.push((*base, total, *len));
            total += *len;
        }
        w.flush().map_err(|e| format!("Failed to flush snapshot file: {}", e))?;
    }
    // `segments` (and their temp files) drop at the end of this function.

    let mmap = if total == 0 {
        None // never mmap a zero-length file
    } else {
        let file = File::open(&final_path)
            .map_err(|e| format!("Failed to open snapshot file: {}", e))?;
        Some(unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| format!("Failed to mmap snapshot file: {}", e))?)
    };

    Ok(SnapshotStore { _temp: temp, mmap, index })
}

/// Read one region in chunks, streaming its bytes to a fresh segment file.
/// Returns `(base, segment, actual_len)`, or `None` if nothing was readable.
fn write_region_segment(
    platform: &dyn PlatformAPI,
    pid: u32,
    base: u64,
    size: usize,
) -> Option<(u64, TempPath, usize)> {
    let seg_path = unique_temp_path("snapseg", pid);
    let file = File::create(&seg_path).ok()?;
    let temp = TempPath::new(seg_path);
    let mut w = BufWriter::new(file);
    let mut written = 0usize;
    for_each_region_chunk(platform, pid, base, size, false, |_, data| {
        if w.write_all(data).is_err() {
            return false; // stop on write error
        }
        written += data.len();
        true
    });
    w.flush().ok()?;
    if written == 0 {
        return None; // drop empty segment (temp file deleted on drop)
    }
    Some((base, temp, written))
}

// --- Next scan from snapshot ---

/// Compare each region's stored bytes (from the mmap'd snapshot) against freshly
/// read live memory, streaming survivors to `writer`. Regions are processed in
/// ascending order — one region's bytes resident at a time — so peak RAM is one
/// region, not the whole snapshot.
#[allow(clippy::too_many_arguments)]
fn next_from_snapshot(
    platform: &dyn PlatformAPI,
    pid: u32,
    store: &SnapshotStore,
    value_type: ScanValueType,
    alignment: usize,
    compare_type: ScanCompareType,
    value: Option<ScanValue>,
    value2: Option<ScanValue>,
    float_tolerance: f64,
    writer: &mut ScanResultWriter,
) -> Result<(), String> {
    let val_size = value_type.size();

    // Split every region into fixed-size, alignment-tiled chunks so the work is
    // shared across cores even when a few regions dominate. `chunk_step` is a
    // multiple of `alignment`, so aligned positions tile cleanly across chunk
    // boundaries (each position belongs to exactly one chunk). Chunks are listed
    // in ascending address order, which the concat below preserves.
    let chunk_step = (SNAPSHOT_CHUNK_BYTES / alignment).max(1) * alignment;
    let mut chunks: Vec<(usize, usize, usize)> = Vec::new(); // (region_index, c_start, c_end)
    for (ri, &(_, _, len)) in store.regions().iter().enumerate() {
        let mut off = 0usize;
        while off < len {
            let end = (off + chunk_step).min(len);
            chunks.push((ri, off, end));
            off = end;
        }
    }

    // Compare each chunk against live memory in parallel (on the ambient scoped
    // pool installed by `next_scan`), streaming survivors to a per-chunk segment
    // file. Peak RAM is ~`threads × SNAPSHOT_CHUNK_BYTES` — the old bytes come
    // from the mmap (page cache, evictable) and only one chunk of live bytes is
    // resident per thread.
    let segments: Vec<Option<TempPath>> = chunks
        .par_iter()
        .map(|&(ri, c_start, c_end)| {
            compare_snapshot_chunk(
                platform, pid, store, ri, c_start, c_end,
                value_type, val_size, alignment,
                compare_type, value, value2, float_tolerance,
            )
        })
        .collect::<Result<Vec<Option<TempPath>>, String>>()?;

    // Concatenate survivors into the output writer in ascending order.
    for seg in segments.into_iter().flatten() {
        append_segment_records(writer, &seg)?;
    }
    Ok(())
}

/// Compare positions `[c_start, c_end)` of region `ri` (old bytes from the mmap'd
/// snapshot vs freshly read live memory), streaming survivors to a fresh segment
/// file. Returns the segment guard, or `None` if the chunk had no survivors. The
/// live read covers an extra `val_size - 1` bytes past `c_end` so a value that
/// straddles the chunk boundary is still fully evaluated.
#[allow(clippy::too_many_arguments)]
fn compare_snapshot_chunk(
    platform: &dyn PlatformAPI,
    pid: u32,
    store: &SnapshotStore,
    ri: usize,
    c_start: usize,
    c_end: usize,
    value_type: ScanValueType,
    val_size: usize,
    alignment: usize,
    compare_type: ScanCompareType,
    value: Option<ScanValue>,
    value2: Option<ScanValue>,
    float_tolerance: f64,
) -> Result<Option<TempPath>, String> {
    let (base, _off, len) = store.regions()[ri];
    let old_data = store.region_bytes(ri);

    // Live bytes for this chunk, with overlap to cover boundary-straddling values.
    let read_end = (c_end + val_size - 1).min(len);
    let read_len = read_end.saturating_sub(c_start);
    if read_len < val_size {
        return Ok(None);
    }
    let new_data = read_region_chunked(platform, pid, base + c_start as u64, read_len);

    let mut seg = LazySegment::new(value_type, pid, "snapres");
    let mut pos = c_start;
    while pos < c_end {
        if pos + val_size > len {
            break; // value would run past the region
        }
        let rel = pos - c_start;
        if rel + val_size > new_data.len() || pos + val_size > old_data.len() {
            break; // live read was short here (region shrank / unreadable)
        }
        let old_bytes = &old_data[pos..pos + val_size];
        let new_bytes = &new_data[rel..rel + val_size];
        if compare_value_next(new_bytes, old_bytes, value_type, compare_type, value, value2, float_tolerance) {
            let mut stored = [0u8; 8];
            stored[..val_size].copy_from_slice(new_bytes);
            seg.push(base + pos as u64, &stored)?;
        }
        pos += alignment;
    }

    seg.finish()
}

// --- Next scan from filtered entries ---

/// Stream the previous candidate set (from its mmap'd results file) through the
/// comparison in bounded batches, writing survivors to `writer`. Within each
/// batch, nearby addresses are grouped into proximity reads and compared in
/// parallel; survivors stay in ascending order.
#[allow(clippy::too_many_arguments)]
fn next_from_filtered(
    platform: &dyn PlatformAPI,
    pid: u32,
    reader: &ScanResultReader,
    value_type: ScanValueType,
    val_size: usize,
    compare_type: ScanCompareType,
    value: Option<ScanValue>,
    value2: Option<ScanValue>,
    float_tolerance: f64,
    writer: &mut ScanResultWriter,
) -> Result<(), String> {
    let n = reader.len();
    let mut i = 0;
    while i < n {
        let end = (i + NEXT_SCAN_BATCH).min(n);
        let entries = reader.batch(i, end);
        let survivors = compare_filtered_batch(
            platform, pid, &entries, value_type, val_size,
            compare_type, value, value2, float_tolerance,
        );
        for (addr, stored) in survivors {
            writer.push(addr, &stored)
                .map_err(|e| format!("Failed to write scan results file: {}", e))?;
        }
        i = end;
    }
    Ok(())
}

/// Compare one batch of `(address, old_value)` entries against live memory,
/// returning survivors in ascending address order. Nearby addresses (within 4KB)
/// share a single proximity read; groups are compared in parallel.
#[allow(clippy::too_many_arguments)]
fn compare_filtered_batch(
    platform: &dyn PlatformAPI,
    pid: u32,
    entries: &[(u64, [u8; 8])],
    value_type: ScanValueType,
    val_size: usize,
    compare_type: ScanCompareType,
    value: Option<ScanValue>,
    value2: Option<ScanValue>,
    float_tolerance: f64,
) -> Vec<(u64, [u8; 8])> {
    if entries.is_empty() {
        return Vec::new();
    }

    // Group nearby addresses into batch reads (within 4KB proximity).
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut gs = 0usize;
    while gs < entries.len() {
        let group_base = entries[gs].0;
        let mut ge = gs + 1;
        while ge < entries.len() {
            if entries[ge].0 - group_base > 4096 {
                break;
            }
            ge += 1;
        }
        groups.push((gs, ge));
        gs = ge;
    }

    // Process each group in parallel; flatten preserves address order.
    groups
        .par_iter()
        .map(|&(gs, ge)| {
            let mut result = Vec::new();
            let group_base = entries[gs].0;
            let last_addr = entries[ge - 1].0;
            let read_size = (last_addr - group_base) as usize + val_size;
            let read_data = platform.read_memory(pid, group_base, read_size);

            for (addr, old_val) in &entries[gs..ge] {
                let offset = (addr - group_base) as usize;
                let new_bytes = match &read_data {
                    Ok(data) if offset + val_size <= data.len() => &data[offset..offset + val_size],
                    _ => continue, // can't read - drop this entry
                };

                if compare_value_next(new_bytes, &old_val[..val_size], value_type, compare_type, value, value2, float_tolerance) {
                    let mut stored = [0u8; 8];
                    stored[..val_size].copy_from_slice(new_bytes);
                    result.push((*addr, stored));
                }
            }
            result
        })
        .collect::<Vec<Vec<(u64, [u8; 8])>>>()
        .into_iter()
        .flatten()
        .collect()
}

// --- Comparison functions ---

fn compare_value_first(
    bytes: &[u8],
    value_type: ScanValueType,
    compare_type: ScanCompareType,
    target: ScanValue,
    target2: Option<ScanValue>,
    float_tolerance: f64,
) -> bool {
    match value_type {
        ScanValueType::U8 => {
            let curr = bytes[0] as u64;
            let t = scan_value_as_u64(target);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_first(curr, t, t2, compare_type)
        }
        ScanValueType::U16 => {
            let curr = u16::from_le_bytes([bytes[0], bytes[1]]) as u64;
            let t = scan_value_as_u64(target);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_first(curr, t, t2, compare_type)
        }
        ScanValueType::U32 => {
            let curr = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
            let t = scan_value_as_u64(target);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_first(curr, t, t2, compare_type)
        }
        ScanValueType::U64 => {
            let curr = u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
            let t = scan_value_as_u64(target);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_first(curr, t, t2, compare_type)
        }
        ScanValueType::F32 => {
            let curr = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64;
            let t = scan_value_as_f64(target);
            let t2 = target2.map(scan_value_as_f64);
            compare_float_first(curr, t, t2, compare_type, float_tolerance)
        }
        ScanValueType::F64 => {
            let curr = f64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
            let t = scan_value_as_f64(target);
            let t2 = target2.map(scan_value_as_f64);
            compare_float_first(curr, t, t2, compare_type, float_tolerance)
        }
    }
}

fn compare_value_next(
    new_bytes: &[u8],
    old_bytes: &[u8],
    value_type: ScanValueType,
    compare_type: ScanCompareType,
    target: Option<ScanValue>,
    target2: Option<ScanValue>,
    float_tolerance: f64,
) -> bool {
    match value_type {
        ScanValueType::U8 => {
            let curr = new_bytes[0] as u64;
            let prev = old_bytes[0] as u64;
            let t = target.map(scan_value_as_u64);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_next(curr, prev, t, t2, compare_type)
        }
        ScanValueType::U16 => {
            let curr = u16::from_le_bytes([new_bytes[0], new_bytes[1]]) as u64;
            let prev = u16::from_le_bytes([old_bytes[0], old_bytes[1]]) as u64;
            let t = target.map(scan_value_as_u64);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_next(curr, prev, t, t2, compare_type)
        }
        ScanValueType::U32 => {
            let curr = u32::from_le_bytes([new_bytes[0], new_bytes[1], new_bytes[2], new_bytes[3]]) as u64;
            let prev = u32::from_le_bytes([old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3]]) as u64;
            let t = target.map(scan_value_as_u64);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_next(curr, prev, t, t2, compare_type)
        }
        ScanValueType::U64 => {
            let curr = u64::from_le_bytes([new_bytes[0], new_bytes[1], new_bytes[2], new_bytes[3], new_bytes[4], new_bytes[5], new_bytes[6], new_bytes[7]]);
            let prev = u64::from_le_bytes([old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3], old_bytes[4], old_bytes[5], old_bytes[6], old_bytes[7]]);
            let t = target.map(scan_value_as_u64);
            let t2 = target2.map(scan_value_as_u64);
            compare_int_next(curr, prev, t, t2, compare_type)
        }
        ScanValueType::F32 => {
            let curr = f32::from_le_bytes([new_bytes[0], new_bytes[1], new_bytes[2], new_bytes[3]]) as f64;
            let prev = f32::from_le_bytes([old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3]]) as f64;
            let t = target.map(scan_value_as_f64);
            let t2 = target2.map(scan_value_as_f64);
            compare_float_next(curr, prev, t, t2, compare_type, float_tolerance)
        }
        ScanValueType::F64 => {
            let curr = f64::from_le_bytes([new_bytes[0], new_bytes[1], new_bytes[2], new_bytes[3], new_bytes[4], new_bytes[5], new_bytes[6], new_bytes[7]]);
            let prev = f64::from_le_bytes([old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3], old_bytes[4], old_bytes[5], old_bytes[6], old_bytes[7]]);
            let t = target.map(scan_value_as_f64);
            let t2 = target2.map(scan_value_as_f64);
            compare_float_next(curr, prev, t, t2, compare_type, float_tolerance)
        }
    }
}

fn compare_int_first(curr: u64, target: u64, target2: Option<u64>, compare_type: ScanCompareType) -> bool {
    match compare_type {
        ScanCompareType::ExactValue => curr == target,
        ScanCompareType::BiggerThan => curr > target,
        ScanCompareType::SmallerThan => curr < target,
        ScanCompareType::ValueBetween => {
            let t2 = target2.unwrap_or(target);
            curr >= target && curr <= t2
        }
        ScanCompareType::UnknownInitialValue => true,
        _ => false, // should not happen for first scan
    }
}

fn compare_int_next(curr: u64, prev: u64, target: Option<u64>, target2: Option<u64>, compare_type: ScanCompareType) -> bool {
    match compare_type {
        ScanCompareType::ExactValue => curr == target.unwrap_or(0),
        ScanCompareType::BiggerThan => curr > target.unwrap_or(0),
        ScanCompareType::SmallerThan => curr < target.unwrap_or(0),
        ScanCompareType::ValueBetween => {
            let t = target.unwrap_or(0);
            let t2 = target2.unwrap_or(t);
            curr >= t && curr <= t2
        }
        ScanCompareType::IncreasedValue => curr > prev,
        ScanCompareType::DecreasedValue => curr < prev,
        ScanCompareType::IncreasedValueBy => curr == prev.wrapping_add(target.unwrap_or(0)),
        ScanCompareType::DecreasedValueBy => prev == curr.wrapping_add(target.unwrap_or(0)),
        ScanCompareType::Changed => curr != prev,
        ScanCompareType::Unchanged => curr == prev,
        ScanCompareType::UnknownInitialValue => false,
    }
}

fn compare_float_first(curr: f64, target: f64, target2: Option<f64>, compare_type: ScanCompareType, tol: f64) -> bool {
    match compare_type {
        ScanCompareType::ExactValue => (curr - target).abs() <= float_eps(target, tol),
        ScanCompareType::BiggerThan => curr > target,
        ScanCompareType::SmallerThan => curr < target,
        ScanCompareType::ValueBetween => {
            let t2 = target2.unwrap_or(target);
            curr >= target && curr <= t2
        }
        ScanCompareType::UnknownInitialValue => true,
        _ => false,
    }
}

fn compare_float_next(curr: f64, prev: f64, target: Option<f64>, target2: Option<f64>, compare_type: ScanCompareType, tol: f64) -> bool {
    let eps = float_eps(curr, tol);
    match compare_type {
        ScanCompareType::ExactValue => {
            let t = target.unwrap_or(0.0);
            (curr - t).abs() <= float_eps(t, tol)
        }
        ScanCompareType::BiggerThan => curr > target.unwrap_or(0.0),
        ScanCompareType::SmallerThan => curr < target.unwrap_or(0.0),
        ScanCompareType::ValueBetween => {
            let t = target.unwrap_or(0.0);
            let t2 = target2.unwrap_or(t);
            curr >= t && curr <= t2
        }
        ScanCompareType::IncreasedValue => curr > prev,
        ScanCompareType::DecreasedValue => curr < prev,
        ScanCompareType::IncreasedValueBy => {
            let t = target.unwrap_or(0.0);
            (curr - prev - t).abs() <= eps
        }
        ScanCompareType::DecreasedValueBy => {
            let t = target.unwrap_or(0.0);
            (prev - curr - t).abs() <= eps
        }
        ScanCompareType::Changed => (curr - prev).abs() > eps,
        ScanCompareType::Unchanged => (curr - prev).abs() <= eps,
        ScanCompareType::UnknownInitialValue => false,
    }
}

fn float_eps(value: f64, tol: f64) -> f64 {
    (value.abs() * tol).max(f64::EPSILON)
}

// --- Value conversion helpers ---

fn scan_value_as_u64(v: ScanValue) -> u64 {
    match v {
        ScanValue::U8(x) => x as u64,
        ScanValue::U16(x) => x as u64,
        ScanValue::U32(x) => x as u64,
        ScanValue::U64(x) => x,
        ScanValue::F32(x) => x as u64,
        ScanValue::F64(x) => x as u64,
    }
}

fn scan_value_as_f64(v: ScanValue) -> f64 {
    match v {
        ScanValue::U8(x) => x as f64,
        ScanValue::U16(x) => x as f64,
        ScanValue::U32(x) => x as f64,
        ScanValue::U64(x) => x as f64,
        ScanValue::F32(x) => x as f64,
        ScanValue::F64(x) => x,
    }
}

fn bytes_to_scan_value(bytes: &[u8], value_type: ScanValueType) -> ScanValue {
    match value_type {
        ScanValueType::U8 => ScanValue::U8(bytes[0]),
        ScanValueType::U16 => ScanValue::U16(u16::from_le_bytes([bytes[0], bytes[1]])),
        ScanValueType::U32 => ScanValue::U32(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        ScanValueType::U64 => ScanValue::U64(u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])),
        ScanValueType::F32 => ScanValue::F32(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        ScanValueType::F64 => ScanValue::F64(f64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])),
    }
}

fn read_current_value(platform: &dyn PlatformAPI, pid: u32, address: u64, value_type: ScanValueType) -> Option<ScanValue> {
    let size = value_type.size();
    let data = platform.read_memory(pid, address, size).ok()?;
    if data.len() < size {
        return None;
    }
    Some(bytes_to_scan_value(&data, value_type))
}
