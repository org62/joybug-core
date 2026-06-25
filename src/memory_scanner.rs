use std::collections::HashMap;
use std::time::Instant;

use rayon::prelude::*;

use crate::interfaces::PlatformAPI;
use crate::protocol::{ScanCompareType, ScanValue, ScanValueType};

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

enum ScanStorage {
    RegionSnapshot(Vec<(u64, Vec<u8>)>),
    FilteredEntries(Vec<ScanEntry>),
}

struct ScanEntry {
    address: u64,
    value: [u8; 8],
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
            // Read all regions in parallel, then filter empties / count sequentially.
            let raw: Vec<(u64, Vec<u8>)> = install_pool(thread_count, || {
                regions
                    .par_iter()
                    .map(|(base, size)| (*base, read_region_chunked(platform, pid, *base, *size)))
                    .collect()
            });
            let mut snapshots = Vec::with_capacity(raw.len());
            let mut total = 0u64;
            for (base, data) in raw {
                if !data.is_empty() {
                    // Count how many aligned positions fit
                    total += ((data.len().saturating_sub(val_size - 1)) / alignment) as u64;
                    snapshots.push((base, data));
                }
            }
            (ScanStorage::RegionSnapshot(snapshots), total)
        } else {
            let value = value.unwrap(); // validated above
            // Scan each region in parallel; collect per-region results then flatten so
            // entries stay in ascending address order.
            let entries: Vec<ScanEntry> = install_pool(thread_count, || {
                regions
                    .par_iter()
                    .map(|(base, size)| {
                        scan_region_first(
                            platform, pid, *base, *size, value_type, alignment,
                            compare_type, value, value2, float_tolerance,
                        )
                    })
                    .collect::<Vec<Vec<ScanEntry>>>()
            })
            .into_iter()
            .flatten()
            .collect();
            let count = entries.len() as u64;
            (ScanStorage::FilteredEntries(entries), count)
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

        let old_storage = std::mem::replace(
            &mut state.storage,
            ScanStorage::FilteredEntries(Vec::new()),
        );

        let new_entries = install_pool(thread_count, || match old_storage {
            ScanStorage::RegionSnapshot(snapshots) => {
                next_scan_from_snapshot(
                    platform, pid, &snapshots, value_type, alignment,
                    compare_type, value, value2, float_tolerance,
                )
            }
            ScanStorage::FilteredEntries(entries) => {
                next_scan_from_filtered(
                    platform, pid, entries, value_type, val_size,
                    compare_type, value, value2, float_tolerance,
                )
            }
        });

        let match_count = new_entries.len() as u64;
        state.storage = ScanStorage::FilteredEntries(new_entries);
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
            ScanStorage::RegionSnapshot(_) => {
                Err("Cannot get individual results from unknown initial value scan; run a next scan first".into())
            }
            ScanStorage::FilteredEntries(entries) => {
                let total_count = entries.len() as u64;
                let start = (offset as usize).min(entries.len());
                let end = (start + count as usize).min(entries.len());
                let slice = &entries[start..end];

                let mut addresses = Vec::with_capacity(slice.len());
                let mut values = Vec::with_capacity(slice.len());

                for entry in slice {
                    addresses.push(entry.address);
                    // Re-read current value from process memory
                    let val = read_current_value(platform, state.pid, entry.address, state.value_type)
                        .unwrap_or_else(|| bytes_to_scan_value(&entry.value, state.value_type));
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

pub(crate) fn read_region_chunked(platform: &dyn PlatformAPI, pid: u32, base: u64, size: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(size);
    let mut offset = 0usize;
    while offset < size {
        let read_size = CHUNK_SIZE.min(size - offset);
        match platform.read_memory(pid, base + offset as u64, read_size) {
            Ok(data) => {
                result.extend_from_slice(&data);
                offset += data.len();
                if data.len() < read_size {
                    break; // partial read
                }
            }
            Err(_) => break,
        }
    }
    result
}

// --- First scan ---

fn scan_region_first(
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
) -> Vec<ScanEntry> {
    let val_size = value_type.size();
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < size {
        let read_size = CHUNK_SIZE.min(size - offset);
        let read_addr = base + offset as u64;
        match platform.read_memory(pid, read_addr, read_size) {
            Ok(data) => {
                if data.len() >= val_size {
                    let mut pos = 0usize;
                    while pos + val_size <= data.len() {
                        let bytes = &data[pos..pos + val_size];
                        if compare_value_first(bytes, value_type, compare_type, value, value2, float_tolerance) {
                            let mut stored = [0u8; 8];
                            stored[..val_size].copy_from_slice(bytes);
                            entries.push(ScanEntry {
                                address: read_addr + pos as u64,
                                value: stored,
                            });
                        }
                        pos += alignment;
                    }
                }
                offset += data.len();
                if data.len() < read_size {
                    break;
                }
            }
            Err(_) => {
                offset += read_size;
            }
        }
    }
    entries
}

// --- Next scan from snapshot ---

fn next_scan_from_snapshot(
    platform: &dyn PlatformAPI,
    pid: u32,
    snapshots: &[(u64, Vec<u8>)],
    value_type: ScanValueType,
    alignment: usize,
    compare_type: ScanCompareType,
    value: Option<ScanValue>,
    value2: Option<ScanValue>,
    float_tolerance: f64,
) -> Vec<ScanEntry> {
    let val_size = value_type.size();

    // Re-read and compare each region in parallel; flatten preserves address order.
    snapshots
        .par_iter()
        .map(|(base, old_data)| {
            let mut entries = Vec::new();
            // Re-read the region
            let new_data = read_region_chunked(platform, pid, *base, old_data.len());
            let compare_len = old_data.len().min(new_data.len());
            if compare_len < val_size {
                return entries;
            }

            let mut pos = 0usize;
            while pos + val_size <= compare_len {
                let old_bytes = &old_data[pos..pos + val_size];
                let new_bytes = &new_data[pos..pos + val_size];
                if compare_value_next(new_bytes, old_bytes, value_type, compare_type, value, value2, float_tolerance) {
                    let mut stored = [0u8; 8];
                    stored[..val_size].copy_from_slice(new_bytes);
                    entries.push(ScanEntry {
                        address: base + pos as u64,
                        value: stored,
                    });
                }
                pos += alignment;
            }
            entries
        })
        .collect::<Vec<Vec<ScanEntry>>>()
        .into_iter()
        .flatten()
        .collect()
}

// --- Next scan from filtered entries ---

fn next_scan_from_filtered(
    platform: &dyn PlatformAPI,
    pid: u32,
    entries: Vec<ScanEntry>,
    value_type: ScanValueType,
    val_size: usize,
    compare_type: ScanCompareType,
    value: Option<ScanValue>,
    value2: Option<ScanValue>,
    float_tolerance: f64,
) -> Vec<ScanEntry> {
    if entries.is_empty() {
        return Vec::new();
    }

    // Group nearby addresses into batch reads (within 4KB proximity). Compute the
    // batch index ranges sequentially (cheap), then process them in parallel.
    let mut batches: Vec<(usize, usize)> = Vec::new();
    let mut batch_start = 0usize;
    while batch_start < entries.len() {
        let batch_base = entries[batch_start].address;
        let mut batch_end = batch_start + 1;
        while batch_end < entries.len() {
            let span = entries[batch_end].address - batch_base;
            if span > 4096 {
                break;
            }
            batch_end += 1;
        }
        batches.push((batch_start, batch_end));
        batch_start = batch_end;
    }

    // Process each batch in parallel; flatten preserves address order.
    batches
        .par_iter()
        .map(|&(batch_start, batch_end)| {
            let mut result = Vec::new();
            let batch_base = entries[batch_start].address;

            // Read the range covering all entries in this batch
            let last_addr = entries[batch_end - 1].address;
            let read_size = (last_addr - batch_base) as usize + val_size;
            let read_data = platform.read_memory(pid, batch_base, read_size);

            for entry in &entries[batch_start..batch_end] {
                let offset = (entry.address - batch_base) as usize;
                let new_bytes = match &read_data {
                    Ok(data) if offset + val_size <= data.len() => &data[offset..offset + val_size],
                    _ => continue, // can't read - drop this entry
                };

                if compare_value_next(new_bytes, &entry.value[..val_size], value_type, compare_type, value, value2, float_tolerance) {
                    let mut stored = [0u8; 8];
                    stored[..val_size].copy_from_slice(new_bytes);
                    result.push(ScanEntry {
                        address: entry.address,
                        value: stored,
                    });
                }
            }
            result
        })
        .collect::<Vec<Vec<ScanEntry>>>()
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
