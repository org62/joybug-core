//! Cheat Engine-style pointer scanner.
//!
//! Finds chains of pointers that start at a *static* module base and resolve to a
//! target address. The scan has two phases, both parallelised over the rayon pool
//! shared with [`crate::memory_scanner`]:
//!
//! 1. Build a reverse pointer map: read every readable committed region, extract
//!    every pointer-sized (8-byte) aligned value that points inside committed
//!    memory, and store `(value, slot_address)` sorted by value for range lookups.
//! 2. Walk backward from the target, level by level: at each node find slots whose
//!    stored value is within `[current - max_offset, current]`, record the offset,
//!    and either emit a result (when the slot is static) and/or descend.

use std::collections::BinaryHeap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use memmap2::{Mmap, MmapOptions};
use rayon::prelude::*;

use crate::interfaces::PlatformAPI;
use crate::memory_scanner::{enumerate_scannable_regions, install_pool, read_region_chunked};
use crate::protocol::PointerPath;

/// Pointer size on the supported 64-bit targets (x64 / ARM64).
const POINTER_SIZE: usize = 8;
/// Max distinct candidate slots processed at a single node (branch cap), keeping
/// the reverse walk from exploding exponentially on hot pointer values.
const MAX_OFFSETS_PER_NODE: usize = 1024;
/// Hard cap on the live frontier size per level to bound memory and keep each
/// level's wall-clock short enough that the time budget stays responsive.
const FRONTIER_CAP: usize = 200_000;
/// Wall-clock budget for the reverse walk. A module-restricted scan emits few
/// paths, so the `max_results` early-exit never fires and the walk would
/// otherwise explore the whole pointer graph; this guarantees termination.
const SCAN_BUDGET_MS: u128 = 10_000;
/// Phase-1 work unit: regions are split into chunks of about this size so a
/// single huge region is shared across cores instead of pinning one thread.
/// Rounded down to a multiple of `alignment` so pointer slots tile cleanly.
const PARALLEL_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Size of one pointer-map candidate `(value, slot)`.
const PAIR_BYTES: usize = std::mem::size_of::<(u64, u64)>();

/// When the map exceeds the RAM budget we spill sorted runs of this many pairs
/// (~256 MB) so each run sorts quickly (sequentially, concurrently across worker
/// threads) and RAM stays bounded.
const RUN_PAIRS: usize = 16 * 1024 * 1024;

/// Run-spill threshold in pairs; overridable via `JOYBUG_PTRSCAN_RUN_PAIRS`
/// (tests force a tiny value to exercise the many-run merge path).
fn run_pairs_threshold() -> usize {
    if let Ok(v) = std::env::var("JOYBUG_PTRSCAN_RUN_PAIRS") {
        if let Ok(n) = v.parse::<usize>() {
            return n.max(1);
        }
    }
    RUN_PAIRS
}

/// A temp file deleted on drop. Backs spilled runs and the merged pointer map.
struct TempFile {
    path: PathBuf,
    file: std::fs::File,
}

impl TempFile {
    fn create(dir: &std::path::Path, pid: u32, counter: &AtomicU64) -> Result<Self, String> {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = dir.join(format!("joybug_ptrmap_{}_{}_{}.bin", pid, id, nanos));
        let file = std::fs::OpenOptions::new()
            .create(true).read(true).write(true).truncate(true)
            .open(&path)
            .map_err(|e| format!("Failed to create temp file {:?}: {}", path, e))?;
        Ok(TempFile { path, file })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The sorted pointer map, either resident in RAM or backed by a read-only
/// memory-mapped temp file (so it can exceed physical RAM without thrashing —
/// read-only pages evict cleanly, with no write-back).
enum PointerMap {
    Ram(Vec<(u64, u64)>),
    Disk { _temp: TempFile, mmap: Mmap, len: usize },
}

impl PointerMap {
    fn as_slice(&self) -> &[(u64, u64)] {
        match self {
            PointerMap::Ram(v) => v,
            PointerMap::Disk { mmap, len, .. } => {
                if *len == 0 {
                    &[]
                } else {
                    // The file holds raw (u64, u64) pairs written by this binary.
                    unsafe { std::slice::from_raw_parts(mmap.as_ptr() as *const (u64, u64), *len) }
                }
            }
        }
    }

    fn location(&self) -> &'static str {
        match self {
            PointerMap::Ram(_) => "RAM",
            PointerMap::Disk { .. } => "disk",
        }
    }
}

/// RAM budget for the in-memory pointer map, in pairs. Defaults to ~50% of
/// available physical RAM; overridable via `JOYBUG_PTRSCAN_MAP_BUDGET_MB` (mainly
/// for tests, to force the disk path). Above this the scan spills to disk.
fn map_budget_pairs() -> usize {
    if let Ok(v) = std::env::var("JOYBUG_PTRSCAN_MAP_BUDGET_MB") {
        if let Ok(mb) = v.parse::<usize>() {
            return (mb * 1024 * 1024 / PAIR_BYTES).max(1024);
        }
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut status) != 0 {
            let bytes = (status.ullAvailPhys as u128 / 2) as usize;
            return (bytes / PAIR_BYTES).max(64 * 1024 * 1024);
        }
    }
    512 * 1024 * 1024 / PAIR_BYTES // ~ fallback
}

/// Stateless: pointer-scan results live in files identified by path (so they
/// survive a target restart — the caller persists the path). No per-scan state.
pub struct PointerScanner;

/// Unique temp-file path for a scan's results.
fn results_file_path(pid: u32) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("joybug_ptrresults_{}_{}.bin", pid, nanos))
}

/// A node in the reverse walk: the address we are currently looking for pointers
/// *to*, the offset chain discovered so far (ordered base->target), and the set of
/// slot addresses already visited on this path (for cycle detection).
#[derive(Clone)]
struct WalkNode {
    current: u64,
    chain: Vec<u64>,
    visited: Vec<u64>,
}

impl PointerScanner {
    pub fn new() -> Self {
        Self
    }

    /// Run an initial pointer scan. Returns `(results_path, match_count, scan_time_us)`.
    ///
    /// `allowed_modules`, when `Some`, restricts the static base of every emitted
    /// path to modules whose base address is in the list (e.g. only the main
    /// executable). `None` considers every loaded module.
    #[allow(clippy::too_many_arguments)]
    pub fn start_scan(
        &mut self,
        platform: &dyn PlatformAPI,
        pid: u32,
        target_address: u64,
        max_offset: u64,
        max_depth: u32,
        alignment: Option<usize>,
        max_results: Option<u64>,
        allowed_modules: Option<Vec<u64>>,
        thread_count: Option<usize>,
        writable_only: bool,
    ) -> Result<(String, u64, u64), String> {
        let alignment = alignment.unwrap_or(POINTER_SIZE).max(1);
        // Results stream to disk, so there is no in-RAM cap by default; `None`
        // means unlimited (still bounded by depth, frontier, and the time budget).
        let max_results = max_results.map(|n| n as usize).unwrap_or(usize::MAX);
        let start = Instant::now();

        // Committed regions to scan for pointer slots. By default all readable
        // regions (static pointers also live in read-only module data); with
        // `writable_only` we scan only writable regions (heap/stack/.data) — much
        // faster on processes with large read-only mappings, but misses static
        // roots in read-only sections.
        let regions = enumerate_scannable_regions(platform, pid, writable_only)?;

        // Sorted, disjoint region ranges for the "is this value a plausible
        // pointer?" bounds filter.
        let mut region_ranges: Vec<(u64, u64)> =
            regions.iter().map(|(b, s)| (*b, b + *s as u64)).collect();
        region_ranges.sort_unstable_by_key(|r| r.0);

        // Snapshot the module list ONCE: it backs both the static-slot ranges and
        // the name table written to the results file, so a stored `module_index`
        // maps to the right name (the live list order is HashMap-seeded and not
        // stable across runs, so the name — not the index — is the durable key).
        let modules = platform.list_modules(pid).unwrap_or_default();
        let module_names: Vec<String> = modules.iter().map(|m| m.name.clone()).collect();

        // Module ranges define which slot addresses count as "static", optionally
        // restricted to the caller's selected base modules.
        let module_ranges = build_module_ranges(&modules, allowed_modules.as_deref());

        // Optional per-phase timing for benchmarking (set JOYBUG_PTRSCAN_TIMING=1).
        let timing = std::env::var("JOYBUG_PTRSCAN_TIMING").is_ok();
        let total_bytes: u64 = regions.iter().map(|(_, s)| *s as u64).sum();
        if timing {
            eprintln!("[ptrscan] regions={} committed={:.2}GB setup={:?}",
                regions.len(), total_bytes as f64 / 1e9, start.elapsed());
        }

        // Phase 1: build the reverse pointer map in RAM. Split regions into
        // fixed-size chunks so a single huge region doesn't pin one core, then
        // merge the per-chunk results with a parallel tree reduction (no
        // single-threaded flatten). Chunk boundaries are multiples of `alignment`
        // so pointer slots tile cleanly across them.
        let chunk_step = (PARALLEL_CHUNK_BYTES / alignment).max(1) * alignment;
        // (region_base, region_size, chunk_start_off, chunk_end_off)
        let mut chunks: Vec<(u64, usize, usize, usize)> = Vec::new();
        for (base, size) in &regions {
            let mut off = 0usize;
            while off < *size {
                let end = (off + chunk_step).min(*size);
                chunks.push((*base, *size, off, end));
                off = end;
            }
        }

        // Global committed-address span for the fast pointer reject in the scan.
        let global_min = region_ranges.first().map(|r| r.0).unwrap_or(0);
        let global_max = region_ranges.iter().map(|r| r.1).max().unwrap_or(0);

        // Phase 2 always reverse-walks from the target (map sorted by value).
        // A module filter is applied at *emission* time through `module_ranges`
        // (the walk still climbs every incoming pointer regardless of staticness),
        // so a filtered scan returns exactly the subset of the unfiltered paths
        // whose static root lies in the selected modules — never fewer. Seeding a
        // forward search from a module's static pointers instead would miss paths
        // on a large process once the frontier cap/time budget truncates it.
        let by_value = true;

        // Build the sorted pointer map. Stays in RAM when it fits the budget,
        // else spills sorted runs to disk and merges into a read-only mmap.
        let t_build = Instant::now();
        let read_ns = AtomicU64::new(0);
        let scan_ns = AtomicU64::new(0);
        let budget_pairs = map_budget_pairs();
        let map = build_pointer_map(
            platform, pid, &chunks, &region_ranges, global_min, global_max, alignment,
            by_value, budget_pairs, thread_count, &read_ns, &scan_ns,
        )?;
        let pairs = map.as_slice();
        if timing {
            let secs = t_build.elapsed().as_secs_f64().max(1e-9);
            eprintln!("[ptrscan] build map: {} candidates ({:.2}GB, {}) in {:?} ({:.2}GB/s read | core-time read={:.1}s scan={:.1}s)",
                pairs.len(), pairs.len() as f64 * PAIR_BYTES as f64 / 1e9, map.location(), t_build.elapsed(),
                total_bytes as f64 / 1e9 / secs,
                read_ns.load(Ordering::Relaxed) as f64 / 1e9, scan_ns.load(Ordering::Relaxed) as f64 / 1e9);
        }

        // Stream found paths to a disk results file — no in-RAM cap, so a broad
        // scan can keep millions of paths (Cheat-Engine style). The walk's
        // wall-clock budget (SCAN_BUDGET_MS) is measured from here, not from scan
        // start, so a long (disk-path) map build doesn't eat the walk's budget.
        let results_path = results_file_path(pid);
        let mut writer = crate::pointer_results::ResultWriter::create(&results_path, (max_depth as usize).max(1), &module_names)
            .map_err(|e| format!("Failed to create results file: {}", e))?;

        let t_walk = Instant::now();
        let count = reverse_walk(pairs, &module_ranges, target_address, max_offset, max_depth, max_results, thread_count, t_walk, |p| { let _ = writer.push(p); });
        let match_count = writer.finish().map_err(|e| format!("Failed to finalize results: {}", e))?;
        if timing {
            eprintln!("[ptrscan] walk: {} paths in {:?}", count, t_walk.elapsed());
            eprintln!("[ptrscan] TOTAL: {:?} ({} paths -> {})", start.elapsed(), match_count, results_path.display());
        }

        let scan_time_us = start.elapsed().as_micros() as u64;
        Ok((results_path.to_string_lossy().into_owned(), match_count, scan_time_us))
    }

    /// Read a page of results from `results_path`, re-deriving each path's module
    /// base from the *current* module list (so display is correct after a restart).
    ///
    /// When `offset_filter` is non-empty, only paths whose chain offsets contain
    /// *every* listed value (order-independent) are returned; `offset`/`count`
    /// then page over the filtered set and the returned total is the match count.
    pub fn get_results(
        &self,
        platform: &dyn PlatformAPI,
        pid: u32,
        results_path: &str,
        offset: u64,
        count: u64,
        offset_filter: &[u64],
    ) -> Result<(Vec<PointerPath>, u64), String> {
        let reader = crate::pointer_results::ResultReader::open(std::path::Path::new(results_path))?;
        // Page (and optionally filter) over the whole file, then re-base each
        // returned path by the module *name* stored in the file (stable across
        // restarts), not by its index into the freshly-seeded live module list.
        let (mut paths, total) = reader.page_filtered(offset_filter, offset as usize, count as usize);
        let modules = platform.list_modules(pid).unwrap_or_default();
        let base_index = crate::pointer_results::module_base_index(&modules);
        for p in &mut paths {
            if let Some(name) = reader.module_name(p.module_index) {
                if let Some(base) = crate::pointer_results::resolve_module_base(&base_index, name) {
                    p.module_base = base;
                }
            }
        }
        Ok((paths, total))
    }

    pub fn reset_scan(&self, results_path: &str) -> Result<(), String> {
        let _ = std::fs::remove_file(results_path);
        Ok(())
    }

    /// Commit a quick filter: keep only paths whose chain offsets contain every
    /// value in `offset_filter`, write them to a new file (carrying the same
    /// module-name table so it stays restart-safe), delete the old file, and
    /// return `(new_results_path, match_count, elapsed_us)`. An empty filter keeps
    /// everything (a straight copy). No live process is needed — this is a pure
    /// file-to-file transform.
    pub fn apply_filter(
        &self,
        results_path: &str,
        offset_filter: &[u64],
    ) -> Result<(String, u64, u64), String> {
        let start = Instant::now();
        let reader = crate::pointer_results::ResultReader::open(std::path::Path::new(results_path))?;
        let new_path = results_file_path(0);
        let mut writer = crate::pointer_results::ResultWriter::create(&new_path, reader.max_offsets(), reader.module_names())
            .map_err(|e| format!("Failed to create results file: {}", e))?;
        for i in 0..reader.len() {
            let Some(p) = reader.get(i) else { continue };
            if offset_filter.iter().all(|f| p.offsets.contains(f)) {
                writer.push(&p).map_err(|e| format!("Failed to write filtered results: {}", e))?;
            }
        }
        let match_count = writer.finish().map_err(|e| format!("Failed to finalize filtered results: {}", e))?;
        let _ = std::fs::remove_file(results_path); // old file superseded
        let elapsed_us = start.elapsed().as_micros() as u64;
        Ok((new_path.to_string_lossy().into_owned(), match_count, elapsed_us))
    }

    /// Re-resolve every path in `results_path` against the live process, keep only
    /// those that still resolve to `target_address`, and write the survivors to a
    /// new file (the old one is deleted). Module bases are re-derived from the
    /// current module list, so this works after the target moves or a restart
    /// re-bases modules — the Cheat-Engine "rescan pointermap" workflow.
    /// Returns `(new_results_path, match_count, scan_time_us)`.
    pub fn rescan(
        &self,
        platform: &dyn PlatformAPI,
        pid: u32,
        results_path: &str,
        target_address: u64,
    ) -> Result<(String, u64, u64), String> {
        let start = Instant::now();
        let reader = crate::pointer_results::ResultReader::open(std::path::Path::new(results_path))?;
        let modules = platform
            .list_modules(pid)
            .map_err(|e| format!("Failed to list modules: {}", e))?;
        // Re-base by stored module name (stable across restarts); see get_results.
        let base_index = crate::pointer_results::module_base_index(&modules);
        // Pre-resolve each table entry's live base once: table index -> Option<base>.
        let table_bases: Vec<Option<u64>> = reader
            .module_names()
            .iter()
            .map(|name| crate::pointer_results::resolve_module_base(&base_index, name))
            .collect();

        let new_path = results_file_path(pid);
        // Carry the same module-name table forward so the rescanned file stays
        // self-describing and survives further restarts.
        let mut writer = crate::pointer_results::ResultWriter::create(&new_path, reader.max_offsets(), reader.module_names())
            .map_err(|e| format!("Failed to create results file: {}", e))?;

        // Resolve in parallel batches (bounded RAM) and stream survivors out.
        const BATCH: usize = 64 * 1024;
        let total = reader.len();
        let mut i = 0;
        while i < total {
            let end = (i + BATCH).min(total);
            let batch: Vec<PointerPath> = (i..end).filter_map(|j| reader.get(j)).collect();
            let survivors: Vec<PointerPath> = install_pool(None, || {
                batch
                    .par_iter()
                    .filter_map(|p| {
                        let base = if p.module_index >= 0 {
                            (*table_bases.get(p.module_index as usize)?)?
                        } else {
                            p.module_base
                        };
                        // addr = base + base_offset; for off: addr = read_u64(addr) + off
                        let mut addr = base.checked_add(p.base_offset)?;
                        for &off in &p.offsets {
                            let bytes = platform.read_memory(pid, addr, 8).ok()?;
                            if bytes.len() < 8 {
                                return None;
                            }
                            let ptr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                            addr = ptr.checked_add(off)?;
                        }
                        if addr == target_address {
                            Some(PointerPath {
                                module_index: p.module_index,
                                module_base: base,
                                base_offset: p.base_offset,
                                offsets: p.offsets.clone(),
                                resolved: target_address,
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            });
            for s in &survivors {
                writer.push(s).map_err(|e| format!("Failed to write rescan results: {}", e))?;
            }
            i = end;
        }

        let match_count = writer.finish().map_err(|e| format!("Failed to finalize rescan results: {}", e))?;
        let _ = std::fs::remove_file(results_path); // old file superseded
        let scan_time_us = start.elapsed().as_micros() as u64;
        Ok((new_path.to_string_lossy().into_owned(), match_count, scan_time_us))
    }
}

impl Default for PointerScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Breadth-first frontier driver shared by both search directions: at each level
/// expand every node in parallel, collect emitted paths, and cap the next
/// frontier. Stops at `max_depth` levels, once `max_results` paths are found, or
/// when the wall-clock budget is exhausted. Only seed construction and the
/// per-node `expand` differ between the two directions.
fn run_levels<N: Send + Sync>(
    seeds: Vec<N>,
    max_depth: u32,
    max_results: usize,
    thread_count: Option<usize>,
    start: std::time::Instant,
    expand: impl Fn(&N) -> (Vec<PointerPath>, Vec<N>) + Sync,
    mut sink: impl FnMut(&PointerPath),
) -> usize {
    // Process each level's frontier in batches, checking the wall-clock budget
    // *between batches*. With a large `max_offset` on a dense map a single level
    // can explode into tens of millions of nodes; expanding the whole frontier at
    // once would run for minutes before the budget (checked only per level) could
    // stop it. Batching bounds the in-flight work — and thus the overrun — to one
    // small batch, so the walk can't blow far past the budget. Found paths are
    // streamed to `sink` (a disk writer) so results are never capped in RAM.
    const BATCH: usize = 4096;
    let mut count: usize = 0;
    let mut frontier = seeds;

    'levels: for _level in 0..max_depth {
        if frontier.is_empty()
            || count >= max_results
            || start.elapsed().as_millis() >= SCAN_BUDGET_MS
        {
            break;
        }

        let mut next_frontier: Vec<N> = Vec::new();
        for batch in frontier.chunks(BATCH) {
            if start.elapsed().as_millis() >= SCAN_BUDGET_MS {
                break 'levels;
            }
            let expanded: Vec<(Vec<PointerPath>, Vec<N>)> = install_pool(thread_count, || {
                batch.par_iter().map(|node| expand(node)).collect()
            });
            for (emitted, next) in expanded {
                for p in &emitted {
                    sink(p);
                    count += 1;
                }
                if next_frontier.len() < FRONTIER_CAP {
                    next_frontier.extend(next);
                }
            }
            if count >= max_results {
                break 'levels;
            }
        }
        next_frontier.truncate(FRONTIER_CAP);
        frontier = next_frontier;
    }

    count
}

/// Reverse walk from the target toward static bases (no module restriction).
/// `pairs` must be sorted by value.
#[allow(clippy::too_many_arguments)]
fn reverse_walk(
    pairs: &[(u64, u64)],
    module_ranges: &[(u64, u64, i32, u64)],
    target_address: u64,
    max_offset: u64,
    max_depth: u32,
    max_results: usize,
    thread_count: Option<usize>,
    start: std::time::Instant,
    sink: impl FnMut(&PointerPath),
) -> usize {
    let seeds = vec![WalkNode {
        current: target_address,
        chain: Vec::new(),
        visited: vec![target_address],
    }];
    run_levels(seeds, max_depth, max_results, thread_count, start, |node| {
        expand_node(node, pairs, module_ranges, max_offset, target_address)
    }, sink)
}

/// Expand one walk node: returns the paths it completes (static slots found) and
/// the child nodes to explore at the next level.
fn expand_node(
    node: &WalkNode,
    pairs: &[(u64, u64)],
    module_ranges: &[(u64, u64, i32, u64)],
    max_offset: u64,
    target_address: u64,
) -> (Vec<PointerPath>, Vec<WalkNode>) {
    let lo = node.current.saturating_sub(max_offset);
    let hi = node.current;

    let mut emitted = Vec::new();
    let mut next = Vec::new();

    // All slots whose stored value falls in [lo, hi], via binary search.
    let start = pairs.partition_point(|p| p.0 < lo);
    let mut processed = 0usize;
    let mut i = start;
    while i < pairs.len() && pairs[i].0 <= hi {
        let (value, slot_addr) = pairs[i];
        i += 1;

        // Cycle detection: never revisit a slot already on this path.
        if node.visited.contains(&slot_addr) {
            continue;
        }

        let offset = node.current - value;

        // Offset chain ordered base->target: this offset is closer to the target
        // than anything already in the chain, so it goes in front.
        let mut chain = Vec::with_capacity(node.chain.len() + 1);
        chain.push(offset);
        chain.extend_from_slice(&node.chain);

        if let Some((module_index, module_base)) = find_static(slot_addr, module_ranges) {
            emitted.push(PointerPath {
                module_index,
                module_base,
                base_offset: slot_addr - module_base,
                offsets: chain.clone(),
                resolved: target_address,
            });
        }

        // Keep climbing toward deeper static bases regardless of staticness.
        let mut visited = node.visited.clone();
        visited.push(slot_addr);
        next.push(WalkNode {
            current: slot_addr,
            chain,
            visited,
        });

        processed += 1;
        if processed >= MAX_OFFSETS_PER_NODE {
            break;
        }
    }

    (emitted, next)
}

/// Read a region and extract every aligned 8-byte value that points inside a
/// committed region, paired with the slot address holding it.
/// Extract candidate pointers from one chunk `[c_start, c_end)` of a region.
///
/// Reads a small overlap (`POINTER_SIZE - alignment`) past `c_end` so a slot that
/// starts inside the chunk but extends past its end is still fully read — but
/// never past the region end, so slots straddling the region boundary are skipped
/// (matching a whole-region scan). `c_start` is a multiple of `alignment`, so the
/// per-chunk slot sets tile the region with no gaps or double-counting.
#[allow(clippy::too_many_arguments)]
fn extract_pointers_chunk(
    platform: &dyn PlatformAPI,
    pid: u32,
    region_base: u64,
    region_size: usize,
    c_start: usize,
    c_end: usize,
    alignment: usize,
    region_ranges: &[(u64, u64)],
    global_min: u64,
    global_max: u64,
    read_ns: &AtomicU64,
    scan_ns: &AtomicU64,
) -> Vec<(u64, u64)> {
    // Overlap is 0 when alignment >= POINTER_SIZE (slots never cross c_end then).
    let read_end = c_end.saturating_add(POINTER_SIZE.saturating_sub(alignment)).min(region_size);
    if read_end <= c_start {
        return Vec::new();
    }
    let t_read = Instant::now();
    let data = read_region_chunked(platform, pid, region_base + c_start as u64, read_end - c_start);
    read_ns.fetch_add(t_read.elapsed().as_nanos() as u64, Ordering::Relaxed);

    let t_scan = Instant::now();
    let mut out = Vec::new();
    let mut pos = c_start;
    while pos < c_end && pos + POINTER_SIZE <= region_size {
        let di = pos - c_start;
        if di + POINTER_SIZE > data.len() {
            break; // partial read (unmapped tail)
        }
        let value = u64::from_le_bytes(data[di..di + POINTER_SIZE].try_into().unwrap());
        // Fast reject: most slots hold non-pointer data outside the committed
        // address span, killed here in two comparisons before the binary search.
        if value >= global_min && value < global_max && in_ranges(value, region_ranges) {
            out.push((value, region_base + pos as u64));
        }
        pos += alignment;
    }
    scan_ns.fetch_add(t_scan.elapsed().as_nanos() as u64, Ordering::Relaxed);
    out
}

#[inline]
fn sort_key(p: &(u64, u64), by_value: bool) -> u64 {
    if by_value { p.0 } else { p.1 }
}

/// Build the sorted pointer map.
///
/// Workers extract candidates into a shared buffer; each full buffer (`RUN_PAIRS`)
/// is sorted into a run. Runs stay in RAM until `budget_pairs` is reached, then
/// spill to disk. If nothing spilled, the result is an in-RAM `Vec`; otherwise all
/// runs (RAM + disk) are k-way merged into a single sorted file that is mmap'd
/// read-only — so the map can exceed physical RAM without write-back thrash, and
/// memory never holds more than the budget at once. No data is read twice.
#[allow(clippy::too_many_arguments)]
fn build_pointer_map(
    platform: &dyn PlatformAPI,
    pid: u32,
    chunks: &[(u64, usize, usize, usize)],
    region_ranges: &[(u64, u64)],
    global_min: u64,
    global_max: u64,
    alignment: usize,
    by_value: bool,
    budget_pairs: usize,
    thread_count: Option<usize>,
    read_ns: &AtomicU64,
    scan_ns: &AtomicU64,
) -> Result<PointerMap, String> {
    let dir = std::env::temp_dir();
    let run_pairs = run_pairs_threshold();
    let counter = AtomicU64::new(0);
    let buffer: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
    let ram_runs: Mutex<Vec<Vec<(u64, u64)>>> = Mutex::new(Vec::new());
    let ram_pairs = AtomicUsize::new(0);
    let disk_runs: Mutex<Vec<TempFile>> = Mutex::new(Vec::new());
    let err: Mutex<Option<String>> = Mutex::new(None);

    install_pool(thread_count, || {
        chunks.par_iter().for_each(|(b, s, cs, ce)| {
            if err.lock().unwrap().is_some() {
                return;
            }
            let found = extract_pointers_chunk(platform, pid, *b, *s, *cs, *ce, alignment, region_ranges, global_min, global_max, read_ns, scan_ns);
            if found.is_empty() {
                return;
            }
            // Append under the lock; take the full buffer out to sort+stash it
            // without holding the lock (other workers fill a fresh buffer).
            let taken = {
                let mut buf = buffer.lock().unwrap();
                buf.extend(found);
                if buf.len() >= run_pairs { Some(std::mem::take(&mut *buf)) } else { None }
            };
            if let Some(mut run) = taken {
                run.sort_unstable_by_key(|p| sort_key(p, by_value));
                // Keep the run in RAM if we're under budget, else spill to disk.
                if ram_pairs.load(Ordering::Relaxed) + run.len() <= budget_pairs {
                    ram_pairs.fetch_add(run.len(), Ordering::Relaxed);
                    ram_runs.lock().unwrap().push(run);
                } else {
                    match write_run(&dir, pid, &counter, &run) {
                        Ok(tf) => disk_runs.lock().unwrap().push(tf),
                        Err(e) => *err.lock().unwrap() = Some(e),
                    }
                }
            }
        });
    });
    if let Some(e) = err.into_inner().unwrap() {
        return Err(e);
    }

    let mut buffer = buffer.into_inner().unwrap();
    let mut ram_runs = ram_runs.into_inner().unwrap();
    let mut disk_runs = disk_runs.into_inner().unwrap();
    if !buffer.is_empty() {
        buffer.sort_unstable_by_key(|p| sort_key(p, by_value));
        if ram_pairs.load(Ordering::Relaxed) + buffer.len() <= budget_pairs {
            ram_runs.push(buffer);
        } else {
            disk_runs.push(write_run(&dir, pid, &counter, &buffer)?);
        }
    }

    // Nothing spilled: concatenate the RAM runs and sort the whole in parallel.
    if disk_runs.is_empty() {
        let total: usize = ram_runs.iter().map(|r| r.len()).sum();
        let mut v: Vec<(u64, u64)> = Vec::with_capacity(total);
        for r in ram_runs {
            v.extend(r);
        }
        install_pool(thread_count, || {
            if by_value {
                v.par_sort_unstable_by_key(|p| p.0);
            } else {
                v.par_sort_unstable_by_key(|p| p.1);
            }
        });
        return Ok(PointerMap::Ram(v));
    }

    // Spilled: k-way merge the RAM runs and the disk runs (mmap'd read-only) into
    // a single sorted file, then mmap it read-only for the walk.
    let mut disk_sources: Vec<Run> = Vec::with_capacity(disk_runs.len());
    for tf in &disk_runs {
        disk_sources.push(Run::open(tf)?);
    }
    let mut sources: Vec<&[(u64, u64)]> = Vec::with_capacity(ram_runs.len() + disk_sources.len());
    for r in &ram_runs {
        if !r.is_empty() {
            sources.push(r.as_slice());
        }
    }
    for d in &disk_sources {
        let s = d.as_slice();
        if !s.is_empty() {
            sources.push(s);
        }
    }

    let out = TempFile::create(&dir, pid, &counter)?;
    let total = kway_merge(&sources, by_value, &out.file)?;
    if total == 0 {
        return Ok(PointerMap::Ram(Vec::new()));
    }
    let mmap = unsafe { MmapOptions::new().len(total * PAIR_BYTES).map(&out.file) }
        .map_err(|e| format!("Failed to mmap merged pointer map: {}", e))?;
    Ok(PointerMap::Disk { _temp: out, mmap, len: total })
}

/// Write a sorted run of pairs to a new temp file (raw little-endian pairs).
fn write_run(dir: &std::path::Path, pid: u32, counter: &AtomicU64, pairs: &[(u64, u64)]) -> Result<TempFile, String> {
    let tf = TempFile::create(dir, pid, counter)?;
    let bytes = unsafe { std::slice::from_raw_parts(pairs.as_ptr() as *const u8, pairs.len() * PAIR_BYTES) };
    {
        let mut w = std::io::BufWriter::new(&tf.file);
        w.write_all(bytes).map_err(|e| format!("Failed to write run: {}", e))?;
        w.flush().map_err(|e| format!("Failed to flush run: {}", e))?;
    }
    Ok(tf)
}

/// A spilled run, accessed as a `&[(u64, u64)]` slice over a read-only mmap.
struct Run {
    _mmap: Mmap,
    len: usize,
}

impl Run {
    fn open(tf: &TempFile) -> Result<Self, String> {
        let bytes = tf.file.metadata().map(|m| m.len() as usize).unwrap_or(0);
        let len = bytes / PAIR_BYTES;
        let mmap = unsafe { MmapOptions::new().len(len * PAIR_BYTES).map(&tf.file) }
            .map_err(|e| format!("Failed to mmap run: {}", e))?;
        Ok(Run { _mmap: mmap, len })
    }
    fn as_slice(&self) -> &[(u64, u64)] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self._mmap.as_ptr() as *const (u64, u64), self.len) }
        }
    }
}

struct HeapItem {
    key: u64,
    pair: (u64, u64),
    run: usize,
}
impl PartialEq for HeapItem {
    fn eq(&self, o: &Self) -> bool { self.key == o.key }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(o)) }
}
impl Ord for HeapItem {
    // Reversed so the BinaryHeap (a max-heap) yields the smallest key first.
    fn cmp(&self, o: &Self) -> std::cmp::Ordering { o.key.cmp(&self.key) }
}

/// K-way merge sorted `sources` into `out_file`; returns the number of pairs written.
fn kway_merge(sources: &[&[(u64, u64)]], by_value: bool, out_file: &std::fs::File) -> Result<usize, String> {
    let mut pos = vec![0usize; sources.len()];
    let mut heap: BinaryHeap<HeapItem> = BinaryHeap::with_capacity(sources.len());
    for (i, s) in sources.iter().enumerate() {
        if let Some(&p) = s.first() {
            heap.push(HeapItem { key: sort_key(&p, by_value), pair: p, run: i });
        }
    }
    let mut w = std::io::BufWriter::new(out_file);
    let mut total = 0usize;
    while let Some(item) = heap.pop() {
        let bytes = unsafe { std::slice::from_raw_parts(&item.pair as *const (u64, u64) as *const u8, PAIR_BYTES) };
        w.write_all(bytes).map_err(|e| format!("Merge write failed: {}", e))?;
        total += 1;
        let r = item.run;
        pos[r] += 1;
        if let Some(&p) = sources[r].get(pos[r]) {
            heap.push(HeapItem { key: sort_key(&p, by_value), pair: p, run: r });
        }
    }
    w.flush().map_err(|e| format!("Merge flush failed: {}", e))?;
    Ok(total)
}

/// Build sorted module ranges `(start, end, module_index, module_base)`. When
/// `allowed` is `Some`, only modules whose base is in the list are included.
/// `module_index` is the position in `modules`, which must be the same snapshot
/// whose names are written to the results file, so a stored index maps to the
/// right name later.
fn build_module_ranges(
    modules: &[crate::protocol::ModuleInfo],
    allowed: Option<&[u64]>,
) -> Vec<(u64, u64, i32, u64)> {
    let mut ranges: Vec<(u64, u64, i32, u64)> = modules
        .iter()
        .enumerate()
        .filter_map(|(idx, m)| {
            let size = m.size.unwrap_or(0);
            if size == 0 {
                return None;
            }
            if let Some(allowed) = allowed {
                if !allowed.contains(&m.base) {
                    return None;
                }
            }
            Some((m.base, m.base + size, idx as i32, m.base))
        })
        .collect();
    ranges.sort_unstable_by_key(|r| r.0);
    ranges
}

/// Is `v` inside one of the (sorted, disjoint) committed region ranges?
fn in_ranges(v: u64, ranges: &[(u64, u64)]) -> bool {
    let idx = ranges.partition_point(|r| r.0 <= v);
    if idx == 0 {
        return false;
    }
    let (start, end) = ranges[idx - 1];
    v >= start && v < end
}

/// If `addr` falls inside a module, return `(module_index, module_base)`.
fn find_static(addr: u64, module_ranges: &[(u64, u64, i32, u64)]) -> Option<(i32, u64)> {
    let idx = module_ranges.partition_point(|m| m.0 <= addr);
    if idx == 0 {
        return None;
    }
    let (start, end, index, base) = module_ranges[idx - 1];
    if addr >= start && addr < end {
        Some((index, base))
    } else {
        None
    }
}
