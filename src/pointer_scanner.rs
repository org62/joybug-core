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

use std::collections::HashMap;
use std::time::Instant;

use rayon::prelude::*;

use crate::interfaces::PlatformAPI;
use crate::memory_scanner::{enumerate_scannable_regions, install_pool, read_region_chunked};
use crate::protocol::PointerPath;

/// Pointer size on the supported 64-bit targets (x64 / ARM64).
const POINTER_SIZE: usize = 8;
/// Default cap on the number of returned paths.
const DEFAULT_MAX_RESULTS: u64 = 10_000;
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

pub struct PointerScanner {
    scans: HashMap<u64, Vec<PointerPath>>,
    next_id: u64,
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
        Self {
            scans: HashMap::new(),
            next_id: 1,
        }
    }

    /// Run an initial pointer scan. Returns `(scan_id, match_count, scan_time_us)`.
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
    ) -> Result<(u64, u64, u64), String> {
        let alignment = alignment.unwrap_or(POINTER_SIZE).max(1);
        let max_results = max_results.unwrap_or(DEFAULT_MAX_RESULTS) as usize;
        let start = Instant::now();

        // Readable committed regions (not just writable: static pointers live in
        // read-only module data sections too).
        let regions = enumerate_scannable_regions(platform, pid, false)?;

        // Sorted, disjoint region ranges for the "is this value a plausible
        // pointer?" bounds filter.
        let mut region_ranges: Vec<(u64, u64)> =
            regions.iter().map(|(b, s)| (*b, b + *s as u64)).collect();
        region_ranges.sort_unstable_by_key(|r| r.0);

        // Module ranges define which slot addresses count as "static", optionally
        // restricted to the caller's selected base modules.
        let module_ranges = build_module_ranges(platform, pid, allowed_modules.as_deref());

        // Phase 1: reverse pointer map, built in parallel per region then merged
        // and sorted by value.
        let mut pairs: Vec<(u64, u64)> = install_pool(thread_count, || {
            regions
                .par_iter()
                .map(|(base, size)| {
                    extract_pointers(platform, pid, *base, *size, alignment, &region_ranges)
                })
                .collect::<Vec<Vec<(u64, u64)>>>()
        })
        .into_iter()
        .flatten()
        .collect();

        // Phase 2. Two strategies:
        //  * Modules selected -> forward search seeded from those modules' static
        //    pointers. The seed set is small, so we never explore the whole
        //    reverse graph; the module restriction *prunes the search* rather
        //    than just filtering emitted paths.
        //  * No modules -> reverse walk from the target (a single seed; there is
        //    no small static seed set to start from otherwise).
        let use_forward = allowed_modules.as_ref().is_some_and(|m| !m.is_empty());

        let mut results = if use_forward {
            // Index by slot address for forward "read slot" / "slots in range".
            install_pool(thread_count, || pairs.par_sort_unstable_by_key(|p| p.1));
            forward_search(
                &pairs, &module_ranges, target_address, max_offset, max_depth,
                max_results, thread_count, start,
            )
        } else {
            // Index by value for reverse "what points near here" lookups.
            install_pool(thread_count, || pairs.par_sort_unstable_by_key(|p| p.0));
            reverse_walk(
                &pairs, &module_ranges, target_address, max_offset, max_depth,
                max_results, thread_count, start,
            )
        };

        // Show the most promising paths first: smallest offsets, shortest chains.
        results.sort_by(|a, b| a.offsets.cmp(&b.offsets));
        if results.len() > max_results {
            results.truncate(max_results);
        }

        let scan_id = self.next_id;
        self.next_id += 1;
        let match_count = results.len() as u64;
        let scan_time_us = start.elapsed().as_micros() as u64;
        self.scans.insert(scan_id, results);

        Ok((scan_id, match_count, scan_time_us))
    }

    pub fn get_results(
        &self,
        scan_id: u64,
        offset: u64,
        count: u64,
    ) -> Result<(Vec<PointerPath>, u64), String> {
        let results = self
            .scans
            .get(&scan_id)
            .ok_or_else(|| format!("Pointer scan ID {} not found", scan_id))?;
        let total_count = results.len() as u64;
        let start = (offset as usize).min(results.len());
        let end = (start + count as usize).min(results.len());
        Ok((results[start..end].to_vec(), total_count))
    }

    pub fn reset_scan(&mut self, scan_id: u64) -> Result<(), String> {
        self.scans
            .remove(&scan_id)
            .map(|_| ())
            .ok_or_else(|| format!("Pointer scan ID {} not found", scan_id))
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
) -> Vec<PointerPath> {
    let mut results: Vec<PointerPath> = Vec::new();
    let mut frontier = seeds;

    for _level in 0..max_depth {
        if frontier.is_empty()
            || results.len() >= max_results
            || start.elapsed().as_millis() >= SCAN_BUDGET_MS
        {
            break;
        }

        let expanded: Vec<(Vec<PointerPath>, Vec<N>)> = install_pool(thread_count, || {
            frontier.par_iter().map(|node| expand(node)).collect()
        });

        let mut next_frontier: Vec<N> = Vec::new();
        for (emitted, next) in expanded {
            results.extend(emitted);
            if next_frontier.len() < FRONTIER_CAP {
                next_frontier.extend(next);
            }
        }
        next_frontier.truncate(FRONTIER_CAP);
        frontier = next_frontier;
    }

    results
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
) -> Vec<PointerPath> {
    let seeds = vec![WalkNode {
        current: target_address,
        chain: Vec::new(),
        visited: vec![target_address],
    }];
    run_levels(seeds, max_depth, max_results, thread_count, start, |node| {
        expand_node(node, pairs, module_ranges, max_offset, target_address)
    })
}

/// A node in the forward search: the static base it started from, the value last
/// read, the offset chain so far, and the slots visited (cycle detection).
#[derive(Clone)]
struct ForwardNode {
    base: u64,
    value: u64,
    chain: Vec<u64>,
    visited: Vec<u64>,
}

/// Forward search seeded from the static pointers in the selected modules.
/// `pairs` must be sorted by slot address. Each path starts at a static base and
/// follows `read + offset` steps until it lands within `max_offset` of the target.
#[allow(clippy::too_many_arguments)]
fn forward_search(
    pairs: &[(u64, u64)],
    module_ranges: &[(u64, u64, i32, u64)],
    target_address: u64,
    max_offset: u64,
    max_depth: u32,
    max_results: usize,
    thread_count: Option<usize>,
    start: std::time::Instant,
) -> Vec<PointerPath> {
    // Seeds: every recorded pointer slot that lives in a selected module.
    let seeds: Vec<ForwardNode> = pairs
        .iter()
        .filter(|p| find_static(p.1, module_ranges).is_some())
        .map(|p| ForwardNode {
            base: p.1,
            value: p.0,
            chain: Vec::new(),
            visited: vec![p.1],
        })
        .collect();
    run_levels(seeds, max_depth, max_results, thread_count, start, |node| {
        forward_expand(node, pairs, module_ranges, max_offset, max_depth, target_address)
    })
}

/// Expand one forward node: emit a path if the target is now within reach, and
/// produce children for the next level.
fn forward_expand(
    node: &ForwardNode,
    pairs: &[(u64, u64)],
    module_ranges: &[(u64, u64, i32, u64)],
    max_offset: u64,
    max_depth: u32,
    target_address: u64,
) -> (Vec<PointerPath>, Vec<ForwardNode>) {
    let mut emitted = Vec::new();
    let mut next = Vec::new();
    let depth = node.chain.len() as u32;

    // Close: the last read value points within max_offset of the target.
    if target_address >= node.value
        && target_address - node.value <= max_offset
        && depth + 1 <= max_depth
    {
        if let Some((module_index, module_base)) = find_static(node.base, module_ranges) {
            let mut offsets = node.chain.clone();
            offsets.push(target_address - node.value);
            emitted.push(PointerPath {
                module_index,
                module_base,
                base_offset: node.base - module_base,
                offsets,
                resolved: target_address,
            });
        }
    }

    // Descend: follow every pointer slot in [value, value + max_offset].
    if depth + 1 < max_depth {
        let lo = node.value;
        let hi = node.value.saturating_add(max_offset);
        let begin = pairs.partition_point(|p| p.1 < lo);
        let mut processed = 0usize;
        let mut i = begin;
        while i < pairs.len() && pairs[i].1 <= hi {
            let (child_value, child_slot) = pairs[i];
            i += 1;
            if node.visited.contains(&child_slot) {
                continue;
            }
            let mut chain = node.chain.clone();
            chain.push(child_slot - node.value);
            let mut visited = node.visited.clone();
            visited.push(child_slot);
            next.push(ForwardNode { base: node.base, value: child_value, chain, visited });
            processed += 1;
            if processed >= MAX_OFFSETS_PER_NODE {
                break;
            }
        }
    }

    (emitted, next)
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
fn extract_pointers(
    platform: &dyn PlatformAPI,
    pid: u32,
    base: u64,
    size: usize,
    alignment: usize,
    region_ranges: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    let data = read_region_chunked(platform, pid, base, size);
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + POINTER_SIZE <= data.len() {
        let value = u64::from_le_bytes(data[pos..pos + POINTER_SIZE].try_into().unwrap());
        if in_ranges(value, region_ranges) {
            out.push((value, base + pos as u64));
        }
        pos += alignment;
    }
    out
}

/// Build sorted module ranges `(start, end, module_index, module_base)`. When
/// `allowed` is `Some`, only modules whose base is in the list are included.
fn build_module_ranges(
    platform: &dyn PlatformAPI,
    pid: u32,
    allowed: Option<&[u64]>,
) -> Vec<(u64, u64, i32, u64)> {
    let modules = platform.list_modules(pid).unwrap_or_default();
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
