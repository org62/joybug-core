//! Runtime string scanner.
//!
//! Discovers printable ASCII and UTF-16LE strings in a target's memory over an
//! arbitrary `[start_address, start_address+size)` span (the caller passes a
//! module's `[base, base+size)`). Like [`crate::pointer_scanner`] it is stateless
//! and file-backed: results stream to a temp file identified by its path, paged
//! back via [`crate::string_results`].
//!
//! Detection is a streaming state machine fed 1 MB memory chunks, so a large
//! region never has to be resident in full. Run state carries across chunk
//! boundaries within a region (strings that span a boundary are not missed) and
//! is flushed at each region boundary and on any read discontinuity.

use std::time::Instant;

use rayon::prelude::*;

use crate::interfaces::PlatformAPI;
use crate::memory_scanner::{
    delete_results_file, enumerate_scannable_regions, for_each_region_chunk, install_pool,
    unique_temp_path,
};
use crate::protocol::{ScanRegionFilter, StringEncoding, StringEncodingFilter, StringHit, StringSortKey};
use crate::string_results::{contains_ascii_ci, StringResultReader, StringResultWriter, MAX_STORED_CHARS};

/// Default cap on the number of stored hits. A broad scan can exceed this; the
/// first `DEFAULT_CAP` (in address order) are kept and `capped` is reported true.
const DEFAULT_CAP: usize = 1_000_000;

/// Regions are scanned in address-ascending batches of about this many bytes.
/// Batching bounds peak memory to one batch's hits (not the whole span's) and
/// lets the scan stop scheduling work once the hit cap is reached.
const BATCH_BYTES: usize = 64 * 1024 * 1024;

fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// Per-scan detector settings, threaded through the run state machine.
struct DetectorConfig {
    min_len: usize,
    /// Detect ASCII runs.
    ascii: bool,
    /// Detect UTF-16 runs.
    utf16: bool,
    /// Lowercased needle a string's stored text must contain (empty = keep all).
    /// Matches over the stored text only, which caps at [`MAX_STORED_CHARS`], so
    /// a needle appearing only past that point of a very long string won't match.
    needle_lower: Vec<u8>,
}

impl DetectorConfig {
    fn new(min_len: usize, encodings: StringEncodingFilter, contains: &str) -> Self {
        DetectorConfig {
            min_len,
            ascii: !matches!(encodings, StringEncodingFilter::Utf16),
            utf16: !matches!(encodings, StringEncodingFilter::Ascii),
            needle_lower: contains.to_lowercase().into_bytes(),
        }
    }
}

/// An in-progress string run. Most runs are short printable garbage rejected by
/// `min_len`, and one starts every few bytes of binary data, so the stored text
/// lives in a fixed inline buffer — the byte-level hot loop never touches the
/// heap; only accepted hits allocate (in [`emit`]).
struct Run {
    start: u64,
    /// True character count (may exceed the stored/truncated text length).
    len: u32,
    /// Stored text bytes (printable ASCII), capped at [`MAX_STORED_CHARS`].
    text: [u8; MAX_STORED_CHARS],
}

impl Run {
    fn start_at(start: u64) -> Self {
        Run { start, len: 0, text: [0; MAX_STORED_CHARS] }
    }

    fn push_char(&mut self, b: u8) {
        if (self.len as usize) < MAX_STORED_CHARS {
            self.text[self.len as usize] = b;
        }
        self.len += 1;
    }

    /// The stored (possibly truncated) text.
    fn text(&self) -> &[u8] {
        &self.text[..(self.len as usize).min(MAX_STORED_CHARS)]
    }
}

/// Streaming detector state, carried across chunks within one region.
#[derive(Default)]
struct RunState {
    /// Address the next fed byte is expected at; a mismatch signals a read gap.
    next_addr: Option<u64>,
    ascii: Option<Run>,
    utf16: Option<Run>,
    /// A printable byte awaiting its UTF-16 high byte (address, byte).
    pending_low: Option<(u64, u8)>,
}

fn emit(run: Run, encoding: StringEncoding, cfg: &DetectorConfig, out: &mut Vec<StringHit>) {
    if (run.len as usize) >= cfg.min_len
        && (cfg.needle_lower.is_empty() || contains_ascii_ci(run.text(), &cfg.needle_lower))
    {
        out.push(StringHit {
            address: run.start,
            encoding,
            length: run.len,
            truncated: run.len as usize > MAX_STORED_CHARS,
            text: String::from_utf8_lossy(run.text()).into_owned(),
        });
    }
}

fn finish_ascii(state: &mut RunState, cfg: &DetectorConfig, out: &mut Vec<StringHit>) {
    if let Some(run) = state.ascii.take() {
        emit(run, StringEncoding::Ascii, cfg, out);
    }
}

fn finish_utf16(state: &mut RunState, cfg: &DetectorConfig, out: &mut Vec<StringHit>) {
    if let Some(run) = state.utf16.take() {
        emit(run, StringEncoding::Utf16, cfg, out);
    }
}

/// Feed one UTF-16 byte through the pair machine. When not in a pair, every
/// printable byte becomes a candidate low byte; the next byte must be 0x00 to
/// complete a character. This naturally covers both byte parities.
fn feed_utf16_byte(state: &mut RunState, a: u64, b: u8, cfg: &DetectorConfig, out: &mut Vec<StringHit>) {
    if let Some((la, lb)) = state.pending_low.take() {
        if b == 0x00 {
            // (lb, 0x00) is a valid UTF-16 character.
            state.utf16.get_or_insert_with(|| Run::start_at(la)).push_char(lb);
        } else {
            // Pair invalid: end the run, then reconsider `b` as a new low byte.
            finish_utf16(state, cfg, out);
            if is_printable(b) {
                state.pending_low = Some((a, b));
            }
        }
    } else if is_printable(b) {
        state.pending_low = Some((a, b));
    } else {
        finish_utf16(state, cfg, out);
    }
}

/// Feed one memory chunk. `chunk_addr` is the absolute address of `data[0]`.
fn feed_chunk(
    state: &mut RunState,
    chunk_addr: u64,
    data: &[u8],
    cfg: &DetectorConfig,
    out: &mut Vec<StringHit>,
) {
    // A read gap (skipped chunk) breaks contiguity — flush before continuing.
    if let Some(expected) = state.next_addr {
        if chunk_addr != expected {
            finish_ascii(state, cfg, out);
            finish_utf16(state, cfg, out);
            state.pending_low = None;
        }
    }

    for (i, &b) in data.iter().enumerate() {
        let a = chunk_addr + i as u64;
        if cfg.ascii {
            if is_printable(b) {
                state.ascii.get_or_insert_with(|| Run::start_at(a)).push_char(b);
            } else {
                finish_ascii(state, cfg, out);
            }
        }
        if cfg.utf16 {
            feed_utf16_byte(state, a, b, cfg, out);
        }
    }

    state.next_addr = Some(chunk_addr + data.len() as u64);
}

/// Emit any runs still open at a region boundary.
fn flush(state: &mut RunState, cfg: &DetectorConfig, out: &mut Vec<StringHit>) {
    finish_ascii(state, cfg, out);
    finish_utf16(state, cfg, out);
    state.pending_low = None;
    state.next_addr = None;
}

/// Scan a raw byte buffer for ASCII/UTF-16 strings without a live process.
/// `base` is the address assigned to `bytes[0]` (e.g. a file offset, RVA, or VA);
/// each hit's `address` is `base + index`. Session-independent — used by the
/// standalone PE viewer to scan a file buffer.
pub fn scan_bytes(
    bytes: &[u8],
    base: u64,
    min_len: usize,
    encodings: StringEncodingFilter,
    contains: &str,
) -> Vec<StringHit> {
    let cfg = DetectorConfig::new(min_len, encodings, contains);
    let mut state = RunState::default();
    let mut out = Vec::new();
    feed_chunk(&mut state, base, bytes, &cfg, &mut out);
    flush(&mut state, &cfg, &mut out);
    out
}

fn scan_region(
    platform: &dyn PlatformAPI,
    pid: u32,
    base: u64,
    size: usize,
    cfg: &DetectorConfig,
) -> Vec<StringHit> {
    let mut state = RunState::default();
    let mut out = Vec::new();
    for_each_region_chunk(platform, pid, base, size, true, |chunk_addr, data| {
        feed_chunk(&mut state, chunk_addr, data, cfg, &mut out);
        true
    });
    flush(&mut state, cfg, &mut out);
    out
}

/// Results live in files identified by path (no per-scan state), plus a cache
/// of the most recently paged file's reader: records are variable length, so
/// re-opening rebuilds an O(records) offset index — too slow to redo on every
/// page/sort/filter request.
pub struct StringScanner {
    cached: Option<(String, StringResultReader)>,
}

impl StringScanner {
    pub fn new() -> Self {
        Self { cached: None }
    }

    /// Scan `[start_address, start_address+size)` for strings of at least
    /// `min_length` characters (clamped to `2..=128`), visiting only regions
    /// matching `region_filter`, detecting only `encodings`, and (when
    /// `contains` is non-empty) storing only strings containing it
    /// case-insensitively. Returns `(results_path, match_count, scan_time_us, capped)`.
    #[allow(clippy::too_many_arguments)]
    pub fn start_scan(
        &self,
        platform: &dyn PlatformAPI,
        pid: u32,
        start_address: u64,
        size: u64,
        min_length: u32,
        max_results: Option<u64>,
        thread_count: Option<usize>,
        region_filter: ScanRegionFilter,
        encodings: StringEncodingFilter,
        contains: &str,
    ) -> Result<(String, u64, u64, bool), String> {
        let start = Instant::now();
        let min_len = (min_length as usize).clamp(2, 128);
        let cfg = DetectorConfig::new(min_len, encodings, contains);
        let cap = max_results.map(|n| n as usize).unwrap_or(DEFAULT_CAP).max(1);
        let span_lo = start_address;
        let span_hi = start_address.saturating_add(size);

        // Committed regions matching the filter, clipped to the span, ascending.
        let regions = enumerate_scannable_regions(platform, pid, region_filter)?;
        let mut clipped: Vec<(u64, usize)> = regions
            .iter()
            .filter_map(|&(base, sz)| {
                let lo = base.max(span_lo);
                let hi = base.saturating_add(sz as u64).min(span_hi);
                if lo < hi {
                    Some((lo, (hi - lo) as usize))
                } else {
                    None
                }
            })
            .collect();
        clipped.sort_unstable_by_key(|r| r.0);

        let results_path = unique_temp_path("strresults", pid);
        let mut writer = StringResultWriter::create(&results_path)
            .map_err(|e| format!("Failed to create results file: {}", e))?;

        // Scan address-ascending batches of regions, each batch's regions in
        // parallel. Every region's hits are ascending and batches are written in
        // order, so the results file is address-sorted (making the Address sort
        // free). Once the cap is reached, remaining hits and batches are skipped
        // and `capped` is reported (conservatively so if the cap landed exactly
        // on the last hit but regions were left unscanned).
        let mut written = 0usize;
        let mut capped = false;
        install_pool(thread_count, || -> Result<(), String> {
            let mut rest: &[(u64, usize)] = &clipped;
            while !rest.is_empty() && !capped {
                let mut take = 1;
                let mut bytes = rest[0].1;
                while take < rest.len() && bytes < BATCH_BYTES {
                    bytes += rest[take].1;
                    take += 1;
                }
                let (batch, tail) = rest.split_at(take);
                rest = tail;

                let per_region: Vec<Vec<StringHit>> = batch
                    .par_iter()
                    .map(|&(base, sz)| scan_region(platform, pid, base, sz, &cfg))
                    .collect();
                for hit in per_region.iter().flatten() {
                    if written >= cap {
                        capped = true;
                        break;
                    }
                    writer
                        .push(hit)
                        .map_err(|e| format!("Failed to write result: {}", e))?;
                    written += 1;
                }
                capped = capped || (written >= cap && !rest.is_empty());
            }
            Ok(())
        })?;
        let match_count = writer
            .finish()
            .map_err(|e| format!("Failed to finalize results: {}", e))?;

        let scan_time_us = start.elapsed().as_micros() as u64;
        Ok((results_path.to_string_lossy().into_owned(), match_count, scan_time_us, capped))
    }

    /// Read a page of results, applying `filter` and `sort`/`ascending`.
    pub fn get_results(
        &mut self,
        results_path: &str,
        offset: u64,
        count: u64,
        filter: &str,
        sort: StringSortKey,
        ascending: bool,
    ) -> Result<(Vec<StringHit>, u64), String> {
        if self.cached.as_ref().is_none_or(|(p, _)| p != results_path) {
            let reader = StringResultReader::open(std::path::Path::new(results_path))?;
            self.cached = Some((results_path.to_string(), reader));
        }
        let (_, reader) = self.cached.as_ref().unwrap();
        Ok(reader.page(filter, sort, ascending, offset as usize, count as usize))
    }

    pub fn reset_scan(&mut self, results_path: &str) -> Result<(), String> {
        // Drop the cached mmap first — Windows can't delete a mapped file.
        if self.cached.as_ref().is_some_and(|(p, _)| p == results_path) {
            self.cached = None;
        }
        delete_results_file(results_path, "joybug_strresults_")
    }
}

impl Default for StringScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the detector directly over in-memory byte buffers (no platform).
    fn detect_cfg(chunks: &[(u64, &[u8])], cfg: &DetectorConfig) -> Vec<StringHit> {
        let mut state = RunState::default();
        let mut out = Vec::new();
        for (addr, data) in chunks {
            feed_chunk(&mut state, *addr, data, cfg, &mut out);
        }
        flush(&mut state, cfg, &mut out);
        out
    }

    fn detect(chunks: &[(u64, &[u8])], min_len: usize) -> Vec<StringHit> {
        detect_cfg(chunks, &DetectorConfig::new(min_len, StringEncodingFilter::Both, ""))
    }

    #[test]
    fn finds_ascii_run() {
        let hits = detect(&[(0x1000, b"\x00Hello\x00")], 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, 0x1001);
        assert_eq!(hits[0].text, "Hello");
        assert!(matches!(hits[0].encoding, StringEncoding::Ascii));
        assert!(!hits[0].truncated);
    }

    #[test]
    fn respects_min_length() {
        // "Hi" is length 2; with min 3 it is dropped, with min 2 it is kept.
        assert!(detect(&[(0, b"Hi\x00")], 3).is_empty());
        assert_eq!(detect(&[(0, b"Hi\x00")], 2).len(), 1);
    }

    #[test]
    fn finds_utf16_both_parities() {
        // Even parity: "AB" at offset 0.
        let even = detect(&[(0x2000, b"A\x00B\x00")], 2);
        assert_eq!(even.len(), 1);
        assert_eq!(even[0].text, "AB");
        assert_eq!(even[0].address, 0x2000);
        assert!(matches!(even[0].encoding, StringEncoding::Utf16));

        // Odd parity: a leading 0x00 shifts the string to offset 1.
        let odd = detect(&[(0x3000, b"\x00A\x00B\x00")], 2);
        assert_eq!(odd.len(), 1);
        assert_eq!(odd[0].text, "AB");
        assert_eq!(odd[0].address, 0x3001);
    }

    #[test]
    fn ascii_does_not_produce_utf16() {
        // Pure ASCII text has non-zero high bytes, so no UTF-16 run forms.
        let hits = detect(&[(0, b"Hello\x00")], 3);
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].encoding, StringEncoding::Ascii));
    }

    #[test]
    fn ascii_run_spans_chunk_boundary() {
        // "Hello" split across two chunks must be found as one string.
        let hits = detect(&[(0x1000, b"Hel"), (0x1003, b"lo\x00")], 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, 0x1000);
        assert_eq!(hits[0].text, "Hello");
    }

    #[test]
    fn utf16_char_spans_chunk_boundary() {
        // The low byte ends chunk 1; the 0x00 high byte begins chunk 2.
        let hits = detect(&[(0x4000, b"A\x00B"), (0x4003, b"\x00")], 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "AB");
        assert_eq!(hits[0].address, 0x4000);
    }

    #[test]
    fn embedded_nul_splits_ascii() {
        // "AB\0CD" yields two ASCII strings at min length 2.
        let mut hits = detect(&[(0x5000, b"AB\x00CD\x00")], 2);
        hits.retain(|h| matches!(h.encoding, StringEncoding::Ascii));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].text, "AB");
        assert_eq!(hits[0].address, 0x5000);
        assert_eq!(hits[1].text, "CD");
        assert_eq!(hits[1].address, 0x5003);
    }

    #[test]
    fn truncates_long_string() {
        let long: Vec<u8> = std::iter::repeat(b'x').take(MAX_STORED_CHARS + 50).chain([0u8]).collect();
        let hits = detect(&[(0, &long)], 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].length, (MAX_STORED_CHARS + 50) as u32);
        assert_eq!(hits[0].text.chars().count(), MAX_STORED_CHARS);
        assert!(hits[0].truncated);
    }

    #[test]
    fn encoding_filter_limits_detection() {
        // "Hi" (ASCII) followed by UTF-16 "AB" — each filter sees only its kind.
        // (The double NUL keeps the pair machine from absorbing the 'i'.)
        let data: &[u8] = b"Hi\x00\x00A\x00B\x00";
        let ascii_only = detect_cfg(&[(0, data)], &DetectorConfig::new(2, StringEncodingFilter::Ascii, ""));
        assert!(ascii_only.iter().all(|h| matches!(h.encoding, StringEncoding::Ascii)));
        assert!(ascii_only.iter().any(|h| h.text == "Hi"));

        let utf16_only = detect_cfg(&[(0, data)], &DetectorConfig::new(2, StringEncodingFilter::Utf16, ""));
        assert!(utf16_only.iter().all(|h| matches!(h.encoding, StringEncoding::Utf16)));
        assert!(utf16_only.iter().any(|h| h.text == "AB"));
    }

    #[test]
    fn contains_filter_drops_non_matches() {
        let data: &[u8] = b"hello\x00world\x00HELLOES\x00";
        let hits = detect_cfg(&[(0, data)], &DetectorConfig::new(3, StringEncodingFilter::Ascii, "Hell"));
        let texts: Vec<_> = hits.iter().map(|h| h.text.as_str()).collect();
        assert_eq!(texts, vec!["hello", "HELLOES"]);
    }

    #[test]
    fn read_gap_flushes_run() {
        // A non-contiguous second chunk must not merge with the first's run.
        let hits = detect(&[(0x1000, b"abc"), (0x9000, b"def\x00")], 3);
        let texts: Vec<_> = hits.iter().map(|h| h.text.clone()).collect();
        assert!(texts.contains(&"abc".to_string()));
        assert!(texts.contains(&"def".to_string()));
        // "abc" was flushed at the gap, so no "abcdef" merged run exists.
        assert!(!texts.iter().any(|t| t.contains("abcdef")));
    }
}
