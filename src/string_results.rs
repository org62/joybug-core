//! Disk-backed string-scan results.
//!
//! A module scan can yield hundreds of thousands of strings, so hits are streamed
//! to a file of variable-length records and read back via a read-only mmap for
//! paging, filtering, and sorting. The file is identified by its path — joybug2
//! keeps no per-connection state — mirroring [`crate::pointer_results`].
//!
//! Record layout (little-endian): `address(u64) + full_len(u32) + flags(u8) +
//! stored_len(u16) + text[stored_len]`. `full_len` is the string's true length in
//! characters; `stored_len` is the (possibly truncated) UTF-8 text actually kept.
//! `flags` bit0 = UTF-16 encoding, bit1 = truncated. All stored characters are in
//! the printable ASCII range by construction of the scanner, so `text` is valid
//! UTF-8.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use memmap2::{Mmap, MmapOptions};

use crate::protocol::{StringEncoding, StringHit, StringSortKey};

const MAGIC: u64 = 0x4A42_5354_5253_4331; // "JBSTRSC1"
const HEADER_BYTES: usize = 8;
/// Fixed-size prefix of every record, before the variable-length text.
const REC_HEADER_BYTES: usize = 8 + 4 + 1 + 2;

/// Max characters kept per string. Longer strings are still counted (`full_len`)
/// and flagged truncated, but only this many characters are stored.
pub const MAX_STORED_CHARS: usize = 256;

const FLAG_UTF16: u8 = 0b01;
const FLAG_TRUNCATED: u8 = 0b10;

/// Streams string hits to a variable-length results file.
pub struct StringResultWriter {
    w: BufWriter<File>,
    count: u64,
}

impl StringResultWriter {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);
        w.write_all(&MAGIC.to_le_bytes())?;
        Ok(Self { w, count: 0 })
    }

    pub fn push(&mut self, hit: &StringHit) -> std::io::Result<()> {
        let bytes = hit.text.as_bytes();
        let stored_len = bytes.len().min(u16::MAX as usize);
        let mut flags = 0u8;
        if matches!(hit.encoding, StringEncoding::Utf16) {
            flags |= FLAG_UTF16;
        }
        if hit.truncated {
            flags |= FLAG_TRUNCATED;
        }
        self.w.write_all(&hit.address.to_le_bytes())?;
        self.w.write_all(&hit.length.to_le_bytes())?;
        self.w.write_all(&[flags])?;
        self.w.write_all(&(stored_len as u16).to_le_bytes())?;
        self.w.write_all(&bytes[..stored_len])?;
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<u64> {
        self.w.flush()?;
        Ok(self.count)
    }
}

/// `stored_len` field (bytes of text kept) of the record starting at `pos`.
fn stored_len_at(m: &[u8], pos: usize) -> usize {
    u16::from_le_bytes(m[pos + 13..pos + 15].try_into().unwrap()) as usize
}

/// Allocation-free ASCII-case-insensitive substring test. Exact for ASCII text
/// (scan-stored strings, PDB type names); an empty needle matches everything.
pub(crate) fn contains_ascii_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// Case-insensitive ASCII ordering (matches the scanner's printable-ASCII text).
fn cmp_ascii_ci(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.iter()
        .map(|c| c.to_ascii_lowercase())
        .cmp(b.iter().map(|c| c.to_ascii_lowercase()))
}

/// Reads a string-scan results file via mmap. An index of record byte-offsets is
/// built once at open (records are variable length), then reused for every page.
pub struct StringResultReader {
    mmap: Mmap,
    /// Byte offset of each record start, in file (address-ascending) order.
    offsets: Vec<usize>,
}

impl StringResultReader {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open results file: {}", e))?;
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| format!("Failed to mmap results file: {}", e))?;
        if mmap.len() < HEADER_BYTES {
            return Err("Results file truncated".to_string());
        }
        let magic = u64::from_le_bytes(mmap[0..8].try_into().unwrap());
        if magic != MAGIC {
            return Err("Not a string-scan results file (or incompatible version)".to_string());
        }
        let mut offsets = Vec::new();
        let mut pos = HEADER_BYTES;
        while pos + REC_HEADER_BYTES <= mmap.len() {
            let rec_end = pos + REC_HEADER_BYTES + stored_len_at(&mmap, pos);
            if rec_end > mmap.len() {
                break; // trailing partial record (truncated file) — ignore
            }
            offsets.push(pos);
            pos = rec_end;
        }
        Ok(Self { mmap, offsets })
    }

    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    fn address_at(&self, pos: usize) -> u64 {
        u64::from_le_bytes(self.mmap[pos..pos + 8].try_into().unwrap())
    }

    /// `full_len` field (true character count) of the record starting at `pos`.
    fn length_at(&self, pos: usize) -> u32 {
        u32::from_le_bytes(self.mmap[pos + 8..pos + 12].try_into().unwrap())
    }

    /// Raw stored text bytes (printable ASCII by construction, so valid UTF-8).
    fn text_bytes_at(&self, pos: usize) -> &[u8] {
        let begin = pos + REC_HEADER_BYTES;
        &self.mmap[begin..begin + stored_len_at(&self.mmap, pos)]
    }

    fn record_at(&self, pos: usize) -> StringHit {
        let flags = self.mmap[pos + 12];
        StringHit {
            address: self.address_at(pos),
            encoding: if flags & FLAG_UTF16 != 0 {
                StringEncoding::Utf16
            } else {
                StringEncoding::Ascii
            },
            length: self.length_at(pos),
            text: String::from_utf8_lossy(self.text_bytes_at(pos)).into_owned(),
            truncated: flags & FLAG_TRUNCATED != 0,
        }
    }

    /// Page over records after applying a case-insensitive substring `filter`
    /// (empty = all) and sorting by `sort`/`ascending`. Returns the requested
    /// page `[offset, offset+count)` of matches plus the total match count across
    /// the whole file. Records are stored address-ascending, so the `Address`
    /// sort pages straight over the (filtered) index with no copy or sort; only
    /// a `Value` sort materializes and reorders an index.
    pub fn page(
        &self,
        filter: &str,
        sort: StringSortKey,
        ascending: bool,
        offset: usize,
        count: usize,
    ) -> (Vec<StringHit>, u64) {
        let needle = filter.to_lowercase();
        // Matching record offsets, in file (address-ascending) order. The
        // unfiltered case borrows the index instead of copying it.
        let filtered: Vec<usize>;
        let matched: &[usize] = if needle.is_empty() {
            &self.offsets
        } else {
            filtered = self
                .offsets
                .iter()
                .copied()
                .filter(|&pos| contains_ascii_ci(self.text_bytes_at(pos), needle.as_bytes()))
                .collect();
            &filtered
        };
        let total = matched.len() as u64;
        let begin = offset.min(matched.len());
        let end = offset.saturating_add(count).min(matched.len());

        let out: Vec<StringHit> = match sort {
            StringSortKey::Address if ascending => {
                matched[begin..end].iter().map(|&pos| self.record_at(pos)).collect()
            }
            StringSortKey::Address => matched
                .iter()
                .rev()
                .skip(begin)
                .take(end - begin)
                .map(|&pos| self.record_at(pos))
                .collect(),
            StringSortKey::Value => {
                // Ties (equal strings) fall back to address order so page
                // boundaries stay consistent across requests.
                let sel = if ascending {
                    select_page(matched, begin, end, |a, b| {
                        cmp_ascii_ci(self.text_bytes_at(a), self.text_bytes_at(b)).then(a.cmp(&b))
                    })
                } else {
                    select_page(matched, begin, end, |a, b| {
                        cmp_ascii_ci(self.text_bytes_at(b), self.text_bytes_at(a)).then(a.cmp(&b))
                    })
                };
                sel.iter().map(|&pos| self.record_at(pos)).collect()
            }
            StringSortKey::Length => {
                // Ties stay address-ascending in both directions (pos is the
                // file offset, and the file is address-ordered).
                let sel = if ascending {
                    select_page(matched, begin, end, |a, b| {
                        (self.length_at(a), a).cmp(&(self.length_at(b), b))
                    })
                } else {
                    select_page(matched, begin, end, |a, b| {
                        (std::cmp::Reverse(self.length_at(a)), a)
                            .cmp(&(std::cmp::Reverse(self.length_at(b)), b))
                    })
                };
                sel.iter().map(|&pos| self.record_at(pos)).collect()
            }
        };
        (out, total)
    }
}

/// The page `[begin, end)` of `matched` under `cmp`, without fully sorting:
/// selection partitions the copy in O(n) average, then only the page window is
/// sorted. `cmp` must be a total order (break ties!) so page boundaries are
/// stable across requests.
fn select_page(
    matched: &[usize],
    begin: usize,
    end: usize,
    mut cmp: impl FnMut(usize, usize) -> std::cmp::Ordering,
) -> Vec<usize> {
    let mut v = matched.to_vec();
    if begin >= v.len() {
        return Vec::new();
    }
    if begin > 0 {
        v.select_nth_unstable_by(begin, |&a, &b| cmp(a, b));
    }
    let tail = &mut v[begin..];
    let k = (end - begin).min(tail.len());
    if k == 0 {
        return Vec::new();
    }
    if k < tail.len() {
        tail.select_nth_unstable_by(k - 1, |&a, &b| cmp(a, b));
    }
    let window = &mut tail[..k];
    window.sort_unstable_by(|&a, &b| cmp(a, b));
    window.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "joybug_strresults_unit_{}_{}.bin",
            tag,
            std::process::id()
        ))
    }

    fn hit(address: u64, enc: StringEncoding, text: &str) -> StringHit {
        StringHit {
            address,
            encoding: enc,
            length: text.chars().count() as u32,
            text: text.to_string(),
            truncated: false,
        }
    }

    #[test]
    fn round_trips_records_and_filters_and_sorts() {
        let path = tmp_path("rw");
        {
            let mut w = StringResultWriter::create(&path).unwrap();
            w.push(&hit(0x1000, StringEncoding::Ascii, "hello")).unwrap();
            w.push(&hit(0x2000, StringEncoding::Utf16, "World")).unwrap();
            w.push(&hit(0x3000, StringEncoding::Ascii, "apple")).unwrap();
            assert_eq!(w.finish().unwrap(), 3);
        }
        let reader = StringResultReader::open(&path).unwrap();
        assert_eq!(reader.len(), 3);

        // No filter, address ascending == file order.
        let (page, total) = reader.page("", StringSortKey::Address, true, 0, 10);
        assert_eq!(total, 3);
        assert_eq!(page.iter().map(|h| h.address).collect::<Vec<_>>(), vec![0x1000, 0x2000, 0x3000]);
        assert!(matches!(page[1].encoding, StringEncoding::Utf16));

        // Address descending.
        let (page, _) = reader.page("", StringSortKey::Address, false, 0, 10);
        assert_eq!(page[0].address, 0x3000);

        // Value ascending: apple, hello, World (case-insensitive).
        let (page, _) = reader.page("", StringSortKey::Value, true, 0, 10);
        assert_eq!(page.iter().map(|h| h.text.clone()).collect::<Vec<_>>(), vec!["apple", "hello", "World"]);

        // Case-insensitive substring filter.
        let (page, total) = reader.page("LL", StringSortKey::Address, true, 0, 10);
        assert_eq!(total, 1);
        assert_eq!(page[0].text, "hello");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sorts_by_length_with_address_ties() {
        let path = tmp_path("len");
        {
            let mut w = StringResultWriter::create(&path).unwrap();
            w.push(&hit(0x1000, StringEncoding::Ascii, "abcdef")).unwrap(); // len 6
            w.push(&hit(0x2000, StringEncoding::Ascii, "xy")).unwrap(); // len 2
            w.push(&hit(0x3000, StringEncoding::Ascii, "abc")).unwrap(); // len 3
            w.push(&hit(0x4000, StringEncoding::Ascii, "def")).unwrap(); // len 3 (tie)
            w.finish().unwrap();
        }
        let reader = StringResultReader::open(&path).unwrap();

        let (page, total) = reader.page("", StringSortKey::Length, true, 0, 10);
        assert_eq!(total, 4);
        assert_eq!(page.iter().map(|h| h.length).collect::<Vec<_>>(), vec![2, 3, 3, 6]);
        // Length ties keep address order.
        assert_eq!(page[1].address, 0x3000);
        assert_eq!(page[2].address, 0x4000);

        let (page, _) = reader.page("", StringSortKey::Length, false, 0, 10);
        assert_eq!(page.iter().map(|h| h.length).collect::<Vec<_>>(), vec![6, 3, 3, 2]);
        // Ties stay address-ascending even when descending by length.
        assert_eq!(page[1].address, 0x3000);
        assert_eq!(page[2].address, 0x4000);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn paginates_matches() {
        let path = tmp_path("page");
        {
            let mut w = StringResultWriter::create(&path).unwrap();
            for i in 0..100u64 {
                w.push(&hit(0x1000 + i * 0x10, StringEncoding::Ascii, &format!("str{:03}", i)))
                    .unwrap();
            }
            w.finish().unwrap();
        }
        let reader = StringResultReader::open(&path).unwrap();
        let (page, total) = reader.page("", StringSortKey::Address, true, 40, 10);
        assert_eq!(total, 100);
        assert_eq!(page.len(), 10);
        assert_eq!(page[0].text, "str040");
        assert_eq!(page[9].text, "str049");
        let _ = std::fs::remove_file(&path);
    }
}
