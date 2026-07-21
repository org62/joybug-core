//! Original on-disk PE images and section-aware RVA→file-offset translation.
//!
//! `OriginalModuleImage` reads a module's file from disk and keeps the raw file
//! bytes plus a section map, so callers can compare live (in-memory) code
//! against what was loaded from disk — detecting patches, hooks, and
//! self-modifying code. DIR64 base relocations are applied into the file-byte
//! buffer for the module's actual load base so ASLR-moved absolute addresses
//! in code don't false-positive as "patched".
//!
//! We deliberately do NOT use pelite's `to_view()` (it builds a SizeOfImage
//! buffer via `copy_from_slice`, which panics whenever a section's VirtualSize
//! differs from its SizeOfRawData — the common case).
//!
//! Modules whose file can't be read/parsed (synthetic names, non-x64 images,
//! unreadable paths) get an `unavailable` sentinel so callers can cache the
//! "can't compare this module" answer instead of retrying disk I/O.

use std::path::Path;

use pelite::pe64::{Pe, PeFile};
use tracing::{debug, warn};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_REL_BASED_DIR64: u8 = 10;

/// A section's file/virtual-address mapping, parsed from a PE's section headers.
pub struct SectionMap {
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub virt_addr: u32,
    pub virt_size: u32,
}

impl From<&crate::pe_types::ImageSectionHeader> for SectionMap {
    fn from(s: &crate::pe_types::ImageSectionHeader) -> Self {
        Self {
            raw_ptr: s.PointerToRawData,
            raw_size: s.SizeOfRawData,
            virt_addr: s.VirtualAddress,
            virt_size: s.VirtualSize,
        }
    }
}

/// The section whose virtual span (`max(VirtualSize, SizeOfRawData)`) covers `rva`.
fn section_for(sections: &[SectionMap], rva: u32) -> Option<&SectionMap> {
    sections.iter().find(|s| {
        let span = s.virt_size.max(s.raw_size);
        rva >= s.virt_addr && rva < s.virt_addr + span
    })
}

/// Strict RVA→file-offset translation that requires `len` bytes of initialized
/// data (within `SizeOfRawData`) in a single section — so callers never read
/// past a section's on-disk bytes into padding or the next section. RVAs
/// outside any section (e.g. the PE headers) yield `None`.
pub fn rva_to_offset(sections: &[SectionMap], rva: u32, len: usize) -> Option<usize> {
    let s = section_for(sections, rva)?;
    let sec_off = rva - s.virt_addr;
    if (sec_off as usize) + len > s.raw_size as usize {
        return None; // beyond initialized (file-backed) data
    }
    Some(s.raw_ptr as usize + sec_off as usize)
}

/// Loose RVA→file-offset translation for file viewers: no initialized-data
/// guard, and RVAs outside any section (the PE headers) map to themselves.
pub fn rva_to_offset_loose(sections: &[SectionMap], rva: u32) -> usize {
    match section_for(sections, rva) {
        Some(s) => (s.raw_ptr as u64 + (rva - s.virt_addr) as u64) as usize,
        None => rva as usize,
    }
}

/// A module's original on-disk bytes plus the metadata needed to read original
/// code bytes at a VA. Executable sections are compared (RWX included, so
/// patches in packed/self-modifying code are caught). `unavailable` entries
/// carry no bytes and never match — they cache the "can't compare this module"
/// answer.
pub struct OriginalModuleImage {
    base: u64,
    image_size: u64,
    /// Raw file bytes, with DIR64 relocations applied for the actual load base.
    bytes: Vec<u8>,
    sections: Vec<SectionMap>,
    /// `[start_rva, end_rva)` spans of executable sections — the only regions we
    /// compare. Includes writable (RWX) sections so patches/hooks in packed or
    /// self-modifying code are flagged; the tradeoff is that genuinely-mutated
    /// data in an RWX section can also show as "patched" if the disassembler
    /// decodes it as an instruction at a viewed address.
    code_ranges: Vec<(u32, u32)>,
    pub unavailable: bool,
}

impl OriginalModuleImage {
    fn unavailable(base: u64) -> Self {
        Self { base, image_size: 0, bytes: Vec::new(), sections: Vec::new(), code_ranges: Vec::new(), unavailable: true }
    }

    /// Read `path` from disk and build a rebased image. Never fails — any problem
    /// yields an `unavailable` sentinel so the caller caches it.
    pub fn build(path: &str, base: u64) -> Self {
        // Skip synthetic module names ("Unknown_0x..", "main.exe" fallbacks) and
        // anything that isn't a real absolute path on disk.
        if !Path::new(path).is_absolute() || !Path::new(path).exists() {
            debug!("pe_image: no on-disk file for module '{}' — unavailable", path);
            return Self::unavailable(base);
        }

        let mut bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                warn!("pe_image: failed to read '{}': {}", path, e);
                return Self::unavailable(base);
            }
        };

        // Parse headers/sections/relocs from an immutable borrow, collect what we
        // need, then drop the borrow before mutating `bytes` for relocations.
        struct Parsed {
            image_size: u64,
            preferred: u64,
            sections: Vec<SectionMap>,
            code_ranges: Vec<(u32, u32)>,
            dir64_rvas: Vec<u32>,
        }

        let parsed = {
            let pe = match PeFile::from_bytes(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    debug!("pe_image: pe64 parse failed for '{}': {:?}", path, e);
                    return Self::unavailable(base);
                }
            };

            let optional = pe.optional_header();
            let image_size = optional.SizeOfImage as u64;
            let preferred = optional.ImageBase;

            let sections: Vec<SectionMap> = pe
                .section_headers()
                .iter()
                .map(|s| SectionMap {
                    raw_ptr: s.PointerToRawData,
                    raw_size: s.SizeOfRawData,
                    virt_addr: s.VirtualAddress,
                    virt_size: s.VirtualSize,
                })
                .collect();

            let code_ranges: Vec<(u32, u32)> = pe
                .section_headers()
                .iter()
                .filter(|s| s.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
                .map(|s| (s.VirtualAddress, s.VirtualAddress.wrapping_add(s.VirtualSize)))
                .collect();

            // Only collect reloc RVAs if we'll actually rebase, and only for
            // executable sections — those are the only bytes we ever compare,
            // and the bulk of DIR64 relocs target `.rdata`/`.data`.
            let mut dir64_rvas = Vec::new();
            if base != preferred {
                if let Ok(relocs) = pe.base_relocs() {
                    relocs.for_each(|rva, ty| {
                        if ty == IMAGE_REL_BASED_DIR64
                            && code_ranges.iter().any(|&(s, e)| rva >= s && rva < e)
                        {
                            dir64_rvas.push(rva);
                        }
                    });
                }
            }

            Parsed { image_size, preferred, sections, code_ranges, dir64_rvas }
        };

        // Apply DIR64 relocations into the file-byte buffer at each site's file
        // offset. Skip any site with no backing file bytes (uninitialized tail).
        let delta = base.wrapping_sub(parsed.preferred);
        if delta != 0 {
            for rva in &parsed.dir64_rvas {
                if let Some(off) = rva_to_offset(&parsed.sections, *rva, 8) {
                    let cur = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
                    bytes[off..off + 8].copy_from_slice(&cur.wrapping_add(delta).to_le_bytes());
                }
            }
        }

        debug!(
            "pe_image: built image for '{}' base=0x{:X} size=0x{:X} code_ranges={} relocs={} delta=0x{:X}",
            path, base, parsed.image_size, parsed.code_ranges.len(), parsed.dir64_rvas.len(), delta
        );

        Self {
            base,
            image_size: parsed.image_size,
            bytes,
            sections: parsed.sections,
            code_ranges: parsed.code_ranges,
            unavailable: false,
        }
    }

    pub fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.base + self.image_size
    }

    /// True when `va` sits in an executable section (including RWX).
    pub fn is_code(&self, va: u64) -> bool {
        let Some(rva) = va.checked_sub(self.base) else { return false };
        let rva = rva as u32;
        self.code_ranges.iter().any(|(s, e)| rva >= *s && rva < *e)
    }

    /// Original file bytes for `[va, va+len)`, or `None` when the range isn't
    /// backed by initialized on-disk data in a single section.
    pub fn bytes_at(&self, va: u64, len: usize) -> Option<&[u8]> {
        let rva = va.checked_sub(self.base)? as u32;
        let off = rva_to_offset(&self.sections, rva, len)?;
        self.bytes.get(off..off + len)
    }
}
