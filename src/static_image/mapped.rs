//! A PE file laid out the way the loader would map it: sections at their
//! virtual addresses, zero-filled tails, relocations applied for the chosen
//! base. This is the address space xref scanning and process-less emulation
//! run against; the raw file bytes stay untouched in `PeImage`.

use pelite::PeFile;
use unicorn_engine::unicorn_const::Prot;

use crate::emulator::Emulator;
use crate::pe_image::{
    IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use crate::pe_types::ModuleExtraInfo;

pub const PAGE_SIZE: u64 = 0x1000;

/// One section (or the header block) of the mapped image.
#[derive(Debug, Clone)]
pub struct MappedRegion {
    /// Page-aligned start, relative to the image base.
    pub rva: u32,
    /// Page-aligned size.
    pub size: u32,
    pub prot: Prot,
    pub executable: bool,
}

impl MappedRegion {
    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.rva && (rva as u64) < self.rva as u64 + self.size as u64
    }
}

/// The image as mapped at `base`.
#[derive(Debug, Clone)]
pub struct MappedImage {
    pub base: u64,
    /// `SizeOfImage` bytes (rounded up to a page).
    pub bytes: Vec<u8>,
    pub regions: Vec<MappedRegion>,
}

fn section_prot(characteristics: u32) -> Prot {
    let mut prot = Prot::NONE;
    if characteristics & IMAGE_SCN_MEM_READ != 0 { prot |= Prot::READ; }
    if characteristics & IMAGE_SCN_MEM_WRITE != 0 { prot |= Prot::WRITE; }
    if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 { prot |= Prot::EXEC; }
    if prot == Prot::NONE { prot = Prot::READ; }
    prot
}

impl MappedImage {
    /// Lay `file` out at `base`. Relocations are applied when `base` differs
    /// from the file's preferred `ImageBase` (DIR64 for PE32+, HIGHLOW for
    /// PE32), across every section.
    pub fn build(info: &ModuleExtraInfo, file: &[u8], base: u64) -> MappedImage {
        let oh = &info.nt_headers.OptionalHeader;
        let size_of_image = Emulator::align_size(oh.SizeOfImage.max(oh.SizeOfHeaders) as u64) as usize;
        let mut bytes = vec![0u8; size_of_image];

        // Headers at RVA 0.
        let hdr_len = (oh.SizeOfHeaders as usize).min(file.len()).min(bytes.len());
        bytes[..hdr_len].copy_from_slice(&file[..hdr_len]);
        let mut regions = vec![MappedRegion {
            rva: 0,
            size: Emulator::align_size(oh.SizeOfHeaders.max(1) as u64) as u32,
            prot: Prot::READ,
            executable: false,
        }];

        for s in &info.sections {
            let va = s.VirtualAddress as usize;
            if va >= bytes.len() {
                continue;
            }
            let raw_start = s.PointerToRawData as usize;
            let raw_len = (s.SizeOfRawData as usize)
                .min(file.len().saturating_sub(raw_start))
                .min(bytes.len() - va);
            // A section's initialized data is its file bytes, clamped to its
            // virtual size when that is smaller (the loader maps VirtualSize).
            let copy_len = if s.VirtualSize != 0 { raw_len.min(Emulator::align_size(s.VirtualSize as u64) as usize) } else { raw_len };
            if copy_len > 0 && raw_start < file.len() {
                bytes[va..va + copy_len].copy_from_slice(&file[raw_start..raw_start + copy_len]);
            }
            let span = (s.VirtualSize.max(s.SizeOfRawData)).max(1) as u64;
            let rva = (s.VirtualAddress as u64 & !(PAGE_SIZE - 1)) as u32;
            let end = Emulator::align_size(s.VirtualAddress as u64 + span).min(bytes.len() as u64);
            regions.push(MappedRegion {
                rva,
                size: end.saturating_sub(rva as u64) as u32,
                prot: section_prot(s.Characteristics),
                executable: s.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            });
        }

        let preferred = oh.ImageBase;
        let delta = base.wrapping_sub(preferred);
        if delta != 0 {
            if let Ok(pe) = PeFile::from_bytes(file) {
                if let Ok(relocs) = pe.base_relocs() {
                    relocs.for_each(|rva, ty| {
                        let off = rva as usize;
                        match ty {
                            IMAGE_REL_BASED_DIR64 if off + 8 <= bytes.len() => {
                                let cur = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
                                bytes[off..off + 8].copy_from_slice(&cur.wrapping_add(delta).to_le_bytes());
                            }
                            IMAGE_REL_BASED_HIGHLOW if off + 4 <= bytes.len() => {
                                let cur = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
                                bytes[off..off + 4].copy_from_slice(&cur.wrapping_add(delta as u32).to_le_bytes());
                            }
                            _ => {}
                        }
                    });
                }
            }
        }

        MappedImage { base, bytes, regions }
    }

    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn end(&self) -> u64 {
        self.base + self.size()
    }

    pub fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.end()
    }

    pub fn rva_of(&self, va: u64) -> Option<u32> {
        self.contains(va).then(|| (va - self.base) as u32)
    }

    /// The region containing `va`.
    pub fn region_at(&self, va: u64) -> Option<&MappedRegion> {
        let rva = self.rva_of(va)?;
        // Later (section) regions win over the header block when they overlap.
        self.regions.iter().rev().find(|r| r.contains_rva(rva))
    }

    /// `[va, va+len)` of the mapped bytes, or `None` when it leaves the image.
    pub fn slice(&self, va: u64, len: usize) -> Option<&[u8]> {
        let rva = self.rva_of(va)? as usize;
        self.bytes.get(rva..rva.checked_add(len)?)
    }

    /// The mapped bytes from `va` to the end of the image, capped at `max`.
    pub fn slice_from(&self, va: u64, max: usize) -> Option<&[u8]> {
        let rva = self.rva_of(va)? as usize;
        let end = rva.saturating_add(max).min(self.bytes.len());
        self.bytes.get(rva..end)
    }

    /// Executable regions as `(va, bytes)`.
    pub fn code_regions(&self) -> impl Iterator<Item = (u64, &[u8])> + '_ {
        self.regions.iter().filter(|r| r.executable).filter_map(move |r| {
            let start = r.rva as usize;
            let end = (start + r.size as usize).min(self.bytes.len());
            (end > start).then(|| (self.base + r.rva as u64, &self.bytes[start..end]))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_platform::parse_module_extra_info_from_bytes;

    /// A minimal PE32 with one RX section (`.text` at RVA 0x1000, raw 0x200)
    /// containing `push 0x00401234`, and a HIGHLOW relocation for its imm32.
    fn tiny_pe32(with_reloc: bool) -> Vec<u8> {
        let mut f = vec![0u8; 0x600];
        f[0] = b'M'; f[1] = b'Z';
        f[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let nt = 0x80;
        f[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let fh = nt + 4;
        f[fh..fh + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
        let nsec: u16 = if with_reloc { 2 } else { 1 };
        f[fh + 2..fh + 4].copy_from_slice(&nsec.to_le_bytes());
        f[fh + 16..fh + 18].copy_from_slice(&0xE0u16.to_le_bytes()); // SizeOfOptionalHeader
        f[fh + 18..fh + 20].copy_from_slice(&0x0102u16.to_le_bytes());
        let oh = fh + 20;
        f[oh..oh + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        f[oh + 16..oh + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        f[oh + 28..oh + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
        f[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        f[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        f[oh + 56..oh + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        f[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        f[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        if with_reloc {
            // Data directory 5 (base reloc) -> RVA 0x2000, size 12.
            let dd = oh + 96 + 5 * 8;
            f[dd..dd + 4].copy_from_slice(&0x2000u32.to_le_bytes());
            f[dd + 4..dd + 8].copy_from_slice(&12u32.to_le_bytes());
        }
        let sh = oh + 0xE0;
        let mut sec = |i: usize, name: &[u8], vsize: u32, va: u32, rsize: u32, raw: u32, chars: u32| {
            let s = sh + i * 40;
            f[s..s + name.len()].copy_from_slice(name);
            f[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            f[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
            f[s + 16..s + 20].copy_from_slice(&rsize.to_le_bytes());
            f[s + 20..s + 24].copy_from_slice(&raw.to_le_bytes());
            f[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
        };
        sec(0, b".text", 0x10, 0x1000, 0x200, 0x200, 0x6000_0020);
        if with_reloc {
            sec(1, b".reloc", 12, 0x2000, 0x200, 0x400, 0x4200_0040);
        }
        // .text: push 0x00401234 ; ret
        f[0x200] = 0x68;
        f[0x201..0x205].copy_from_slice(&0x0040_1234u32.to_le_bytes());
        f[0x205] = 0xC3;
        if with_reloc {
            // Reloc block: page RVA 0x1000, size 12, one HIGHLOW entry at 0x1001, one pad.
            f[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
            f[0x404..0x408].copy_from_slice(&12u32.to_le_bytes());
            f[0x408..0x40A].copy_from_slice(&((3u16 << 12) | 0x001).to_le_bytes());
            f[0x40A..0x40C].copy_from_slice(&0u16.to_le_bytes());
        }
        f
    }

    #[test]
    fn maps_sections_at_virtual_addresses_with_zero_tail() {
        let file = tiny_pe32(false);
        let info = parse_module_extra_info_from_bytes(&file).unwrap();
        let img = MappedImage::build(&info, &file, 0x400000);
        assert_eq!(img.bytes.len(), 0x3000);
        assert_eq!(&img.bytes[..2], b"MZ");
        assert_eq!(img.bytes[0x1000], 0x68);
        assert_eq!(img.slice(0x401005, 1), Some(&[0xC3][..]));
        // Past SizeOfRawData is zero.
        assert!(img.bytes[0x1200..0x2000].iter().all(|&b| b == 0));
        let text = img.region_at(0x401000).unwrap();
        assert_eq!(text.rva, 0x1000);
        assert!(text.executable);
        assert!(img.region_at(0x400000).is_some_and(|h| !h.executable));
        assert!(img.region_at(0x403000).is_none());
        assert_eq!(img.code_regions().count(), 1);
    }

    #[test]
    fn applies_highlow_relocation_for_a_different_base() {
        let file = tiny_pe32(true);
        let info = parse_module_extra_info_from_bytes(&file).unwrap();
        let at_home = MappedImage::build(&info, &file, 0x400000);
        assert_eq!(&at_home.bytes[0x1001..0x1005], &0x0040_1234u32.to_le_bytes());
        let moved = MappedImage::build(&info, &file, 0x10_000_000);
        assert_eq!(&moved.bytes[0x1001..0x1005], &(0x0040_1234u32 + 0x0FC0_0000).to_le_bytes());
        // The raw file is untouched.
        assert_eq!(&file[0x201..0x205], &0x0040_1234u32.to_le_bytes());
    }
}
