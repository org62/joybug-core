//! ELF file facts the backend needs: load layout, entry, interpreter,
//! dynamic symbols. Parsed from the file on disk with `object`.

use std::fs;
use std::path::Path;

use object::elf;
use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};
use object::{Object, ObjectSymbol};

use crate::interfaces::PlatformError;

/// The link-time layout of an ELF image.
#[derive(Debug, Clone)]
pub struct ElfLayout {
    /// Lowest `PT_LOAD` vaddr, page-aligned: `module base = load bias + min_vaddr`.
    pub min_vaddr: u64,
    /// `align_up(max(p_vaddr + p_memsz)) - min_vaddr`.
    pub size: u64,
    /// `e_entry` (link-time).
    pub entry: u64,
    /// The program-header table's link-time vaddr (`PT_PHDR`, or derived), for
    /// computing the load bias from `AT_PHDR`.
    pub phdr_vaddr: Option<u64>,
    /// `PT_INTERP`, when dynamically linked.
    pub interp: Option<String>,
}

pub fn read_layout(path: &Path) -> Result<ElfLayout, PlatformError> {
    let data = fs::read(path).map_err(|e| PlatformError::OsError(format!("read {}: {e}", path.display())))?;
    layout_from_bytes(&data)
}

pub fn layout_from_bytes(data: &[u8]) -> Result<ElfLayout, PlatformError> {
    let file = ElfFile64::<object::Endianness>::parse(data)
        .map_err(|e| PlatformError::Other(format!("not a 64-bit ELF: {e}")))?;
    let endian = file.endian();
    let header = file.elf_header();
    let mut min_vaddr = u64::MAX;
    let mut max_end = 0u64;
    let mut phdr_vaddr = None;
    let mut interp = None;
    let mut first_load_off0: Option<u64> = None;
    for ph in file.elf_program_headers() {
        match ph.p_type(endian) {
            elf::PT_LOAD => {
                let start = ph.p_vaddr(endian);
                let end = start + ph.p_memsz(endian);
                min_vaddr = min_vaddr.min(start & !0xfff);
                max_end = max_end.max(end);
                if ph.p_offset(endian) == 0 && first_load_off0.is_none() {
                    first_load_off0 = Some(start);
                }
            }
            elf::PT_PHDR => phdr_vaddr = Some(ph.p_vaddr(endian)),
            elf::PT_INTERP => {
                if let Ok(bytes) = ph.data(endian, data) {
                    let s = bytes.split(|&b| b == 0).next().unwrap_or(&[]);
                    interp = Some(String::from_utf8_lossy(s).into_owned());
                }
            }
            _ => {}
        }
    }
    if min_vaddr == u64::MAX {
        return Err(PlatformError::Other("ELF has no PT_LOAD segment".into()));
    }
    // No PT_PHDR (static executables): the table lives in the first segment
    // at its file offset.
    if phdr_vaddr.is_none() {
        phdr_vaddr = first_load_off0.map(|start| start + header.e_phoff(endian));
    }
    Ok(ElfLayout {
        min_vaddr,
        size: ((max_end + 0xfff) & !0xfff) - min_vaddr,
        entry: header.e_entry(endian),
        phdr_vaddr,
        interp,
    })
}

/// The link-time value of a dynamic symbol (`.dynsym`), e.g. ld.so's
/// `_r_debug` / `_dl_debug_state`.
pub fn dynamic_symbol_value(path: &Path, name: &str) -> Result<Option<u64>, PlatformError> {
    let data = fs::read(path).map_err(|e| PlatformError::OsError(format!("read {}: {e}", path.display())))?;
    let file = object::File::parse(&*data).map_err(|e| PlatformError::Other(format!("parse {}: {e}", path.display())))?;
    Ok(file
        .dynamic_symbols()
        .chain(file.symbols())
        .find(|s| s.name() == Ok(name) && s.is_definition())
        .map(|s| s.address()))
}

/// `EI_CLASS` of the file, when it starts with the ELF magic.
fn elf_class(path: &Path) -> Option<u8> {
    let mut ident = [0u8; 5];
    std::fs::File::open(path).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut ident)).ok()?;
    (&ident[..4] == b"\x7fELF").then_some(ident[4])
}

/// Is this an ELF file at all? Five bytes, where `read_layout` reads the
/// whole file to say no.
pub fn is_elf(path: &Path) -> bool {
    elf_class(path).is_some()
}

/// Is this a 32-bit ELF (which the backend does not debug)?
pub fn is_elf32(path: &Path) -> bool {
    elf_class(path) == Some(elf::ELFCLASS32)
}
