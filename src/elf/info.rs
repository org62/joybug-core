//! `ModuleExtraInfo` for an ELF module: what the Module Info view, the
//! memory-region section badges and the module-entry breakpoints read.
//!
//! The type is PE-shaped (the UI and the Windows side own it), so the ELF
//! facts are placed where their PE counterparts live: section headers become
//! `IMAGE_SECTION_HEADER`s with the executable/readable/writable flags, the
//! dynamic symbol table's definitions are the export directory, the GOT/PLT
//! relocations the import directory (attributed to the `DT_NEEDED` set as a
//! whole — a dynamic symbol names no library), `e_entry` the entry point and
//! `.eh_frame` the exception directory. Header fields with no ELF meaning are
//! zero; `Signature` carries the ELF magic so a reader can tell.

use std::collections::BTreeMap;
use std::path::Path;

use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationTarget, SectionFlags, SectionKind};

use crate::interfaces::PlatformError;
use crate::pe_types::{
    DosHeader, ElfDynamicEntry, ElfHeader, ElfInfo, ElfProgramHeader, ElfSectionHeader, ExportEntry, ExportInfo,
    ExportKind, ImageDataDirectory, ImageFileHeader, ImageOptionalHeader, ImageSectionHeader, ImportDescriptorInfo,
    ImportEntry, ImportItem, ImportKind, ModuleExtraInfo, NtHeaders, RuntimeFunction,
};

/// IMAGE_SCN_* bits the UI and the specs test for.
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_INIT: u64 = 12;
/// `.dynamic` tags whose value is a `.dynstr` offset.
const DT_STRING_TAGS: [u64; 5] = [DT_NEEDED, 14 /* SONAME */, 15 /* RPATH */, 29 /* RUNPATH */, 0x6fff_fffe /* VERNEED */];
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

pub fn module_extra_info(path: &Path) -> Result<ModuleExtraInfo, PlatformError> {
    let data = std::fs::read(path).map_err(|e| PlatformError::OsError(format!("{}: {e}", path.display())))?;
    module_extra_info_from_bytes(&data, path)
}

/// [`module_extra_info`] over bytes already in memory; `path` only labels
/// errors and names the export directory.
pub fn module_extra_info_from_bytes(data: &[u8], path: &Path) -> Result<ModuleExtraInfo, PlatformError> {
    let layout = super::layout::layout_from_bytes(data)?;
    let file = object::File::parse(data).map_err(|e| PlatformError::Other(format!("{}: {e}", path.display())))?;
    let min_vaddr = layout.min_vaddr;
    let rva = |va: u64| -> u32 { va.saturating_sub(min_vaddr).min(u32::MAX as u64) as u32 };

    // --- sections: the allocated ones, in file order ---------------------
    let mut sections = Vec::new();
    let (mut size_of_code, mut size_of_init, mut size_of_uninit, mut base_of_code) = (0u32, 0u32, 0u32, 0u32);
    for section in file.sections() {
        let SectionFlags::Elf { sh_flags } = section.flags() else { continue };
        if sh_flags & SHF_ALLOC == 0 || section.size() == 0 {
            continue;
        }
        let name = section.name().unwrap_or("");
        let mut characteristics = IMAGE_SCN_MEM_READ;
        if sh_flags & SHF_EXECINSTR != 0 {
            characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
        }
        if sh_flags & SHF_WRITE != 0 {
            characteristics |= IMAGE_SCN_MEM_WRITE;
        }
        let in_file = !matches!(section.kind(), SectionKind::UninitializedData | SectionKind::UninitializedTls);
        characteristics |= if in_file { IMAGE_SCN_CNT_INITIALIZED_DATA } else { IMAGE_SCN_CNT_UNINITIALIZED_DATA };
        let size = section.size().min(u32::MAX as u64) as u32;
        let (file_offset, raw_size) = match section.file_range() {
            Some((offset, len)) if in_file => (offset.min(u32::MAX as u64) as u32, len.min(u32::MAX as u64) as u32),
            _ => (0, 0),
        };
        let mut name_bytes = [0u8; 8];
        for (dst, src) in name_bytes.iter_mut().zip(name.bytes()) {
            *dst = src;
        }
        let va = rva(section.address());
        if characteristics & IMAGE_SCN_CNT_CODE != 0 {
            size_of_code = size_of_code.saturating_add(size);
            if base_of_code == 0 || va < base_of_code {
                base_of_code = va;
            }
        } else if in_file {
            size_of_init = size_of_init.saturating_add(size);
        } else {
            size_of_uninit = size_of_uninit.saturating_add(size);
        }
        sections.push(ImageSectionHeader {
            Name: name_bytes,
            VirtualSize: size,
            VirtualAddress: va,
            SizeOfRawData: raw_size,
            PointerToRawData: file_offset,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: characteristics,
        });
    }

    // --- exports: every defined dynamic symbol -----------------------------
    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut export_entries: Vec<ExportEntry> = Vec::new();
    let mut seen = BTreeMap::new();
    for symbol in file.dynamic_symbols() {
        if !symbol.is_definition() || symbol.address() == 0 {
            continue;
        }
        let Ok(name) = symbol.name() else { continue };
        if seen.insert((name.to_string(), symbol.address()), ()).is_some() {
            continue;
        }
        export_entries.push(ExportEntry {
            ordinal: export_entries.len() as u32 + 1,
            name: Some(name.to_string()),
            kind: ExportKind::Symbol { rva: rva(symbol.address()) },
        });
    }
    let exports = (!export_entries.is_empty()).then(|| ExportInfo { dll_name: file_name.clone(), ordinal_base: 1, entries: export_entries });

    // --- imports: the DT_NEEDED set, with the GOT slots as the IAT ---------
    let needed = needed_libraries(&file);
    let mut got_entries: Vec<ImportEntry> = Vec::new();
    if let (Some(relocations), Some(table)) = (file.dynamic_relocations(), file.dynamic_symbol_table()) {
        for (offset, relocation) in relocations {
            let RelocationTarget::Symbol(index) = relocation.target() else { continue };
            let Ok(symbol) = table.symbol_by_index(index) else { continue };
            if symbol.is_definition() {
                continue; // a relative/local fixup, not an import
            }
            let Ok(name) = symbol.name() else { continue };
            if name.is_empty() {
                continue;
            }
            got_entries.push(ImportEntry {
                iat_rva: rva(offset),
                kind: ImportKind::Item(ImportItem::ByName { name: name.to_string(), hint: 0 }),
            });
        }
    }
    got_entries.sort_by_key(|e| e.iat_rva);
    let mut imports: Vec<ImportDescriptorInfo> = Vec::new();
    if !needed.is_empty() || !got_entries.is_empty() {
        // One descriptor carries the slots: ELF does not say which NEEDED
        // library satisfies a symbol, the loader's search order does.
        let label = if needed.is_empty() { "(dynamic)".to_string() } else { needed.join(", ") };
        imports.push(ImportDescriptorInfo { dll_name: label, entries: got_entries });
    }

    // --- function table ----------------------------------------------------
    let runtime_functions = super::symbols::eh_frame_function_table_from_bytes(data).map(|table| {
        table
            .entries
            .iter()
            .map(|e| RuntimeFunction { BeginAddress: e.BeginAddress, EndAddress: e.EndAddress, UnwindData: e.UnwindData })
            .collect::<Vec<_>>()
    });

    // --- headers -------------------------------------------------------------
    let is_shared = matches!(file.kind(), object::ObjectKind::Dynamic);
    // A shared object's e_entry is meaningless; its first initializer is what
    // "break on module entry" means there — the DllMain analog: `DT_INIT` when
    // it has one, else the first `.init_array` entry (glibc's own libraries
    // have only the array). ld.so runs it before the program continues. A
    // library with neither reports none, as a DLL without an entry point would.
    let entry = if is_shared {
        dynamic_tag(&file, DT_INIT)
            .filter(|&v| v != 0)
            .or_else(|| first_init_array_entry(&file))
            .map(rva)
            .unwrap_or(0)
    } else if layout.entry == 0 {
        0
    } else {
        rva(layout.entry)
    };
    let magic = u32::from_le_bytes([0x7F, b'E', b'L', b'F']);
    let dos_header = DosHeader {
        e_magic: 0x457F,
        e_cblp: 0, e_cp: 0, e_crlc: 0, e_cparhdr: 0, e_minalloc: 0, e_maxalloc: 0, e_ss: 0, e_sp: 0, e_csum: 0,
        e_ip: 0, e_cs: 0, e_lfarlc: 0, e_ovno: 0, e_res: [0; 4], e_oemid: 0, e_oeminfo: 0, e_res2: [0; 10], e_lfanew: 0,
    };
    let nt_headers = NtHeaders {
        Signature: magic,
        FileHeader: ImageFileHeader {
            Machine: IMAGE_FILE_MACHINE_AMD64,
            NumberOfSections: sections.len().min(u16::MAX as usize) as u16,
            TimeDateStamp: 0,
            PointerToSymbolTable: 0,
            NumberOfSymbols: file.symbols().count().min(u32::MAX as usize) as u32,
            SizeOfOptionalHeader: 0xF0,
            Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | if is_shared { IMAGE_FILE_DLL } else { 0 },
        },
        OptionalHeader: ImageOptionalHeader {
            Magic: crate::pe_types::IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            MajorLinkerVersion: 0,
            MinorLinkerVersion: 0,
            SizeOfCode: size_of_code,
            SizeOfInitializedData: size_of_init,
            SizeOfUninitializedData: size_of_uninit,
            AddressOfEntryPoint: entry,
            BaseOfCode: base_of_code,
            BaseOfData: None,
            ImageBase: min_vaddr,
            SectionAlignment: 0x1000,
            FileAlignment: 0x1000,
            MajorOperatingSystemVersion: 0,
            MinorOperatingSystemVersion: 0,
            MajorImageVersion: 0,
            MinorImageVersion: 0,
            MajorSubsystemVersion: 0,
            MinorSubsystemVersion: 0,
            Win32VersionValue: 0,
            SizeOfImage: layout.size.min(u32::MAX as u64) as u32,
            SizeOfHeaders: 0,
            CheckSum: 0,
            Subsystem: 0,
            DllCharacteristics: 0,
            SizeOfStackReserve: 0,
            SizeOfStackCommit: 0,
            SizeOfHeapReserve: 0,
            SizeOfHeapCommit: 0,
            LoaderFlags: 0,
            NumberOfRvaAndSizes: 16,
            DataDirectory: [ImageDataDirectory { VirtualAddress: 0, Size: 0 }; 16],
        },
    };

    let elf = Some(native_info(data, &file, min_vaddr));
    Ok(ModuleExtraInfo { dos_header, nt_headers, sections, imports, exports, runtime_functions, tls_callbacks: Vec::new(), elf })
}

/// The headers as they are in the file, for the viewer.
fn native_info(data: &[u8], file: &object::File<'_>, min_vaddr: u64) -> ElfInfo {
    use object::read::elf::{FileHeader as _, ProgramHeader as _, SectionHeader as _};
    use object::Endianness;

    let dynstr = file.section_by_name(".dynstr").and_then(|s| s.data().ok()).unwrap_or(&[]);
    let dynamic: Vec<ElfDynamicEntry> = dynamic_entries(file)
        .map(|(tag, value)| ElfDynamicEntry {
            tag,
            value,
            string: DT_STRING_TAGS.contains(&tag).then(|| dynstr_at(dynstr, value)).flatten(),
        })
        .collect();
    let dyn_string = |tag: u64| dynamic.iter().find(|e| e.tag == tag).and_then(|e| e.string.clone());
    let interp = file
        .section_by_name(".interp")
        .and_then(|s| s.data().ok())
        .and_then(|d| std::str::from_utf8(d.split(|&b| b == 0).next()?).ok().map(str::to_string));

    // Only x86-64 (64-bit) targets are debugged, which `layout_from_bytes`
    // already enforced; a parse failure here leaves the raw tables empty.
    let (header, program_headers, sections) = match object::read::elf::ElfFile64::<Endianness>::parse(data) {
        Ok(elf) => {
            let endian = elf.endian();
            let h = elf.elf_header();
            let ident = h.e_ident();
            let header = ElfHeader {
                class: ident.class,
                data: ident.data,
                os_abi: ident.os_abi,
                abi_version: ident.abi_version,
                e_type: h.e_type(endian),
                e_machine: h.e_machine(endian),
                e_version: h.e_version(endian),
                e_entry: h.e_entry(endian),
                e_phoff: h.e_phoff(endian),
                e_shoff: h.e_shoff(endian),
                e_flags: h.e_flags(endian),
                e_ehsize: h.e_ehsize(endian),
                e_phentsize: h.e_phentsize(endian),
                e_phnum: h.e_phnum(endian),
                e_shentsize: h.e_shentsize(endian),
                e_shnum: h.e_shnum(endian),
                e_shstrndx: h.e_shstrndx(endian),
            };
            let program_headers = elf
                .elf_program_headers()
                .iter()
                .map(|p| ElfProgramHeader {
                    p_type: p.p_type(endian),
                    p_flags: p.p_flags(endian),
                    p_offset: p.p_offset(endian),
                    p_vaddr: p.p_vaddr(endian),
                    p_paddr: p.p_paddr(endian),
                    p_filesz: p.p_filesz(endian),
                    p_memsz: p.p_memsz(endian),
                    p_align: p.p_align(endian),
                })
                .collect();
            let table = elf.elf_section_table();
            let sections = table
                .iter()
                .map(|sh| ElfSectionHeader {
                    name: table.section_name(endian, sh).ok().map(|n| String::from_utf8_lossy(n).into_owned()).unwrap_or_default(),
                    sh_type: sh.sh_type(endian),
                    sh_flags: sh.sh_flags(endian),
                    sh_addr: sh.sh_addr(endian),
                    sh_offset: sh.sh_offset(endian),
                    sh_size: sh.sh_size(endian),
                    sh_link: sh.sh_link(endian),
                    sh_info: sh.sh_info(endian),
                    sh_addralign: sh.sh_addralign(endian),
                    sh_entsize: sh.sh_entsize(endian),
                })
                .collect();
            (header, program_headers, sections)
        }
        Err(_) => (
            ElfHeader {
                class: 0, data: 0, os_abi: 0, abi_version: 0, e_type: 0, e_machine: 0, e_version: 0, e_entry: 0, e_phoff: 0,
                e_shoff: 0, e_flags: 0, e_ehsize: 0, e_phentsize: 0, e_phnum: 0, e_shentsize: 0, e_shnum: 0, e_shstrndx: 0,
            },
            Vec::new(),
            Vec::new(),
        ),
    };
    ElfInfo {
        header,
        program_headers,
        sections,
        needed: dynamic.iter().filter(|e| e.tag == DT_NEEDED).filter_map(|e| e.string.clone()).collect(),
        soname: dyn_string(DT_SONAME),
        rpath: dyn_string(DT_RPATH),
        runpath: dyn_string(DT_RUNPATH),
        dynamic,
        interp,
        build_id: super::debug_file::build_id(file).map(|id| id.iter().map(|b| format!("{b:02x}")).collect()),
        debuglink: super::debug_file::debuglink(file).map(|l| l.name),
        min_vaddr,
    }
}

/// The NUL-terminated string at `offset` in `.dynstr`.
fn dynstr_at(dynstr: &[u8], offset: u64) -> Option<String> {
    let start = usize::try_from(offset).ok().filter(|&s| s < dynstr.len())?;
    let end = dynstr[start..].iter().position(|&b| b == 0).map(|p| start + p).unwrap_or(dynstr.len());
    Some(String::from_utf8_lossy(&dynstr[start..end]).into_owned())
}

/// The `(tag, value)` entries of `.dynamic`, up to `DT_NULL`.
fn dynamic_entries<'a>(file: &object::File<'a>) -> impl Iterator<Item = (u64, u64)> + 'a {
    let data = file.section_by_name(".dynamic").and_then(|s| s.data().ok()).unwrap_or(&[]);
    data.chunks_exact(16)
        .map(|e| (u64::from_le_bytes(e[..8].try_into().unwrap()), u64::from_le_bytes(e[8..].try_into().unwrap())))
        .take_while(|&(tag, _)| tag != DT_NULL)
}

/// The value of the first `.dynamic` entry with `tag`.
fn dynamic_tag(file: &object::File<'_>, tag: u64) -> Option<u64> {
    dynamic_entries(file).find(|&(t, _)| t == tag).map(|(_, v)| v)
}

/// The first non-zero `.init_array` entry (a link-time address; the loader's
/// RELATIVE fixup adds the load bias at runtime, which the caller's RVA math
/// accounts for).
fn first_init_array_entry(file: &object::File<'_>) -> Option<u64> {
    let section = file.section_by_name(".init_array")?;
    let data = section.data().ok()?;
    data.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).find(|&v| v != 0)
}

/// `DT_NEEDED` names from `.dynamic`, in table order.
fn needed_libraries(file: &object::File<'_>) -> Vec<String> {
    let Some(Ok(dynstr)) = file.section_by_name(".dynstr").map(|s| s.data()) else { return Vec::new() };
    dynamic_entries(file).filter(|&(tag, _)| tag == DT_NEEDED).filter_map(|(_, val)| dynstr_at(dynstr, val)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libc_has_sections_exports_and_a_got() {
        let Some(libc) = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]
            .iter()
            .find(|p| Path::new(p).exists())
        else {
            return;
        };
        let info = module_extra_info(Path::new(libc)).expect("libc parses");
        let text = info.sections.iter().find(|s| s.name_string() == ".text").expect(".text");
        assert!(text.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0);
        assert!(info.exports.as_ref().map(|e| e.entries.len()).unwrap_or(0) > 1000);
        assert_ne!(info.nt_headers.OptionalHeader.AddressOfEntryPoint, 0, "libc's DT_INIT is its module entry");
        assert!(info.runtime_functions.as_ref().map(|r| r.len()).unwrap_or(0) > 1000);
        assert!(!info.imports.is_empty());
    }
}
