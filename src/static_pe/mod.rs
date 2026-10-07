//! A PE file opened from disk: the format-specific half of
//! [`crate::static_image::StaticImage`] — PE header parsing, PDB discovery
//! and loading, and the resource tree. Everything else (hex, disassembly,
//! symbols, strings, byte search, xrefs, functions, emulation) is the shared
//! image, reached through `Deref`.

use std::path::Path;

use crate::interfaces::{Architecture, ModuleSymbol, SymbolConfig, SymbolProvider};
use crate::windows_platform::{parse_module_extra_info_from_bytes, parse_pdb_matching_pe, WindowsSymbolProvider};

pub use crate::static_image::{
    collect_functions, emu_layout, emulate, BytePattern, EmuLayout, EmulateSpec, FunctionEntry, ImportRef, MappedImage,
    MappedRegion, StaticFile, StaticImage, StaticTarget, SymbolLoad, Xref, XrefIndex, XrefKind, DEFAULT_MAX_INSTRUCTIONS,
    DEFAULT_STACK_SIZE,
};

/// The name this type had when only PE files could be opened.
pub type PeSymbolLoad = SymbolLoad;

/// Offset of the NT headers (the "PE\0\0" signature) via the DOS header, with
/// both magics validated.
pub fn nt_headers_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 0x40 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    if bytes.len() < e_lfanew + 6 || &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    Some(e_lfanew)
}

/// One leaf of the resource tree.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResourceEntry {
    /// Type name (`RT_ICON`, `#24`, or a string name).
    pub type_name: String,
    pub name: String,
    pub lang: String,
    pub rva: u32,
    pub va: u64,
    pub size: u32,
    pub code_page: u32,
}

/// A PE file opened from disk.
pub struct PeImage(StaticImage);

impl std::ops::Deref for PeImage {
    type Target = StaticImage;
    fn deref(&self) -> &StaticImage { &self.0 }
}

impl std::ops::DerefMut for PeImage {
    fn deref_mut(&mut self) -> &mut StaticImage { &mut self.0 }
}

/// Find and parse the symbols for the PE at `path` (loaded at `base`, `size`
/// bytes on disk): an explicit PDB (GUID/age validated), else discovery next
/// to the file, in the local cache and — unless `offline` — on the symbol
/// server. Unsorted; `PeImage::set_symbols` sorts.
pub fn discover_symbols(path: &str, base: u64, size: usize, pdb_path: Option<&Path>, offline: bool) -> Result<Vec<ModuleSymbol>, String> {
    match pdb_path {
        Some(pdb) => parse_pdb_matching_pe(Path::new(path), pdb)
            .map_err(|e| format!("{}", e))
            .and_then(|r| {
                r.map_err(|m| {
                    format!("PDB GUID/age mismatch: PE {}:{} vs PDB {}:{}", m.pe_guid, m.pe_age, m.pdb_guid, m.pdb_age)
                })
            }),
        None => {
            let cfg = SymbolConfig { symbol_path: None, offline };
            WindowsSymbolProvider::with_config(&cfg)
                .and_then(|mut p| p.load_symbols_for_module(path, base, Some(size)).map(|_| p))
                .and_then(|p| p.list_symbols(path))
                .map_err(|e| format!("{}", e))
        }
    }
}

impl PeImage {
    /// Open `path`, parse it and — when `pdb` is given or a PDB sits next to
    /// the file / in a local symbol cache — load symbols without touching the
    /// network. `base` overrides the load base (default: the file's ImageBase).
    pub fn open(path: &str, base: Option<u64>, pdb: Option<&Path>) -> Result<PeImage, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("Failed to read '{}': {}", path, e))?;
        let mut img = Self::from_bytes(path, bytes, base)?;
        img.load_symbols(pdb, true);
        Ok(img)
    }

    /// Build from bytes already in memory. `path` labels the image (module
    /// name, PDB lookup); it need not exist on disk.
    pub fn from_bytes(path: &str, bytes: Vec<u8>, base: Option<u64>) -> Result<PeImage, String> {
        if bytes.starts_with(b"\x7FELF") {
            return Err("This is an ELF file, not a PE; open it with the ELF image (elf.open / the viewer handles both).".to_string());
        }
        nt_headers_offset(&bytes).ok_or_else(|| "Not a valid PE file (missing MZ/PE headers).".to_string())?;
        let info = parse_module_extra_info_from_bytes(&bytes).map_err(|e| format!("Failed to parse PE: {:?}", e))?;
        let machine = info.nt_headers.FileHeader.Machine;
        let arch = Architecture::from_machine(machine).ok_or_else(|| {
            format!("Unsupported PE machine 0x{:04X}. Supported: x86, x64 and ARM64 images.", machine)
        })?;
        let base = match base {
            Some(b) => b,
            None => match info.nt_headers.OptionalHeader.ImageBase {
                // A zero ImageBase (some hand-built images) would make every VA an
                // RVA; fall back to the linker defaults for the format.
                0 if info.nt_headers.OptionalHeader.is_pe32() => 0x40_0000,
                0 => 0x1_4000_0000,
                ib => ib,
            },
        };
        Ok(PeImage(StaticImage::new(path, bytes, info, arch, base, None)))
    }

    /// Load symbols from an explicit PDB (GUID/age validated) or by discovery
    /// (next to the file, local cache, and — unless `offline` — the symbol
    /// server). Replaces any previously loaded set on success.
    pub fn load_symbols(&mut self, pdb_path: Option<&Path>, offline: bool) -> SymbolLoad {
        let parsed = discover_symbols(self.path(), self.base(), self.file_size(), pdb_path, offline);
        self.set_symbols(parsed)
    }

    /// Leaves of the resource tree (type / name / language).
    pub fn resources(&self) -> Vec<ResourceEntry> {
        use pelite::resources::{Entry, Name};
        use pelite::PeFile;
        let mut out = Vec::new();
        let Ok(pe) = PeFile::from_bytes(self.bytes()) else { return out };
        let Ok(res) = pe.resources() else { return out };
        let Ok(root) = res.root() else { return out };
        let name_str = |n: Result<Name<'_>, pelite::Error>| n.map(|n| n.to_string()).unwrap_or_else(|_| "<invalid>".into());
        let mut push = |type_name: &str, name: &str, lang: String, data: pelite::resources::DataEntry<'_>| {
            let d = data.image();
            out.push(ResourceEntry {
                type_name: type_name.to_string(), name: name.to_string(), lang,
                rva: d.OffsetToData, va: self.base() + d.OffsetToData as u64,
                size: d.Size, code_page: d.CodePage,
            });
        };
        for type_entry in root.entries() {
            let type_name = match type_entry.name() {
                Ok(Name::Id(id)) => resource_type_name(id),
                other => name_str(other),
            };
            let Ok(Entry::Directory(names)) = type_entry.entry() else { continue };
            for name_entry in names.entries() {
                let name = name_str(name_entry.name());
                match name_entry.entry() {
                    Ok(Entry::Directory(langs)) => {
                        for lang_entry in langs.entries() {
                            if let Ok(Entry::DataEntry(data)) = lang_entry.entry() {
                                push(&type_name, &name, name_str(lang_entry.name()), data);
                            }
                        }
                    }
                    Ok(Entry::DataEntry(data)) => push(&type_name, &name, String::new(), data),
                    Err(_) => {}
                }
            }
        }
        out
    }
}

/// Well-known `RT_*` resource type ids.
fn resource_type_name(id: u32) -> String {
    let name = match id {
        1 => "RT_CURSOR", 2 => "RT_BITMAP", 3 => "RT_ICON", 4 => "RT_MENU", 5 => "RT_DIALOG",
        6 => "RT_STRING", 7 => "RT_FONTDIR", 8 => "RT_FONT", 9 => "RT_ACCELERATOR", 10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE", 12 => "RT_GROUP_CURSOR", 14 => "RT_GROUP_ICON", 16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE", 19 => "RT_PLUGPLAY", 20 => "RT_VXD", 21 => "RT_ANICURSOR", 22 => "RT_ANIICON",
        23 => "RT_HTML", 24 => "RT_MANIFEST",
        _ => return format!("#{}", id),
    };
    name.to_string()
}

