//! Offline PE analysis: a PE file opened from disk, with no process behind it.
//!
//! [`PeImage`] owns the raw file bytes and everything derived from them —
//! parsed headers, section map, optional PDB symbols, the loader-style
//! [`MappedImage`], the [`XrefIndex`], the recovered function list — and
//! offers disassembly, string and byte-pattern search, cross-references,
//! function recovery and process-less emulation on top. Both the Lua `pe`
//! global and the UI's PE viewer sit on it.

use std::path::Path;
use std::sync::OnceLock;

use crate::interfaces::{
    align_backward_instructions, backward_resync_window, function_decode_window, Architecture, DisassemblerError,
    DisassemblerProvider, Instruction, ModuleSymbol, SymbolConfig, SymbolInfo, SymbolProvider,
};
use crate::pe_image::{rva_to_offset_loose, SectionMap};
use crate::pe_types::{split_import_spec, ImportItem, ImportKind, ModuleExtraInfo};
use crate::protocol::{StringEncodingFilter, StringHit};
use crate::windows_platform::disassembler::CapstoneDisassembler;
use crate::windows_platform::{
    decode_wide_until_nul, matches_tokens, parse_module_extra_info_from_bytes, parse_pdb_matching_pe, query_tokens,
    WindowsSymbolProvider,
};

pub mod emu_target;
pub mod mapped;
pub mod pattern;
pub mod xrefs;

pub use emu_target::{emulate, emu_layout, EmuLayout, EmulateSpec, StaticTarget, DEFAULT_MAX_INSTRUCTIONS, DEFAULT_STACK_SIZE};
pub use mapped::{MappedImage, MappedRegion};
pub use pattern::BytePattern;
pub use xrefs::{collect_functions, FunctionEntry, Xref, XrefIndex, XrefKind};

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

/// Result of a symbol-load attempt.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PeSymbolLoad {
    pub loaded: bool,
    pub count: usize,
    pub error: Option<String>,
}

/// One import, flattened out of the descriptor tree.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportRef {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    /// Address of the IAT slot the loader fills in.
    pub iat_va: u64,
}

impl ImportRef {
    /// `kernel32!WriteFile`, or `kernel32!#12` for an ordinal import.
    pub fn qualified_name(&self) -> String {
        let dll = crate::formatting::dll_stem(&self.dll);
        match (&self.name, self.ordinal) {
            (Some(name), _) => format!("{}!{}", dll, name),
            (None, Some(ord)) => format!("{}!#{}", dll, ord),
            (None, None) => dll.to_string(),
        }
    }
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
pub struct PeImage {
    path: String,
    /// File stem, the way symbols are qualified (`kernel32!CreateFileW`).
    module_name: String,
    bytes: Vec<u8>,
    info: ModuleExtraInfo,
    base: u64,
    arch: Architecture,
    sections: Vec<SectionMap>,
    /// Symbols sorted ascending by RVA, once a PDB is loaded.
    symbols: Option<Vec<ModuleSymbol>>,
    symbol_load: PeSymbolLoad,
    mapped: OnceLock<MappedImage>,
    xrefs: OnceLock<XrefIndex>,
    functions: OnceLock<Vec<FunctionEntry>>,
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
        let sections = info.sections.iter().map(SectionMap::from).collect();
        Ok(PeImage {
            path: path.to_string(),
            module_name: crate::formatting::module_stem(path),
            bytes,
            info,
            base,
            arch,
            sections,
            symbols: None,
            symbol_load: PeSymbolLoad::default(),
            mapped: OnceLock::new(),
            xrefs: OnceLock::new(),
            functions: OnceLock::new(),
        })
    }

    // ---- Identity ----

    pub fn path(&self) -> &str { &self.path }
    pub fn info(&self) -> &ModuleExtraInfo { &self.info }
    pub fn base(&self) -> u64 { self.base }
    pub fn arch(&self) -> Architecture { self.arch }
    pub fn image_size(&self) -> u64 { self.info.nt_headers.OptionalHeader.SizeOfImage as u64 }
    pub fn file_size(&self) -> usize { self.bytes.len() }
    pub fn module_name(&self) -> &str { &self.module_name }

    /// Entry point VA (0 when the image has none).
    pub fn entry_point(&self) -> u64 {
        match self.info.nt_headers.OptionalHeader.AddressOfEntryPoint {
            0 => 0,
            rva => self.base + rva as u64,
        }
    }

    // ---- Raw file bytes ----

    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Splice `data` into the raw file at `offset` (the hex editor's write
    /// path). The mapped image is patched in place when it is built; the
    /// derived code views (xrefs, functions) are rebuilt lazily only when the
    /// write lands in an executable region, so data and header edits cost
    /// nothing. Headers are parsed once at open and are not re-read.
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) -> Result<(), String> {
        let end = offset.checked_add(data.len()).filter(|&e| e <= self.bytes.len()).ok_or_else(|| {
            format!("Write out of range: offset {} + {} bytes exceeds file size {}", offset, data.len(), self.bytes.len())
        })?;
        self.bytes[offset..end].copy_from_slice(data);

        if self.mapped.get().is_none() {
            return Ok(());
        }
        // Mirror into the mapped image when the whole write sits in one
        // section's raw data (or the headers); otherwise rebuild it.
        let contiguous = self.sections.iter().any(|s| {
            let raw_end = s.raw_ptr as usize + s.raw_size as usize;
            offset >= s.raw_ptr as usize && end <= raw_end
        }) || end <= self.info.nt_headers.OptionalHeader.SizeOfHeaders as usize;
        let va = if contiguous { self.offset_to_va(offset) } else { None };
        let mapped = self.mapped.get_mut().unwrap();
        let rva = va.and_then(|va| mapped.rva_of(va)).map(|rva| rva as usize).filter(|rva| rva + data.len() <= mapped.bytes.len());
        let executable = va.and_then(|va| mapped.region_at(va)).is_some_and(|r| r.executable);
        match rva {
            Some(rva) => {
                mapped.bytes[rva..rva + data.len()].copy_from_slice(data);
                if executable {
                    self.xrefs.take();
                    self.functions.take();
                }
            }
            None => {
                self.mapped.take();
                self.xrefs.take();
                self.functions.take();
            }
        }
        Ok(())
    }

    /// Translate a VA to a file offset via the section table. RVAs outside any
    /// section (the PE headers) map to themselves.
    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.base)? as u32;
        Some(rva_to_offset_loose(&self.sections, rva))
    }

    /// Translate a file offset to a VA. Offsets inside the headers map to
    /// `base + offset`; offsets in section raw data to that section's VA.
    pub fn offset_to_va(&self, offset: usize) -> Option<u64> {
        let off = offset as u64;
        if let Some(s) = self.sections.iter().find(|s| off >= s.raw_ptr as u64 && off < s.raw_ptr as u64 + s.raw_size as u64) {
            return Some(self.base + s.virt_addr as u64 + (off - s.raw_ptr as u64));
        }
        (off < self.info.nt_headers.OptionalHeader.SizeOfHeaders as u64).then(|| self.base + off)
    }

    // ---- Mapped image ----

    /// The image as the loader would map it at `base` (built once).
    pub fn mapped(&self) -> &MappedImage {
        self.mapped.get_or_init(|| MappedImage::build(&self.info, &self.bytes, self.base))
    }

    /// `len` mapped bytes at `va`, or `None` when the range leaves the image.
    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        self.mapped().slice(va, len)
    }

    /// Little-endian unsigned integer of `size` (1/2/4/8) bytes at `va`.
    pub fn read_uint(&self, va: u64, size: usize) -> Option<u64> {
        let bytes = self.read(va, size)?;
        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(bytes);
        Some(u64::from_le_bytes(buf))
    }

    /// NUL-terminated string at `va`: UTF-16 when `wide`, else ASCII/Latin-1.
    /// Reads up to `max_chars` characters (the terminator is not counted).
    pub fn read_string(&self, va: u64, wide: bool, max_chars: usize) -> Option<String> {
        let unit = if wide { 2 } else { 1 };
        let avail = self.mapped().slice_from(va, max_chars * unit)?;
        if wide {
            Some(decode_wide_until_nul(avail))
        } else {
            let end = avail.iter().position(|&b| b == 0).unwrap_or(avail.len());
            Some(avail[..end].iter().map(|&b| b as char).collect())
        }
    }

    // ---- Symbols ----

    /// Load symbols from an explicit PDB (GUID/age validated) or by discovery
    /// (next to the file, local cache, and — unless `offline` — the symbol
    /// server). Replaces any previously loaded set on success.
    pub fn load_symbols(&mut self, pdb_path: Option<&Path>, offline: bool) -> PeSymbolLoad {
        let parsed = discover_symbols(&self.path, self.base, self.bytes.len(), pdb_path, offline);
        self.set_symbols(parsed)
    }

    /// Install a symbol set parsed by [`discover_symbols`] (which a caller may
    /// run without holding a lock on the image — a server download can take a
    /// while). Returns the load status now recorded on the image.
    pub fn set_symbols(&mut self, parsed: Result<Vec<ModuleSymbol>, String>) -> PeSymbolLoad {
        let status = match parsed {
            Ok(mut syms) => {
                syms.sort_by_key(|s| s.rva);
                let status = PeSymbolLoad { loaded: true, count: syms.len(), error: None };
                self.symbols = Some(syms);
                // Symbol functions and names feed the recovered function list.
                self.functions.take();
                status
            }
            Err(e) => PeSymbolLoad { loaded: false, count: 0, error: Some(e) },
        };
        self.symbol_load = status.clone();
        status
    }

    pub fn symbol_load(&self) -> &PeSymbolLoad { &self.symbol_load }
    pub fn has_symbols(&self) -> bool { self.symbols.is_some() }

    /// Nearest symbol at-or-below `rva`, bounded to within the image.
    pub fn resolve_rva(&self, rva: u32) -> Option<&ModuleSymbol> {
        if rva as u64 >= self.image_size() {
            return None;
        }
        let syms = self.symbols.as_ref()?;
        let idx = syms.partition_point(|s| s.rva <= rva);
        if idx == 0 { None } else { Some(&syms[idx - 1]) }
    }

    /// `module!symbol+offset` for `va`.
    pub fn resolve_va(&self, va: u64) -> Option<SymbolInfo> {
        let rva = va.checked_sub(self.base)? as u32;
        let sym = self.resolve_rva(rva)?;
        Some(SymbolInfo {
            module_name: self.module_name.clone(),
            symbol_name: sym.name.clone(),
            offset: (rva - sym.rva) as u64,
        })
    }

    /// Symbols whose module or name contains every token of `pattern`.
    pub fn find_symbols(&self, pattern: &str, limit: usize) -> Vec<&ModuleSymbol> {
        let Some(syms) = self.symbols.as_ref() else { return Vec::new() };
        let tokens = query_tokens(pattern);
        syms.iter()
            .filter(|s| matches_tokens(&tokens, &self.module_name, &s.name))
            .take(limit.max(1))
            .collect()
    }

    /// The symbol named exactly `name` (case-insensitive, `module!` prefix ignored).
    pub fn find_symbol_exact(&self, name: &str) -> Option<&ModuleSymbol> {
        let bare = name.rsplit_once('!').map(|(_, n)| n).unwrap_or(name);
        self.symbols.as_ref()?.iter().find(|s| s.name.eq_ignore_ascii_case(bare))
    }

    // ---- Disassembly ----

    fn decode(&self, data: &[u8], va: u64, count: usize) -> Result<Vec<Instruction>, DisassemblerError> {
        let disasm = CapstoneDisassembler::new()?;
        if self.symbols.is_some() {
            disasm.disassemble_with_symbols(self.arch, data, va, count, |addr| self.resolve_va(addr))
        } else {
            disasm.disassemble(self.arch, data, va, count)
        }
    }

    /// `count` instructions from `va`, symbolised when a PDB is loaded.
    pub fn disassemble(&self, va: u64, count: usize) -> Result<Vec<Instruction>, DisassemblerError> {
        let window = count.saturating_mul(self.arch.max_instruction_len()).saturating_add(self.arch.max_instruction_len());
        let Some(data) = self.mapped().slice_from(va, window) else { return Ok(Vec::new()) };
        self.decode(data, va, count)
    }

    /// Up to `count` instructions ending immediately before `target`
    /// (x64dbg-style self-resynchronising decode, clamped to the region).
    pub fn disassemble_backward(&self, target: u64, count: usize) -> Result<Vec<Instruction>, DisassemblerError> {
        if count == 0 || target == 0 {
            return Ok(Vec::new());
        }
        let mapped = self.mapped();
        let mut start = target.saturating_sub(backward_resync_window(self.arch, count));
        if let Some(region) = mapped.region_at(target - 1) {
            let region_start = mapped.base + region.rva as u64;
            if region_start > start && region_start <= target {
                start = region_start;
            }
        }
        if start >= target {
            return Ok(Vec::new());
        }
        let Some(data) = mapped.slice(start, (target - start) as usize) else { return Ok(Vec::new()) };
        let instructions = self.decode(data, start, usize::MAX)?;
        Ok(align_backward_instructions(instructions, target, count))
    }

    /// `(instructions, start, end, name)` of the function containing `va`:
    /// bounds from `.pdata` when present, else from the recovered function
    /// list; without either, a window of `max_instructions` from `va`.
    pub fn disassemble_function(&self, va: u64, max_instructions: usize)
        -> Result<(Vec<Instruction>, Option<u64>, Option<u64>, Option<String>), DisassemblerError>
    {
        let rva = va.checked_sub(self.base).map(|r| r as u32);
        let mut bounds = rva.and_then(|rva| self.info.runtime_function_bounds(rva))
            .map(|(b, e)| (self.base + b as u64, self.base + e as u64));
        if bounds.is_none() {
            let funcs = self.functions();
            let idx = funcs.partition_point(|f| f.start <= va);
            if let Some(f) = idx.checked_sub(1).map(|i| &funcs[i]) {
                if let Some(end) = f.end.filter(|&e| va < e) {
                    bounds = Some((f.start, end));
                }
            }
        }
        let name = bounds.and_then(|(s, _)| self.resolve_va(s)).filter(|s| s.offset == 0).map(|s| s.format_symbol());
        let (start, count, trim) = function_decode_window(bounds, va, max_instructions);
        let mut instrs = self.disassemble(start, count)?;
        if let Some((s, e)) = trim {
            instrs.retain(|i| i.address >= s && i.address < e);
        }
        let (fs, fe) = bounds.map(|(s, e)| (Some(s), Some(e))).unwrap_or((None, None));
        Ok((instrs, fs, fe, name))
    }

    // ---- Data ----

    /// ASCII/UTF-16 strings in the mapped image; each hit's address is a VA.
    pub fn strings(&self, min_len: usize, encodings: StringEncodingFilter, contains: &str) -> Vec<StringHit> {
        let mapped = self.mapped();
        crate::string_scanner::scan_bytes(&mapped.bytes, mapped.base, min_len.max(1), encodings, contains)
    }

    /// Strings in the raw file; each hit's address is a file offset.
    pub fn strings_in_file(&self, min_len: usize, encodings: StringEncodingFilter, contains: &str) -> Vec<StringHit> {
        crate::string_scanner::scan_bytes(&self.bytes, 0, min_len.max(1), encodings, contains)
    }

    /// VAs where `pattern` (`"ff 15 ?? ?? 69 00"`) matches in the mapped image.
    pub fn find_bytes(&self, pattern: &str, max: usize) -> Result<Vec<u64>, String> {
        let pat = BytePattern::parse(pattern)?;
        let mapped = self.mapped();
        Ok(pat.find_all(&mapped.bytes, max).into_iter().map(|off| mapped.base + off as u64).collect())
    }

    /// The import table, flattened.
    pub fn imports(&self) -> Vec<ImportRef> {
        let mut out = Vec::new();
        for desc in &self.info.imports {
            for entry in &desc.entries {
                let (name, ordinal) = match &entry.kind {
                    ImportKind::Item(ImportItem::ByName { name, .. }) => (Some(name.clone()), None),
                    ImportKind::Item(ImportItem::ByOrdinal { ordinal }) => (None, Some(*ordinal)),
                    ImportKind::Error(_) => continue,
                };
                out.push(ImportRef { dll: desc.dll_name.clone(), name, ordinal, iat_va: self.base + entry.iat_rva as u64 });
            }
        }
        out
    }

    /// VA of the IAT slot for `"kernel32!WriteFile"` / `"WriteFile"` / `"#12"`.
    pub fn import_slot(&self, spec: &str) -> Option<u64> {
        let (dll, func) = split_import_spec(spec);
        self.info.find_import_slot(dll, func).map(|rva| self.base + rva as u64)
    }

    /// Leaves of the resource tree (type / name / language).
    pub fn resources(&self) -> Vec<ResourceEntry> {
        use pelite::resources::{Entry, Name};
        use pelite::PeFile;
        let mut out = Vec::new();
        let Ok(pe) = PeFile::from_bytes(&self.bytes) else { return out };
        let Ok(res) = pe.resources() else { return out };
        let Ok(root) = res.root() else { return out };
        let name_str = |n: Result<Name<'_>, pelite::Error>| n.map(|n| n.to_string()).unwrap_or_else(|_| "<invalid>".into());
        let mut push = |type_name: &str, name: &str, lang: String, data: pelite::resources::DataEntry<'_>| {
            let d = data.image();
            out.push(ResourceEntry {
                type_name: type_name.to_string(), name: name.to_string(), lang,
                rva: d.OffsetToData, va: self.base + d.OffsetToData as u64,
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

    // ---- Cross-references ----

    /// The reference index (built once from a sweep of the code sections).
    pub fn xrefs(&self) -> &XrefIndex {
        self.xrefs.get_or_init(|| XrefIndex::build(self.mapped(), self.arch))
    }

    pub fn xrefs_to(&self, va: u64) -> Vec<Xref> { self.xrefs().xrefs_to(va) }
    pub fn xrefs_from(&self, va: u64) -> Vec<Xref> { self.xrefs().xrefs_from(va) }

    /// References to an import's IAT slot: every `call/jmp [slot]` and every
    /// load of the slot.
    pub fn xrefs_to_import(&self, spec: &str) -> Option<Vec<Xref>> {
        self.import_slot(spec).map(|slot| self.xrefs_to(slot))
    }

    /// Recovered function starts, sorted by address (built once; rebuilt
    /// after a code edit or a symbol load).
    pub fn functions(&self) -> &[FunctionEntry] {
        self.functions.get_or_init(|| {
            collect_functions(self.mapped(), &self.info, self.symbols.as_deref(), self.xrefs(), self.arch)
        })
    }

    // ---- Emulation ----

    /// Emulate code from this file with no process behind it.
    pub fn emulate(&self, spec: &EmulateSpec) -> Result<crate::emulator::EmulationResult, crate::emulator::EmulatorError> {
        emu_target::emulate(self, spec)
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
