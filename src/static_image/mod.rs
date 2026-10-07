//! A PE or ELF file laid out at its load base, with no process behind it:
//! the static half of the debugger. [`StaticImage`] holds what the two
//! formats share once their headers are parsed — the mapped image, the
//! symbol table, disassembly, strings, byte-pattern search, cross-references,
//! function recovery and process-less emulation. `static_pe::PeImage` and
//! `static_elf::ElfImage` build one from their own headers and add what only
//! their format has (PDB discovery and resources; ELF debug files).

use std::path::Path;
use std::sync::OnceLock;

use crate::interfaces::{
    align_backward_instructions, backward_resync_window, decode_function_listing, Architecture,
    DisassemblerError, DisassemblerProvider, Instruction, ModuleSymbol, SymbolInfo,
};
use crate::pe_image::{rva_to_offset_loose, SectionMap};
use crate::pe_types::{split_import_spec, ImportItem, ImportKind, ModuleExtraInfo};
use crate::protocol::{StringEncodingFilter, StringHit};
use crate::windows_platform::disassembler::CapstoneDisassembler;
use crate::windows_platform::{decode_wide_until_nul, matches_tokens, query_tokens};

pub mod emu_target;
pub mod mapped;
pub mod pattern;
pub mod xrefs;

pub use emu_target::{emulate, emu_layout, EmuLayout, EmulateSpec, StaticTarget, DEFAULT_MAX_INSTRUCTIONS, DEFAULT_STACK_SIZE};
pub use mapped::{MappedImage, MappedRegion};
pub use pattern::BytePattern;
pub use xrefs::{collect_functions, FunctionEntry, Xref, XrefIndex, XrefKind};

use crate::static_elf::ElfImage;
use crate::static_pe::{PeImage, ResourceEntry};

/// Result of a symbol-load attempt.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SymbolLoad {
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

/// An executable image laid out at its load base, with no process behind it.
/// Built by [`crate::static_pe::PeImage`] (PE) or [`crate::static_elf::ElfImage`]
/// (ELF) from their own headers; everything here is format-neutral.
pub struct StaticImage {
    path: String,
    /// File stem, the way symbols are qualified (`kernel32!CreateFileW`).
    module_name: String,
    bytes: Vec<u8>,
    info: ModuleExtraInfo,
    base: u64,
    arch: Architecture,
    sections: Vec<SectionMap>,
    /// Symbols sorted ascending by RVA, once loaded (PDB, or the ELF's own tables).
    symbols: Option<Vec<ModuleSymbol>>,
    symbol_load: SymbolLoad,
    mapped: OnceLock<MappedImage>,
    xrefs: OnceLock<XrefIndex>,
    functions: OnceLock<Vec<FunctionEntry>>,
}

impl StaticImage {
    /// Assemble an image from parsed headers. `symbols` are installed as the
    /// format's loader produced them (sorted here).
    pub(crate) fn new(path: &str, bytes: Vec<u8>, info: ModuleExtraInfo, arch: Architecture, base: u64, symbols: Option<Result<Vec<ModuleSymbol>, String>>) -> StaticImage {
        let sections = info.sections.iter().map(SectionMap::from).collect();
        let mut img = StaticImage {
            path: path.to_string(),
            module_name: crate::formatting::module_stem(path),
            bytes,
            info,
            base,
            arch,
            sections,
            symbols: None,
            symbol_load: SymbolLoad::default(),
            mapped: OnceLock::new(),
            xrefs: OnceLock::new(),
            functions: OnceLock::new(),
        };
        if let Some(parsed) = symbols {
            img.set_symbols(parsed);
        }
        img
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

    /// Install a symbol set (parsed by the format's loader, which a caller may
    /// run without holding a lock on the image — a server download can take a
    /// while). Returns the load status now recorded on the image.
    pub fn set_symbols(&mut self, parsed: Result<Vec<ModuleSymbol>, String>) -> SymbolLoad {
        let status = match parsed {
            Ok(mut syms) => {
                syms.sort_by_key(|s| s.rva);
                let status = SymbolLoad { loaded: true, count: syms.len(), error: None };
                self.symbols = Some(syms);
                // Symbol functions and names feed the recovered function list.
                self.functions.take();
                status
            }
            Err(e) => SymbolLoad { loaded: false, count: 0, error: Some(e) },
        };
        self.symbol_load = status.clone();
        status
    }

    pub fn symbol_load(&self) -> &SymbolLoad { &self.symbol_load }
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
        let instrs = decode_function_listing(bounds, va, max_instructions, |start, count| self.disassemble(start, count))?;
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

/// An opened file of either format, for callers that serve both (the image
/// viewer, Lua). Derefs to the shared [`StaticImage`]; the format-specific
/// operations dispatch.
pub enum StaticFile {
    Pe(PeImage),
    Elf(ElfImage),
}

impl StaticFile {
    /// Open `path` as whatever it is: an ELF by its magic, else a PE.
    /// `debug_file` is a PDB for a PE, a separate ELF debug file for an ELF.
    pub fn open(path: &str, base: Option<u64>, debug_file: Option<&Path>) -> Result<StaticFile, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("Failed to read '{}': {}", path, e))?;
        if bytes.starts_with(b"\x7FELF") {
            ElfImage::from_bytes(path, bytes, base, debug_file).map(StaticFile::Elf)
        } else {
            let mut img = PeImage::from_bytes(path, bytes, base)?;
            img.load_symbols(debug_file, true);
            Ok(StaticFile::Pe(img))
        }
    }

    pub fn format(&self) -> &'static str {
        match self {
            StaticFile::Pe(_) => "pe",
            StaticFile::Elf(_) => "elf",
        }
    }

    pub fn image(&self) -> &StaticImage {
        match self {
            StaticFile::Pe(p) => p,
            StaticFile::Elf(e) => e,
        }
    }

    pub fn image_mut(&mut self) -> &mut StaticImage {
        match self {
            StaticFile::Pe(p) => p,
            StaticFile::Elf(e) => e,
        }
    }

    pub fn as_pe(&self) -> Option<&PeImage> {
        match self {
            StaticFile::Pe(p) => Some(p),
            StaticFile::Elf(_) => None,
        }
    }

    pub fn as_pe_mut(&mut self) -> Option<&mut PeImage> {
        match self {
            StaticFile::Pe(p) => Some(p),
            StaticFile::Elf(_) => None,
        }
    }

    /// (Re)load symbols from `debug_file` (a PDB / an ELF debug file), or by
    /// discovery (PE: next to the file, the cache and — unless `offline` —
    /// the symbol server; ELF: the file's own tables).
    pub fn load_symbols(&mut self, debug_file: Option<&Path>, offline: bool) -> SymbolLoad {
        match self {
            StaticFile::Pe(p) => p.load_symbols(debug_file, offline),
            StaticFile::Elf(e) => e.load_symbols(debug_file),
        }
    }

    /// The PE resource tree; an ELF has none.
    pub fn resources(&self) -> Vec<ResourceEntry> {
        match self {
            StaticFile::Pe(p) => p.resources(),
            StaticFile::Elf(_) => Vec::new(),
        }
    }
}

impl std::ops::Deref for StaticFile {
    type Target = StaticImage;
    fn deref(&self) -> &StaticImage { self.image() }
}

impl std::ops::DerefMut for StaticFile {
    fn deref_mut(&mut self) -> &mut StaticImage { self.image_mut() }
}
