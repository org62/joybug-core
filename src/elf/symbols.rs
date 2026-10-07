//! Symbols for ELF modules: `.symtab`/`.dynsym` from the file itself plus,
//! for a stripped module, its separate debug file (`debug_file`), with the
//! manager's background loading and caches shared with the PDB world.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use pelite::image::RUNTIME_FUNCTION;
use tracing::{trace, warn};

use crate::interfaces::{Address, ModuleSymbol, ResolvedSymbol, SymbolConfig, SymbolError, SymbolProvider};
use super::debug_file;
use crate::protocol::{ModuleInfo, PdbMismatchInfo};
use crate::symbols::backend::{FunctionTable, SymbolBackend};
use crate::symbols::symbol_provider::{hex_encode, ModuleLineTable};
use crate::symbols::type_provider::ModuleTypeInfo;

/// Symbols of one ELF file, RVAs relative to `min_vaddr` (so that
/// `base + rva == l_addr + st_value`). Also says whether the file carries
/// DWARF line information.
/// ELF images that exist only in the target's memory (the vdso), by module
/// name, so the symbol loader can parse them like a file. The kernel maps the
/// same vdso into every process, so one copy per name is enough.
static IN_MEMORY_IMAGES: Mutex<Vec<(String, std::sync::Arc<[u8]>)>> = Mutex::new(Vec::new());

/// Make the bytes of a memory-only module (`[vdso]`) available to the symbol
/// loader under that module name.
pub fn register_in_memory_image(name: &str, bytes: Vec<u8>) {
    let mut images = IN_MEMORY_IMAGES.lock().unwrap();
    images.retain(|(n, _)| n != name);
    images.push((name.to_string(), bytes.into()));
}

fn in_memory_image(name: &str) -> Option<std::sync::Arc<[u8]>> {
    IN_MEMORY_IMAGES.lock().unwrap().iter().find(|(n, _)| n == name).map(|(_, b)| b.clone())
}

pub fn parse_elf_symbols(path: &Path) -> Result<(Vec<ModuleSymbol>, bool), SymbolError> {
    let name = path.display().to_string();
    let data: std::sync::Arc<[u8]> = match in_memory_image(&name) {
        Some(bytes) => bytes,
        None => std::fs::read(path).map_err(SymbolError::IoError)?.into(),
    };
    parse_elf_symbols_from_bytes(&data, path)
}

/// [`parse_elf_symbols`] over bytes already in memory; `path` labels errors.
/// Returns the symbols and whether the file carries DWARF.
pub fn parse_elf_symbols_from_bytes(data: &[u8], path: &Path) -> Result<(Vec<ModuleSymbol>, bool), SymbolError> {
    let (file, layout) = parse(data, path)?;
    let (out, has_lines) = collect_symbols(&file, &layout);
    if out.is_empty() {
        return Err(SymbolError::SymbolsNotFound(format!("{}: no symbols", path.display())));
    }
    Ok((out, has_lines))
}

fn parse<'a>(data: &'a [u8], path: &Path) -> Result<(object::File<'a>, super::layout::ElfLayout), SymbolError> {
    let layout = super::layout::layout_from_bytes(data).map_err(|e| SymbolError::SymbolsNotFound(e.to_string()))?;
    let file = object::File::parse(data).map_err(|e| SymbolError::SymbolsNotFound(format!("{}: {e}", path.display())))?;
    Ok((file, layout))
}

fn has_dwarf(file: &object::File<'_>) -> bool {
    [".debug_line", ".zdebug_line", ".debug_info", ".zdebug_info"].iter().any(|n| file.section_by_name(n).is_some())
}

/// Every defined symbol of `file` (possibly none), and whether it carries DWARF.
fn collect_symbols(file: &object::File<'_>, layout: &super::layout::ElfLayout) -> (Vec<ModuleSymbol>, bool) {
    let has_lines = has_dwarf(file);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if !sym.is_definition() || sym.address() == 0 {
            continue;
        }
        let is_function = match sym.kind() {
            SymbolKind::Text => true,
            SymbolKind::Data | SymbolKind::Unknown => false,
            _ => continue,
        };
        let Ok(raw) = sym.name() else { continue };
        if raw.is_empty() {
            continue;
        }
        let rva = sym.address().wrapping_sub(layout.min_vaddr);
        if rva > u32::MAX as u64 {
            continue;
        }
        let name = demangle(raw);
        if !seen.insert((name.clone(), rva as u32)) {
            continue;
        }
        out.push(ModuleSymbol { name, rva: rva as u32, is_function });
    }
    (out, has_lines)
}

fn demangle(raw: &str) -> String {
    if raw.starts_with("_R") || raw.starts_with("_ZN") {
        if let Ok(d) = rustc_demangle::try_demangle(raw) {
            return format!("{d:#}");
        }
    }
    raw.to_string()
}

#[derive(Default)]
struct LoadedModule {
    base: Address,
    symbols: Vec<ModuleSymbol>,
    has_lines: bool,
    /// The separate debug file the symbols (and DWARF) came from, if any.
    debug_file: Option<PathBuf>,
}

/// The per-worker provider: a cache of parsed files.
#[derive(Default)]
pub struct ElfSymbolProvider {
    loaded: Mutex<HashMap<String, LoadedModule>>,
    /// Never ask a debuginfod server (local debug files still resolve).
    offline: bool,
}

impl SymbolProvider for ElfSymbolProvider {
    /// The module's own tables, merged with its separate debug file when one
    /// is installed or (unless offline) a debuginfod server has it: a
    /// distribution binary keeps only its `.dynsym` exports, the debug file
    /// has the `.symtab` with every local function and the DWARF.
    fn load_symbols_for_module(&mut self, module_path: &str, module_base: Address, _module_size: Option<usize>) -> Result<(), SymbolError> {
        let path = Path::new(module_path);
        let in_memory = in_memory_image(module_path);
        if module_path.starts_with('[') && in_memory.is_none() {
            return Err(SymbolError::SymbolsNotFound(format!("{module_path}: no file to read symbols from")));
        }
        let data: std::sync::Arc<[u8]> = match in_memory {
            Some(bytes) => bytes,
            None => std::fs::read(path).map_err(SymbolError::IoError)?.into(),
        };
        let (file, layout) = parse(&data, path)?;
        let (mut symbols, mut has_lines) = collect_symbols(&file, &layout);

        let mut debug_file = None;
        if !module_path.starts_with('[') {
            let found = debug_file::find_local(path, &file)
                .or_else(|| if self.offline { None } else { debug_file::build_id(&file).and_then(|id| debug_file::fetch_debuginfod(&id)) });
            if let Some(found) = found {
                match std::fs::read(&found).map_err(SymbolError::IoError).and_then(|d| parse(&d, &found).map(|(f, l)| collect_symbols(&f, &l))) {
                    Ok((debug_symbols, debug_lines)) => {
                        trace!(module_path, debug_file = %found.display(), count = debug_symbols.len(), "separate debug file");
                        // The debug file's table is the full one; the module's
                        // exports are a subset of it (dedup is by name + RVA).
                        let mut seen: std::collections::HashSet<(String, u32)> = debug_symbols.iter().map(|s| (s.name.clone(), s.rva)).collect();
                        let mut merged = debug_symbols;
                        merged.extend(symbols.into_iter().filter(|s| seen.insert((s.name.clone(), s.rva))));
                        symbols = merged;
                        has_lines = debug_lines;
                        debug_file = Some(found);
                    }
                    Err(e) => warn!(module_path, debug_file = %found.display(), error = %e, "separate debug file unreadable; using the module's own symbols"),
                }
            }
        }
        if symbols.is_empty() {
            return Err(SymbolError::SymbolsNotFound(format!("{module_path}: no symbols")));
        }
        self.loaded
            .lock()
            .unwrap()
            .insert(module_path.to_string(), LoadedModule { base: module_base, symbols, has_lines, debug_file });
        Ok(())
    }

    fn find_symbol(&self, symbol_name: &str, max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        let loaded = self.loaded.lock().unwrap();
        let (module_filter, name) = match symbol_name.split_once('!') {
            Some((m, n)) => (Some(m.to_ascii_lowercase()), n),
            None => (None, symbol_name),
        };
        let mut out = Vec::new();
        for (path, module) in loaded.iter() {
            let stem = crate::formatting::module_stem(path);
            if module_filter.as_deref().is_some_and(|f| f != stem.to_ascii_lowercase()) {
                continue;
            }
            for s in module.symbols.iter().filter(|s| s.name == name) {
                out.push(ResolvedSymbol {
                    name: format!("{stem}!{}", s.name),
                    module_name: stem.clone(),
                    rva: s.rva,
                    va: module.base + s.rva as u64,
                    is_function: s.is_function,
                });
                if out.len() >= max_results {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    fn list_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        self.loaded
            .lock()
            .unwrap()
            .get(module_path)
            .map(|m| m.symbols.clone())
            .ok_or_else(|| SymbolError::ModuleNotLoaded(module_path.to_string()))
    }

    fn resolve_rva_to_symbol(&self, module_path: &str, rva: u32) -> Result<Option<ModuleSymbol>, SymbolError> {
        let loaded = self.loaded.lock().unwrap();
        let module = loaded.get(module_path).ok_or_else(|| SymbolError::ModuleNotLoaded(module_path.to_string()))?;
        Ok(module.symbols.iter().filter(|s| s.rva <= rva).max_by_key(|s| s.rva).cloned())
    }

    /// The separate debug file, else the module itself when it carries DWARF.
    fn debug_file_path(&self, module_path: &str) -> Option<String> {
        let loaded = self.loaded.lock().unwrap();
        let module = loaded.get(module_path)?;
        match &module.debug_file {
            Some(f) => Some(f.display().to_string()),
            None => module.has_lines.then(|| module_path.to_string()),
        }
    }
}

/// The ELF/DWARF side of the symbol manager.
pub struct ElfBackend;

impl SymbolBackend for ElfBackend {
    fn new_provider(&self, cfg: &SymbolConfig) -> Result<Box<dyn SymbolProvider>, SymbolError> {
        Ok(Box::new(ElfSymbolProvider { offline: cfg.offline, ..Default::default() }))
    }

    /// The provider already read the module's own tables (and its debug
    /// file) in one go, so when that failed there is nothing left to fall
    /// back to.
    fn fallback_symbols(&self, module_path: &str) -> Result<Vec<ModuleSymbol>, String> {
        Err(format!("{module_path}: no symbol table in the module or a debug file"))
    }

    fn parse_lines(&self, debug_file: &Path) -> Result<ModuleLineTable, SymbolError> {
        super::dwarf::parse_line_table(debug_file)
    }

    fn parse_types(&self, debug_file: &Path) -> Result<ModuleTypeInfo, SymbolError> {
        super::dwarf_types::parse_types(debug_file)
    }

    /// The ELF counterpart of `.pdata`: every FDE in `.eh_frame` is one
    /// function range. Entries are module-relative like the PE ones, so the
    /// coverage and function-bounds code upstream reads them unchanged.
    fn function_table(&self, module_path: &str) -> Option<FunctionTable> {
        eh_frame_function_table(Path::new(module_path))
    }

    /// A user-supplied ELF with debug info for `module`: the unstripped
    /// binary, a copy of it, or an `objcopy --only-keep-debug` file. Unless
    /// `force`, its GNU build-id must match the module's (when both have one).
    fn load_debug_file(&self, module: &ModuleInfo, debug_file: &Path, force: bool) -> Result<Result<Vec<ModuleSymbol>, PdbMismatchInfo>, SymbolError> {
        if !force {
            let want = build_id(Path::new(&module.name));
            let have = build_id(debug_file);
            if let (Some(want), Some(have)) = (&want, &have) {
                if want != have {
                    // The wire type is PE/PDB-shaped; the build-ids go in
                    // the GUID slots and the ages are meaningless.
                    return Ok(Err(PdbMismatchInfo { pe_guid: hex_encode(want), pe_age: 0, pdb_guid: hex_encode(have), pdb_age: 0 }));
                }
            }
        }
        let (symbols, _) = parse_elf_symbols(debug_file)?;
        Ok(Ok(symbols))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With the distribution's debug package installed, a stripped ld.so
    /// resolves its local functions and reports the debug file it used.
    #[test]
    fn stripped_module_gains_locals_from_its_debug_file() {
        let Some(ld) = ["/lib64/ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
            .and_then(|p| std::fs::canonicalize(p).ok())
        else {
            return;
        };
        let data = std::fs::read(&ld).unwrap();
        let file = object::File::parse(&*data).unwrap();
        if debug_file::find_local(&ld, &file).is_none() {
            return; // no debug package here
        }
        let mut provider = ElfSymbolProvider { offline: true, ..Default::default() };
        let path = ld.display().to_string();
        provider.load_symbols_for_module(&path, 0x7000_0000_0000, None).expect("loads");
        let symbols = provider.list_symbols(&path).unwrap();
        assert!(symbols.iter().any(|s| s.name == "_dl_start" && s.is_function), "local symbol from the debug file");
        assert!(symbols.iter().any(|s| s.name == "_dl_debug_state"), "export from the module itself");
        let debug = provider.debug_file_path(&path).expect("debug file reported");
        assert!(debug.ends_with(".debug") || debug.ends_with("/debuginfo"), "{debug}");
    }

    #[test]
    fn libc_exports_are_readable() {
        let libc = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]
            .into_iter()
            .map(Path::new)
            .find(|p| p.exists());
        let Some(libc) = libc else { return };
        let (symbols, _) = parse_elf_symbols(libc).expect("libc parses");
        assert!(symbols.iter().any(|s| s.name == "__libc_start_main" && s.is_function), "exported entry present");
        assert!(symbols.iter().any(|s| s.name == "write"));
    }
}

/// Function ranges from the module's `.eh_frame`, as module-relative
/// `RUNTIME_FUNCTION`s sorted by start. `None` when the file has no unwind
/// table (or cannot be read); an FDE that fails to parse is skipped.
pub fn eh_frame_function_table(path: &Path) -> Option<FunctionTable> {
    let data = std::fs::read(path).ok()?;
    eh_frame_function_table_from_bytes(&data)
}

/// [`eh_frame_function_table`] over bytes already in memory.
pub fn eh_frame_function_table_from_bytes(data: &[u8]) -> Option<FunctionTable> {
    let layout = super::layout::layout_from_bytes(data).ok()?;
    let file = object::File::parse(data).ok()?;
    let eh = file.section_by_name(".eh_frame")?;
    let bytes = eh.uncompressed_data().ok()?;
    let mut bases = BaseAddresses::default().set_eh_frame(eh.address());
    if let Some(text) = file.section_by_name(".text") {
        bases = bases.set_text(text.address());
    }
    let section = EhFrame::new(&bytes, LittleEndian);
    let mut entries = Vec::new();
    let mut iter = section.entries(&bases);
    while let Ok(Some(entry)) = iter.next() {
        let CieOrFde::Fde(partial) = entry else { continue };
        let Ok(fde) = partial.parse(|s, b, o| s.cie_from_offset(b, o)) else { continue };
        let start = fde.initial_address();
        let len = fde.len();
        if len == 0 || start < layout.min_vaddr {
            continue;
        }
        let Ok(begin) = u32::try_from(start - layout.min_vaddr) else { continue };
        let Ok(end) = u32::try_from(begin as u64 + len) else { continue };
        entries.push(RUNTIME_FUNCTION { BeginAddress: begin, EndAddress: end, UnwindData: 0 });
    }
    if entries.is_empty() {
        return None;
    }
    entries.sort_by_key(|e| e.BeginAddress);
    entries.dedup_by_key(|e| e.BeginAddress);
    Some(FunctionTable { entries, chain_map: HashMap::new() })
}

#[cfg(test)]
mod eh_frame_tests {
    use super::*;

    #[test]
    fn libc_has_a_function_table_from_eh_frame() {
        let Some(libc) = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]
            .iter()
            .find(|p| Path::new(p).exists())
        else {
            return;
        };
        let table = eh_frame_function_table(Path::new(libc)).expect("libc has .eh_frame");
        assert!(table.entries.len() > 1000, "{} entries", table.entries.len());
        assert!(table.entries.windows(2).all(|w| w[0].BeginAddress < w[1].BeginAddress));
        assert!(table.entries.iter().all(|e| e.EndAddress > e.BeginAddress));
    }
}

/// The GNU build-id (`.note.gnu.build-id`) of the ELF at `path`, when it has one.
fn build_id(path: &Path) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    debug_file::build_id(&object::File::parse(&*data).ok()?)
}
