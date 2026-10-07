//! An ELF file opened from disk: the format-specific half of
//! [`crate::static_image::StaticImage`] — ELF header parsing through
//! `crate::elf`, symbols from the file's own tables or a separate debug file.
//! Everything else (hex, disassembly, symbols, strings, byte search, xrefs,
//! functions, emulation) is the shared image, reached through `Deref`.
//!
//! The ELF facts land where the shared views expect them: allocated sections
//! are the section table, the dynamic symbol table the export directory, GOT
//! slots the import table (attributed to the `DT_NEEDED` set as a whole),
//! `.eh_frame` the exception directory. Resources and TLS callbacks are empty.

use std::path::Path;

use crate::interfaces::{Architecture, ModuleSymbol};
use crate::static_image::{StaticImage, SymbolLoad};

/// An ELF file opened from disk.
pub struct ElfImage(StaticImage);

impl std::ops::Deref for ElfImage {
    type Target = StaticImage;
    fn deref(&self) -> &StaticImage { &self.0 }
}

impl std::ops::DerefMut for ElfImage {
    fn deref_mut(&mut self) -> &mut StaticImage { &mut self.0 }
}

/// Where a position-independent image (link-time base 0) is laid out unless
/// a base is given: the address the x86-64 kernel typically picks.
pub const DEFAULT_PIE_BASE: u64 = 0x5555_5555_4000;

impl ElfImage {
    /// Open `path` and parse it; symbols come from the file's own tables, or
    /// from `debug_file` (an unstripped copy, `objcopy --only-keep-debug`)
    /// when given. `base` overrides the load base (default: the link-time
    /// base, or [`DEFAULT_PIE_BASE`] for a position-independent image).
    pub fn open(path: &str, base: Option<u64>, debug_file: Option<&Path>) -> Result<ElfImage, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("Failed to read '{}': {}", path, e))?;
        Self::from_bytes(path, bytes, base, debug_file)
    }

    /// Build from bytes already in memory. `path` labels the image (module
    /// name, error messages); it need not exist on disk.
    pub fn from_bytes(path: &str, bytes: Vec<u8>, base: Option<u64>, debug_file: Option<&Path>) -> Result<ElfImage, String> {
        use object::Object;
        if !bytes.starts_with(b"\x7FELF") {
            return Err("Not a valid ELF file (missing the ELF magic).".to_string());
        }
        let info = crate::elf::info::module_extra_info_from_bytes(&bytes, Path::new(path)).map_err(|e| format!("Failed to parse ELF: {e}"))?;
        let file = object::File::parse(&*bytes).map_err(|e| format!("Failed to parse ELF: {e}"))?;
        let arch = match file.architecture() {
            object::Architecture::X86_64 => Architecture::X64,
            object::Architecture::I386 => Architecture::X86,
            object::Architecture::Aarch64 => Architecture::Arm64,
            other => return Err(format!("Unsupported ELF machine {other:?}. Supported: x86, x86-64 and AArch64 images.")),
        };
        let base = match base {
            Some(b) => b,
            None => match info.nt_headers.OptionalHeader.ImageBase {
                0 => DEFAULT_PIE_BASE,
                ib => ib,
            },
        };
        let symbols = parse_symbols(&bytes, path, debug_file);
        Ok(ElfImage(StaticImage::new(path, bytes, info, arch, base, Some(symbols))))
    }

    /// Replace the symbols with those of `debug_file` (a separate ELF with
    /// debug info), or reload the file's own when none is given.
    pub fn load_symbols(&mut self, debug_file: Option<&Path>) -> SymbolLoad {
        let parsed = parse_symbols(self.bytes(), self.path(), debug_file);
        self.set_symbols(parsed)
    }
}

/// The symbols of `debug_file` when one is given, else the image's own.
fn parse_symbols(bytes: &[u8], path: &str, debug_file: Option<&Path>) -> Result<Vec<ModuleSymbol>, String> {
    match debug_file {
        Some(debug) => crate::elf::symbols::parse_elf_symbols(debug),
        None => crate::elf::symbols::parse_elf_symbols_from_bytes(bytes, Path::new(path)),
    }
    .map(|(symbols, _)| symbols)
    .map_err(|e| e.to_string())
}
