//! ELF and DWARF parsing with no process behind it, on every OS: the layout
//! of an ELF file (`layout`), its `ModuleExtraInfo` (`info`), its symbols,
//! `.eh_frame` function table and the `SymbolBackend` the Linux platform
//! uses (`symbols`), the separate debug files of stripped modules
//! (`debug_file`), DWARF line tables (`dwarf`) and types (`dwarf_types`).
//! `static_pe::PeImage` opens ELF files through here, so the offline image
//! viewer, xrefs, function recovery and process-less emulation work for ELF
//! on Windows as well as Linux.

pub mod debug_file;
pub mod dwarf;
pub mod dwarf_types;
pub mod info;
pub mod layout;
pub mod symbols;
