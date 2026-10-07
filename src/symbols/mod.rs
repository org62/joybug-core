//! Symbol resolution: the per-process `SymbolManager` (background loading,
//! lookups, line tables, types) and the file-format providers behind it.
//! Compiled on every OS; the PDB/PE provider is pure Rust (`pdb`, `pelite`).

pub mod backend;
pub mod module_extra;
pub mod symbol_manager;
pub mod symbol_provider;
pub mod type_provider;
