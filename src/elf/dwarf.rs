//! DWARF line tables -> the manager's `ModuleLineTable` (the same shape the
//! PDB parser produces, so the source view, line stepping and the
//! disassembly annotations work unchanged).

use std::collections::HashMap;
use std::path::Path;

use gimli::{EndianSlice, LittleEndian};
use object::{Object, ObjectSection};

use crate::interfaces::{LineEntry, SourceFileEntry, SymbolError};
use crate::symbols::symbol_provider::ModuleLineTable;

/// The DWARF sections of an ELF file, decompressed and owned, keyed by id.
pub(super) fn load_sections(path: &Path, file: &object::File<'_>) -> Result<HashMap<gimli::SectionId, Vec<u8>>, SymbolError> {
    let mut sections: HashMap<gimli::SectionId, Vec<u8>> = HashMap::new();
    for id in [
        gimli::SectionId::DebugAbbrev,
        gimli::SectionId::DebugInfo,
        gimli::SectionId::DebugLine,
        gimli::SectionId::DebugLineStr,
        gimli::SectionId::DebugStr,
        gimli::SectionId::DebugStrOffsets,
        gimli::SectionId::DebugAddr,
        gimli::SectionId::DebugRanges,
        gimli::SectionId::DebugRngLists,
        gimli::SectionId::DebugAranges,
        gimli::SectionId::DebugLocLists,
        gimli::SectionId::DebugLoc,
        gimli::SectionId::DebugTypes,
    ] {
        if let Some(section) = file.section_by_name(id.name()) {
            let bytes = section
                .uncompressed_data()
                .map_err(|e| SymbolError::PdbParsingFailed(format!("{}: {} {e}", path.display(), id.name())))?;
            sections.insert(id, bytes.into_owned());
        }
    }
    Ok(sections)
}

/// A `gimli::Dwarf` over owned sections.
pub(super) fn dwarf_over<'a>(sections: &'a HashMap<gimli::SectionId, Vec<u8>>, empty: &'a Vec<u8>) -> Result<gimli::Dwarf<EndianSlice<'a, LittleEndian>>, SymbolError> {
    gimli::Dwarf::load(|id| -> Result<EndianSlice<'a, LittleEndian>, SymbolError> {
        Ok(EndianSlice::new(sections.get(&id).unwrap_or(empty), LittleEndian))
    })
}

pub fn parse_line_table(path: &Path) -> Result<ModuleLineTable, SymbolError> {
    let data = std::fs::read(path).map_err(SymbolError::IoError)?;
    let layout = super::layout::layout_from_bytes(&data).map_err(|e| SymbolError::PdbParsingFailed(e.to_string()))?;
    let file = object::File::parse(&*data).map_err(|e| SymbolError::PdbParsingFailed(format!("{}: {e}", path.display())))?;
    let sections = load_sections(path, &file)?;
    let empty: Vec<u8> = Vec::new();
    let dwarf = dwarf_over(&sections, &empty)?;

    let mut table = ModuleLineTable::default();
    let mut file_dedup: HashMap<String, u32> = HashMap::new();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let Some(program) = unit.line_program.clone() else { continue };
        let comp_dir = unit.comp_dir.as_ref().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
        let header = program.header().clone();
        // Unit-local file index -> global index.
        let mut local_files: HashMap<u64, u32> = HashMap::new();
        let mut rows = program.rows();
        // A row's extent runs to the next row's address (same sequence).
        let mut pending: Option<(u64, u32, u32, Option<u32>)> = None; // (addr, file, line, col)
        let flush = |table: &mut ModuleLineTable, end: u64, pending: &mut Option<(u64, u32, u32, Option<u32>)>| {
            if let Some((addr, file, line, col)) = pending.take() {
                if line != 0 && end >= addr && addr >= layout.min_vaddr {
                    table.lines.push(LineEntry {
                        rva: (addr - layout.min_vaddr) as u32,
                        length: (end - addr).min(u32::MAX as u64) as u32,
                        file_index: file,
                        line_start: line,
                        line_end: line,
                        col_start: col,
                        col_end: None,
                    });
                }
            }
        };
        while let Ok(Some((_, row))) = rows.next_row() {
            if row.end_sequence() {
                flush(&mut table, row.address(), &mut pending);
                continue;
            }
            if !row.is_stmt() {
                continue;
            }
            let file_index = match local_files.get(&row.file_index()) {
                Some(&i) => i,
                None => {
                    let Some(fe) = row.file(&header) else { continue };
                    let name = dwarf.attr_string(&unit, fe.path_name()).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                    let dir = fe
                        .directory(&header)
                        .and_then(|d| dwarf.attr_string(&unit, d).ok())
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let mut full = std::path::PathBuf::new();
                    if !Path::new(&dir).is_absolute() {
                        full.push(&comp_dir);
                    }
                    full.push(&dir);
                    full.push(&name);
                    let path = full.to_string_lossy().into_owned();
                    let (checksum_kind, checksum) = if header.file_has_md5() {
                        ("md5".to_string(), fe.md5().iter().map(|b| format!("{b:02x}")).collect::<String>())
                    } else {
                        ("none".to_string(), String::new())
                    };
                    let global = *file_dedup.entry(path.clone()).or_insert_with(|| {
                        table.files.push(SourceFileEntry { path, checksum_kind, checksum });
                        (table.files.len() - 1) as u32
                    });
                    local_files.insert(row.file_index(), global);
                    global
                }
            };
            let line = row.line().map(|l| l.get() as u32).unwrap_or(0);
            let col = match row.column() {
                gimli::ColumnType::LeftEdge => None,
                gimli::ColumnType::Column(c) => Some(c.get() as u32),
            };
            // Same address as the pending row: the later one wins (gcc emits
            // a view entry first).
            if let Some((addr, ..)) = pending {
                if addr == row.address() {
                    pending = Some((addr, file_index, line, col));
                    continue;
                }
            }
            flush(&mut table, row.address(), &mut pending);
            pending = Some((row.address(), file_index, line, col));
        }
    }
    table.lines.sort_by_key(|l| l.rva);
    table.lines.dedup_by_key(|l| l.rva);
    for (i, l) in table.lines.iter().enumerate() {
        table.by_file.entry(l.file_index).or_default().push(i as u32);
    }
    for idx in table.by_file.values_mut() {
        idx.sort_by_key(|&i| table.lines[i as usize].line_start);
    }
    if table.lines.is_empty() {
        return Err(SymbolError::SymbolsNotFound(format!("{}: no DWARF line information", path.display())));
    }
    Ok(table)
}

impl From<gimli::Error> for SymbolError {
    fn from(e: gimli::Error) -> Self {
        SymbolError::PdbParsingFailed(format!("DWARF: {e}"))
    }
}
