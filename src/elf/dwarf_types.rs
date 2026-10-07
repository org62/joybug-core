//! DWARF type information -> the manager's `ModuleTypeInfo` (the same record
//! model the PDB parser fills, so the Types view and the typed memory overlay
//! work unchanged on Linux).
//!
//! Record indices are `.debug_info` offsets of the defining DIEs, which fit
//! the model's u32 keys for any practical debug file. One pass over every
//! unit's DIEs converts: base types to primitives, struct/class/union to UDTs
//! with a synthesized field list, enums to enums with their enumerators,
//! typedef/const/volatile to modifiers, pointers/references to pointers,
//! arrays to arrays, subroutine types to functions. Members with
//! `DW_AT_bit_size` become bitfield records like PDB's `LF_BITFIELD`.

use std::collections::HashMap;
use std::path::Path;

use gimli::{AttributeValue, EndianSlice, LittleEndian};

use crate::interfaces::SymbolError;
use crate::protocol::{TypeClass, TypeEnumValue, UdtKind};
use crate::symbols::type_provider::{ModuleTypeInfo, OwnedMember, OwnedType};

type Slice<'a> = EndianSlice<'a, LittleEndian>;

/// Field lists and bitfields have no DIE of their own; they get indices past
/// the section's end, which no DIE can occupy.
struct Synth {
    next: u32,
}

impl Synth {
    fn alloc(&mut self) -> u32 {
        let i = self.next;
        self.next = self.next.wrapping_add(1);
        i
    }
}

pub fn parse_types(path: &Path) -> Result<ModuleTypeInfo, SymbolError> {
    let data = std::fs::read(path).map_err(SymbolError::IoError)?;
    let file = object::File::parse(&*data).map_err(|e| SymbolError::PdbParsingFailed(format!("{}: {e}", path.display())))?;
    let sections = super::dwarf::load_sections(path, &file)?;
    if !sections.contains_key(&gimli::SectionId::DebugInfo) {
        return Err(SymbolError::SymbolsNotFound(format!("{}: no .debug_info", path.display())));
    }
    let empty: Vec<u8> = Vec::new();
    let dwarf = super::dwarf::dwarf_over(&sections, &empty)?;
    let info_len = sections.get(&gimli::SectionId::DebugInfo).map(|s| s.len()).unwrap_or(0);
    let mut synth = Synth { next: u32::try_from(info_len).unwrap_or(u32::MAX / 2).saturating_add(1) };

    let mut types: HashMap<u32, OwnedType> = HashMap::new();
    let mut by_name: HashMap<String, u32> = HashMap::new();

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let unit = unit;
        let unit_base = match unit.header.offset() {
            gimli::UnitSectionOffset::DebugInfoOffset(o) => o.0 as u64,
            gimli::UnitSectionOffset::DebugTypesOffset(_) => continue,
        };
        let index_of = |offset: gimli::UnitOffset| -> u32 { (unit_base + offset.0 as u64).min(u32::MAX as u64 - 1) as u32 };
        let mut entries = unit.entries();
        // Depth-first walk with explicit nesting so a UDT's members are the
        // children at depth+1 of its DIE.
        while let Ok(Some((_, entry))) = entries.next_dfs() {
            let tag = entry.tag();
            let index = index_of(entry.offset());
            let name = attr_string(&dwarf, &unit, entry.attr_value(gimli::DW_AT_name).ok().flatten());
            let byte_size = attr_u64(entry.attr_value(gimli::DW_AT_byte_size).ok().flatten()).unwrap_or(0) as u32;
            let type_ref = entry.attr_value(gimli::DW_AT_type).ok().flatten().and_then(|v| match v {
                AttributeValue::UnitRef(o) => Some(index_of(o)),
                AttributeValue::DebugInfoRef(o) => Some(o.0.min(u32::MAX as usize - 1) as u32),
                _ => None,
            });
            let declaration = matches!(entry.attr_value(gimli::DW_AT_declaration).ok().flatten(), Some(AttributeValue::Flag(true)));
            match tag {
                gimli::DW_TAG_base_type => {
                    let encoding = entry
                        .attr_value(gimli::DW_AT_encoding)
                        .ok()
                        .flatten()
                        .and_then(|v| if let AttributeValue::Encoding(e) = v { Some(e) } else { None });
                    let class = match encoding {
                        Some(gimli::DW_ATE_boolean) => TypeClass::Bool,
                        Some(gimli::DW_ATE_float) => TypeClass::Float,
                        Some(gimli::DW_ATE_signed_char) if byte_size == 1 => TypeClass::Char,
                        Some(gimli::DW_ATE_unsigned_char) if byte_size == 1 => TypeClass::Char,
                        Some(gimli::DW_ATE_UTF) if byte_size == 2 => TypeClass::WChar,
                        Some(gimli::DW_ATE_signed) | Some(gimli::DW_ATE_signed_char) => TypeClass::Int,
                        Some(gimli::DW_ATE_unsigned) | Some(gimli::DW_ATE_unsigned_char) | Some(gimli::DW_ATE_UTF) => TypeClass::UInt,
                        _ => TypeClass::Void,
                    };
                    let static_name: &'static str = intern(name.as_deref().unwrap_or("?"));
                    types.insert(index, OwnedType::Primitive { name: static_name, size: byte_size, class, pointer: false });
                }
                gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type => {
                    let kind = match tag {
                        gimli::DW_TAG_union_type => UdtKind::Union,
                        gimli::DW_TAG_class_type => UdtKind::Class,
                        _ => UdtKind::Struct,
                    };
                    let (members, bitfields) = collect_members(&dwarf, &unit, entry, &index_of, &mut synth);
                    for (bf_index, record) in bitfields {
                        types.insert(bf_index, record);
                    }
                    let fields = if members.is_empty() {
                        None
                    } else {
                        let fl = synth.alloc();
                        types.insert(fl, OwnedType::FieldList { members, enumerates: Vec::new(), continuation: None });
                        Some(fl)
                    };
                    let name = name.unwrap_or_else(|| format!("<anonymous {}>", kind_word(kind)));
                    if !declaration && !name.starts_with('<') {
                        by_name.entry(name.clone()).or_insert(index);
                    }
                    types.insert(index, OwnedType::Udt { name, size: byte_size, fields, kind, forward: declaration });
                }
                gimli::DW_TAG_enumeration_type => {
                    let enumerates = collect_enumerators(&dwarf, &unit, entry);
                    let fields = if enumerates.is_empty() {
                        None
                    } else {
                        let fl = synth.alloc();
                        types.insert(fl, OwnedType::FieldList { members: Vec::new(), enumerates, continuation: None });
                        Some(fl)
                    };
                    // Enums carry their own size; the PDB model reads it off
                    // the underlying type, so synthesize one when DWARF has none.
                    let underlying = type_ref.unwrap_or_else(|| {
                        let u = synth.alloc();
                        types.insert(u, OwnedType::Primitive { name: "int", size: byte_size.max(4), class: TypeClass::Int, pointer: false });
                        u
                    });
                    let name = name.unwrap_or_else(|| "<anonymous enum>".to_string());
                    if !declaration && !name.starts_with('<') {
                        by_name.entry(name.clone()).or_insert(index);
                    }
                    types.insert(index, OwnedType::Enum { name, underlying, fields, forward: declaration });
                }
                gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type | gimli::DW_TAG_atomic_type => {
                    match type_ref {
                        Some(underlying) => types.insert(index, OwnedType::Modifier { underlying }),
                        // `typedef void x` / `const void`: no referent means void.
                        None => types.insert(index, OwnedType::Primitive { name: "void", size: 0, class: TypeClass::Void, pointer: false }),
                    };
                }
                gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type | gimli::DW_TAG_ptr_to_member_type => {
                    let size = if byte_size == 0 { 8 } else { byte_size };
                    let underlying = type_ref.unwrap_or_else(|| {
                        let v = synth.alloc();
                        types.insert(v, OwnedType::Primitive { name: "void", size: 0, class: TypeClass::Void, pointer: false });
                        v
                    });
                    types.insert(index, OwnedType::Pointer { underlying, size });
                }
                gimli::DW_TAG_array_type => {
                    let Some(element) = type_ref else { continue };
                    let count = array_count(&dwarf, &unit, entry);
                    // Element size is only known once the whole table exists;
                    // store the count and fix up below.
                    types.insert(index, OwnedType::Array { element, total_size: count.unwrap_or(0) });
                }
                gimli::DW_TAG_subroutine_type => {
                    types.insert(index, OwnedType::Function);
                }
                _ => {}
            }
        }
    }

    // Arrays: DWARF gives an element count, the model wants a byte total.
    let array_indices: Vec<u32> = types
        .iter()
        .filter_map(|(i, t)| matches!(t, OwnedType::Array { .. }).then_some(*i))
        .collect();
    for i in array_indices {
        let Some(OwnedType::Array { element, total_size: count }) = types.get(&i).cloned() else { continue };
        let elem_size = size_of(&types, element, 0);
        types.insert(i, OwnedType::Array { element, total_size: count.saturating_mul(elem_size) });
    }

    if types.is_empty() {
        return Err(SymbolError::SymbolsNotFound(format!("{}: no type information", path.display())));
    }
    Ok(ModuleTypeInfo::from_records(types, by_name))
}

fn kind_word(kind: UdtKind) -> &'static str {
    match kind {
        UdtKind::Struct => "struct",
        UdtKind::Class => "class",
        UdtKind::Union => "union",
        UdtKind::Enum => "enum",
    }
}

/// Byte size of a type, through modifiers; 0 when unknown.
fn size_of(types: &HashMap<u32, OwnedType>, index: u32, depth: u32) -> u32 {
    if depth > 16 {
        return 0;
    }
    match types.get(&index) {
        Some(OwnedType::Primitive { size, pointer, .. }) => if *pointer { 8 } else { *size },
        Some(OwnedType::Udt { size, .. }) => *size,
        Some(OwnedType::Enum { underlying, .. }) => size_of(types, *underlying, depth + 1),
        Some(OwnedType::Pointer { size, .. }) => *size,
        Some(OwnedType::Modifier { underlying }) | Some(OwnedType::Bitfield { underlying, .. }) => size_of(types, *underlying, depth + 1),
        Some(OwnedType::Array { total_size, .. }) => *total_size,
        _ => 0,
    }
}

/// The model's primitive names are `&'static str` (PDB primitives are a fixed
/// set). DWARF base-type names are an open set but tiny per program; intern
/// them for the process lifetime.
fn intern(name: &str) -> &'static str {
    use std::sync::Mutex;
    static NAMES: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let mut names = NAMES.lock().unwrap();
    if let Some(existing) = names.iter().find(|n| **n == name) {
        return existing;
    }
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    names.push(leaked);
    leaked
}

fn attr_string(dwarf: &gimli::Dwarf<Slice<'_>>, unit: &gimli::Unit<Slice<'_>>, value: Option<AttributeValue<Slice<'_>>>) -> Option<String> {
    let value = value?;
    dwarf.attr_string(unit, value).ok().map(|s| s.to_string_lossy().into_owned())
}

fn attr_u64(value: Option<AttributeValue<Slice<'_>>>) -> Option<u64> {
    match value? {
        AttributeValue::Udata(v) => Some(v),
        AttributeValue::Data1(v) => Some(v as u64),
        AttributeValue::Data2(v) => Some(v as u64),
        AttributeValue::Data4(v) => Some(v as u64),
        AttributeValue::Data8(v) => Some(v),
        AttributeValue::Sdata(v) => Some(v as u64),
        _ => None,
    }
}

fn attr_i64(value: Option<AttributeValue<Slice<'_>>>) -> Option<i64> {
    match value? {
        AttributeValue::Sdata(v) => Some(v),
        AttributeValue::Udata(v) => Some(v as i64),
        AttributeValue::Data1(v) => Some(v as i64),
        AttributeValue::Data2(v) => Some(v as i64),
        AttributeValue::Data4(v) => Some(v as i64),
        AttributeValue::Data8(v) => Some(v as i64),
        _ => None,
    }
}

/// A member's byte offset: a constant, or (DWARF 2) a location expression
/// that is a single `DW_OP_plus_uconst`.
fn member_offset(value: Option<AttributeValue<Slice<'_>>>, unit: &gimli::Unit<Slice<'_>>) -> u32 {
    match value {
        Some(AttributeValue::Exprloc(expr)) => {
            let mut ops = expr.operations(unit.encoding());
            match ops.next() {
                Ok(Some(gimli::Operation::PlusConstant { value })) => value as u32,
                _ => 0,
            }
        }
        other => attr_u64(other).unwrap_or(0) as u32,
    }
}

/// The members of a UDT DIE: `(members, bitfield records)`. Members are the
/// `DW_TAG_member` children; a bitfield member gets a synthesized record
/// wrapping its storage type.
fn collect_members(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    udt: &gimli::DebuggingInformationEntry<Slice<'_>>,
    index_of: &dyn Fn(gimli::UnitOffset) -> u32,
    synth: &mut Synth,
) -> (Vec<OwnedMember>, Vec<(u32, OwnedType)>) {
    let mut members = Vec::new();
    let mut bitfields = Vec::new();
    let Ok(mut tree) = unit.entries_tree(Some(udt.offset())) else { return (members, bitfields) };
    let Ok(root) = tree.root() else { return (members, bitfields) };
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }
        let name = attr_string(dwarf, unit, entry.attr_value(gimli::DW_AT_name).ok().flatten()).unwrap_or_default();
        let Some(field_type) = entry.attr_value(gimli::DW_AT_type).ok().flatten().and_then(|v| match v {
            AttributeValue::UnitRef(o) => Some(index_of(o)),
            AttributeValue::DebugInfoRef(o) => Some(o.0.min(u32::MAX as usize - 1) as u32),
            _ => None,
        }) else {
            continue;
        };
        let bit_size = attr_u64(entry.attr_value(gimli::DW_AT_bit_size).ok().flatten());
        let (offset, field_type) = match bit_size {
            Some(bits) => {
                // DWARF 4+: data_bit_offset from the struct start. DWARF 2/3:
                // byte offset + bit_offset counted from the storage unit's
                // high end (big-endian style); convert for little-endian.
                let storage = attr_u64(entry.attr_value(gimli::DW_AT_byte_size).ok().flatten()).unwrap_or(4) as u32;
                let (byte_off, bit_pos) = match attr_u64(entry.attr_value(gimli::DW_AT_data_bit_offset).ok().flatten()) {
                    Some(dbo) => ((dbo / 8) as u32 & !(storage - 1).max(0), (dbo % (storage as u64 * 8)) as u32),
                    None => {
                        let byte_off = member_offset(entry.attr_value(gimli::DW_AT_data_member_location).ok().flatten(), unit);
                        let hi = attr_u64(entry.attr_value(gimli::DW_AT_bit_offset).ok().flatten()).unwrap_or(0) as u32;
                        (byte_off, storage * 8 - hi - bits as u32)
                    }
                };
                let bf = synth.alloc();
                bitfields.push((bf, OwnedType::Bitfield { underlying: field_type, length: bits.min(255) as u8, position: bit_pos.min(255) as u8 }));
                (byte_off, bf)
            }
            None => (member_offset(entry.attr_value(gimli::DW_AT_data_member_location).ok().flatten(), unit), field_type),
        };
        members.push(OwnedMember { name, field_type, offset });
    }
    (members, bitfields)
}

fn collect_enumerators(dwarf: &gimli::Dwarf<Slice<'_>>, unit: &gimli::Unit<Slice<'_>>, en: &gimli::DebuggingInformationEntry<Slice<'_>>) -> Vec<TypeEnumValue> {
    let mut out = Vec::new();
    let Ok(mut tree) = unit.entries_tree(Some(en.offset())) else { return out };
    let Ok(root) = tree.root() else { return out };
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_enumerator {
            continue;
        }
        let name = attr_string(dwarf, unit, entry.attr_value(gimli::DW_AT_name).ok().flatten()).unwrap_or_default();
        let value = attr_i64(entry.attr_value(gimli::DW_AT_const_value).ok().flatten()).unwrap_or(0);
        out.push(TypeEnumValue { name, value });
    }
    out
}

/// Element count of an array DIE from its `DW_TAG_subrange_type` children
/// (multi-dimensional arrays multiply out).
fn array_count(_dwarf: &gimli::Dwarf<Slice<'_>>, unit: &gimli::Unit<Slice<'_>>, arr: &gimli::DebuggingInformationEntry<Slice<'_>>) -> Option<u32> {
    let mut tree = unit.entries_tree(Some(arr.offset())).ok()?;
    let root = tree.root().ok()?;
    let mut children = root.children();
    let mut total: u64 = 1;
    let mut any = false;
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        let count = match attr_u64(entry.attr_value(gimli::DW_AT_count).ok().flatten()) {
            Some(c) => c,
            None => {
                let upper = attr_i64(entry.attr_value(gimli::DW_AT_upper_bound).ok().flatten())?;
                let lower = attr_i64(entry.attr_value(gimli::DW_AT_lower_bound).ok().flatten()).unwrap_or(0);
                (upper - lower + 1).max(0) as u64
            }
        };
        total = total.saturating_mul(count);
        any = true;
    }
    any.then_some(total.min(u32::MAX as u64) as u32)
}
