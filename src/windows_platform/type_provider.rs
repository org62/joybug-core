//! PDB type (TPI stream) parsing.
//!
//! Mirrors `symbol_provider`'s `parse_pdb_to_*` free functions: the whole TPI
//! stream is parsed once into owned, PDB-lifetime-free records (`OwnedType`), so
//! type layouts can be resolved on demand afterwards without keeping the PDB (and
//! its backing file) alive. `ModuleTypeInfo` is cached per module in
//! `SymbolManager`, alongside the symbol and line-table caches.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use pdb::{FallibleIterator, TypeData, TypeIndex};
use tracing::trace;

use crate::interfaces::SymbolError;
use crate::protocol::{TypeClass, TypeEnumValue, TypeLayout, TypeMember, TypeRef, UdtKind};
use crate::windows_platform::symbol_provider::open_pdb;

/// Owned representation of one TPI record. Indices are raw `TypeIndex` values (u32).
#[derive(Debug, Clone)]
enum OwnedType {
    Primitive {
        name: &'static str,
        /// Size of the value itself (not the pointer, if `pointer` is set).
        size: u32,
        /// Value category (always a scalar `TypeClass` variant).
        class: TypeClass,
        /// The record is a pointer to the primitive (PDB encodes e.g. `void*`
        /// as a primitive with an indirection).
        pointer: bool,
    },
    Udt {
        name: String,
        size: u32,
        fields: Option<u32>,
        kind: UdtKind,
        forward: bool,
    },
    Enum {
        name: String,
        underlying: u32,
        fields: Option<u32>,
        forward: bool,
    },
    Pointer {
        underlying: u32,
        size: u32,
    },
    Modifier {
        underlying: u32,
    },
    Array {
        element: u32,
        total_size: u32,
    },
    Bitfield {
        underlying: u32,
        length: u8,
        position: u8,
    },
    FieldList {
        members: Vec<OwnedMember>,
        enumerates: Vec<TypeEnumValue>,
        continuation: Option<u32>,
    },
    /// A function/procedure type — only meaningful as a pointer target.
    Function,
    /// A record we don't model (argument lists, method lists, …).
    Other,
}

#[derive(Debug, Clone)]
struct OwnedMember {
    name: String,
    field_type: u32,
    offset: u32,
}

/// Browse-list entry for one named type. Module identity isn't known to the PDB;
/// the caller adds it when building the outgoing `TypeSummary`.
pub struct TypeSummaryEntry {
    pub name: String,
    pub size: u32,
    pub kind: UdtKind,
    pub index: u32,
}

/// Parsed type information for a single module's PDB.
pub struct ModuleTypeInfo {
    /// Every TPI record, keyed by raw type index.
    types: HashMap<u32, OwnedType>,
    /// Name → index of the *definition* (non-forward-ref) record. Used both to
    /// resolve a type by name and to redirect forward references to the real body.
    by_name: HashMap<String, u32>,
    /// Browse list: one entry per named, non-forward struct/class/union/enum,
    /// sorted by name.
    summaries: Vec<TypeSummaryEntry>,
}

const MAX_TYPE_REF_DEPTH: u32 = 16;

impl ModuleTypeInfo {
    /// Type summaries (browse list), sorted by name.
    pub fn summaries(&self) -> &[TypeSummaryEntry] {
        &self.summaries
    }

    /// Resolve a named type to a full one-level layout.
    pub fn resolve_by_name(&self, name: &str, module_base: u64) -> Option<TypeLayout> {
        let index = *self.by_name.get(name)?;
        self.resolve(index, module_base)
    }

    /// Resolve a type by its raw TPI index to a full one-level layout.
    /// Follows forward references to the real definition.
    pub fn resolve(&self, index: u32, module_base: u64) -> Option<TypeLayout> {
        let index = self.definition_index(index);
        match self.types.get(&index)? {
            OwnedType::Udt {
                name,
                size,
                fields,
                kind,
                ..
            } => {
                let members = fields
                    .map(|f| self.collect_members(f))
                    .unwrap_or_default();
                Some(TypeLayout {
                    name: name.clone(),
                    size: *size,
                    kind: *kind,
                    index,
                    module_base,
                    members,
                    enum_values: Vec::new(),
                })
            }
            OwnedType::Enum {
                name,
                underlying,
                fields,
                ..
            } => {
                let enum_values = fields
                    .map(|f| self.collect_enumerates(f))
                    .unwrap_or_default();
                Some(TypeLayout {
                    name: name.clone(),
                    size: self.type_ref(*underlying, 0).size,
                    kind: UdtKind::Enum,
                    index,
                    module_base,
                    members: Vec::new(),
                    enum_values,
                })
            }
            _ => None,
        }
    }

    /// The index of the real definition for `index`: if it names a forward-ref
    /// UDT/enum, redirect to the body via the name index.
    fn definition_index(&self, index: u32) -> u32 {
        match self.types.get(&index) {
            Some(OwnedType::Udt { name, forward: true, .. })
            | Some(OwnedType::Enum { name, forward: true, .. }) => {
                self.by_name.get(name).copied().unwrap_or(index)
            }
            _ => index,
        }
    }

    /// Walk a FieldList chain (following continuations), visiting each list's
    /// members and enumerates.
    fn walk_field_lists(&self, fields_index: u32, mut visit: impl FnMut(&[OwnedMember], &[TypeEnumValue])) {
        let mut next = Some(fields_index);
        let mut guard = 0;
        while let Some(fi) = next {
            guard += 1;
            if guard > 256 {
                break; // pathological continuation chain
            }
            let Some(OwnedType::FieldList {
                members,
                enumerates,
                continuation,
            }) = self.types.get(&fi)
            else {
                break;
            };
            visit(members, enumerates);
            next = *continuation;
        }
    }

    /// Collect struct members from a FieldList chain.
    fn collect_members(&self, fields_index: u32) -> Vec<TypeMember> {
        let mut out = Vec::new();
        self.walk_field_lists(fields_index, |members, _| {
            out.extend(members.iter().map(|m| self.member(m)));
        });
        out
    }

    /// Collect enum values from a FieldList chain.
    fn collect_enumerates(&self, fields_index: u32) -> Vec<TypeEnumValue> {
        let mut out = Vec::new();
        self.walk_field_lists(fields_index, |_, enumerates| {
            out.extend(enumerates.iter().cloned());
        });
        out
    }

    fn member(&self, m: &OwnedMember) -> TypeMember {
        // A bitfield member points at a Bitfield record wrapping the storage type.
        if let Some(OwnedType::Bitfield {
            underlying,
            length,
            position,
        }) = self.types.get(&m.field_type)
        {
            return TypeMember {
                name: m.name.clone(),
                offset: m.offset,
                type_ref: self.type_ref(*underlying, 0),
                bit_position: Some(*position),
                bit_length: Some(*length),
            };
        }
        TypeMember {
            name: m.name.clone(),
            offset: m.offset,
            type_ref: self.type_ref(m.field_type, 0),
            bit_position: None,
            bit_length: None,
        }
    }

    /// Build a display `TypeRef` for a type index. Resolves modifiers, pointers and
    /// arrays; UDT/enum references stop at their index (expanded lazily elsewhere).
    fn type_ref(&self, index: u32, depth: u32) -> TypeRef {
        if depth > MAX_TYPE_REF_DEPTH {
            return TypeRef {
                name: "…".to_string(),
                size: 0,
                class: TypeClass::Unknown,
            };
        }
        match self.types.get(&index) {
            Some(OwnedType::Primitive {
                name,
                size,
                class,
                pointer,
            }) => {
                if *pointer {
                    let pointee = TypeRef {
                        name: name.to_string(),
                        size: *size,
                        class: class.clone(),
                    };
                    TypeRef {
                        name: format!("{} *", name),
                        size: 8,
                        class: TypeClass::Pointer {
                            pointee: Box::new(pointee),
                        },
                    }
                } else {
                    TypeRef {
                        name: name.to_string(),
                        size: *size,
                        class: class.clone(),
                    }
                }
            }
            Some(OwnedType::Modifier { underlying }) => self.type_ref(*underlying, depth + 1),
            Some(OwnedType::Pointer { underlying, size }) => {
                let pointee = self.type_ref(*underlying, depth + 1);
                TypeRef {
                    name: format!("{} *", pointee.name),
                    size: *size,
                    class: TypeClass::Pointer {
                        pointee: Box::new(pointee),
                    },
                }
            }
            Some(OwnedType::Array {
                element,
                total_size,
            }) => {
                let elem = self.type_ref(*element, depth + 1);
                let count = if elem.size > 0 {
                    *total_size / elem.size
                } else {
                    0
                };
                TypeRef {
                    name: format!("{}[{}]", elem.name, count),
                    size: *total_size,
                    class: TypeClass::Array {
                        element: Box::new(elem),
                        count,
                    },
                }
            }
            Some(OwnedType::Udt { name, size, .. }) => {
                let def = self.by_name.get(name).copied().unwrap_or(index);
                TypeRef {
                    name: name.clone(),
                    size: *size,
                    class: TypeClass::Udt { index: def },
                }
            }
            Some(OwnedType::Enum {
                name, underlying, ..
            }) => {
                let def = self.by_name.get(name).copied().unwrap_or(index);
                TypeRef {
                    name: name.clone(),
                    size: self.type_ref(*underlying, depth + 1).size,
                    class: TypeClass::Enum { index: def },
                }
            }
            Some(OwnedType::Bitfield { underlying, .. }) => self.type_ref(*underlying, depth + 1),
            Some(OwnedType::Function) => TypeRef {
                name: "<function>".to_string(),
                size: 0,
                class: TypeClass::Unknown,
            },
            _ => TypeRef {
                name: format!("t#{}", index),
                size: 0,
                class: TypeClass::Unknown,
            },
        }
    }
}

/// Parse the whole TPI stream of a PDB into owned type records.
/// Free function mirroring `parse_pdb_to_symbols` / `parse_pdb_to_lines`.
pub(crate) fn parse_pdb_to_types(pdb_path: &Path) -> Result<ModuleTypeInfo, SymbolError> {
    let mut pdb = open_pdb(pdb_path)?;
    let type_info = pdb
        .type_information()
        .map_err(|e| SymbolError::PdbParsingFailed(format!("type_information from {}: {}", pdb_path.display(), e)))?;

    let mut types: HashMap<u32, OwnedType> = HashMap::new();
    let mut by_name: HashMap<String, u32> = HashMap::new();

    // A finder lets us resolve reserved primitive type indices (< 0x1000), which the
    // TPI stream does not emit as records. We use it in a second pass below.
    let mut type_finder = type_info.finder();

    let mut iter = type_info.iter();
    loop {
        let typ = match iter.next() {
            Ok(Some(t)) => t,
            Ok(None) => break,
            Err(e) => {
                trace!(error = %e, "TPI iteration error, stopping");
                break;
            }
        };
        type_finder.update(&iter);
        let index = typ.index().0;
        let owned = match typ.parse() {
            Ok(data) => convert_type_data(data),
            Err(_) => OwnedType::Other,
        };

        // Record name → definition index for named, non-forward UDTs/enums.
        match &owned {
            OwnedType::Udt {
                name, forward: false, ..
            }
            | OwnedType::Enum {
                name, forward: false, ..
            } if !name.is_empty() => {
                by_name.entry(name.clone()).or_insert(index);
            }
            _ => {}
        }

        types.insert(index, owned);
    }

    // Second pass: resolve reserved primitive indices (< 0x1000) that members,
    // pointers, arrays, etc. reference but the TPI stream never emits as records.
    // Without this, primitive members render as an opaque "t#NN". Only reserved
    // indices can be missing — everything >= 0x1000 was emitted as a record above.
    let mut referenced: HashSet<u32> = HashSet::new();
    for owned in types.values() {
        match owned {
            OwnedType::Pointer { underlying, .. }
            | OwnedType::Modifier { underlying }
            | OwnedType::Array { element: underlying, .. }
            | OwnedType::Bitfield { underlying, .. }
            | OwnedType::Enum { underlying, .. } => {
                if *underlying < 0x1000 {
                    referenced.insert(*underlying);
                }
            }
            OwnedType::FieldList { members, .. } => {
                referenced.extend(members.iter().map(|m| m.field_type).filter(|&i| i < 0x1000));
            }
            _ => {}
        }
    }
    for idx in referenced {
        if types.contains_key(&idx) {
            continue;
        }
        if let Ok(item) = type_finder.find(TypeIndex(idx)) {
            if let Ok(TypeData::Primitive(p)) = item.parse() {
                types.insert(idx, owned_primitive(&p));
            }
        }
    }

    // Build the browse list from the name index so each type appears once.
    let mut summaries: Vec<TypeSummaryEntry> = Vec::new();
    for (name, &index) in &by_name {
        let (size, kind) = match types.get(&index) {
            Some(OwnedType::Udt { size, kind, .. }) => (*size, *kind),
            Some(OwnedType::Enum { .. }) => (0, UdtKind::Enum),
            _ => continue,
        };
        summaries.push(TypeSummaryEntry {
            name: name.clone(),
            size,
            kind,
            index,
        });
    }
    summaries.sort_by(|a, b| a.name.cmp(&b.name));

    trace!(
        path = %pdb_path.display(),
        records = types.len(),
        named = by_name.len(),
        "Parsed PDB type information"
    );

    Ok(ModuleTypeInfo {
        types,
        by_name,
        summaries,
    })
}

fn convert_type_data(data: TypeData<'_>) -> OwnedType {
    match data {
        TypeData::Primitive(p) => owned_primitive(&p),
        TypeData::Class(c) => {
            let kind = match c.kind {
                pdb::ClassKind::Struct => UdtKind::Struct,
                pdb::ClassKind::Class | pdb::ClassKind::Interface => UdtKind::Class,
            };
            OwnedType::Udt {
                name: c.name.to_string().into_owned(),
                size: c.size as u32,
                fields: c.fields.map(|f| f.0),
                kind,
                forward: c.properties.forward_reference(),
            }
        }
        TypeData::Union(u) => OwnedType::Udt {
            name: u.name.to_string().into_owned(),
            size: u.size as u32,
            fields: Some(u.fields.0),
            kind: UdtKind::Union,
            forward: u.properties.forward_reference(),
        },
        TypeData::Enumeration(e) => OwnedType::Enum {
            name: e.name.to_string().into_owned(),
            underlying: e.underlying_type.0,
            fields: Some(e.fields.0),
            forward: e.properties.forward_reference(),
        },
        TypeData::Pointer(p) => {
            let size = match p.attributes.size() {
                0 => 8,
                s => s as u32,
            };
            OwnedType::Pointer {
                underlying: p.underlying_type.0,
                size,
            }
        }
        TypeData::Modifier(m) => OwnedType::Modifier {
            underlying: m.underlying_type.0,
        },
        TypeData::Array(a) => OwnedType::Array {
            element: a.element_type.0,
            // `dimensions` are byte sizes (aggregated for multi-dim); the first
            // (outermost) entry is the total byte size of the array.
            total_size: a.dimensions.first().copied().unwrap_or(0),
        },
        TypeData::Bitfield(b) => OwnedType::Bitfield {
            underlying: b.underlying_type.0,
            length: b.length,
            position: b.position,
        },
        TypeData::Procedure(_) | TypeData::MemberFunction(_) => OwnedType::Function,
        TypeData::FieldList(list) => {
            let mut members = Vec::new();
            let mut enumerates = Vec::new();
            for f in list.fields {
                match f {
                    TypeData::Member(m) => members.push(OwnedMember {
                        name: m.name.to_string().into_owned(),
                        field_type: m.field_type.0,
                        offset: m.offset as u32,
                    }),
                    TypeData::Enumerate(e) => enumerates.push(TypeEnumValue {
                        name: e.name.to_string().into_owned(),
                        value: variant_to_i64(&e.value),
                    }),
                    _ => {}
                }
            }
            OwnedType::FieldList {
                members,
                enumerates,
                continuation: list.continuation.map(|c| c.0),
            }
        }
        _ => OwnedType::Other,
    }
}

fn owned_primitive(p: &pdb::PrimitiveType) -> OwnedType {
    use pdb::PrimitiveKind::*;
    let (name, size, class): (&'static str, u32, TypeClass) = match p.kind {
        Void | NoType => ("void", 0, TypeClass::Void),
        Char | RChar => ("char", 1, TypeClass::Char),
        UChar => ("unsigned char", 1, TypeClass::UInt),
        I8 => ("__int8", 1, TypeClass::Int),
        U8 => ("unsigned __int8", 1, TypeClass::UInt),
        WChar | RChar16 => ("wchar_t", 2, TypeClass::WChar),
        RChar32 => ("char32_t", 4, TypeClass::WChar),
        Short | I16 => ("short", 2, TypeClass::Int),
        UShort | U16 => ("unsigned short", 2, TypeClass::UInt),
        Long | I32 => ("long", 4, TypeClass::Int),
        ULong | U32 => ("unsigned long", 4, TypeClass::UInt),
        Quad | I64 => ("__int64", 8, TypeClass::Int),
        UQuad | U64 => ("unsigned __int64", 8, TypeClass::UInt),
        Octa | I128 => ("__int128", 16, TypeClass::Int),
        UOcta | U128 => ("unsigned __int128", 16, TypeClass::UInt),
        F16 => ("__half", 2, TypeClass::Float),
        F32 | F32PP => ("float", 4, TypeClass::Float),
        F64 => ("double", 8, TypeClass::Float),
        F80 => ("long double", 10, TypeClass::Float),
        F128 => ("__float128", 16, TypeClass::Float),
        Bool8 => ("bool", 1, TypeClass::Bool),
        Bool16 => ("bool16", 2, TypeClass::Bool),
        Bool32 => ("bool32", 4, TypeClass::Bool),
        Bool64 => ("bool64", 8, TypeClass::Bool),
        HRESULT => ("HRESULT", 4, TypeClass::Int),
        _ => ("<primitive>", 0, TypeClass::Void),
    };
    OwnedType::Primitive {
        name,
        size,
        class,
        pointer: p.indirection.is_some(),
    }
}

fn variant_to_i64(v: &pdb::Variant) -> i64 {
    match v {
        pdb::Variant::U8(x) => *x as i64,
        pdb::Variant::U16(x) => *x as i64,
        pdb::Variant::U32(x) => *x as i64,
        pdb::Variant::U64(x) => *x as i64,
        pdb::Variant::I8(x) => *x as i64,
        pdb::Variant::I16(x) => *x as i64,
        pdb::Variant::I32(x) => *x as i64,
        pdb::Variant::I64(x) => *x as i64,
    }
}
