#![cfg(target_os = "linux")]
//! DWARF type information through the ELF symbol backend, on the `hello`
//! test program's own structs.
mod common;
use common::get_test_program_path;
use joybug_core::elf::symbols::ElfBackend;
use joybug_core::protocol::{TypeClass, UdtKind};
use joybug_core::symbols::backend::SymbolBackend;
use std::path::Path;

#[test]
fn dwarf_structs_enums_and_bitfields_resolve() {
    let hello = get_test_program_path("hello");
    let info = ElfBackend.parse_types(Path::new(&hello)).expect("DWARF types");

    let shape = info.resolve_by_name("Shape", 0x400000).expect("struct Shape");
    assert_eq!(shape.kind, UdtKind::Struct);
    assert!(shape.size >= 48, "size {}", shape.size);
    let by_name = |n: &str| shape.members.iter().find(|m| m.name == n).unwrap_or_else(|| panic!("member {n}"));
    let origin = by_name("origin");
    assert_eq!(origin.offset, 0);
    assert!(matches!(origin.type_ref.class, TypeClass::Udt { .. }), "{:?}", origin.type_ref.class);
    assert_eq!(origin.type_ref.name, "Point");
    let flags = by_name("flags");
    assert_eq!(flags.bit_length, Some(3));
    assert_eq!(flags.bit_position, Some(0));
    let filled = by_name("filled");
    assert_eq!(filled.bit_length, Some(1));
    assert_eq!(filled.bit_position, Some(3));
    let color = by_name("color");
    assert!(matches!(color.type_ref.class, TypeClass::Enum { .. }));
    let name = by_name("name");
    assert!(matches!(name.type_ref.class, TypeClass::Pointer { .. }));
    assert_eq!(name.type_ref.size, 8);
    let scale = by_name("scale");
    assert!(matches!(scale.type_ref.class, TypeClass::Array { count: 4, .. }), "{:?}", scale.type_ref);
    assert_eq!(scale.type_ref.size, 32);

    let color = info.resolve_by_name("Color", 0).expect("enum Color");
    assert_eq!(color.kind, UdtKind::Enum);
    assert_eq!(color.enum_values.iter().map(|v| (v.name.as_str(), v.value)).collect::<Vec<_>>(), vec![("RED", 0), ("GREEN", 1), ("BLUE", 2)]);

    let word = info.resolve_by_name("Word", 0).expect("union Word");
    assert_eq!(word.kind, UdtKind::Union);
    assert_eq!(word.size, 4);
    assert!(word.members.iter().all(|m| m.offset == 0));

    assert!(info.summaries().iter().any(|s| s.name == "Point"));
}
