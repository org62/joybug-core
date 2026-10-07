#![cfg(target_os = "linux")]
//! The on-disk image of an ELF module maps file bytes to the right runtime
//! addresses (the Image Patches diff depends on it).
mod common;
use common::get_test_program_path;
use joybug_core::pe_image::OriginalModuleImage;
use object::{Object, ObjectSection};

#[test]
fn elf_image_bytes_match_the_file_at_runtime_addresses() {
    // `hello` is linked without PIE: its lowest PT_LOAD is at 0x400000.
    let path = get_test_program_path("hello");
    let data = std::fs::read(&path).expect("read");
    let file = object::File::parse(&*data).expect("parse");
    let text = file.section_by_name(".text").expect(".text");
    let (off, _) = text.file_range().expect("file range");
    let base = 0x400000u64;
    let image = OriginalModuleImage::build(&path, base);
    assert!(!image.unavailable);
    let va = base + (text.address() - 0x400000);
    let got = image.bytes_at(va, 16).expect("bytes at .text");
    assert_eq!(got, &data[off as usize..off as usize + 16]);
    assert!(image.is_code(va));
    assert!(!image.comparable_code_ranges().is_empty());
}
