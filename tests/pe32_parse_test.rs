// PE32 (32-bit x86) parsing through the format-agnostic pelite wrap: header
// widening, 4-byte IAT slots, no exception directory, TLS callbacks, and PDB
// identification. Uses the system's SysWOW64 images so no debug session or
// cross-compiled fixture is needed; a host without a WOW64 layer skips.
#![cfg(windows)]

use joybug_core::pe_types::{ImportKind, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC};
use joybug_core::windows_platform::parse_module_extra_info_from_bytes;
use joybug_core::windows_platform::extract_pdb_identifier_from_file;
use std::path::{Path, PathBuf};

const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

fn windows_dir() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()))
}

/// `Some(bytes)` for a system image, `None` (with a note) when it is absent.
fn read_system_image(sub: &str, name: &str) -> Option<(PathBuf, Vec<u8>)> {
    let path = windows_dir().join(sub).join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Some((path, bytes)),
        Err(e) => {
            println!("skipping: cannot read {}: {}", path.display(), e);
            None
        }
    }
}

/// Stride between the IAT slots of consecutive by-name entries in the first
/// descriptor that has at least two of them.
fn first_iat_stride(info: &joybug_core::pe_types::ModuleExtraInfo) -> Option<u32> {
    info.imports.iter().find_map(|desc| {
        let slots: Vec<u32> = desc
            .entries
            .iter()
            .filter(|e| matches!(e.kind, ImportKind::Item(_)))
            .map(|e| e.iat_rva)
            .collect();
        (slots.len() >= 2).then(|| slots[1] - slots[0])
    })
}

#[test]
fn pe32_kernel32_headers_imports_exports() {
    let Some((_, bytes)) = read_system_image("SysWOW64", "kernel32.dll") else { return };
    let info = parse_module_extra_info_from_bytes(&bytes).expect("parse PE32");

    let fh = &info.nt_headers.FileHeader;
    let oh = &info.nt_headers.OptionalHeader;
    assert_eq!(fh.Machine, IMAGE_FILE_MACHINE_I386);
    assert_eq!(oh.Magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    assert!(oh.is_pe32());
    assert_eq!(oh.pointer_size(), 4);
    assert!(oh.BaseOfData.is_some(), "PE32 carries BaseOfData");
    assert!(oh.ImageBase != 0 && oh.ImageBase <= u32::MAX as u64, "ImageBase {:#x} must fit 32 bits", oh.ImageBase);
    assert!(oh.SizeOfStackReserve <= u32::MAX as u64);
    assert!(info.sections.iter().any(|s| s.Name.starts_with(b".text")));

    // Imports: real entries, every slot inside the IAT directory, 4-byte stride.
    let iat = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    assert!(iat.VirtualAddress != 0, "kernel32 has an IAT directory");
    let entries: Vec<_> = info
        .imports
        .iter()
        .flat_map(|d| d.entries.iter())
        .filter(|e| matches!(e.kind, ImportKind::Item(_)))
        .collect();
    assert!(!entries.is_empty(), "expected named imports, got {:?}", info.imports.first().map(|d| &d.dll_name));
    for e in &entries {
        assert!(
            e.iat_rva >= iat.VirtualAddress && e.iat_rva < iat.VirtualAddress + iat.Size,
            "IAT slot {:#x} outside IAT dir [{:#x}, {:#x})",
            e.iat_rva, iat.VirtualAddress, iat.VirtualAddress + iat.Size
        );
    }
    assert_eq!(first_iat_stride(&info), Some(4), "PE32 IAT slots are 4 bytes apart");

    // Exports and the (absent) exception directory.
    let exports = info.exports.as_ref().expect("kernel32 exports");
    assert!(exports.entries.iter().any(|e| e.name.as_deref() == Some("CreateFileW")));
    assert!(info.runtime_functions.is_none(), "x86 images have no exception directory");
}

#[test]
fn pe32_tls_directory_with_no_callbacks_parses() {
    // kernelbase.dll (32-bit) has a TLS directory whose callback table is empty:
    // exercises the `Wrap::T32` callbacks arm without producing entries.
    let Some((_, bytes)) = read_system_image("SysWOW64", "kernelbase.dll") else { return };
    let info = parse_module_extra_info_from_bytes(&bytes).expect("parse PE32");
    assert!(info.nt_headers.OptionalHeader.is_pe32());
    let image_size = info.nt_headers.OptionalHeader.SizeOfImage;
    for &rva in &info.tls_callbacks {
        assert!(rva != 0 && rva < image_size, "TLS callback RVA {:#x} outside image", rva);
    }
}

#[test]
fn pe32plus_kernel32_still_parses_as_64bit() {
    // Regression guard for the wrap migration: the 64-bit image keeps its
    // 8-byte IAT stride, has no BaseOfData and does have an exception directory.
    let Some((_, bytes)) = read_system_image("System32", "kernel32.dll") else { return };
    let info = parse_module_extra_info_from_bytes(&bytes).expect("parse PE32+");
    let oh = &info.nt_headers.OptionalHeader;
    assert_eq!(oh.Magic, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    assert!(!oh.is_pe32());
    assert!(oh.BaseOfData.is_none());
    assert_eq!(first_iat_stride(&info), Some(8));
    assert!(info.runtime_functions.as_ref().is_some_and(|rf| !rf.is_empty()));
}

#[test]
fn pe32_pdb_identifier_is_extracted() {
    let Some((path, _)) = read_system_image("SysWOW64", "kernel32.dll") else { return };
    let id = extract_pdb_identifier_from_file(Path::new(&path)).expect("CodeView record from PE32");
    assert!(id.name.to_ascii_lowercase().ends_with("kernel32.pdb"), "pdb name {:?}", id.name);
    assert!(id.age > 0);
}
