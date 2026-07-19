// Verifies PE parsing surfaces the entry point and TLS callbacks
// (ModuleExtraInfo.tls_callbacks) without needing a live debug session.
mod common;

use common::get_test_program_path;
use joybug2::windows_platform::parse_module_extra_info_from_bytes;

#[test]
fn tls_test_exposes_entry_point_and_tls_callbacks() {
    let exe = get_test_program_path("tls_test");
    let bytes = std::fs::read(&exe).expect("read tls_test.exe");

    let info = parse_module_extra_info_from_bytes(&bytes).expect("parse PE");

    let entry_rva = info.nt_headers.OptionalHeader.AddressOfEntryPoint;
    assert!(entry_rva != 0, "entry point RVA should be non-zero");

    assert!(
        !info.tls_callbacks.is_empty(),
        "tls_test.exe should have at least one TLS callback, got none"
    );

    // Every callback RVA must land inside the image.
    let image_size = info.nt_headers.OptionalHeader.SizeOfImage;
    for &rva in &info.tls_callbacks {
        assert!(rva != 0, "TLS callback RVA should be non-zero");
        assert!(rva < image_size, "TLS callback RVA 0x{:X} outside image (size 0x{:X})", rva, image_size);
    }
}
