//! The offline image over an ELF file: headers, symbols, disassembly,
//! strings, byte search, xrefs, function recovery and process-less emulation,
//! on every OS (the file is just bytes). Uses the `hello` test program.
mod common;
use common::get_test_program_path;
use joybug_core::protocol::StringEncodingFilter;
use joybug_core::static_elf::ElfImage;
use joybug_core::static_image::{EmulateSpec, StaticFile};

fn open_hello() -> ElfImage {
    let path = get_test_program_path("hello");
    ElfImage::open(&path, None, None).expect("open hello as an image")
}

#[test]
fn elf_image_headers_symbols_and_code_views() {
    let img = open_hello();
    assert_eq!(img.base(), 0x400000, "non-PIE hello links at 0x400000");
    // The format-neutral entry point sorts the file by its magic.
    let any = StaticFile::open(&get_test_program_path("hello"), None, None).expect("open by magic");
    assert_eq!(any.format(), "elf");
    assert!(joybug_core::static_pe::PeImage::open(&get_test_program_path("hello"), None, None).is_err(), "PeImage stays PE-only");
    assert!(img.entry_point() > img.base());
    assert!(img.info().sections.iter().any(|s| s.name_string() == ".text"));

    // Symbols come from the ELF's own table at open; no PDB involved.
    assert!(img.has_symbols());
    let main = img.find_symbol_exact("main").expect("main symbol");
    let main_va = img.base() + main.rva as u64;
    assert!(img.find_symbol_exact("hello!compute").is_some(), "module-qualified lookup");

    // Disassembly at the entry and at main, symbolised.
    let at_entry = img.disassemble(img.entry_point(), 8).expect("disassemble entry");
    assert!(at_entry.len() >= 4);
    let (insns, _, _, _) = img.disassemble_function(main_va, 200).expect("function listing");
    assert!(insns.iter().any(|i| i.mnemonic == "call"), "main calls hello_marker");

    // Strings and bytes from the mapped image.
    let hits = img.strings(5, StringEncodingFilter::Both, "hello from");
    assert!(hits.iter().any(|h| h.text.contains("hello from the debuggee")), "{:?}", hits.iter().map(|h| &h.text).collect::<Vec<_>>());
    let endbr = img.find_bytes("F3 0F 1E FA", 10).expect("pattern");
    assert!(!endbr.is_empty());

    // Cross references: `_start` passes `main` to `__libc_start_main`, so
    // something references it; functions are recovered from .eh_frame + symbols.
    assert!(!img.xrefs_to(main_va).is_empty(), "xrefs to main");
    assert!(img.functions().iter().any(|f| f.start == main_va), "main is a recovered function");
    assert!(img.functions().iter().any(|f| f.source == "pdata"), ".eh_frame-sourced functions");
}

#[test]
fn elf_image_emulates_a_function_without_a_process() {
    let img = open_hello();
    let compute = img.find_symbol_exact("compute").expect("compute");
    let va = img.base() + compute.rva as u64;
    // compute(x): g_counter += x; return g_counter * 2 — g_counter starts at 0
    // in the mapped .data/.bss, so compute(21) is 42.
    let mut spec = EmulateSpec::at(va);
    spec.registers.push(("rdi".to_string(), 21));
    let result = img.emulate(&spec).expect("emulate compute");
    let joybug_core::protocol::RegisterSnapshot::X64(regs) = &result.final_registers else { panic!("x64 registers") };
    assert_eq!(regs.rax, 42, "stop: {:?}", result.stop_reason);
}
