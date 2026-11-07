//! The decompiler over a file on disk: the offline image's `decompile`, the
//! names it takes from our symbols, the line → address map, and the request
//! queue. No process, no server.

mod common;

use common::get_test_program_path;
use joybug_core::decompiler::{self, DecompileError, DecompileRequest};
use joybug_core::static_image::StaticFile;

/// A fixture program, a function of it, and a function that calls that one.
#[cfg(windows)]
const FIXTURE: (&str, &str, &str) = ("xtea_test", "xtea_encrypt", "main");
#[cfg(target_os = "linux")]
const FIXTURE: (&str, &str, &str) = ("hello", "compute", "hello_marker");

fn open_fixture() -> StaticFile {
    StaticFile::open(&get_test_program_path(FIXTURE.0), None, None).expect("open the fixture")
}

fn symbol_va(image: &StaticFile, name: &str) -> u64 {
    image.base() + image.find_symbol_exact(name).unwrap_or_else(|| panic!("{name} symbol")).rva as u64
}

#[test]
fn decompiles_a_function_with_our_names_and_a_line_map() {
    let image = open_fixture();
    let (_, callee, caller) = FIXTURE;
    let callee_va = symbol_va(&image, callee);

    let function = image.decompile(callee_va).expect("decompile the callee");
    assert_eq!(function.start_rva, callee_va - image.base());
    assert_eq!(function.name, callee, "the function is named from our symbols");
    assert!(function.code.contains(callee) && function.code.contains("{"), "C text: {}", function.code);

    // Every mapped line is a real line of the text and points into the function.
    let line_count = function.code.lines().count() as u32;
    let (_, start, end, _) = image.disassemble_function(callee_va, 4000).expect("function listing");
    let (start, end) = (start.expect("bounds") - image.base(), end.expect("bounds") - image.base());
    assert!(!function.lines.is_empty(), "lines carry addresses");
    for mapping in &function.lines {
        assert!((1..=line_count).contains(&mapping.line), "line {} of {line_count}", mapping.line);
        assert!(mapping.rvas.windows(2).all(|w| w[0] < w[1]), "sorted, unique");
        for rva in &mapping.rvas {
            assert!((start..end).contains(rva), "{rva:#x} outside {start:#x}..{end:#x}");
        }
    }

    // An address in the middle of the function selects the same function.
    let inside = image.base() + function.lines.last().unwrap().rvas[0];
    assert_ne!(inside, callee_va);
    let again = image.decompile(inside).expect("decompile by an inner address");
    assert_eq!((again.start_rva, &again.code), (function.start_rva, &function.code));

    // The caller names its callee by our symbol, not by an address.
    let calling = image.decompile(symbol_va(&image, caller)).expect("decompile the caller");
    assert!(calling.code.contains(callee), "{caller} calls {callee}: {}", calling.code);
}

#[test]
fn rejects_what_is_not_a_function_or_an_image() {
    let image = open_fixture();
    assert!(matches!(image.decompile(image.base() - 1), Err(DecompileError::NoFunction)));

    let not_an_image = std::env::temp_dir().join(format!("joybug-decompile-{}.txt", std::process::id()));
    std::fs::write(&not_an_image, b"plain text").unwrap();
    let request = DecompileRequest {
        image_path: not_an_image.to_string_lossy().into_owned(),
        rva: 0,
        function: None,
        symbols: None,
        client: None,
    };
    let result = decompiler::global().decompile(request.clone());
    assert!(matches!(result, Err(DecompileError::Load(_))), "{result:?}");
    std::fs::remove_file(&not_an_image).unwrap();
    let result = decompiler::global().decompile(request);
    assert!(matches!(result, Err(DecompileError::Load(_))), "a missing file: {result:?}");
}

/// A debug MSVC build calls its functions through `jmp` thunks no symbol
/// names. A caller shows them under the name of where they lead, and the
/// thunk's own address decompiles as the thunk — not as the tail of the
/// function the engine happens to know before it.
#[cfg(windows)]
#[test]
fn names_jump_thunks_after_their_targets() {
    let image = open_fixture();
    let (_, callee, caller) = FIXTURE;
    let (listing, ..) = image.disassemble_function(symbol_va(&image, caller), 4000).expect("caller listing");
    let thunk = listing
        .iter()
        .filter(|i| i.is_call)
        .filter_map(|i| i.jump_target)
        .find(|&target| {
            let first = image.disassemble(target, 1).ok().and_then(|v| v.into_iter().next());
            first.is_some_and(|i| i.mnemonic == "jmp" && i.jump_target == Some(symbol_va(&image, callee)))
        })
        .expect("the caller reaches the callee through a jmp thunk");

    let calling = image.decompile(symbol_va(&image, caller)).expect("decompile the caller");
    assert!(!calling.code.contains(&format!("sub_{thunk:x}")), "the thunk is named: {}", calling.code);

    let function = image.decompile(thunk).expect("decompile the thunk");
    assert_eq!(function.start_rva, thunk - image.base(), "the thunk is a function of its own");
    assert!(function.code.contains(callee), "it leads to {callee}: {}", function.code);
}

/// ELF files must decompile on Windows too, at RVAs relative to their PT_LOAD
/// base rather than being passed to the PE parser.
#[test]
fn decompiles_elf_at_its_link_time_base() {
    // A self-contained ELF64 executable: one load segment, .text returning 42,
    // and a section-name table. No cross compiler or platform fixture is needed.
    let mut bytes = vec![0u8; 0x160];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value) in [(16, 2u16), (18, 62), (52, 64), (54, 56), (56, 1), (58, 64), (60, 3), (62, 2)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(20, 1u32), (64, 1), (68, 5), (0xe0, 1), (0xe4, 1), (0x120, 7), (0x124, 3)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (24, 0x40_0080u64), (32, 64), (40, 0xa0),
        (80, 0x40_0000), (88, 0x40_0000), (96, 0x160), (104, 0x160), (112, 0x1000),
        (0xe8, 6), (0xf0, 0x40_0080), (0xf8, 0x80), (0x100, 6), (0x110, 16),
        (0x138, 0x88), (0x140, 17), (0x150, 1),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x80..0x86].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    bytes[0x88..0x99].copy_from_slice(b"\0.text\0.shstrtab\0");
    let path = std::env::temp_dir().join(format!("joybug-decompiler-elf-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let image = StaticFile::open(path.to_str().unwrap(), None, None).expect("open ELF");
    assert_eq!(image.base(), 0x40_0000);
    let mut request = image.decompile_request(image.base() + 0x80, None).unwrap();
    request.function = Some((0x80, 0x86));
    request.symbols = Some(decompiler::SymbolSet::new(vec![(0x80, "answer".into())]));
    let result = decompiler::global().decompile(request);
    std::fs::remove_file(&path).unwrap();
    let function = result.expect("decompile ELF");
    assert_eq!(function.name, "answer");
    assert_eq!((function.start_rva, function.size), (0x80, 6));
    assert!(regex::Regex::new(r"return\s+(?:42|0x2a)\s*;").unwrap().is_match(&function.code), "{}", function.code);
    for mapping in &function.lines {
        assert!(mapping.rvas.iter().all(|rva| (0x80..0x86).contains(rva)), "ELF line addresses are RVAs");
    }
}
