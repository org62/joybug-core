#![cfg(windows)]

mod common;

use common::TestServer;
use joybug2::protocol_io::DebugSession;
use joybug2::pe_types::{ExportKind, ImportItem, ImportKind};
use pelite::pe64::image::IMAGE_NT_HEADERS_SIGNATURE;
use std::path::Path;

#[test]
fn test_module_extra_info_print() {
    joybug2::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let _ = DebugSession::new((), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            let modules = session.list_modules(pid)?;
            println!("Modules: {:?}", modules);
            // Find kernel32.dll specifically (case-insensitive, matches by file name)
            let kernel32_mod = modules.iter().find(|m| {
                let file_name = Path::new(&m.name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&m.name);
                file_name.eq_ignore_ascii_case("kernelbase.dll")
            });

            if let Some(k32) = kernel32_mod {
                println!("Selected module: {} @ 0x{:x}", k32.name, k32.base);
                let info = session.get_module_extra_info(pid, k32.base)?;
                println!("DOS Header:\n{}", info.dos_header);
                println!("NT Headers:\n{}", info.nt_headers);
                println!("Sections ({}):", info.sections.len());
                for (i, sec) in info.sections.iter().enumerate() {
                    println!("#{}\n{}", i, sec);
                }
                println!("Imports ({}):", info.imports.len());
                for imp in &info.imports {
                    println!("{}", imp);
                }
                if let Some(exports) = &info.exports {
                    println!("Exports ({}):", exports.entries.len());
                    println!("{}", exports);
                } else {
                    println!("Exports: <none>");
                }

                // Runtime function info (Exception Directory)
                if let Some(rfs) = &info.runtime_functions {
                    println!("\nRUNTIME_FUNCTION Information (Exception Directory):");
                    println!("Number of RUNTIME_FUNCTION entries: {}", rfs.len());
                    println!("{:<8} {:<12} {:<12} {:<12} {:<12}", "Index", "BeginAddr", "EndAddr", "UnwindData", "Size");
                    println!("{}", "-".repeat(64));
                    for (i, rf) in rfs.iter().enumerate() {
                        let size = rf.EndAddress.saturating_sub(rf.BeginAddress);
                        println!(
                            "{:<8} {:#010x}   {:#010x}   {:#010x}   {:#010x}",
                            i,
                            rf.BeginAddress,
                            rf.EndAddress,
                            rf.UnwindData,
                            size
                        );
                    }
                } else {
                    println!("\nRUNTIME_FUNCTION Information (Exception Directory): <none>");
                }
                // Assertions begin
                // 1) NT headers signature matches pelite's IMAGE_NT_HEADERS_SIGNATURE
                assert_eq!(
                    info.nt_headers.Signature,
                    IMAGE_NT_HEADERS_SIGNATURE,
                    "Unexpected NT headers signature",
                );

                // 2) Ensure .text section is present
                let has_text_section = info
                    .sections
                    .iter()
                    .any(|s| s.name_string().eq_ignore_ascii_case(".text"));
                assert!(has_text_section, ".text section not found");

                // 3) Ensure NtTerminateProcess is imported from ntdll
                let has_nt_terminate_process_import = info.imports.iter().any(|desc| {
                    desc.dll_name.eq_ignore_ascii_case("ntdll.dll")
                        && desc.entries.iter().any(|e| match &e.kind {
                            ImportKind::Item(ImportItem::ByName { name, .. }) => {
                                name == "NtTerminateProcess"
                            }
                            _ => false,
                        })
                });
                assert!(
                    has_nt_terminate_process_import,
                    "NtTerminateProcess import from ntdll.dll not found"
                );

                // 4) Ensure WriteConsoleA is present in exports and capture its RVA
                let exports = info
                    .exports
                    .as_ref()
                    .expect("Module has no exports while expecting WriteConsoleA");
                let write_console_entry = exports
                    .entries
                    .iter()
                    .find(|e| e.name.as_deref() == Some("WriteConsoleA"))
                    .expect("WriteConsoleA export not found");

                let write_console_rva = match write_console_entry.kind {
                    ExportKind::Symbol { rva } => rva,
                    ExportKind::Forward { .. } => panic!(
                        "WriteConsoleA is a forwarded export; no RVA to validate against runtime functions"
                    ),
                    ExportKind::Error(ref e) => panic!("Export error for WriteConsoleA: {}", e),
                };

                // 5) RVA of WriteConsoleA should be covered by a RUNTIME_FUNCTION entry
                let runtime_functions = info
                    .runtime_functions
                    .as_ref()
                    .expect("No runtime functions present to validate against");
                let covered_by_rf = runtime_functions.iter().any(|rf| {
                    // Treat ranges as [BeginAddress, EndAddress)
                    (rf.BeginAddress <= write_console_rva) && (write_console_rva < rf.EndAddress)
                });
                assert!(
                    covered_by_rf,
                    "WriteConsoleA RVA {:#x} is not covered by any RUNTIME_FUNCTION entry",
                    write_console_rva
                );
                // Assertions end
            } else {
                panic!("kernel32.dll not found in module list");
            }
            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("Debug session failed");
}


