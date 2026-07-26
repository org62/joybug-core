#![cfg(windows)]

mod common;

use common::TestServer;
use joybug_core::formatting::memory::{protect_to_str, state_to_str, type_to_str};
use joybug_core::protocol_io::DebugSession;
use std::path::Path;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_READONLY, PAGE_READWRITE,
};

#[test]
fn test_memory_regions() {
    joybug_core::init_tracing();

    let server = TestServer::spawn();
    let server_addr = server.address().to_string();

    let _ = DebugSession::new((), Some(server_addr.as_str()))
        .expect("Failed to connect to debug server")
        .on_initial_breakpoint(|session, pid, _tid, _addr| {
            // =============================================
            // TEST 1: Enumerate all memory regions
            // =============================================
            println!("\n========== TEST 1: Enumerate Memory Regions ==========\n");

            let regions = session.enumerate_memory_regions(pid)?;

            println!("=== Memory Regions ({} total) ===\n", regions.len());
            println!(
                "{:<18} {:>12} {:>12} {:>20} {:>12}",
                "Base Address", "Size", "State", "Type", "Protect"
            );
            println!("{}", "-".repeat(80));

            // Print first 20 committed regions for brevity
            let committed_regions: Vec<_> = regions
                .iter()
                .filter(|r| r.state == MEM_COMMIT)
                .take(20)
                .collect();

            for region in &committed_regions {
                println!(
                    "{:#018x} {:>12} {:>12} {:>20} {:>12}",
                    region.base_address,
                    format!("{:#x}", region.region_size),
                    state_to_str(region.state),
                    type_to_str(region.region_type),
                    protect_to_str(region.protect),
                );
            }

            // Assertions
            assert!(!regions.is_empty(), "Should have at least one memory region");

            // Count regions by state
            let committed_count = regions.iter().filter(|r| r.state == MEM_COMMIT).count();
            let reserved_count = regions
                .iter()
                .filter(|r| state_to_str(r.state) == "MEM_RESERVE")
                .count();
            let free_count = regions
                .iter()
                .filter(|r| state_to_str(r.state) == "MEM_FREE")
                .count();

            println!("\n=== Summary ===");
            println!("Committed regions: {}", committed_count);
            println!("Reserved regions: {}", reserved_count);
            println!("Free regions: {}", free_count);

            assert!(committed_count > 0, "Should have committed regions");

            // Count regions by type
            let image_count = regions.iter().filter(|r| r.region_type == MEM_IMAGE).count();
            let private_count = regions.iter().filter(|r| r.region_type == MEM_PRIVATE).count();
            let mapped_count = regions
                .iter()
                .filter(|r| type_to_str(r.region_type) == "MEM_MAPPED")
                .count();

            println!("Image regions: {}", image_count);
            println!("Private regions: {}", private_count);
            println!("Mapped regions: {}", mapped_count);

            assert!(image_count > 0, "Should have image regions (loaded modules)");

            // Verify regions don't overlap
            let mut prev_end: u64 = 0;
            for region in &regions {
                assert!(
                    region.base_address >= prev_end,
                    "Regions should not overlap: prev_end={:#x}, base={:#x}",
                    prev_end,
                    region.base_address
                );
                prev_end = region.base_address.saturating_add(region.region_size);
            }

            // =============================================
            // TEST 2: Query memory region by address
            // =============================================
            println!("\n========== TEST 2: Query Memory Region by Address ==========\n");

            let modules = session.list_modules(pid)?;

            // Find kernel32.dll or kernelbase.dll
            let target_module = modules.iter().find(|m| {
                let file_name = Path::new(&m.name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&m.name);
                file_name.eq_ignore_ascii_case("kernel32.dll")
                    || file_name.eq_ignore_ascii_case("kernelbase.dll")
            });

            let module = target_module.expect("Should find kernel32.dll or kernelbase.dll");
            println!("Testing with module: {} @ {:#x}", module.name, module.base);

            // Query memory region at the module base address
            let region = session.query_memory_region(pid, module.base)?;

            println!("\n=== Memory Region at Module Base ===");
            println!("Base Address:       {:#018x}", region.base_address);
            println!("Allocation Base:    {:#018x}", region.allocation_base);
            println!("Region Size:        {:#x}", region.region_size);
            println!(
                "State:              {} ({:#x})",
                state_to_str(region.state),
                region.state
            );
            println!(
                "Type:               {} ({:#x})",
                type_to_str(region.region_type),
                region.region_type
            );
            println!(
                "Protect:            {} ({:#x})",
                protect_to_str(region.protect),
                region.protect
            );

            // Assertions for module memory region
            assert_eq!(
                region.base_address, module.base,
                "Region base should match module base"
            );
            assert_eq!(
                region.allocation_base, module.base,
                "Allocation base should match module base"
            );
            assert_eq!(
                region.state, MEM_COMMIT,
                "Module memory should be committed"
            );
            assert_eq!(
                region.region_type, MEM_IMAGE,
                "Module memory should be MEM_IMAGE type"
            );

            // Query a region slightly into the module
            let offset_addr = module.base + 0x1000;
            let offset_region = session.query_memory_region(pid, offset_addr)?;

            println!("\n=== Memory Region at Module Base + 0x1000 ===");
            println!("Query Address:      {:#018x}", offset_addr);
            println!("Base Address:       {:#018x}", offset_region.base_address);
            println!("Allocation Base:    {:#018x}", offset_region.allocation_base);

            assert_eq!(
                offset_region.allocation_base, module.base,
                "Offset region allocation base should still be module base"
            );
            assert_eq!(
                offset_region.region_type, MEM_IMAGE,
                "Offset region should still be MEM_IMAGE"
            );

            // =============================================
            // TEST 3: Protection flags analysis
            // =============================================
            println!("\n========== TEST 3: Protection Flags Analysis ==========\n");

            let executable_regions: Vec<_> = regions
                .iter()
                .filter(|r| r.state == MEM_COMMIT && (r.protect & 0xF0) != 0)
                .collect();

            let readonly_regions: Vec<_> = regions
                .iter()
                .filter(|r| r.state == MEM_COMMIT && r.protect == PAGE_READONLY)
                .collect();

            let readwrite_regions: Vec<_> = regions
                .iter()
                .filter(|r| r.state == MEM_COMMIT && r.protect == PAGE_READWRITE)
                .collect();

            println!(
                "Executable regions (PAGE_EXECUTE*): {}",
                executable_regions.len()
            );
            println!(
                "Read-only regions (PAGE_READONLY): {}",
                readonly_regions.len()
            );
            println!(
                "Read-write regions (PAGE_READWRITE): {}",
                readwrite_regions.len()
            );

            println!("\nSample executable regions:");
            for region in executable_regions.iter().take(5) {
                println!(
                    "  {:#018x} - size: {:#x}, protect: {} ({:#x})",
                    region.base_address,
                    region.region_size,
                    protect_to_str(region.protect),
                    region.protect
                );
            }

            assert!(
                !executable_regions.is_empty(),
                "Should have executable regions"
            );
            assert!(
                !readwrite_regions.is_empty(),
                "Should have read-write regions"
            );

            println!("\n========== ALL TESTS PASSED ==========\n");
            Ok(())
        })
        .launch("cmd.exe /c echo test".to_string())
        .expect("Debug session failed");
}
