#[allow(unused_imports)]
pub use joybug_core::local_server::LocalServer as TestServer;
use joybug_core::interfaces::{Architecture, InstructionFormatter, ResolvedSymbol};
use joybug_core::protocol::ModuleInfo;
use joybug_core::protocol_io::DebugSession;

/// Get the path to a compiled test program built by build.rs.
#[allow(dead_code)]
/// Searches OUT_DIR first, then falls back to scanning target/{debug,release}/build/*/out/.
pub fn get_test_program_path(name: &str) -> String {
    try_get_test_program_path(name).unwrap_or_else(|| {
        panic!(
            "Could not find {}{}. Make sure to build the project first.",
            name,
            std::env::consts::EXE_SUFFIX
        )
    })
}

/// [`get_test_program_path`] that returns `None` instead of panicking - for
/// fixtures build.rs may legitimately skip (the 32-bit `*32.exe` programs
/// need an x86 cross toolchain).
#[allow(dead_code)]
pub fn try_get_test_program_path(name: &str) -> Option<String> {
    use std::path::{Path, PathBuf};
    let file_name = format!("{}{}", name, std::env::consts::EXE_SUFFIX);
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_dir = std::env::var("OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("target").join("debug").join("build"));

    let expected_path = out_dir.join(&file_name);
    if expected_path.exists() {
        return Some(expected_path.to_string_lossy().to_string());
    }

    for profile in &["debug", "release"] {
        let search_dir = manifest_dir.join("target").join(profile).join("build");
        if let Ok(entries) = std::fs::read_dir(&search_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let candidate = entry.path().join("out").join(&file_name);
                    if candidate.exists() {
                        return Some(candidate.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    None
}

/// Case-insensitive file-name match: does `image_name`'s basename equal `target`?
#[allow(dead_code)]
pub fn module_file_name_matches(image_name: &str, target: &str) -> bool {
    std::path::Path::new(image_name)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|f| f.eq_ignore_ascii_case(target))
        .unwrap_or(false)
}

/// Enumerate unique function-entry VAs for a loaded module from its
/// RUNTIME_FUNCTION table (PE exception directory): filters invalid entries
/// (`EndAddress <= BeginAddress`), dedupes by `BeginAddress`, and returns
/// `module_base + BeginAddress` for each. Returns an empty vec (with a WARN
/// print) when the module has no extra info or no exception directory.
#[allow(dead_code)]
#[cfg(windows)]
pub fn runtime_function_entry_vas<T>(
    session: &mut DebugSession<T>,
    pid: u32,
    module_base: u64,
) -> Vec<u64> {
    let info = match session.get_module_extra_info(pid, module_base) {
        Ok(info) => info,
        Err(e) => {
            println!("  WARN: Failed to get extra info for module @ 0x{:x}: {}", module_base, e);
            return Vec::new();
        }
    };
    let Some(rfs) = &info.runtime_functions else {
        println!("  WARN: No RUNTIME_FUNCTION entries for module @ 0x{:x}", module_base);
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    rfs.iter()
        .filter(|rf| rf.EndAddress > rf.BeginAddress)
        .filter(|rf| seen.insert(rf.BeginAddress))
        .map(|rf| module_base + rf.BeginAddress as u64)
        .collect()
}

/// Find a symbol by query string, filtered to a specific module.
#[allow(dead_code)]
pub fn find_symbol<T>(
    session: &mut DebugSession<T>,
    query: &str,
    module_filter: &str,
) -> anyhow::Result<ResolvedSymbol> {
    session
        .find_symbols(query, 10)?
        .into_iter()
        .find(|s| s.module_name.to_lowercase().contains(&module_filter.to_lowercase()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Could not find symbol '{}' in module '{}'",
                query,
                module_filter
            )
        })
}

/// Find a module by name substring.
#[allow(dead_code)]
pub fn find_module<T>(
    session: &mut DebugSession<T>,
    pid: u32,
    name: &str,
) -> anyhow::Result<ModuleInfo> {
    session
        .list_modules(pid)?
        .into_iter()
        .find(|m| m.name.to_lowercase().contains(&name.to_lowercase()))
        .ok_or_else(|| anyhow::anyhow!("Could not find module containing '{}'", name))
}

/// Print disassembly at the given address and the current call stack.
#[allow(dead_code)]
pub fn print_disassembly_and_callstack<T>(
    session: &mut DebugSession<T>,
    pid: u32,
    tid: u32,
    address: u64,
) -> anyhow::Result<()> {
    let arch = session.get_process_architecture(pid).unwrap_or_else(|_| Architecture::from_native());
    let disassembly = session.disassemble_memory(pid, address, 10, arch)?;
    println!("{}", disassembly.format_disassembly());
    let call_stack = session.get_call_stack(pid, tid)?;
    println!("Call stack:");
    for frame in call_stack {
        if let Some(symbol) = &frame.symbol {
            println!("  {}", symbol.format_symbol());
        } else {
            panic!("  Symbol: <unknown>");
        }
    }
    Ok(())
}
