#![cfg(windows)]

#[allow(unused_imports)]
pub use joybug2::local_server::LocalServer as TestServer;
use joybug2::interfaces::{Architecture, InstructionFormatter, ResolvedSymbol};
use joybug2::protocol::ModuleInfo;
use joybug2::protocol_io::DebugSession;

/// Get the path to a compiled test program exe built by build.rs.
#[allow(dead_code)]
/// Searches OUT_DIR first, then falls back to scanning target/{debug,release}/build/*/out/.
pub fn get_test_program_path(name: &str) -> String {
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        format!("{}\\target\\debug\\build", manifest_dir)
    });

    let expected_path = format!("{}\\{}.exe", out_dir, name);
    if std::path::Path::new(&expected_path).exists() {
        return expected_path;
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for profile in &["debug", "release"] {
        let search_dir = format!("{}\\target\\{}\\build", manifest_dir, profile);
        if let Ok(entries) = std::fs::read_dir(&search_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let candidate = entry.path().join("out").join(format!("{}.exe", name));
                    if candidate.exists() {
                        return candidate.to_string_lossy().to_string();
                    }
                }
            }
        }
    }

    panic!(
        "Could not find {}.exe. Make sure to build the project first.",
        name
    );
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
    let arch = Architecture::from_native();
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
