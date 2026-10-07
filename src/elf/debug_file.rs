//! Separate debug files for stripped ELF modules, found the way gdb finds
//! them. Distributions strip `.symtab` and DWARF out of their binaries into
//! `-dbg`/`-dbgsym` packages, so the module itself yields a handful of
//! `.dynsym` exports and nothing else; its debug file is located
//!
//! 1. by GNU build-id: `/usr/lib/debug/.build-id/xx/yyyy....debug`, and the
//!    debuginfod client cache (`~/.cache/debuginfod_client/<id>/debuginfo`),
//! 2. by `.gnu_debuglink`: the named file next to the module, under its
//!    `.debug/`, or under `/usr/lib/debug` mirroring its directory, CRC-checked,
//! 3. from a debuginfod server (`DEBUGINFOD_URLS`), downloaded into that same
//!    client cache so gdb and this debugger share one copy.
//!
//! The ELF counterpart of the PDB symbol-server lookup.

use std::path::{Path, PathBuf};
use std::time::Duration;

use object::{Object, ObjectSection};
use tracing::{debug, trace, warn};

/// Where distributions install detached debug files.
const DEBUG_FILE_DIRECTORY: &str = "/usr/lib/debug";

/// How long a debuginfod "not found" is believed (the client's `cache_miss_s`).
const CACHE_MISS: Duration = Duration::from_secs(600);

/// `.gnu_debuglink`: the debug file's name and the CRC32 of its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugLink {
    pub name: String,
    pub crc: u32,
}

/// The module's GNU build-id (`.note.gnu.build-id`), when it has one.
pub fn build_id(file: &object::File<'_>) -> Option<Vec<u8>> {
    file.build_id().ok().flatten().map(|b| b.to_vec())
}

/// The module's `.gnu_debuglink`: a NUL-terminated name padded to 4 bytes,
/// then the CRC32.
pub fn debuglink(file: &object::File<'_>) -> Option<DebugLink> {
    let data = file.section_by_name(".gnu_debuglink")?.data().ok()?;
    let nul = data.iter().position(|&b| b == 0)?;
    let name = std::str::from_utf8(&data[..nul]).ok()?;
    let crc_at = (nul + 1 + 3) & !3;
    let crc = u32::from_le_bytes(data.get(crc_at..crc_at + 4)?.try_into().ok()?);
    (!name.is_empty()).then(|| DebugLink { name: name.to_string(), crc })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `$DEBUGINFOD_CACHE_PATH`, else `$XDG_CACHE_HOME/debuginfod_client`, else
/// `~/.cache/debuginfod_client` — the debuginfod client's own layout.
fn debuginfod_cache_dir() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("DEBUGINFOD_CACHE_PATH").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    dirs::cache_dir().map(|c| c.join("debuginfod_client"))
}

/// The client cache's slot for a build-id (given in hex).
fn debuginfod_cache_file(id: &str) -> Option<PathBuf> {
    Some(debuginfod_cache_dir()?.join(id).join("debuginfo"))
}

/// A debug file already on disk for `module`, or `None`.
pub fn find_local(module: &Path, file: &object::File<'_>) -> Option<PathBuf> {
    if let Some(id) = build_id(file) {
        let id = hex(&id);
        let (dir, rest) = id.split_at(2.min(id.len()));
        let by_id = Path::new(DEBUG_FILE_DIRECTORY).join(".build-id").join(dir).join(format!("{rest}.debug"));
        if by_id.is_file() {
            return Some(by_id);
        }
        if let Some(cached) = debuginfod_cache_file(&id).filter(|p| p.metadata().is_ok_and(|m| m.len() > 0)) {
            return Some(cached);
        }
    }
    let link = debuglink(file)?;
    let dir = module.parent()?;
    let candidates = [
        dir.join(&link.name),
        dir.join(".debug").join(&link.name),
        Path::new(DEBUG_FILE_DIRECTORY).join(dir.strip_prefix("/").unwrap_or(dir)).join(&link.name),
    ];
    candidates.into_iter().find(|candidate| {
        // The link names a file; the CRC says whether it is the right one
        // (a same-named debug file of another build is worse than none).
        candidate != module
            && std::fs::read(candidate).is_ok_and(|data| {
                let ok = crc32fast::hash(&data) == link.crc;
                if !ok {
                    trace!(candidate = %candidate.display(), "debuglink CRC mismatch");
                }
                ok
            })
    })
}

/// The debuginfod servers from `DEBUGINFOD_URLS` (whitespace-separated).
fn debuginfod_urls() -> Vec<String> {
    std::env::var("DEBUGINFOD_URLS")
        .unwrap_or_default()
        .split_whitespace()
        .map(|u| u.trim_end_matches('/').to_string())
        .collect()
}

/// Fetch the debug file for `build_id` from the debuginfod servers into the
/// client cache. `None` when there are no servers, none has it, or the
/// download fails; a "not found" is remembered for a while, as the client
/// does, so a module without published debug info is not re-asked on every
/// load.
pub fn fetch_debuginfod(build_id: &[u8]) -> Option<PathBuf> {
    let urls = debuginfod_urls();
    if urls.is_empty() {
        return None;
    }
    let id = hex(build_id);
    let target = debuginfod_cache_file(&id)?;
    if let Ok(meta) = target.metadata() {
        if meta.len() > 0 {
            return Some(target);
        }
        if meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age < CACHE_MISS) {
            trace!(build_id = %id, "debuginfod miss still cached");
            return None;
        }
    }
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("joybug/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    std::fs::create_dir_all(target.parent()?).ok()?;
    let mut not_found = false;
    for url in &urls {
        let request = format!("{url}/buildid/{id}/debuginfo");
        debug!(url = %request, "fetching debug info from debuginfod");
        let response = match client.get(&request).send() {
            Ok(r) => r,
            Err(e) => {
                warn!(url = %request, error = %e, "debuginfod request failed");
                continue;
            }
        };
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            not_found = true;
            continue;
        }
        if !response.status().is_success() {
            warn!(url = %request, status = %response.status(), "debuginfod request failed");
            continue;
        }
        // Download next to the target and rename, so a reader never sees a
        // partial file as the real thing.
        let tmp = target.with_extension(format!("part.{}", std::process::id()));
        let written = std::fs::File::create(&tmp).and_then(|mut f| {
            let mut response = response;
            response.copy_to(&mut f).map_err(std::io::Error::other)
        });
        match written {
            Ok(n) if n > 0 => {
                if std::fs::rename(&tmp, &target).is_ok() {
                    debug!(build_id = %id, bytes = n, path = %target.display(), "debug info downloaded");
                    return Some(target);
                }
            }
            Ok(_) => {}
            Err(e) => warn!(url = %request, error = %e, "debuginfod download failed"),
        }
        let _ = std::fs::remove_file(&tmp);
    }
    if not_found {
        // The client's negative-cache marker: an empty file, aged by mtime.
        let _ = std::fs::write(&target, b"");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::ObjectSymbol;

    fn system_ld_so() -> Option<PathBuf> {
        ["/lib64/ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
            .and_then(|p| std::fs::canonicalize(p).ok())
    }

    #[test]
    fn debuglink_names_a_debug_file() {
        let Some(ld) = system_ld_so() else { return };
        let data = std::fs::read(&ld).unwrap();
        let file = object::File::parse(&*data).unwrap();
        // Distributions strip ld.so and leave a link; a self-built one may not.
        if let Some(link) = debuglink(&file) {
            assert!(link.name.ends_with(".debug"), "{}", link.name);
            assert_ne!(link.crc, 0);
        }
    }

    #[test]
    fn installed_debug_file_is_found_and_has_locals() {
        let Some(ld) = system_ld_so() else { return };
        let data = std::fs::read(&ld).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let Some(id) = build_id(&file) else { return };
        let id = hex(&id);
        let installed = Path::new(DEBUG_FILE_DIRECTORY).join(".build-id").join(&id[..2]).join(format!("{}.debug", &id[2..]));
        if !installed.exists() {
            return; // no libc6-dbg here
        }
        let found = find_local(&ld, &file).expect("the installed debug file is found");
        assert_eq!(found, installed);
        let debug = std::fs::read(&found).unwrap();
        let debug = object::File::parse(&*debug).unwrap();
        assert_eq!(build_id(&debug).map(|b| hex(&b)).as_deref(), Some(id.as_str()));
        assert!(debug.symbols().any(|s| s.name() == Ok("_dl_start")), "the debug file carries ld.so's local symbols");
    }

    #[test]
    fn no_servers_means_no_fetch() {
        if std::env::var_os("DEBUGINFOD_URLS").is_some_and(|v| !v.is_empty()) {
            return;
        }
        assert_eq!(fetch_debuginfod(&[0u8; 20]), None);
    }
}
