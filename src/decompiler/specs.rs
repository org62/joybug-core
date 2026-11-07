//! The SLEIGH processor specifications Kuna needs, carried inside this crate.
//!
//! Kuna reads them from a directory tree; a host that ships as one executable
//! has none to point at. So the files for the machines we debug (x86, x86-64,
//! AArch64) are packed into `assets/kuna-specs.bin`, embedded with
//! `include_bytes!`, and unpacked once per bundle under the host's cache
//! directory.
//!
//! The compiled `.sla` files in the bundle belong to one Kuna revision — the
//! one pinned in `Cargo.toml`. After moving that pin, regenerate the bundle:
//! `cargo run --example update_kuna_specs` (a test fails until it matches).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static BUNDLE: &[u8] = include_bytes!("../../assets/kuna-specs.bin");

const MAGIC: &[u8; 8] = b"JBKUNA1\n";
static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);

/// The Kuna revision pinned in `Cargo.toml`.
pub fn pinned_kuna_rev() -> &'static str {
    let manifest = include_str!("../../Cargo.toml");
    let line = manifest.lines().find(|l| l.starts_with("kuna-console")).expect("kuna-console dependency");
    let rev = line.split("rev = \"").nth(1).expect("kuna-console pinned by rev");
    &rev[..rev.find('"').expect("closing quote")]
}

/// The processors bundled, and of each only the languages we can meet.
pub const PROCESSORS: &[(&str, &[&str])] = &[
    ("x86", &["x86.sla", "x86-64.sla"]),
    ("AARCH64", &["AARCH64.sla"]),
];

/// What Kuna reads at run time besides the compiled language.
const RUNTIME_EXTENSIONS: &[&str] = &["ldefs", "pspec", "cspec", "dwarf", "opinion", "info"];

/// Pack the bundle from a Kuna checkout whose specs have been compiled
/// (`slacomp -a specs/Ghidra/Processors/<name>`). Paths inside the bundle are
/// relative to the checkout's `specs/` directory.
pub fn pack(kuna_specs_dir: &Path, kuna_rev: &str) -> std::io::Result<Vec<u8>> {
    let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    out.write_all(MAGIC)?;
    write_block(&mut out, kuna_rev.as_bytes())?;
    for (processor, languages) in PROCESSORS {
        let relative = format!("Ghidra/Processors/{processor}/data/languages");
        let mut names: Vec<String> = languages.iter().map(|l| l.to_string()).collect();
        for entry in std::fs::read_dir(kuna_specs_dir.join(&relative))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let extension = Path::new(&name).extension().and_then(|e| e.to_str()).unwrap_or("");
            if entry.file_type()?.is_file() && RUNTIME_EXTENSIONS.contains(&extension) {
                names.push(name);
            }
        }
        names.sort();
        for name in names {
            let path = format!("{relative}/{name}");
            write_block(&mut out, path.as_bytes())?;
            write_block(&mut out, &std::fs::read(kuna_specs_dir.join(&path))?)?;
        }
    }
    out.finish()
}

fn write_block(out: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    out.write_all(&(bytes.len() as u32).to_le_bytes())?;
    out.write_all(bytes)
}

fn read_block(input: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut bytes = vec![0u8; u32::from_le_bytes(len) as usize];
    input.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

/// The Kuna revision a bundle was built from, and its files as `(path, bytes)`.
fn unpack(bundle: &[u8]) -> std::io::Result<(String, Vec<(String, Vec<u8>)>)> {
    let invalid = |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).map_err(|_| invalid("bad text in the spec bundle"));
    let mut input = flate2::read::GzDecoder::new(bundle);
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(invalid("not a Kuna spec bundle"));
    }
    let kuna_rev = text(read_block(&mut input)?.ok_or_else(|| invalid("empty spec bundle"))?)?;
    let mut files = Vec::new();
    while let Some(path) = read_block(&mut input)? {
        let path = text(path)?;
        let stays_inside = path.split('/').all(|part| !matches!(part, "" | "." | "..") && !part.contains(['\\', ':']));
        if !stays_inside {
            return Err(invalid("bad path in the spec bundle"));
        }
        let bytes = read_block(&mut input)?.ok_or_else(|| invalid("truncated spec bundle"))?;
        files.push((path, bytes));
    }
    Ok((kuna_rev, files))
}

/// The directory holding the unpacked specifications, unpacking them under
/// `cache_dir` if this bundle has not been there before.
///
/// The directory is named after the bundle's content and appears by a rename
/// of a finished copy, so concurrent callers, or one killed half way, cannot
/// leave a tree that looks complete and is not. Previous bundles stay available
/// for other running versions of the host.
pub fn ensure_unpacked(cache_dir: &Path) -> Result<PathBuf, String> {
    let root = cache_dir.join("kuna-specs");
    let name = format!("{:08x}-{}", crc32fast::hash(BUNDLE), BUNDLE.len());
    let target = root.join(&name);
    if target.is_dir() {
        return Ok(target);
    }
    let unpack_error = |e| format!(
        "Could not unpack the decompiler's processor specifications to {}: {e}",
        root.display()
    );
    std::fs::create_dir_all(&root).map_err(&unpack_error)?;
    let staging = loop {
        let id = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let staging = root.join(format!("{name}.tmp-{}-{id}", std::process::id()));
        match std::fs::create_dir(&staging) {
            Ok(()) => break staging,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(unpack_error(e)),
        }
    };
    let unpacked = unpack(BUNDLE).and_then(|(_, files)| {
        for (path, bytes) in &files {
            let file = staging.join(path);
            std::fs::create_dir_all(file.parent().unwrap())?;
            std::fs::write(file, bytes)?;
        }
        std::fs::rename(&staging, &target)
    });
    if let Err(e) = unpacked {
        let _ = std::fs::remove_dir_all(&staging);
        // Losing the race to another caller is fine: its copy is the same.
        if !target.is_dir() {
            return Err(unpack_error(e));
        }
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCache(PathBuf);

    impl TestCache {
        fn new() -> Self {
            static NEXT_CACHE_ID: AtomicU64 = AtomicU64::new(0);
            loop {
                let id = NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!("joybug-specs-test-{}-{id}", std::process::id()));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("could not create test cache: {e}"),
                }
            }
        }
    }

    impl Drop for TestCache {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn assert_bundle_contents(root: &Path, files: &[(String, Vec<u8>)]) {
        for (path, expected) in files {
            let actual = std::fs::read(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(actual == *expected, "{path} differs from the embedded bundle");
        }
    }

    #[test]
    fn bundle_matches_the_pinned_kuna_revision() {
        let (kuna_rev, files) = unpack(BUNDLE).expect("the embedded bundle unpacks");
        assert_eq!(
            kuna_rev,
            pinned_kuna_rev(),
            "assets/kuna-specs.bin was built from another Kuna revision: run `cargo run --example update_kuna_specs`"
        );
        for (processor, languages) in PROCESSORS {
            for language in *languages {
                let path = format!("Ghidra/Processors/{processor}/data/languages/{language}");
                assert!(files.iter().any(|(p, b)| *p == path && !b.is_empty()), "{path} missing");
            }
        }
    }

    #[test]
    fn concurrent_extractions_publish_complete_bundles() {
        let cache = TestCache::new();
        let (_, files) = unpack(BUNDLE).unwrap();
        let start = std::sync::Barrier::new(4);
        let roots = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4).map(|_| scope.spawn(|| {
                start.wait();
                let root = ensure_unpacked(&cache.0).unwrap();
                assert_bundle_contents(&root, &files);
                root
            })).collect();
            handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
        });
        assert!(roots.iter().all(|root| root == &roots[0]));
    }

    #[test]
    fn repeated_opens_resolve_complete_content() {
        let cache = TestCache::new();
        let (_, files) = unpack(BUNDLE).unwrap();
        let root = ensure_unpacked(&cache.0).unwrap();
        assert_bundle_contents(&root, &files);
        let reopened = ensure_unpacked(&cache.0).unwrap();
        assert_eq!(reopened, root);
        assert_bundle_contents(&reopened, &files);
    }

    #[test]
    fn extraction_preserves_an_older_bundle_in_use() {
        let cache = TestCache::new();
        let older_root = cache.0.join("kuna-specs").join("00000000-1");
        std::fs::create_dir_all(&older_root).unwrap();
        let spec = older_root.join("processor.sla");
        std::fs::write(&spec, b"older processor specifications").unwrap();

        ensure_unpacked(&cache.0).unwrap();

        // A running host keeps its root and may open more specs later.
        assert_eq!(std::fs::read(&spec).unwrap(), b"older processor specifications");
    }

    #[test]
    fn rejects_paths_that_leave_the_tree() {
        let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        out.write_all(MAGIC).unwrap();
        write_block(&mut out, b"rev").unwrap();
        write_block(&mut out, b"../outside").unwrap();
        write_block(&mut out, b"x").unwrap();
        assert!(unpack(&out.finish().unwrap()).is_err());
    }
}
