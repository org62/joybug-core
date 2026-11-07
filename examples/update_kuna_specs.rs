//! Rebuild `assets/kuna-specs.bin` for the Kuna revision pinned in `Cargo.toml`.
//!
//! `cargo run --example update_kuna_specs [-- <kuna checkout>]`
//!
//! Without a checkout it fetches the pinned revision into a temporary
//! directory. Either way it builds Kuna's SLEIGH compiler there, compiles the
//! bundled processors and packs what `decompiler::specs` unpacks at run time.

use joybug_core::decompiler::specs;
use std::path::{Path, PathBuf};
use std::process::Command;

const KUNA_REPOSITORY: &str = "https://github.com/Noelo-Lab/kuna";

fn run(command: &mut Command) {
    let status = command.status().unwrap_or_else(|e| panic!("failed to run {command:?}: {e}"));
    assert!(status.success(), "{command:?} failed");
}

fn main() {
    let rev = specs::pinned_kuna_rev();
    let given = std::env::args().nth(1).map(PathBuf::from);
    let checkout = given.clone().unwrap_or_else(|| {
        let dir = std::env::temp_dir().join(format!("kuna-{rev}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        run(Command::new("git").args(["init", "-q"]).current_dir(&dir));
        run(Command::new("git").args(["fetch", "-q", "--depth", "1", KUNA_REPOSITORY, rev]).current_dir(&dir));
        run(Command::new("git").args(["checkout", "-q", "FETCH_HEAD"]).current_dir(&dir));
        dir
    });
    let head = Command::new("git").args(["rev-parse", "HEAD"]).current_dir(&checkout).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&head.stdout).trim(), rev, "the checkout is not at the pinned revision");

    let engine = checkout.join("decompiler");
    run(Command::new("cargo").args(["build", "--release", "-p", "kuna-slacomp"]).current_dir(&engine));
    let slacomp = engine.join("target/release").join(format!("slacomp{}", std::env::consts::EXE_SUFFIX));
    let kuna_specs = checkout.join("specs");
    for (processor, _) in specs::PROCESSORS {
        run(Command::new(&slacomp).arg("-a").arg(kuna_specs.join("Ghidra/Processors").join(processor)));
    }

    let bundle = specs::pack(&kuna_specs, rev).expect("pack the specs");
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/kuna-specs.bin");
    std::fs::write(&out, &bundle).unwrap();
    println!("{}: {} bytes, Kuna {rev}", out.display(), bundle.len());
    if given.is_none() {
        let _ = std::fs::remove_dir_all(&checkout);
    }
}
