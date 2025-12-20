use std::env;
use std::path::Path;
use std::process::Command;

/// Compile a test program with MSVC
/// Returns true if compilation succeeded, false if skipped (cl.exe not available)
fn compile_test_program(manifest_dir: &str, out_dir: &str, name: &str) -> bool {
    let test_program_src = Path::new(manifest_dir)
        .join("tests")
        .join("test_programs")
        .join(format!("{}.c", name));

    // Skip if the source file doesn't exist
    if !test_program_src.exists() {
        println!("cargo:warning=Test program source not found: {:?}", test_program_src);
        return false;
    }

    let out_exe = Path::new(out_dir).join(format!("{}.exe", name));
    let out_pdb = Path::new(out_dir).join(format!("{}.pdb", name));
    let out_obj = Path::new(out_dir).join(format!("{}.obj", name));

    println!("cargo:rerun-if-changed=tests/test_programs/{}.c", name);

    // Clean up old build artifacts before recompiling
    // This ensures stale PDB files don't cause symbol resolution issues
    let _ = std::fs::remove_file(&out_exe);
    let _ = std::fs::remove_file(&out_pdb);
    let _ = std::fs::remove_file(&out_obj);

    // Compile with MSVC (cl.exe)
    // This requires running from a Visual Studio Developer Command Prompt
    // or having vcvars64.bat sourced
    let cl_result = Command::new("cl.exe")
        .args(&[
            "/Od",                                      // Disable optimization
            "/Zi",                                      // Generate debug info
            "/W4",                                      // Warning level 4
            &format!("/Fe:{}", out_exe.to_str().unwrap()),  // Output executable
            &format!("/Fd:{}", out_pdb.to_str().unwrap()),  // PDB file
            &format!("/Fo:{}", out_obj.to_str().unwrap()),  // Object file output
            test_program_src.to_str().unwrap(),
            "/link",
            "/DEBUG",                                   // Generate debug info for linker
        ])
        .output();

    match cl_result {
        Ok(output) => {
            if output.status.success() {
                println!("cargo:warning=Successfully compiled {}.exe with MSVC", name);
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!(
                    "cargo:warning=MSVC compilation of {} failed:\nstdout: {}\nstderr: {}",
                    name, stdout, stderr
                );
                false
            }
        }
        Err(e) => {
            println!(
                "cargo:warning=Could not run cl.exe for {}: {}. Test programs will not be available.",
                name, e
            );
            false
        }
    }
}

fn main() {
    // Only compile test programs on Windows
    #[cfg(windows)]
    {
        let out_dir = env::var("OUT_DIR").unwrap();
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

        // Compile all test programs (failures are warnings, not errors)
        let _ = compile_test_program(&manifest_dir, &out_dir, "dereference_test");
        let _ = compile_test_program(&manifest_dir, &out_dir, "disassembly_test");
    }
}
