use std::env;
use std::path::Path;

/// Compile a test program with MSVC
/// Returns true if compilation succeeded, false if skipped (cl.exe not available)
/// If fixed_base is Some, the executable will be linked with that base address
fn compile_test_program(manifest_dir: &str, out_dir: &str, name: &str, fixed_base: Option<u64>) -> bool {
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

    // Use cc crate to find the MSVC compiler via registry/VS installation paths
    // This works without requiring vcvarsall or Developer Command Prompt
    let compiler = match cc::Build::new().try_get_compiler() {
        Ok(c) => c,
        Err(e) => {
            println!("cargo:warning=Could not find MSVC compiler: {}", e);
            return false;
        }
    };

    // Use the compiler's command with proper environment variables set
    let mut cmd = compiler.to_command();
    cmd.args(&[
        "/Od",                                              // Disable optimization
        "/Zi",                                              // Generate debug info
        "/W4",                                              // Warning level 4
        &format!("/Fe:{}", out_exe.to_str().unwrap()),      // Output executable
        &format!("/Fd:{}", out_pdb.to_str().unwrap()),      // PDB file
        &format!("/Fo:{}", out_obj.to_str().unwrap()),      // Object file output
        test_program_src.to_str().unwrap(),
        "/link",
        "/DEBUG",                                           // Generate debug info for linker
    ]);

    // Add fixed base address if specified (for predictable symbol addresses)
    // Note: ARM64 doesn't support /FIXED, so we skip it on that target
    if let Some(base) = fixed_base {
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        if target_arch == "aarch64" {
            // ARM64 doesn't support /FIXED, only set preferred base (may be ignored due to ASLR)
            cmd.args(&[
                &format!("/BASE:0x{:X}", base),
            ]);
        } else {
            cmd.args(&[
                &format!("/BASE:0x{:X}", base),
                "/DYNAMICBASE:NO",                          // Disable ASLR
                "/FIXED",                                   // Fixed base address
            ]);
        }
    }

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
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
                "cargo:warning=Failed to run MSVC compiler: {}",
                e
            );
            false
        }
    }
}

fn main() {
    // Require LIBCLANG_PATH to be set (needed for bindgen in dependencies like capstone-sys)
    if env::var("LIBCLANG_PATH").is_err() {
        panic!(
            "LIBCLANG_PATH environment variable is not set.\n\
             Please set it to the path containing libclang.dll, e.g.:\n\
             set LIBCLANG_PATH=C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Tools\\Llvm\\ARM64\\bin"
        );
    }

    // Only compile test programs on Windows
    #[cfg(windows)]
    {
        let out_dir = env::var("OUT_DIR").unwrap();
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

        // Compile all test programs (failures are warnings, not errors)
        let _ = compile_test_program(&manifest_dir, &out_dir, "dereference_test", None);
        let _ = compile_test_program(&manifest_dir, &out_dir, "disassembly_test", None);
        // xtea_test uses fixed base address for predictable symbol addresses in traces
        let _ = compile_test_program(&manifest_dir, &out_dir, "xtea_test", Some(0x140000000));
        let _ = compile_test_program(&manifest_dir, &out_dir, "emulator_test", None);
        let _ = compile_test_program(&manifest_dir, &out_dir, "exception_test", None);
    }
}
