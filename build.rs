use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    // Only compile test programs on Windows
    #[cfg(windows)]
    {
        let out_dir = env::var("OUT_DIR").unwrap();
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let test_program_src = Path::new(&manifest_dir)
            .join("tests")
            .join("test_programs")
            .join("dereference_test.c");

        // Skip if the source file doesn't exist
        if !test_program_src.exists() {
            panic!("Test program source not found: {:?}", test_program_src);
        }

        let out_exe = Path::new(&out_dir).join("dereference_test.exe");
        let out_pdb = Path::new(&out_dir).join("dereference_test.pdb");
        let out_obj = Path::new(&out_dir).join("dereference_test.obj");

        println!("cargo:rerun-if-changed=tests/test_programs/dereference_test.c");

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
                    println!("cargo:warning=Successfully compiled dereference_test.exe with MSVC");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    panic!(
                        "MSVC compilation failed:\nstdout: {}\nstderr: {}",
                        stdout, stderr
                    );
                }
            }
            Err(e) => {
                panic!(
                    "Could not run cl.exe: {}. Ensure Visual Studio is installed and vcvars64.bat is sourced.",
                    e
                );
            }
        }
    }
}
