/// Shared helpers for emulator integration tests.

/// Get the path to a compiled test program exe
fn get_test_program_path(name: &str) -> String {
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

    panic!("Could not find {}.exe. Make sure to build the project first.", name);
}

/// Get the path to the compiled xtea_test.exe
pub fn get_xtea_test_path() -> String {
    get_test_program_path("xtea_test")
}

/// Get the path to the compiled emulator_test.exe
pub fn get_emulator_test_path() -> String {
    get_test_program_path("emulator_test")
}

/// Test state tracking which modes have been verified
pub struct EmulatorTestState {
    pub basic_tested: bool,
    pub instruction_trace_tested: bool,
    pub basic_block_tested: bool,
    pub module_transition_tested: bool,
    pub syscall_tested: bool,
    pub instruction_trace_syscall_tested: bool,
    pub performance_tested: bool,
    pub instruction_trace_exit_tested: bool,
    pub timeout_tested: bool,
}

impl EmulatorTestState {
    pub fn new() -> Self {
        Self {
            basic_tested: false,
            instruction_trace_tested: false,
            basic_block_tested: false,
            module_transition_tested: false,
            syscall_tested: false,
            instruction_trace_syscall_tested: false,
            performance_tested: false,
            instruction_trace_exit_tested: false,
            timeout_tested: false,
        }
    }

    pub fn all_tested(&self) -> bool {
        self.basic_tested
            && self.instruction_trace_tested
            && self.basic_block_tested
            && self.module_transition_tested
            && self.syscall_tested
            && self.instruction_trace_syscall_tested
            && self.performance_tested
            && self.instruction_trace_exit_tested
    }
}
