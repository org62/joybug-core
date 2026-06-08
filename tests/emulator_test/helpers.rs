/// Shared helpers for emulator integration tests.

use crate::common::get_test_program_path;

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
