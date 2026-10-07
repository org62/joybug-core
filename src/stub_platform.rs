//! The platform used where no live-debugging backend exists (every OS but
//! Windows and Linux). It is the [`crate::PlatformImpl`] there, so `LocalServer`,
//! `jlua --listen` and the Joybug UI build and start normally; any request that
//! needs a live process fails with [`PlatformError::NotImplemented`] (launch and
//! attach say why in words, since those are what a user hits first), and the
//! offline paths - `static_pe`, the emulator, the protocol, the UI - keep working.
//!
//! The stub also documents, by its method list, exactly what a backend owes.

use crate::interfaces::{
    Architecture, CallFrame, DisassemblerError, Instruction, ModuleSymbol, PlatformAPI,
    PlatformError, ResolvedSymbol, Stepper, SymbolConfig, SymbolError,
};
use crate::pe_types::ModuleExtraInfo;
use crate::protocol::{
    DebugEvent, DereferenceEntry, HardwareBreakpointSize, HardwareBreakpointType, MemoryRegionInfo,
    ModuleInfo, ProcessInfo, StepKind, ThreadContext, ThreadInfo,
};

/// Why a live-process request fails here, in words a user can act on.
pub const UNSUPPORTED_MESSAGE: &str =
    "live debugging is not supported on this platform yet (Windows and Linux only); offline image analysis still works";

/// See the module docs.
#[derive(Debug, Default)]
pub struct StubPlatform;

impl StubPlatform {
    pub fn new() -> Self {
        Self::new_with_config(SymbolConfig::default())
    }

    pub fn new_with_config(_symbol_config: SymbolConfig) -> Self {
        Self
    }

    fn unsupported<T>() -> Result<T, PlatformError> {
        Err(PlatformError::Other(UNSUPPORTED_MESSAGE.to_string()))
    }
}

impl Stepper for StubPlatform {
    fn step(&mut self, _pid: u32, _tid: u32, _kind: StepKind) -> Result<Option<DebugEvent>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
}

impl PlatformAPI for StubPlatform {
    fn attach(&mut self, _pid: u32) -> Result<Option<DebugEvent>, PlatformError> {
        Self::unsupported()
    }
    fn detach(&mut self, _pid: u32) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn continue_exec(&mut self, _pid: u32, _tid: u32) -> Result<Option<DebugEvent>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn set_breakpoint(&mut self, _pid: u32, _addr: u64, _tid: Option<u32>) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn remove_breakpoint(&mut self, _pid: u32, _addr: u64) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn set_single_shot_breakpoint(&mut self, _pid: u32, _addr: u64) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn set_hardware_breakpoint(
        &mut self,
        _pid: u32,
        _addr: u64,
        _bp_type: HardwareBreakpointType,
        _size: HardwareBreakpointSize,
    ) -> Result<u8, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn remove_hardware_breakpoint(&mut self, _pid: u32, _addr: u64) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn launch(
        &mut self,
        _command: &str,
        _debug_children: bool,
        _working_directory: Option<&str>,
        _environment: Option<&[(String, String)]>,
    ) -> Result<Option<DebugEvent>, PlatformError> {
        Self::unsupported()
    }
    fn read_memory(&self, _pid: u32, _address: u64, _size: usize) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn write_memory(&self, _pid: u32, _address: u64, _data: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn allocate_memory(&self, _pid: u32, _size: usize, _executable: bool) -> Result<u64, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn read_wide_string(&self, _pid: u32, _address: u64, _max_len: Option<usize>) -> Result<String, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn get_thread_context(&self, _pid: u32, _tid: u32) -> Result<ThreadContext, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn set_thread_context(&self, _pid: u32, _tid: u32, _context: ThreadContext) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn get_function_arguments(&self, _pid: u32, _tid: u32, _count: usize) -> Result<Vec<u64>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn list_modules(&self, _pid: u32) -> Result<Vec<ModuleInfo>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn list_threads(&self, _pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    /// Nothing can be attached to, so the picker shows an empty list rather
    /// than an error.
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        Ok(Vec::new())
    }
    fn find_symbol(&self, _symbol_name: &str, _max_results: usize) -> Result<Vec<ResolvedSymbol>, SymbolError> {
        Ok(Vec::new())
    }
    fn list_symbols(&self, _module_path: &str) -> Result<Vec<ModuleSymbol>, SymbolError> {
        Ok(Vec::new())
    }
    fn resolve_rva_to_symbol(&self, _module_path: &str, _rva: u32) -> Result<Option<ModuleSymbol>, SymbolError> {
        Ok(None)
    }
    fn resolve_address_to_symbol(
        &self,
        _pid: u32,
        _address: u64,
    ) -> Result<Option<(String, ModuleSymbol, u64)>, SymbolError> {
        Ok(None)
    }
    fn disassemble_memory(
        &self,
        _pid: u32,
        _address: u64,
        _count: usize,
        _arch: Architecture,
    ) -> Result<Vec<Instruction>, DisassemblerError> {
        Err(DisassemblerError::InvalidData(UNSUPPORTED_MESSAGE.to_string()))
    }
    fn get_call_stack(&self, _pid: u32, _tid: u32) -> Result<Vec<CallFrame>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn terminate_process(&self, _pid: u32) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn break_into(&self, _pid: u32) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn get_module_extra_info(&self, _pid: u32, _module_base: u64) -> Result<ModuleExtraInfo, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn query_memory_region(&self, _pid: u32, _address: u64) -> Result<MemoryRegionInfo, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn enumerate_memory_regions(&self, _pid: u32) -> Result<Vec<MemoryRegionInfo>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn dereference(
        &self,
        _pid: u32,
        _address: u64,
        _count: usize,
        _reference_base: Option<u64>,
        _probe_start: bool,
    ) -> Result<Vec<DereferenceEntry>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_and_attach_say_why() {
        let mut p = StubPlatform::new();
        for r in [p.launch("x", false, None, None).map(|_| ()), p.attach(1).map(|_| ())] {
            match r {
                Err(PlatformError::Other(m)) => assert!(m.contains("not supported on this platform")),
                other => panic!("expected the unsupported message, got {other:?}"),
            }
        }
        assert!(matches!(p.read_memory(1, 0, 1), Err(PlatformError::NotImplemented)));
        assert!(p.list_processes().unwrap().is_empty());
    }
}
