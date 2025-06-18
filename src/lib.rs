pub mod protocol;
pub mod protocol_io;
pub mod interfaces;
pub mod windows_platform;
pub mod server;

#[cfg(windows)]
pub type PlatformImpl = windows_platform::WindowsPlatform;
#[cfg(not(windows))]
pub struct DummyPlatform;
#[cfg(not(windows))]
impl interfaces::PlatformAPI for DummyPlatform {
    fn attach(&mut self, _pid: u32) -> Result<(), interfaces::PlatformError> { Ok(()) }
    fn continue_exec(&mut self, _pid: u32, _tid: u32) -> Result<Option<crate::protocol::DebugEvent>, interfaces::PlatformError> { Ok(None) }
    fn set_breakpoint(&mut self, _addr: u64) -> Result<(), interfaces::PlatformError> { Ok(()) }
    fn launch(&mut self, _command: &str) -> Result<Option<crate::protocol::DebugEvent>, interfaces::PlatformError> { Ok(None) }
    fn read_memory(&mut self, _pid: u32, _address: u64, _size: usize) -> Result<Vec<u8>, interfaces::PlatformError> { Ok(vec![]) }
    fn write_memory(&mut self, _pid: u32, _address: u64, _data: &[u8]) -> Result<(), interfaces::PlatformError> { Ok(()) }
    fn get_thread_context(&mut self, _pid: u32, _tid: u32) -> Result<crate::protocol::ThreadContext, interfaces::PlatformError> { Err(interfaces::PlatformError::NotImplemented) }
    fn set_thread_context(&mut self, _pid: u32, _tid: u32, _context: crate::protocol::ThreadContext) -> Result<(), interfaces::PlatformError> { Err(interfaces::PlatformError::NotImplemented) }
    fn list_modules(&self, _pid: u32) -> Result<Vec<crate::protocol::ModuleInfo>, interfaces::PlatformError> { Ok(vec![]) }
    fn list_threads(&self, _pid: u32) -> Result<Vec<crate::protocol::ThreadInfo>, interfaces::PlatformError> { Ok(vec![]) }
    fn list_processes(&self) -> Result<Vec<crate::protocol::ProcessInfo>, interfaces::PlatformError> { Ok(vec![]) }
    fn find_symbol(&self, _module_path: &str, _symbol_name: &str) -> Result<Option<interfaces::Symbol>, interfaces::SymbolError> { Err(interfaces::SymbolError::SymbolsNotFound("Not implemented".to_string())) }
    fn list_symbols(&self, _module_path: &str) -> Result<Vec<interfaces::Symbol>, interfaces::SymbolError> { Ok(vec![]) }
    fn resolve_rva_to_symbol(&self, _module_path: &str, _rva: u32) -> Result<Option<interfaces::Symbol>, interfaces::SymbolError> { Ok(None) }
    fn resolve_address_to_symbol(&self, _pid: u32, _address: u64) -> Result<Option<(String, interfaces::Symbol, u64)>, interfaces::SymbolError> { Ok(None) }
}

pub async fn run() -> anyhow::Result<()> {
    server::run_server().await
}

pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(filter)
        .init();
} 