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