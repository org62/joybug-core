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
#[async_trait::async_trait]
impl interfaces::PlatformAPI for DummyPlatform {
    async fn attach(&mut self, _pid: u32) -> Result<(), interfaces::PlatformError> { Ok(()) }
    async fn continue_exec(&mut self) -> Result<(), interfaces::PlatformError> { Ok(()) }
    async fn set_breakpoint(&mut self, _addr: u64) -> Result<(), interfaces::PlatformError> { Ok(()) }
}

pub async fn run() -> anyhow::Result<()> {
    server::run_server().await
} 