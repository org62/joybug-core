pub mod protocol;
pub mod formatting;
pub mod protocol_io;
pub mod interfaces;
pub mod windows_platform;
pub mod server;
pub mod framed_json_stream;

#[cfg(windows)]
pub type PlatformImpl = windows_platform::WindowsPlatform;

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
