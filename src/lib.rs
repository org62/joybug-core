pub mod protocol;
pub mod formatting;
pub mod protocol_io;
pub mod interfaces;
pub mod pe_types;
pub mod windows_platform;
pub mod server;
pub mod framed_json_stream;
pub mod emulator;
pub mod memory_operand;
pub mod tenet_format;
pub mod local_server;

#[cfg(windows)]
pub type PlatformImpl = windows_platform::WindowsPlatform;

pub async fn run() -> anyhow::Result<()> {
    server::run_server().await
}

pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    // Use try_init() to avoid panic when called multiple times (e.g., in tests)
    let _ = tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
