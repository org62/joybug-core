pub mod protocol;
pub mod formatting;
pub mod protocol_io;
pub mod interfaces;
pub mod pe_types;
pub mod pe_image;
/// Offline PE analysis: disassembly, xrefs and process-less emulation of a file on disk.
pub mod static_pe;
pub mod windows_platform;
pub mod server;
pub mod framed_json_stream;
pub mod emulator;
pub mod memory_operand;
pub mod tenet_format;
pub mod local_server;
pub mod assembler;
pub mod memory_scanner;
pub mod pointer_scanner;
pub mod pointer_results;
pub mod string_scanner;
pub mod string_results;
pub mod scan_results;
pub mod freeze_manager;
pub mod scripting;
pub mod inline_hook;
pub mod anti_anti_debug;
pub mod env_block;
/// Host ETW tracing: drives the collector in [`winsandbox::tracer`], run as a
/// mode of the hosting executable rather than a separate binary.
pub mod etw;
/// Windows Sandbox run mode (host-side VM orchestration).
pub mod sandbox;
/// The embedded "this exe can be a sandbox guest" record and its reader.
pub mod guest_marker;
/// The guest side of the sandbox desktop probes (`--ui` role).
pub mod guest_desktop;
/// Raw-argv guest role dispatch shared by every guest-capable binary.
pub mod guest_roles;

#[cfg(windows)]
pub type PlatformImpl = windows_platform::WindowsPlatform;

pub use interfaces::SymbolConfig;

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
