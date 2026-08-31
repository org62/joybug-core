use clap::Parser;
use joybug_core::SymbolConfig;

/// Joybug debug server. Listens for `DebugSession` clients over TCP.
#[derive(Parser, Debug)]
#[command(name = "joybug-core", about = "Joybug debug server")]
struct Args {
    /// Address to bind the debug server to, e.g. `127.0.0.1:9000` or `0.0.0.0:9000`.
    /// Bind `0.0.0.0` to accept connections from another machine (e.g. the host
    /// driving a server running inside a Windows Sandbox). Note: the protocol is
    /// unauthenticated — only bind a routable interface in a trusted/disposable env.
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: String,

    /// Symbol path override (takes precedence over `_NT_SYMBOL_PATH`), e.g.
    /// `srv*C:\symbols*https://msdl.microsoft.com/download/symbols`.
    #[arg(long)]
    symbol_path: Option<String>,

    /// Strip remote symbol-server URLs so nothing is downloaded; local caches and
    /// directories still resolve.
    #[arg(long)]
    offline: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    joybug_core::init_tracing();

    let args = Args::parse();

    println!("Starting joybug-core server on {}...", args.listen);

    let cfg = SymbolConfig {
        symbol_path: args.symbol_path,
        offline: args.offline,
    };

    joybug_core::server::serve(&args.listen, cfg).await?;

    Ok(())
}
