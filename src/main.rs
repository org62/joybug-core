use clap::Parser;

/// Joybug debug server. Listens for `DebugSession` clients over TCP.
///
/// The same executable is a complete sandbox guest: launched with `--out` it
/// is the ETW collector and with `--ui` the desktop probe (see
/// `joybug_core::guest_roles`), so `sbx.provision` can stage it directly.
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

fn main() {
    // Guest roles are decided on the raw argv before clap sees anything: the
    // collector and the desktop probe parse their own argument lists.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(role) = joybug_core::guest_roles::from_argv(&argv) {
        joybug_core::guest_roles::run(role, argv);
    }
    let args = Args::parse();
    joybug_core::guest_roles::run_server(joybug_core::guest_roles::ServerArgs {
        listen: args.listen,
        symbol_path: args.symbol_path,
        offline: args.offline,
    })
}
