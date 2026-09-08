//! One binary, several roles: the guest side of a sandbox session is whatever
//! exe the caller stages (`joybug-core.exe`, `jlua.exe`, the Joybug app), and
//! the flags it is launched with pick what it does. `sandbox::provision` and
//! `sandbox::guest_ui` build their `wsb exec` command lines against this
//! contract, so it lives in exactly one place and every guest-capable binary
//! calls [`from_argv`] + [`run`] before its own CLI parsing.
//!
//! | Flag present | Role |
//! |---|---|
//! | `--out <file>` | ETW collector ([`crate::etw::run_collector`]) |
//! | `--ui <mode>` | desktop probe ([`crate::guest_desktop::run_cli`]) |
//! | `--listen <addr>` | debug server ([`run_server`]) |
//! | none of these | not a guest role: the caller continues normally |
//!
//! The check is a raw argv scan, not an argument parser: a binary's normal
//! CLI (or a GUI launched with arguments it does not control) must fall
//! through untouched, and the collector parses its own, different argument
//! list.

use crate::SymbolConfig;

/// Which guest role an invocation is.
pub enum GuestRole {
    /// ETW collector; it parses the whole argument list itself.
    Tracer,
    /// Desktop probe; it parses the whole argument list itself.
    DesktopUi,
    /// Debug server.
    Server(ServerArgs),
}

/// The debug-server invocation. `main.rs` exposes the same flags through clap
/// for `--help`; this is the parse used when a guest launches it.
pub struct ServerArgs {
    /// Bind address, e.g. `0.0.0.0:9000`.
    pub listen: String,
    pub symbol_path: Option<String>,
    pub offline: bool,
}

/// Decide the role of an invocation from its arguments (without argv[0]), or
/// `None` when it is not a guest launch.
pub fn from_argv(argv: &[String]) -> Option<GuestRole> {
    // Any binary that dispatches guest roles can be a sandbox guest: keep its
    // identity record linked in (see `guest_marker`).
    crate::guest_marker::touch();
    if argv.first().map(String::as_str) == Some(crate::guest_desktop::ROLE_FLAG) {
        return Some(GuestRole::DesktopUi);
    }
    if argv.iter().any(|a| a == "--out") {
        return Some(GuestRole::Tracer);
    }
    let mut args = ServerArgs { listen: String::new(), symbol_path: None, offline: false };
    let mut it = argv.iter();
    let mut is_server = false;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => {
                is_server = true;
                args.listen = it.next().cloned().unwrap_or_default();
            }
            "--symbol-path" => args.symbol_path = it.next().cloned(),
            "--offline" => args.offline = true,
            _ => {}
        }
    }
    is_server.then_some(GuestRole::Server(args))
}

/// Run the role to completion and exit the process.
pub fn run(role: GuestRole, argv: Vec<String>) -> ! {
    match role {
        GuestRole::Tracer => crate::etw::run_collector(argv.into_iter()),
        GuestRole::DesktopUi => crate::guest_desktop::run_cli(argv.into_iter()),
        GuestRole::Server(args) => run_server(args),
    }
}

/// Serve the debug protocol until the process is killed. Failures are printed
/// as well as logged: `wsb exec` discards a guest's stdout, so the caller
/// redirects it to a log in the shared folder that `await_server_ready` tails
/// to explain a server that never came up.
pub fn run_server(args: ServerArgs) -> ! {
    crate::init_tracing();
    let ServerArgs { listen, symbol_path, offline } = args;
    println!("joybug guest server starting on {listen}");
    let cfg = SymbolConfig { symbol_path, offline };
    let runtime = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("failed to start the tokio runtime: {e}");
        std::process::exit(1);
    });
    let code = runtime.block_on(async move {
        match crate::server::serve(&listen, cfg).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("server failed on {listen}: {e}");
                1
            }
        }
    });
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn roles_are_picked_from_their_flags() {
        assert!(matches!(from_argv(&argv("--ui windows --ui-out x")), Some(GuestRole::DesktopUi)));
        assert!(matches!(from_argv(&argv("--out C:/io/e.jsonl -- target.exe")), Some(GuestRole::Tracer)));
        match from_argv(&argv("--listen 0.0.0.0:9000 --symbol-path srv*C:/s --offline")) {
            Some(GuestRole::Server(a)) => {
                assert_eq!(a.listen, "0.0.0.0:9000");
                assert_eq!(a.symbol_path.as_deref(), Some("srv*C:/s"));
                assert!(a.offline);
            }
            _ => panic!("expected the server role"),
        }
        assert!(from_argv(&argv("script.lua --command x.exe")).is_none());
        assert!(from_argv(&[]).is_none());
    }
}
