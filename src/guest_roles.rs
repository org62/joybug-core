//! One binary, several roles: the guest side of a sandbox session is whatever
//! exe the caller stages (`jlua.exe` or the Joybug app), and the flags it is
//! launched with pick what it does. `sandbox::provision` and
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
//! Detecting the *role* is a raw argv scan, not an argument parser: a binary's
//! normal CLI (or a GUI launched with arguments it does not control) must fall
//! through untouched, and the collector and desktop probe parse their own,
//! different argument lists. The server role's arguments, by contrast, have an
//! ordinary grammar, so clap owns them: [`ServerArgs`] is the single definition,
//! flattened into `jlua`'s CLI for `--help` and parsed here for a guest launch.

use crate::SymbolConfig;
use clap::{Args as _, FromArgMatches as _};

/// The desktop-probe role flag (`--ui <mode>`). Defined here, not in
/// `guest_desktop`, because the sniff must work on every OS while the probe
/// itself is Windows-only.
pub const DESKTOP_UI_ROLE_FLAG: &str = "--ui";

/// Which guest role an invocation is.
pub enum GuestRole {
    /// ETW collector; it parses the whole argument list itself.
    Tracer,
    /// Desktop probe; it parses the whole argument list itself.
    DesktopUi,
    /// Debug server.
    Server(ServerArgs),
}

/// The debug-server flags. The one definition of `--listen`/`--symbol-path`/
/// `--offline`: `jlua` flattens this into its own `Args` (so `--help` and the
/// guest launch can't drift apart), and [`from_argv`] parses it for a guest.
#[derive(clap::Args, Debug)]
pub struct ServerArgs {
    /// Run headless as a debug server bound to this address instead of the REPL,
    /// e.g. `127.0.0.1:9000` or `0.0.0.0:9000`. Bind `0.0.0.0` to accept clients
    /// from another machine (e.g. the host driving a server inside a Windows
    /// Sandbox). The protocol is unauthenticated — only bind a routable
    /// interface in a trusted/disposable environment.
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<String>,

    /// Symbol path override (takes precedence over `_NT_SYMBOL_PATH`), e.g.
    /// `srv*C:\symbols*https://msdl.microsoft.com/download/symbols`. Applies to
    /// the local server started for the REPL/script and to `--listen`.
    #[arg(long)]
    pub symbol_path: Option<String>,

    /// Strip remote symbol-server URLs so nothing is downloaded; local caches and
    /// directories still resolve. Applies to the local server and to `--listen`.
    #[arg(long)]
    pub offline: bool,
}

impl ServerArgs {
    /// The symbol configuration these flags describe.
    pub fn symbol_config(&self) -> SymbolConfig {
        SymbolConfig { symbol_path: self.symbol_path.clone(), offline: self.offline }
    }
}

/// Decide the role of an invocation from its arguments (without argv[0]), or
/// `None` when it is not a guest launch.
pub fn from_argv(argv: &[String]) -> Option<GuestRole> {
    // Any binary that dispatches guest roles can be a sandbox guest: keep its
    // identity record linked in (see `guest_marker`).
    crate::guest_marker::touch();
    if argv.first().map(String::as_str) == Some(DESKTOP_UI_ROLE_FLAG) {
        return Some(GuestRole::DesktopUi);
    }
    if argv.iter().any(|a| a == "--out") {
        return Some(GuestRole::Tracer);
    }
    // Sniff the server role on raw argv (both `--listen X` and `--listen=X`),
    // then let clap parse the flags — so a malformed server launch fails with a
    // real CLI error instead of silently binding an empty address.
    if !argv.iter().any(|a| a == "--listen" || a.starts_with("--listen=")) {
        return None;
    }
    let cmd = ServerArgs::augment_args(clap::Command::new("jlua"));
    let matches = cmd
        .try_get_matches_from(std::iter::once("jlua").chain(argv.iter().map(String::as_str)))
        .unwrap_or_else(|e| e.exit());
    Some(GuestRole::Server(ServerArgs::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())))
}

/// Run the role to completion and exit the process.
pub fn run(role: GuestRole, argv: Vec<String>) -> ! {
    match role {
        #[cfg(windows)]
        GuestRole::Tracer => crate::etw::run_collector(argv.into_iter()),
        #[cfg(windows)]
        GuestRole::DesktopUi => crate::guest_desktop::run_cli(argv.into_iter()),
        #[cfg(not(windows))]
        GuestRole::Tracer | GuestRole::DesktopUi => {
            // The ETW collector and the desktop probe only exist inside a
            // Windows Sandbox guest; there is nothing to run here.
            let _ = argv;
            eprintln!("this guest role is only supported on Windows");
            std::process::exit(2)
        }
        GuestRole::Server(args) => run_server(args),
    }
}

/// Serve the debug protocol until the process is killed. Failures are printed
/// as well as logged: `wsb exec` discards a guest's stdout, so the caller
/// redirects it to a log in the shared folder that `await_server_ready` tails
/// to explain a server that never came up.
pub fn run_server(args: ServerArgs) -> ! {
    crate::init_tracing();
    let cfg = args.symbol_config();
    // `--listen` is what selects this role, so clap has already parsed a value.
    let Some(listen) = args.listen else {
        eprintln!("--listen needs an address, e.g. --listen 0.0.0.0:9000");
        std::process::exit(2);
    };
    println!("joybug debug server (jlua --listen) starting on {listen}");
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
                assert_eq!(a.listen.as_deref(), Some("0.0.0.0:9000"));
                assert_eq!(a.symbol_path.as_deref(), Some("srv*C:/s"));
                assert!(a.offline);
            }
            _ => panic!("expected the server role"),
        }
        assert!(from_argv(&argv("script.lua --command x.exe")).is_none());
        assert!(from_argv(&[]).is_none());
    }

    // clap accepts `--flag=value`, so the role sniff must too: it used to match
    // only the bare `--listen` token, and `jlua --listen=addr` silently fell
    // through to the REPL instead of starting a server.
    #[test]
    fn the_equals_form_selects_the_server_role() {
        match from_argv(&argv("--listen=0.0.0.0:9000 --symbol-path=srv*C:/s")) {
            Some(GuestRole::Server(a)) => {
                assert_eq!(a.listen.as_deref(), Some("0.0.0.0:9000"));
                assert_eq!(a.symbol_path.as_deref(), Some("srv*C:/s"));
                assert!(!a.offline);
            }
            _ => panic!("expected the server role"),
        }
    }
}
