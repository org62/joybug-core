//! Windows Sandbox run mode: launch/debug a target *inside* a disposable
//! Windows Sandbox VM — the reusable mechanism, host-application-agnostic.
//!
//! The mechanism leans on joybug-core already being a client/server debugger
//! over TCP: `joybug-core.exe` (the server) runs inside the sandbox, a debug
//! client connects to it over the sandbox's NAT'd IP, and the target is created
//! (`CreateProcessW`) and debugged inside the guest. Nothing downstream of the
//! debug loop changes — it just talks to a different address.
//!
//! Provisioning (see [`provision`]):
//!   1. share the caller-supplied guest-binary folder (one exe: server + collector)
//!      read-only, plus a writable I/O folder + a symbol cache + the user's mounts,
//!   2. boot the sandbox, open the viewer, start the server via `wsb exec`,
//!   3. wait for its IP, then TCP-probe the server until it accepts a connection,
//!   4. return a [`SandboxHandle`] whose `server_url` is the guest address.
//!
//! This module owns NO host data-directory layout and never embeds the guest
//! binaries — all host paths arrive via [`ProvisionConfig`]. A host application
//! (the Tauri app, `jlua`) supplies the staged binary tree and I/O paths.

mod config;
pub mod rewrite;

use std::net::TcpStream;
use std::time::{Duration, Instant};

use tracing::{info, warn};

pub use config::{EtwCaptureSpec, MountSpec, ProvisionConfig, SandboxHandle, SandboxStatus};
// Re-export the winsandbox surface host applications still reference directly, so
// they depend only on `joybug_core::sandbox::*` (not the winsandbox crate).
pub use winsandbox::{
    ensure_supported, is_tracer_done, os_build, pretty_path, RunAs, TraceEvent, DEFAULT_OPS,
    MIN_BUILD,
};

use winsandbox::{RunningSandbox, Sandbox, SandboxConfig, Toggle};

/// Guest mount points (fixed inside the sandbox).
const GUEST_BIN_DIR: &str = r"C:\joybug"; // read-only: the guest exe + VC runtime
const GUEST_IO_DIR: &str = r"C:\io"; // read-write: server.log, events-*.jsonl
const GUEST_SYMBOLS_DIR: &str = r"C:\symbols"; // read-write: persistent PDB cache
/// How long to wait for the guest to boot, get networking, and start the server.
const PROVISION_TIMEOUT: Duration = Duration::from_secs(180);

/// Mechanism-level availability: OS build new enough + `wsb.exe` launchable.
/// A host app layers its own concerns (e.g. embedded guest binaries) on top.
pub fn status() -> SandboxStatus {
    let build = os_build();
    let supported = build >= MIN_BUILD;

    // Probe the CLI by listing (also exercises the feature being installed).
    let wsb_present = match Sandbox::list() {
        Ok(_) => true,
        // wsb.exe missing / feature not installed / OS too old.
        Err(winsandbox::Error::Spawn(_)) | Err(winsandbox::Error::Unsupported { .. }) => false,
        // Ran but reported some other error → the CLI exists.
        Err(_) => true,
    };

    let reason = if !supported {
        Some(format!(
            "Requires Windows 11 24H2 (build {MIN_BUILD}+); this system is build {build}."
        ))
    } else if !wsb_present {
        Some(
            "Windows Sandbox is not available — enable the 'Windows Sandbox' optional feature."
                .to_string(),
        )
    } else {
        None
    };

    SandboxStatus { supported, build, wsb_present, reason }
}

/// Provision a sandbox from `cfg`, start the in-guest server (debug mode) or
/// prepare the run-only tracer command, and return a handle whose `server_url`
/// points at the guest. `cfg.launch_command`/`working_directory` are host-facing
/// and rewritten to guest paths using `cfg.mounts`.
pub fn provision(cfg: &ProvisionConfig) -> Result<SandboxHandle, String> {
    // Preflight: OS build + that no other sandbox is already running (wsb allows
    // only one per user). A previous session's teardown (`wsb stop`) may run on a
    // background thread and take seconds, so on a stop→start or restart the old
    // VM may still be winding down — wait it out before declaring a conflict.
    ensure_supported().map_err(|e| e.to_string())?;
    let preflight_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match Sandbox::list() {
            Ok(list) if list.is_empty() => break,
            Ok(_) if Instant::now() < preflight_deadline => {
                std::thread::sleep(Duration::from_secs(1));
            }
            Ok(_) => {
                return Err(
                    "A Windows Sandbox is already running; only one is supported per user. \
                     Stop it and try again."
                        .to_string(),
                );
            }
            Err(e) => return Err(format!("Could not query Windows Sandbox state: {e}")),
        }
    }

    std::fs::create_dir_all(&cfg.io_dir).map_err(|e| format!("create io dir: {e}"))?;
    std::fs::create_dir_all(&cfg.symbols_dir).map_err(|e| format!("create symbols dir: {e}"))?;

    // Resolve user mounts to guest paths, then rewrite the launch command/cwd.
    let resolved = rewrite::resolve_mounts(&cfg.mounts);
    let (guest_launch_command, guest_working_directory) =
        rewrite::rewrite_command(&cfg.launch_command, cfg.working_directory.as_deref(), &resolved)?;

    // Build the server's symbol arguments. Point the download cache at the shared
    // C:\symbols so fetched PDBs persist on the host.
    let guest_symbol_path =
        format!(r"srv*{GUEST_SYMBOLS_DIR}*https://msdl.microsoft.com/download/symbols");
    // The symbol path has no spaces, so it needs no quotes — which keeps the
    // `cmd /c "..."` server-launch wrapper free of nested quotes.
    let mut server_args =
        format!("--listen 0.0.0.0:{} --symbol-path {}", cfg.server_port, guest_symbol_path);
    if cfg.symbol_offline {
        server_args.push_str(" --offline");
    }

    // Boot a bare networked sandbox. Networking is unconditional — the debug
    // channel (TCP to the in-guest server) requires it. Folders are shared in and
    // the server is started at runtime via `wsb exec` (as SYSTEM) — NOT via
    // <LogonCommand> or boot-time <MappedFolder>, because those need an
    // interactive logon that a headless `wsb start` never performs. `wsb exec -r
    // System` and `wsb share` both work headlessly.
    let sbx_cfg = SandboxConfig::new().networking(Toggle::Enable).memory_mb(cfg.memory_mb);

    info!("starting Windows Sandbox");
    // Take the RAII guard immediately so any early return below still tears the
    // sandbox down.
    let sandbox = Sandbox::start_with(&sbx_cfg)
        .map_err(|e| format!("failed to start sandbox: {e}"))?
        .into_guard();

    // Wait for the guest to boot far enough that `wsb exec` succeeds.
    sandbox
        .wait_until_ready(Duration::from_secs(150))
        .map_err(|e| format!("sandbox guest did not become ready: {e}"))?;
    info!("sandbox guest is ready; sharing folders");

    // Share the guest binaries (read-only), the writable I/O folder (server log +
    // ETW output), the symbol cache, and the user's target mounts.
    sandbox
        .share(&cfg.guest_bin_dir, GUEST_BIN_DIR, false)
        .map_err(|e| format!("share the guest binary folder: {e}"))?;
    sandbox
        .share(&cfg.io_dir, GUEST_IO_DIR, true)
        .map_err(|e| format!("share io folder: {e}"))?;
    sandbox
        .share(&cfg.symbols_dir, GUEST_SYMBOLS_DIR, true)
        .map_err(|e| format!("share symbol cache: {e}"))?;
    for m in &resolved {
        sandbox
            .share(&m.host, &m.guest, !m.read_only)
            .map_err(|e| format!("share mount {}: {e}", m.guest))?;
    }

    let mut run_only_launch_cmd: Option<String> = None;

    let server_url = if cfg.debug {
        // Debug mode: make the sandbox VISIBLE and put the target in the
        // foreground. `wsb connect` both opens the viewer window (so the desktop
        // appears immediately) and establishes the interactive user session that
        // `RunAs::ExistingLogin` requires. Without this the server — and thus the
        // target it CreateProcessW's — runs as SYSTEM in session 0 and renders no
        // window on the interactive desktop.
        info!("opening sandbox viewer (wsb connect)");
        sandbox
            .connect()
            .map_err(|e| format!("failed to open the sandbox window (wsb connect): {e}"))?;
        // Gate: wait until the interactive session actually accepts commands. This
        // waits out connect's async handshake and FAILS the session if it can't be
        // established (rather than silently falling back to a headless launch).
        wait_login_ready(&sandbox, Duration::from_secs(60))?;
        info!("sandbox interactive session established");

        // Open the guest firewall for the server port BEFORE the server binds.
        // Running the server as the interactive user (ExistingLogin) means Windows
        // Firewall now shows an interactive "allow this app?" prompt and BLOCKS
        // inbound until answered — which stalls the host→guest debug channel. A
        // pre-created allow rule (added as SYSTEM) makes inbound deterministic with
        // no prompt. Best-effort: if it fails, await_server_ready still reports the
        // blocked channel loudly.
        allow_server_firewall(&sandbox, cfg.server_port);

        // Start the joybug server in the interactive session (blocking exec on a
        // background thread — a detached `start ""` would be killed when the
        // exec's job closes, exactly like the tracer). The debugger launches the
        // target; the ETW tracer, if enabled, attaches on ProcessCreated.
        let server_cmd = format!(
            r"{bin}\{exe} {args} > {io}\server.log 2>&1",
            bin = GUEST_BIN_DIR,
            exe = cfg.guest_exe,
            args = server_args,
            io = GUEST_IO_DIR,
        );
        // Wrap in cmd so the redirect works; blocking on a thread so it keeps
        // running (the server never exits on its own). ExistingLogin → the target
        // it spawns is visible on the desktop the viewer shows.
        spawn_guest_exec(
            sandbox.id().to_string(),
            format!("cmd.exe /c {server_cmd}"),
            RunAs::ExistingLogin,
        );
        let url = await_server_ready(&sandbox, cfg.server_port, &cfg.io_dir)?;
        info!(%url, "sandbox server ready");
        url
    } else {
        // Run-only ("just launch") mode: no debugger. Make the sandbox VISIBLE and
        // run the target in the foreground, same as debug mode — open the viewer +
        // establish the interactive session.
        info!("opening sandbox viewer (wsb connect) for run-only");
        sandbox
            .connect()
            .map_err(|e| format!("failed to open the sandbox window (wsb connect): {e}"))?;
        wait_login_ready(&sandbox, Duration::from_secs(60))?;
        info!("sandbox interactive session established (run-only)");

        // Build the ETW-tracer command that launches + observes the target, as the
        // interactive user so its window is visible on the desktop the viewer
        // shows. An elevated interactive admin can enable the kernel ETW providers.
        // It is NOT started here — the caller runs it on a watcher thread whose
        // blocking exec returns when the target exits, which is how a run-only
        // session ends and its VM is torn down. `--capture` (if any) must precede
        // `--`, which consumes the rest as the target command line.
        let tracer_cmd = format!(
            r"{bin}\{exe} --out {io}\{out}{flags} -- {launch}",
            bin = GUEST_BIN_DIR,
            exe = cfg.guest_exe,
            io = GUEST_IO_DIR,
            out = cfg.etw_out_file,
            flags = cfg.etw.cmd_flags(),
            launch = guest_launch_command,
        );
        run_only_launch_cmd = Some(tracer_cmd);
        info!("sandbox run-only provisioned (viewer open); target launches on the watcher thread");
        String::new()
    };

    Ok(SandboxHandle {
        sandbox,
        server_url,
        guest_launch_command,
        guest_working_directory,
        io_dir: cfg.io_dir.clone(),
        // Run-only always traces (the tracer is the launcher); debug mode honors
        // the collect-ETW setting.
        etw_enabled: cfg.collect_etw || !cfg.debug,
        etw_out_file: cfg.etw_out_file.clone(),
        debug: cfg.debug,
        run_only_launch_cmd,
        etw: cfg.etw.clone(),
        guest_exe: cfg.guest_exe.clone(),
    })
}

/// Run a guest command via a *blocking* `wsb exec` on the CALLING thread. The
/// blocking exec keeps the guest process alive in the exec's job for its whole
/// lifetime (a detached `start ""` child is killed when the job closes); it
/// returns when the guest process exits or the sandbox is stopped.
///
/// `run_as` selects the guest context: `System` (session 0, non-interactive —
/// the right choice for headless automation and the ETW tracer's kernel
/// providers) or `ExistingLogin` (the interactive user session — required for a
/// debugged target to render a foreground window on the visible desktop; needs
/// `wsb connect` to have established that session first).
pub fn exec_blocking(sandbox_id: &str, cmd: &str, run_as: RunAs) {
    let sandbox = Sandbox::from_id(sandbox_id.to_string());
    if let Err(e) = sandbox.exec(cmd, run_as, None) {
        warn!("guest exec ended with error (target exited, or sandbox stopped): {e}");
    }
}

/// [`exec_blocking`] on a background thread, for guest processes that outlive
/// the caller (the in-guest server, the debug-mode tracer).
fn spawn_guest_exec(sandbox_id: String, cmd: String, run_as: RunAs) {
    std::thread::spawn(move || exec_blocking(&sandbox_id, &cmd, run_as));
}

/// Add a guest Windows Firewall rule allowing inbound TCP to the server port,
/// run as SYSTEM (admin) so it needs no elevation. Without it, a server launched
/// as the interactive user triggers a firewall prompt that blocks the host→guest
/// debug channel until answered. Best-effort — failures are logged, not fatal
/// (the subsequent server-reachability probe surfaces a genuinely blocked port).
fn allow_server_firewall(sandbox: &RunningSandbox, port: u16) {
    let cmd = format!(
        r#"netsh advfirewall firewall add rule name="joybug-core-inbound" dir=in action=allow protocol=TCP localport={port} profile=any"#,
    );
    match sandbox.exec(&cmd, RunAs::System, None) {
        Ok(code) if code == 0 => info!("guest firewall rule added for port {port}"),
        Ok(code) => warn!("guest firewall rule command exited with code {code}"),
        Err(e) => warn!("failed to add guest firewall rule (continuing): {e}"),
    }
}

/// Poll `wsb exec -r ExistingLogin` until the interactive user session accepts a
/// command. This waits out the async `wsb connect` handshake (the session isn't
/// ready the instant `connect` returns) and, on timeout, is the hard gate that
/// FAILS provisioning — visible debugging requires the interactive session, so we
/// do not silently fall back to a headless SYSTEM launch.
fn wait_login_ready(sandbox: &RunningSandbox, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match sandbox.exec("cmd.exe /c exit 0", RunAs::ExistingLogin, None) {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => {
                return Err(format!(
                    "the Windows Sandbox interactive session could not be established \
                     (wsb connect); visible debugging requires it: {e}"
                ));
            }
        }
    }
}

/// Poll for the guest IP, then TCP-probe the in-guest server until it accepts a
/// connection. Returns the reachable `ip:port`. On timeout, includes the tail of
/// the guest server log (captured via the writable share) in the error.
fn await_server_ready(
    sandbox: &RunningSandbox,
    port: u16,
    io_dir: &std::path::Path,
) -> Result<String, String> {
    let deadline = Instant::now() + PROVISION_TIMEOUT;
    let mut last_ip: Option<String> = None;

    loop {
        if Instant::now() >= deadline {
            let log_tail = read_server_log_tail(io_dir);
            return Err(format!(
                "sandbox server did not become reachable within {}s{}",
                PROVISION_TIMEOUT.as_secs(),
                log_tail
            ));
        }

        // Step 1: guest networking up → we have an IPv4.
        if last_ip.is_none() {
            if let Ok(ips) = sandbox.ip() {
                if let Some(ip) = ips.into_iter().find(|s| !s.is_empty()) {
                    last_ip = Some(ip);
                }
            }
        }

        // Step 2: server accepting connections.
        if let Some(ip) = &last_ip {
            let addr = format!("{ip}:{port}");
            if let Ok(sa) = addr.parse() {
                if let Ok(stream) = TcpStream::connect_timeout(&sa, Duration::from_millis(500)) {
                    drop(stream);
                    return Ok(addr);
                }
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Best-effort tail of the guest server log for error reporting.
fn read_server_log_tail(io_dir: &std::path::Path) -> String {
    match std::fs::read_to_string(io_dir.join("server.log")) {
        Ok(s) if !s.trim().is_empty() => {
            let tail: String = s.lines().rev().take(15).collect::<Vec<_>>().into_iter().rev()
                .collect::<Vec<_>>().join("\n");
            format!("\n--- guest server.log (tail) ---\n{tail}")
        }
        _ => String::new(),
    }
}

/// Start the ETW tracer inside the sandbox, attached to the debugger-created
/// process tree rooted at `root_pid`. Runs as SYSTEM (ETW kernel providers
/// require it); its JSONL output lands in the writable I/O share.
///
/// The tracer runs via a *blocking* `wsb exec` on a background thread — NOT a
/// detached `cmd /c start ""`. `wsb exec` runs its command in a job object torn
/// down when the command returns, which kills a `start`-detached child
/// immediately (it never captures anything). A blocking exec keeps the tracer
/// alive in that job for its whole lifetime; the thread stops when the tracer
/// exits (the traced root pid exits, or the sandbox is stopped).
pub fn start_tracer(handle: &SandboxHandle, root_pid: u32) {
    let cmd = format!(
        r"{bin}\{exe} --attach-pid {pid} --out {io}\{out}{flags}",
        bin = GUEST_BIN_DIR,
        exe = handle.guest_exe,
        pid = root_pid,
        io = GUEST_IO_DIR,
        out = handle.etw_out_file,
        flags = handle.etw.cmd_flags(),
    );
    spawn_guest_exec(handle.sandbox.id().to_string(), cmd, RunAs::System);
}

#[cfg(test)]
mod tests {
    use super::config::EtwCaptureSpec;

    fn cap(ops: &[&str]) -> EtwCaptureSpec {
        EtwCaptureSpec { ops: ops.iter().map(|s| s.to_string()).collect(), callstacks: false }
    }

    #[test]
    fn empty_ops_means_tracer_default() {
        assert_eq!(cap(&[]).capture_ops(), None);
        assert_eq!(cap(&[]).cmd_flags(), "");
    }

    #[test]
    fn default_set_omits_flag() {
        // An explicit set equal to the tracer's built-in default (any order)
        // omits the flag so the guest command stays clean.
        let mut ops: Vec<&str> = winsandbox::DEFAULT_OPS.to_vec();
        ops.reverse();
        assert_eq!(cap(&ops).capture_ops(), None);
    }

    #[test]
    fn explicit_ops_pass_through() {
        let mut c = cap(&["file.delete", "registry.set_value"]);
        assert_eq!(c.capture_ops().as_deref(), Some("file.delete,registry.set_value"));
        assert_eq!(c.cmd_flags(), " --capture file.delete,registry.set_value");
        c.callstacks = true;
        assert_eq!(c.cmd_flags(), " --capture file.delete,registry.set_value --stacks");
    }
}
