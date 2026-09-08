//! Windows Sandbox run mode: launch/debug a target *inside* a disposable
//! Windows Sandbox VM — the reusable mechanism, host-application-agnostic.
//!
//! The mechanism leans on joybug-core already being a client/server debugger
//! over TCP: a joybug guest exe (the server) runs inside the sandbox, a debug
//! client connects to it over the sandbox's NAT'd IP, and the target is created
//! (`CreateProcessW`) and debugged inside the guest. Nothing downstream of the
//! debug loop changes — it just talks to a different address.
//!
//! Provisioning (see [`provision`]):
//!   0. preflight: the caller's guest exe carries this build's guest marker
//!      ([`preflight`]), no other sandbox is running, the op set is valid;
//!   1. snapshot the guest-binary folder into the session's io dir
//!      ([`stage_guest_bin`]) and share it read-only, plus the writable I/O
//!      folder, a symbol cache and the user's mounts;
//!   2. boot the sandbox, open the viewer, start the server via `wsb exec`;
//!   3. wait for its IP, then perform the protocol handshake until the server
//!      answers (a revision mismatch fails here, loudly);
//!   4. return a [`SandboxHandle`] whose `server_url` is the guest address.
//!
//! This module owns NO host data-directory layout and never embeds the guest
//! binaries — all host paths arrive via [`ProvisionConfig`]. A host application
//! (the Tauri app, `jlua`) supplies the guest binary and I/O paths.
//!
//! Recovery ([`list`], [`stop_all`], [`attach`], [`install_ctrl_handler`]):
//! Windows allows one sandbox per user, and a driver that dies without stopping
//! its VM leaves the next `provision` refused. These give a script a way back
//! without scraping `wsb.exe list --raw` by hand.

mod config;
pub mod guest_ui;
pub mod preflight;
pub mod rewrite;

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{info, warn};

pub use config::{
    default_symbols_dir, EtwCaptureSpec, MountSpec, ProvisionConfig, SandboxHandle, SandboxStatus,
    DEFAULT_ETW_OUT_FILE, DEFAULT_MEMORY_MB, DEFAULT_SERVER_PORT,
};
// Re-export the winsandbox surface host applications still reference directly, so
// they depend only on `joybug_core::sandbox::*` (not the winsandbox crate).
pub use winsandbox::{
    ensure_supported, expand_ops, is_tracer_done, os_build, pretty_path, RunAs, TraceEvent,
    ALL_OPS, DEFAULT_OPS, MIN_BUILD,
};

use winsandbox::{RunningSandbox, Sandbox, SandboxConfig, Toggle};

/// Guest mount points (fixed inside the sandbox).
const GUEST_BIN_DIR: &str = r"C:\joybug"; // read-only: the guest exe + VC runtime
pub(crate) const GUEST_IO_DIR: &str = r"C:\io"; // read-write: server.log, events-*.jsonl
const GUEST_SYMBOLS_DIR: &str = r"C:\symbols"; // read-write: persistent PDB cache
/// How long to wait for the guest to boot, get networking, and start the server.
const PROVISION_TIMEOUT: Duration = Duration::from_secs(180);
/// Subfolder of `io_dir` holding the per-session snapshot of the guest binaries.
const STAGED_BIN_SUBDIR: &str = "guest-bin";

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

// ---- live-sandbox registry (for the Ctrl handler and diagnostics) ----

static LIVE: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn register_live(id: &str) {
    let mut live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    if !live.iter().any(|x| x == id) {
        live.push(id.to_string());
    }
}

pub(crate) fn unregister_live(id: &str) {
    let mut live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    live.retain(|x| x != id);
}

/// Ids of the sandboxes this process provisioned and has not yet stopped.
pub fn live_ids() -> Vec<String> {
    LIVE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Ids of every sandbox currently running for this user (`wsb list`).
pub fn list() -> Result<Vec<String>, String> {
    Sandbox::list()
        .map(|v| v.into_iter().map(|s| s.id().to_string()).collect())
        .map_err(|e| format!("Could not query Windows Sandbox state: {e}"))
}

/// Stop one sandbox by id.
pub fn stop(id: &str) -> Result<(), String> {
    unregister_live(id);
    Sandbox::from_id(id).stop().map_err(|e| format!("wsb stop --id {id}: {e}"))
}

/// Stop every running sandbox of this user; returns how many were stopped. The
/// recovery for a driver that died with its VM up (RETRO B5).
pub fn stop_all() -> Result<usize, String> {
    let ids = list()?;
    let mut stopped = 0;
    for id in &ids {
        match stop(id) {
            Ok(()) => stopped += 1,
            Err(e) => warn!("{e}"),
        }
    }
    Ok(stopped)
}

/// Adopt an already-running sandbox (from [`list`]) WITHOUT owning its
/// lifetime — dropping the returned handle leaves the VM up; an explicit stop
/// still stops it. `server_url` is filled in when a joybug server answers the
/// handshake on `server_port` at the guest's IP, else left empty. `io_dir` is
/// the host side of the `C:\io` share the sandbox was provisioned with, needed
/// for `exec_capture`/`guest_ui`; `guest_exe` is the staged guest's file name,
/// needed for `guest_ui`. Pass `None` when unknown.
pub fn attach(
    id: &str,
    server_port: u16,
    io_dir: Option<PathBuf>,
    guest_exe: Option<String>,
) -> Result<SandboxHandle, String> {
    let sandbox = Sandbox::from_id(id);
    if !sandbox.is_running().map_err(|e| e.to_string())? {
        return Err(format!("no running sandbox with id {id} (see sbx.list())"));
    }
    let server_url = match sandbox.ip() {
        Ok(ips) => ips
            .into_iter()
            .find(|s| !s.is_empty())
            .map(|ip| format!("{ip}:{server_port}"))
            .filter(|addr| probe_server(addr, Duration::from_secs(3)).is_ok())
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    Ok(SandboxHandle {
        sandbox: RunningSandbox::detached(sandbox),
        server_url,
        guest_launch_command: String::new(),
        guest_working_directory: None,
        io_dir: io_dir.unwrap_or_default(),
        etw_enabled: false,
        etw_out_file: String::new(),
        debug: true,
        run_only_launch_cmd: None,
        etw: EtwCaptureSpec::default(),
        guest_exe: guest_exe.unwrap_or_default(),
        staged_bin_dir: PathBuf::new(),
    })
}

/// Stop every sandbox this process provisioned when the console is closed or
/// Ctrl+C / Ctrl+Break is pressed, so a killed driver does not leave the VM
/// up (RETRO B5). Returns `false` from the handler afterwards, so the default
/// handling (process exit) still runs. Call once, from a console program.
pub fn install_ctrl_handler() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn handler(_ctrl_type: u32) -> windows_sys::Win32::Foundation::BOOL {
        let ids = live_ids();
        for id in ids {
            eprintln!("stopping Windows Sandbox {id} ...");
            let _ = stop(&id);
        }
        0 // FALSE: let the default handler terminate the process
    }
    // SAFETY: registering a plain function pointer; the handler only calls
    // into this module's own (mutex-guarded) state.
    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}

/// Copy the caller's guest-binary folder (top-level files only) into
/// `io_dir\guest-bin` and make sure the VC runtime the guest exe needs is next
/// to it. The snapshot — not the caller's folder — is what gets shared into the
/// VM, because VSMB holds every shared file open for the sandbox's lifetime
/// (RETRO B6): with a snapshot, "swap the guest exe and re-provision" works
/// while a VM is still up, and a caller's build output is never locked.
pub fn stage_guest_bin(guest_bin_dir: &Path, io_dir: &Path) -> Result<PathBuf, String> {
    let dest = io_dir.join(STAGED_BIN_SUBDIR);
    std::fs::create_dir_all(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let entries = std::fs::read_dir(guest_bin_dir)
        .map_err(|e| format!("read guest_bin_dir {}: {e}", guest_bin_dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        // One stat per entry: the directory listing already carries it.
        let Ok(a) = entry.metadata() else { continue };
        if !a.is_file() {
            continue;
        }
        let Some(name) = path.file_name() else { continue };
        let target = dest.join(name);
        // Skip an identical file already staged (same length + mtime) so a
        // repeated provision into the same io dir does not recopy 60 MB.
        if let Ok(b) = std::fs::metadata(&target) {
            if a.len() == b.len() && a.modified().ok() == b.modified().ok() {
                continue;
            }
        }
        std::fs::copy(&path, &target)
            .map_err(|e| format!("stage {} into {}: {e}", path.display(), dest.display()))?;
    }
    stage_vc_runtime(&dest);
    Ok(dest)
}

/// Copy the VC runtime DLLs the guest exe needs into `dir` (the bare sandbox
/// image has no VC++ redistributable; the core binaries link it dynamically).
/// Host arch == guest arch, so the host's own System32 copies are correct.
/// Best-effort: a missing DLL is logged, not fatal (the failure would otherwise
/// surface as a guest 0xC0000135).
fn stage_vc_runtime(dir: &Path) {
    let sys32 = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"));
    for dll in ["vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll"] {
        let dst = dir.join(dll);
        if dst.exists() {
            continue;
        }
        let src = sys32.join(dll);
        if let Err(e) = std::fs::copy(&src, &dst) {
            warn!("could not stage {dll} into the guest folder: {e}");
        }
    }
}

/// Provision a sandbox from `cfg`, start the in-guest server (debug mode) or
/// prepare the run-only tracer command, and return a handle whose `server_url`
/// points at the guest. `cfg.launch_command`/`working_directory` are host-facing
/// and rewritten to guest paths using `cfg.mounts`.
pub fn provision(cfg: &ProvisionConfig) -> Result<SandboxHandle, String> {
    // Preflight, cheapest first: the op vocabulary, the guest exe, then the OS
    // build and that no other sandbox is already running (wsb allows only one
    // per user). A previous session's teardown (`wsb stop`) may run on a
    // background thread and take seconds, so on a stop→start or restart the old
    // VM may still be winding down — wait it out before declaring a conflict.
    cfg.etw.validate()?;
    let guest_src = cfg.guest_bin_dir.join(&cfg.guest_exe);
    preflight::preflight_guest_exe(&guest_src)?;
    info!(exe = %guest_src.display(), "guest exe preflight ok");
    if !cfg.debug && cfg.launch_command.trim().is_empty() {
        return Err("run-only mode needs a `launch_command`: the tracer is the launcher".to_string());
    }
    ensure_supported().map_err(|e| e.to_string())?;
    let preflight_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let ids = list()?;
        if ids.is_empty() {
            break;
        }
        if Instant::now() >= preflight_deadline {
            return Err(format!(
                "A Windows Sandbox is already running ({}); only one is supported per user. \
                 Stop it and try again — from Lua: sbx.stop_all() or sbx.attach(id); from a \
                 shell: wsb stop --id <id>.",
                ids.join(", ")
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    std::fs::create_dir_all(&cfg.io_dir).map_err(|e| format!("create io dir: {e}"))?;
    std::fs::create_dir_all(&cfg.symbols_dir).map_err(|e| format!("create symbols dir: {e}"))?;
    let staged_bin_dir = stage_guest_bin(&cfg.guest_bin_dir, &cfg.io_dir)?;

    // Resolve user mounts to guest paths, then rewrite the launch command/cwd.
    // Debug mode may leave the command empty (the script drives `dbg:launch`).
    let resolved = rewrite::resolve_mounts(&cfg.mounts);
    let (guest_launch_command, guest_working_directory) = if cfg.launch_command.trim().is_empty() {
        (String::new(), None)
    } else {
        rewrite::rewrite_command(&cfg.launch_command, cfg.working_directory.as_deref(), &resolved)?
    };

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
    register_live(sandbox.id());

    // Wait for the guest to boot far enough that `wsb exec` succeeds.
    sandbox
        .wait_until_ready(Duration::from_secs(150))
        .map_err(|e| format!("sandbox guest did not become ready: {e}"))?;
    info!("sandbox guest is ready; sharing folders");

    // Share the guest binaries (read-only snapshot), the writable I/O folder
    // (server log + ETW output), the symbol cache, and the user's target mounts.
    sandbox
        .share(&staged_bin_dir, GUEST_BIN_DIR, false)
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
        let url = await_server_ready(&sandbox, cfg.server_port, &cfg.io_dir, &guest_src)?;
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
        // It is NOT started here — the caller runs it via `run_traced` on a watcher
        // thread whose blocking exec returns when the target exits, which is how a
        // run-only session ends and its VM is torn down. `--capture` (if any) must
        // precede `--`, which consumes the rest as the target command line.
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
        staged_bin_dir,
    })
}

/// Run a guest command via a *blocking* `wsb exec` on the CALLING thread. The
/// blocking exec keeps the guest process alive in the exec's job for its whole
/// lifetime (a detached `start ""` child is killed when the job closes); it
/// returns the guest process's exit code when it exits, or an error when the
/// exec itself failed (sandbox stopped, session gone).
///
/// `run_as` selects the guest context: `System` (session 0, non-interactive —
/// the right choice for headless automation and the ETW tracer's kernel
/// providers) or `ExistingLogin` (the interactive user session — required for a
/// debugged target to render a foreground window on the visible desktop; needs
/// `wsb connect` to have established that session first).
pub fn exec_blocking(sandbox_id: &str, cmd: &str, run_as: RunAs) -> Result<i32, String> {
    let sandbox = Sandbox::from_id(sandbox_id.to_string());
    sandbox
        .exec(cmd, run_as, None)
        .map_err(|e| format!("guest exec failed (target exited abnormally, or sandbox stopped): {e}"))
}

/// [`exec_blocking`] on a background thread, for guest processes that outlive
/// the caller (the in-guest server, the debug-mode tracer).
fn spawn_guest_exec(sandbox_id: String, cmd: String, run_as: RunAs) {
    std::thread::spawn(move || {
        if let Err(e) = exec_blocking(&sandbox_id, &cmd, run_as) {
            warn!("{e}");
        }
    });
}

/// A file name unique across this process for a scratch file in the io share
/// (`<prefix>-<host pid>-<seq>`), so concurrent sessions never collide.
fn scratch_name(prefix: &str) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}-{}-{seq}", std::process::id())
}

/// The last `n` lines of `text`, in order.
fn tail_lines(text: &str, n: usize) -> String {
    let mut lines: Vec<&str> = text.lines().rev().take(n).collect();
    lines.reverse();
    lines.join("\n")
}

/// Run a guest command and capture its combined stdout+stderr through the
/// session's `C:\io` share (which is already mapped — unlike
/// `Sandbox::run_and_capture`, which shares a fresh folder per call). Returns
/// `(exit_code, output)`.
pub fn exec_capture(handle: &SandboxHandle, cmd: &str, run_as: RunAs) -> Result<(i32, String), String> {
    if handle.io_dir.as_os_str().is_empty() {
        return Err("this sandbox handle has no io share (attach it with an `io_dir`)".to_string());
    }
    let name = format!("{}.txt", scratch_name("exec"));
    let wrapped = format!(r#"cmd.exe /c ({cmd}) > {GUEST_IO_DIR}\{name} 2>&1"#);
    let code = exec_blocking(handle.id(), &wrapped, run_as)?;
    let host = handle.io_dir.join(&name);
    let text = std::fs::read_to_string(&host).unwrap_or_default();
    let _ = std::fs::remove_file(&host);
    Ok((code, text))
}

/// Run-only mode: launch the target under the in-guest ETW collector and BLOCK
/// until the traced tree exits, then prove the collector actually ran. Returns
/// the exec's exit code. A capture that never started — the wrong guest binary,
/// a tracer that could not enable ETW — is an error carrying the tracer's own
/// `error` record or the exit code, never a silent "0 events" (RETRO B3).
pub fn run_traced(handle: &SandboxHandle) -> Result<i32, String> {
    let cmd = handle.run_only_launch_cmd.as_deref().ok_or_else(|| {
        "run_traced is only valid for a run-only sandbox (provision with debug = false)".to_string()
    })?;
    let code = exec_blocking(handle.id(), cmd, RunAs::ExistingLogin)?;
    verify_collector_ran(&handle.io_dir.join(&handle.etw_out_file), &handle.guest_exe, code)?;
    Ok(code)
}

/// The `tracer.start` check behind [`run_traced`].
fn verify_collector_ran(out_path: &Path, guest_exe: &str, code: i32) -> Result<(), String> {
    use std::io::BufRead;
    let file = match std::fs::File::open(out_path) {
        Ok(f) => f,
        Err(_) => {
            return Err(format!(
                "the guest ETW collector never started: '{guest_exe}' wrote no '{}' (exec exit \
                 code {code}). The guest exe must provide the collector role (--out); stage \
                 joybug-core.exe, jlua.exe or the Joybug app exe from this build",
                out_path.display()
            ))
        }
    };
    // The `start` record is written before the target is even spawned, so it
    // is at the top of any capture that has one: stream the file and stop
    // there, rather than parsing a whole (possibly huge) capture. Tracer
    // records are the only lines that mention "tracer" at all.
    let mut errors = Vec::new();
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        if !line.contains("\"tracer\"") {
            continue;
        }
        let Some(ev) = TraceEvent::from_json_line(&line) else { continue };
        if ev.kind != "tracer" {
            continue;
        }
        match ev.op.as_str() {
            "start" => return Ok(()),
            "error" => errors.push(ev.message.unwrap_or(line)),
            _ => {}
        }
    }
    let detail = if errors.is_empty() {
        format!("exec exit code {code}")
    } else {
        format!("exec exit code {code}; tracer reported: {}", errors.join(" | "))
    };
    Err(format!(
        "the guest ETW collector never started: '{}' has no tracer.start record ({detail}). \
         The guest exe '{guest_exe}' must provide the collector role (--out)",
        out_path.display()
    ))
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

/// One TCP connect + protocol handshake against `addr`. `Ok` means a joybug
/// server of this build answered; the error distinguishes "nothing listening"
/// (`io`) from "a server that is not this revision" (`mismatch`).
fn probe_server(addr: &str, connect_timeout: Duration) -> Result<(), ProbeError> {
    let sa: std::net::SocketAddr = addr.parse().map_err(|_| ProbeError::Io)?;
    let stream = TcpStream::connect_timeout(&sa, connect_timeout).map_err(|_| ProbeError::Io)?;
    let mut framed = crate::framed_json_stream::FramedJsonStream::new(stream);
    crate::protocol_io::handshake(&mut framed, "sandbox-provision")
        .map(|_| ())
        .map_err(|e| ProbeError::Mismatch(e.to_string()))
}

enum ProbeError {
    /// No connection: the server has not bound yet.
    Io,
    /// Connected, but the handshake failed: a different revision (or not joybug).
    Mismatch(String),
}

/// Poll for the guest IP, then handshake with the in-guest server until it
/// answers. Returns the reachable `ip:port`. A server that accepts the
/// connection but fails the handshake is a revision mismatch and fails
/// provisioning immediately — the old TCP-only probe let that surface later as
/// a hung first request (RETRO B2). On timeout, includes the tail of the guest
/// server log (captured via the writable share) in the error.
fn await_server_ready(
    sandbox: &RunningSandbox,
    port: u16,
    io_dir: &Path,
    guest_exe: &Path,
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

        // Step 2: server accepting connections AND speaking our protocol.
        if let Some(ip) = &last_ip {
            let addr = format!("{ip}:{port}");
            match probe_server(&addr, Duration::from_millis(500)) {
                Ok(()) => return Ok(addr),
                Err(ProbeError::Io) => {}
                Err(ProbeError::Mismatch(msg)) => {
                    return Err(format!(
                        "the in-guest server at {addr} (staged from {}) does not speak this \
                         build's protocol: {msg}{}",
                        guest_exe.display(),
                        read_server_log_tail(io_dir)
                    ));
                }
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Best-effort tail of the guest server log for error reporting.
fn read_server_log_tail(io_dir: &Path) -> String {
    match std::fs::read_to_string(io_dir.join("server.log")) {
        Ok(s) if !s.trim().is_empty() => {
            format!("\n--- guest server.log (tail) ---\n{}", tail_lines(&s, 15))
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
    use super::*;

    fn cap(ops: &[&str]) -> EtwCaptureSpec {
        EtwCaptureSpec { ops: ops.iter().map(|s| s.to_string()).collect(), ..Default::default() }
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
        c.buffer_kb = Some(2048);
        c.buffers = Some(512);
        assert_eq!(
            c.cmd_flags(),
            " --capture file.delete,registry.set_value --stacks --buffer-kb 2048 --buffers 512"
        );
    }

    #[test]
    fn groups_and_aliases_reach_the_guest_expanded() {
        let c = cap(&["audit", "registry.query"]);
        assert_eq!(
            c.capture_ops().as_deref(),
            Some("registry.query_value,audit.open_process,audit.open_thread")
        );
    }

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("joybug-sbx-test-{name}-{}", std::process::id()));
        p
    }

    #[test]
    fn verify_collector_requires_a_start_record() {
        let out = tmp("events.jsonl");
        let _ = std::fs::remove_file(&out);
        let err = verify_collector_ran(&out, "joybug.exe", 0).unwrap_err();
        assert!(err.contains("never started"), "{err}");
        assert!(err.contains("joybug.exe"), "{err}");

        std::fs::write(&out, "{\"kind\":\"tracer\",\"op\":\"error\",\"message\":\"failed to start ETW trace\"}\n").unwrap();
        let err = verify_collector_ran(&out, "joybug.exe", 4).unwrap_err();
        assert!(err.contains("failed to start ETW trace"), "{err}");
        assert!(err.contains("exit code 4"), "{err}");

        std::fs::write(&out, "{\"kind\":\"tracer\",\"op\":\"start\",\"mode\":\"spawn\"}\n{\"kind\":\"tracer\",\"op\":\"done\"}\n").unwrap();
        assert!(verify_collector_ran(&out, "joybug.exe", 0).is_ok());
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn stage_guest_bin_snapshots_top_level_files() {
        let src = tmp("src");
        let io = tmp("io");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&io);
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("guest.exe"), b"exe").unwrap();
        std::fs::write(src.join("sub").join("nested.txt"), b"no").unwrap();

        let staged = stage_guest_bin(&src, &io).unwrap();
        assert_eq!(staged, io.join(STAGED_BIN_SUBDIR));
        assert_eq!(std::fs::read(staged.join("guest.exe")).unwrap(), b"exe");
        assert!(!staged.join("nested.txt").exists(), "subfolders are not staged");
        // The VC runtime is copied from System32 when the source lacks it.
        assert!(staged.join("vcruntime140.dll").exists() || !PathBuf::from(r"C:\Windows\System32\vcruntime140.dll").exists());

        // Re-staging a changed source overwrites the snapshot.
        std::fs::write(src.join("guest.exe"), b"exe-v2-longer").unwrap();
        stage_guest_bin(&src, &io).unwrap();
        assert_eq!(std::fs::read(staged.join("guest.exe")).unwrap(), b"exe-v2-longer");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&io);
    }

    #[test]
    fn live_registry_tracks_ids() {
        register_live("id-a");
        register_live("id-a");
        assert_eq!(live_ids().iter().filter(|s| *s == "id-a").count(), 1);
        unregister_live("id-a");
        assert!(!live_ids().iter().any(|s| s == "id-a"));
    }
}
