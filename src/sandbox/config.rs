//! Canonical input/output types for [`super::provision`], owned by core so the
//! mechanism has no dependency on any host application's config shapes. Callers
//! (the Tauri app, `jlua`) map their own settings onto [`ProvisionConfig`].

use std::path::{Path, PathBuf};

use winsandbox::RunningSandbox;

/// Port the in-guest server listens on unless a caller overrides it.
pub const DEFAULT_SERVER_PORT: u16 = 9000;
/// Guest memory unless a caller overrides it.
pub const DEFAULT_MEMORY_MB: u32 = 4096;
/// Basename of the tracer's output file unless a caller overrides it.
pub const DEFAULT_ETW_OUT_FILE: &str = "events.jsonl";

/// The default `symbols_dir` for an `io_dir`: a `symbols` sibling, so the PDB
/// cache outlives any one session's io folder.
pub fn default_symbols_dir(io_dir: &Path) -> PathBuf {
    io_dir.parent().map(|p| p.join("symbols")).unwrap_or_else(|| io_dir.join("symbols"))
}

// ETW capture config lives in `crate::etw` (available under the `etw` feature,
// which `sandbox` implies) so it is usable for host tracing without a sandbox.
pub use crate::etw::EtwCaptureSpec;

/// A host folder to map into the guest, as supplied by the caller (before path
/// resolution). `resolve_mounts` in [`super::rewrite`] turns these into guest
/// `C:\mounts\<basename>` paths.
#[derive(Debug, Clone)]
pub struct MountSpec {
    pub host_path: String,
    pub read_only: bool,
}

/// Everything [`super::provision`] needs. All host paths are explicit and
/// caller-supplied — core owns no data-directory layout and never embeds the
/// guest binaries (they *are* a `joybug-core.exe` build artifact; embedding them
/// in core would be circular).
#[derive(Debug, Clone)]
pub struct ProvisionConfig {
    /// Host folder holding [`Self::guest_exe`] (+ the VC runtime it needs).
    /// Shared read-only into the guest.
    pub guest_bin_dir: PathBuf,
    /// Filename, inside `guest_bin_dir`, of the executable that provides BOTH
    /// the debug server and the ETW collector.
    ///
    /// One binary serves both roles, selected by the flags it is launched with:
    /// `--listen` starts the server, `--out` starts the collector. Joybug stages
    /// a copy of its own exe, so the guest always runs the same build as the
    /// host and there is no second binary to keep in step.
    pub guest_exe: String,
    /// Host folder shared read-write as the guest's `C:\io` (server log + ETW JSONL).
    pub io_dir: PathBuf,
    /// Host folder shared read-write as the guest's `C:\symbols` (persistent PDB cache).
    pub symbols_dir: PathBuf,
    /// Basename of the tracer's output file inside `io_dir`.
    pub etw_out_file: String,
    /// Port the in-guest server listens on. The guest IP disambiguates it
    /// host-side, so a fixed port is fine.
    pub server_port: u16,
    /// User folders to map into the guest.
    pub mounts: Vec<MountSpec>,
    /// Guest memory in MB.
    pub memory_mb: u32,
    /// Attach the debugger (true) or "just run" the target under ETW (false).
    pub debug: bool,
    /// Run the ETW collector against the target process tree (debug mode only —
    /// run-only mode always traces, the tracer *is* the launcher).
    pub collect_etw: bool,
    /// What the ETW tracer records.
    pub etw: EtwCaptureSpec,
    /// Pass `--offline` to the guest server (never download symbols).
    pub symbol_offline: bool,
    /// Host-facing launch command; rewritten to guest paths via `mounts`. May
    /// be empty in debug mode (the script launches whatever it likes through
    /// `dbg:launch`); run-only mode requires it — the tracer is the launcher.
    pub launch_command: String,
    /// Host-facing working directory; rewritten to guest paths via `mounts`.
    pub working_directory: Option<String>,
}

/// A live sandbox backing a session. Dropping it stops the sandbox (`wsb stop`)
/// via the inner RAII guard.
pub struct SandboxHandle {
    /// RAII guard — `Drop` runs `wsb stop`.
    pub sandbox: RunningSandbox,
    /// `guest_ip:port` a debug client connects to (empty for run-only mode).
    pub server_url: String,
    /// Guest-path-rewritten launch command (target reached via a mapped folder).
    pub guest_launch_command: String,
    /// Guest working directory, if resolved.
    pub guest_working_directory: Option<String>,
    /// Host side of the writable `C:\io` share (where the tracer writes its JSONL).
    pub io_dir: PathBuf,
    /// Whether ETW collection is active for this session.
    pub etw_enabled: bool,
    /// Basename of the tracer's per-session output file inside `io_dir`.
    pub etw_out_file: String,
    /// True for debugger-attached sessions; false for run-only detonation.
    pub debug: bool,
    /// Run-only sessions only: the ETW-tracer command that launches + observes the
    /// target. NOT started in `provision`; the caller runs it on a watcher thread
    /// (a blocking exec that returns when the target exits) so the session can end
    /// and the VM can be torn down. `None` for debug sessions.
    pub run_only_launch_cmd: Option<String>,
    /// What the ETW tracer records — carried so the debug-mode `start_tracer`
    /// (which only sees the handle) can pass it through.
    pub etw: EtwCaptureSpec,
    /// Guest-side filename of the dual-role exe, carried for the same reason.
    pub guest_exe: String,
    /// Host folder actually shared as the guest's `C:\joybug`: a per-session
    /// snapshot of the caller's `guest_bin_dir` (see `stage_guest_bin`), so the
    /// caller's folder is never held open by the VM. Empty for an attached
    /// handle.
    pub staged_bin_dir: PathBuf,
}

impl SandboxHandle {
    /// The sandbox GUID (`wsb --id`).
    pub fn id(&self) -> &str {
        self.sandbox.id()
    }

    /// Whether dropping this handle stops the VM (false for `attach`ed handles).
    pub fn owns_vm(&self) -> bool {
        self.sandbox.owns_vm()
    }
}

impl Drop for SandboxHandle {
    fn drop(&mut self) {
        // The inner guard stops the VM (if owned); forget it for the Ctrl
        // handler either way.
        super::unregister_live(self.sandbox.id());
    }
}

/// Windows Sandbox availability at the mechanism level (OS build + `wsb.exe`).
/// A host app layers its own concerns on top (e.g. whether it embedded guest
/// binaries). Mirrors the JIT-status pattern the app already uses.
#[derive(Debug, Clone)]
pub struct SandboxStatus {
    /// OS build is new enough to have the `wsb.exe` CLI (>= [`winsandbox::MIN_BUILD`]).
    pub supported: bool,
    /// Detected OS build number.
    pub build: u32,
    /// `wsb.exe` is present and launchable (the Windows Sandbox feature is installed).
    pub wsb_present: bool,
    /// Human-readable reason the mode is unavailable, or `None` when usable.
    pub reason: Option<String>,
}
