//! Control Windows Sandbox from Rust.
//!
//! Windows Sandbox has **no public Win32/COM API**. The supported programmatic
//! control surface is the `wsb.exe` command-line interface that ships with
//! Windows 11, version 24H2 (build 26100) and later. This crate is a typed
//! wrapper around that CLI: it launches `wsb.exe`, passes `--raw` so every
//! response is JSON, and parses the results into Rust types.
//!
//! It also uses a genuine Windows API call (`RtlGetVersion`) to verify that the
//! running OS build is new enough to have the CLI at all — see
//! [`ensure_supported`].
//!
//! # Capabilities
//! * [`Sandbox::start`] / [`Sandbox::start_with`] — create and boot a sandbox.
//! * [`Sandbox::share`] — map a host folder into a running sandbox (copy files in/out).
//! * [`Sandbox::exec`] — run a process inside the sandbox.
//! * [`Sandbox::ip`] / [`Sandbox::list`] / [`Sandbox::stop`].
//!
//! # A note on `exec`
//! The CLI cannot capture a process's stdout/stderr. To get output back, run a
//! command that redirects into a *writable shared folder* and read the file on
//! the host. [`Sandbox::run_and_capture`] does exactly that for you.

use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;

/// `CREATE_NO_WINDOW` — spawn `wsb.exe` (a console-subsystem program) without a
/// console window. Without this every `wsb` invocation (readiness polls, share,
/// ip, exec, the tracer) flashes a console window on the host desktop; a debug
/// session issues dozens, producing a storm of flicker. See
/// <https://learn.microsoft.com/windows/win32/procthread/process-creation-flags>.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Build a `wsb.exe` command with the no-window flag applied on Windows.
fn wsb_command() -> Command {
    let mut cmd = Command::new("wsb.exe");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

mod config;
pub mod tracer;
mod trace;
mod tree;
mod version;

pub use config::{MappedFolder, SandboxConfig, Toggle};
pub use trace::{format_access_mask, is_tracer_done, pretty_path, TraceEvent, DEFAULT_OPS};
pub use tree::{PendingStart, ProcessTree};
pub use version::{ensure_supported, os_build, MIN_BUILD};

/// The user context a command runs as inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAs {
    /// Run in the SYSTEM context. Works headlessly, without an interactive
    /// desktop session — the right choice for automation.
    System,
    /// Run in the currently logged-on user's session. Requires an active
    /// interactive session (establish one first with `wsb connect`), otherwise
    /// the command fails.
    ExistingLogin,
}

impl RunAs {
    fn as_arg(self) -> &'static str {
        match self {
            RunAs::System => "System",
            RunAs::ExistingLogin => "ExistingLogin",
        }
    }
}

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `wsb.exe` could not be launched (missing binary, Sandbox feature not
    /// installed, or the OS build is too old).
    #[error("failed to launch wsb.exe: {0}. Windows Sandbox and its CLI require Windows 11 24H2+ with the 'Windows Sandbox' optional feature enabled")]
    Spawn(#[source] std::io::Error),

    /// `wsb.exe` ran but reported a failure. Holds the combined stdout/stderr text.
    #[error("wsb {subcommand} failed: {message}")]
    Cli { subcommand: String, message: String },

    /// The CLI output could not be parsed as the expected JSON shape.
    #[error("could not parse wsb {subcommand} output as JSON: {source}; raw output was: {raw}")]
    Parse {
        subcommand: String,
        raw: String,
        #[source]
        source: serde_json::Error,
    },

    /// The running OS build predates the Windows Sandbox CLI.
    #[error("Windows Sandbox CLI requires OS build {MIN_BUILD} or newer, but this system is build {found}")]
    Unsupported { found: u32 },

    /// A host-side I/O error (e.g. reading captured output back).
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;

// ---- JSON response shapes emitted by `wsb --raw` ----

#[derive(Deserialize)]
struct StartResponse {
    #[serde(rename = "Id")]
    id: String,
}

#[derive(Deserialize)]
struct ListResponse {
    #[serde(rename = "WindowsSandboxEnvironments")]
    environments: Vec<Environment>,
}

#[derive(Deserialize)]
struct Environment {
    #[serde(rename = "Id")]
    id: String,
}

#[derive(Deserialize)]
struct IpResponse {
    #[serde(rename = "Networks")]
    networks: Vec<Network>,
}

#[derive(Deserialize)]
struct Network {
    #[serde(rename = "IpV4Address")]
    ip_v4_address: String,
}

#[derive(Deserialize)]
struct ExecResponse {
    #[serde(rename = "ExitCode")]
    exit_code: i32,
}

/// A handle to a Windows Sandbox environment, identified by its GUID.
///
/// A `Sandbox` value is just an ID; dropping it does **not** stop the sandbox.
/// Call [`Sandbox::stop`] explicitly (or use [`RunningSandbox`] for RAII).
#[derive(Debug, Clone)]
pub struct Sandbox {
    id: String,
}

impl Sandbox {
    /// Wrap an existing sandbox ID (e.g. one returned by [`Sandbox::list`]).
    pub fn from_id(id: impl Into<String>) -> Self {
        Sandbox { id: id.into() }
    }

    /// The sandbox's GUID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Start a sandbox with default settings.
    pub fn start() -> Result<Self> {
        ensure_supported()?;
        let v = run_wsb("start", &["start", "--raw"])?;
        let resp: StartResponse = parse("start", &v)?;
        Ok(Sandbox { id: resp.id })
    }

    /// Start a sandbox from a [`SandboxConfig`] (mapped folders, networking,
    /// logon command, memory, etc.).
    pub fn start_with(config: &SandboxConfig) -> Result<Self> {
        ensure_supported()?;
        let xml = config.to_xml();
        let v = run_wsb("start", &["start", "--config", &xml, "--raw"])?;
        let resp: StartResponse = parse("start", &v)?;
        Ok(Sandbox { id: resp.id })
    }

    /// List the IDs of all running sandboxes for the current user.
    pub fn list() -> Result<Vec<Sandbox>> {
        ensure_supported()?;
        let v = run_wsb("list", &["list", "--raw"])?;
        let resp: ListResponse = parse("list", &v)?;
        Ok(resp
            .environments
            .into_iter()
            .map(|e| Sandbox { id: e.id })
            .collect())
    }

    /// Whether this sandbox appears in the running list.
    pub fn is_running(&self) -> Result<bool> {
        Ok(Self::list()?.iter().any(|s| s.id == self.id))
    }

    /// The sandbox's IPv4 address(es). Requires networking to be enabled.
    pub fn ip(&self) -> Result<Vec<String>> {
        let v = run_wsb("ip", &["ip", "--id", &self.id, "--raw"])?;
        let resp: IpResponse = parse("ip", &v)?;
        Ok(resp.networks.into_iter().map(|n| n.ip_v4_address).collect())
    }

    /// Map a host folder into the running sandbox.
    ///
    /// `sandbox_path` is where it appears inside the guest (e.g. `C:\host`).
    /// With `allow_write = true` the guest can write back to the host folder —
    /// this is how you copy files *out* of the sandbox.
    pub fn share(
        &self,
        host_path: impl AsRef<Path>,
        sandbox_path: impl AsRef<Path>,
        allow_write: bool,
    ) -> Result<()> {
        let host = host_path.as_ref().to_string_lossy().into_owned();
        let sbox = sandbox_path.as_ref().to_string_lossy().into_owned();
        let mut args = vec!["share", "--id", &self.id, "-f", &host, "-s", &sbox];
        if allow_write {
            args.push("--allow-write");
        }
        run_wsb("share", &args)?;
        Ok(())
    }

    /// Execute a command inside the sandbox and return the process's exit code.
    ///
    /// The CLI does not capture stdout/stderr — see [`Sandbox::run_and_capture`]
    /// if you need the output. `command` is a full command line
    /// (e.g. `r"cmd.exe /c ipconfig /all"`).
    pub fn exec(&self, command: &str, run_as: RunAs, working_dir: Option<&str>) -> Result<i32> {
        let mut args = vec![
            "exec", "--id", &self.id, "-r", run_as.as_arg(), "-c", command, "--raw",
        ];
        if let Some(dir) = working_dir {
            args.push("-d");
            args.push(dir);
        }
        let v = run_wsb("exec", &args)?;
        let resp: ExecResponse = parse("exec", &v)?;
        Ok(resp.exit_code)
    }

    /// Run a command and capture its combined stdout+stderr.
    ///
    /// This works around the CLI's lack of I/O by sharing `work_dir` into the
    /// sandbox writably, redirecting output to a file there, then reading it
    /// back on the host. `work_dir` must be an existing host folder.
    ///
    /// Returns `(exit_code, captured_output)`.
    pub fn run_and_capture(
        &self,
        command: &str,
        run_as: RunAs,
        work_dir: impl AsRef<Path>,
    ) -> Result<(i32, String)> {
        let work_dir = work_dir.as_ref();
        let guest_dir = r"C:\winsandbox-io";
        self.share(work_dir, guest_dir, true)?;

        // Unique per call so concurrent captures on the same sandbox can't clobber
        // each other's output file: sandbox id tail + a process-wide counter.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let stem = self.id.rsplit('-').next().unwrap_or("out");
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let out_name = format!("out-{stem}-{seq}.txt");
        let guest_out = format!(r"{guest_dir}\{out_name}");

        // Wrap so redirection is handled by cmd.exe regardless of `command`.
        let wrapped = format!(r#"cmd.exe /c ({command}) > "{guest_out}" 2>&1"#);
        let code = self.exec(&wrapped, run_as, None)?;

        let host_out = work_dir.join(&out_name);
        let text = std::fs::read_to_string(&host_out).unwrap_or_default();
        let _ = std::fs::remove_file(&host_out);
        Ok((code, text))
    }

    /// Stop the sandbox and release its resources.
    pub fn stop(&self) -> Result<()> {
        run_wsb("stop", &["stop", "--id", &self.id, "--raw"])?;
        Ok(())
    }

    /// Open the interactive sandbox viewer window (`wsb connect`) so a user can
    /// see and interact with the running guest desktop. Non-blocking: it spawns
    /// the viewer process and returns immediately.
    pub fn connect(&self) -> Result<()> {
        wsb_command()
            .args(["connect", "--id", &self.id])
            .spawn()
            .map_err(Error::Spawn)?;
        Ok(())
    }

    /// Convert this handle into an RAII guard that stops the sandbox on drop.
    pub fn into_guard(self) -> RunningSandbox {
        RunningSandbox { sandbox: Some(self) }
    }
}

/// RAII wrapper that calls [`Sandbox::stop`] when dropped. Deref to [`Sandbox`]
/// for all operations.
pub struct RunningSandbox {
    sandbox: Option<Sandbox>,
}

impl std::ops::Deref for RunningSandbox {
    type Target = Sandbox;
    fn deref(&self) -> &Sandbox {
        self.sandbox.as_ref().expect("sandbox present until drop")
    }
}

impl RunningSandbox {
    /// Stop now and consume the guard, surfacing any error (unlike `drop`).
    pub fn stop(mut self) -> Result<()> {
        if let Some(s) = self.sandbox.take() {
            s.stop()?;
        }
        Ok(())
    }
}

impl Drop for RunningSandbox {
    fn drop(&mut self) {
        if let Some(s) = self.sandbox.take() {
            let _ = s.stop();
        }
    }
}

// ---- internal helpers ----

/// Run `wsb.exe` with the given args, returning parsed JSON (or `Null` when the
/// command produces no output, as `stop` does).
fn run_wsb(subcommand: &str, args: &[&str]) -> Result<serde_json::Value> {
    let output = wsb_command()
        .args(args)
        .output()
        .map_err(Error::Spawn)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let trimmed = stdout.trim();

    // Valid JSON on stdout is the success signal. `wsb`'s own process exit code
    // can mirror an inner command's non-zero exit (e.g. `exec` of a failing
    // program), so a non-zero status with parseable JSON is still a success —
    // the inner code lives inside that JSON. Genuine CLI failures (bad id,
    // guest not ready) print plain text instead, which fails to parse.
    if !trimmed.is_empty() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            return Ok(v);
        }
    }

    // No JSON. Empty output on a clean exit means "no result" (e.g. `stop`).
    if trimmed.is_empty() && output.status.success() {
        return Ok(serde_json::Value::Null);
    }

    Err(Error::Cli {
        subcommand: subcommand.to_string(),
        message: combine(&stdout, &stderr),
    })
}

fn parse<T: serde::de::DeserializeOwned>(
    subcommand: &str,
    value: &serde_json::Value,
) -> Result<T> {
    serde_json::from_value(value.clone()).map_err(|source| Error::Parse {
        subcommand: subcommand.to_string(),
        raw: value.to_string(),
        source,
    })
}

fn combine(stdout: &str, stderr: &str) -> String {
    let mut parts = Vec::new();
    let o = stdout.trim();
    let e = stderr.trim();
    if !o.is_empty() {
        parts.push(o.to_string());
    }
    if !e.is_empty() {
        parts.push(e.to_string());
    }
    if parts.is_empty() {
        "wsb.exe reported failure with no output".to_string()
    } else {
        parts.join(" | ")
    }
}
