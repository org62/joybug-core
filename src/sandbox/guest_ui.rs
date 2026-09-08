//! See the guest desktop from the host (RETRO F4): a screenshot, the window
//! tree, and any window's text — including the contents of an edit control,
//! which is how a payload that "displays a string on a form" gives it up
//! without pixels.
//!
//! Everything runs *inside* the guest, in the interactive session: the staged
//! guest exe is launched in its `--ui` role ([`crate::guest_desktop`]) through
//! `wsb exec`, and its result comes back through the `C:\io` share. That is the
//! right side of the fence: the host's view of the sandbox is a viewer window
//! that may be obscured, scaled or closed, whereas the guest sees its own
//! desktop exactly. The role's stdout/stderr are captured to a log in the
//! share too, so a failure carries the guest's own error.

use std::path::{Path, PathBuf};

use super::{exec_capture, scratch_name, tail_lines, RunAs, SandboxHandle, GUEST_BIN_DIR, GUEST_IO_DIR};
use crate::guest_desktop::UiMode;

pub use crate::guest_desktop::GuestWindow;

/// Run the guest exe's `--ui` role in `mode`, returning the host path of its
/// output file.
fn run_mode(handle: &SandboxHandle, mode: UiMode) -> Result<PathBuf, String> {
    if handle.guest_exe.is_empty() {
        return Err("this sandbox handle does not know its guest exe (attach it with a `guest_exe`)".to_string());
    }
    let name = format!("{}.{}", scratch_name(&format!("ui-{}", mode.name())), mode.ext());
    let host_out = handle.io_dir.join(&name);
    let cmd = format!(
        r"{GUEST_BIN_DIR}\{} {}",
        handle.guest_exe,
        mode.cli_args(&format!(r"{GUEST_IO_DIR}\{name}")),
    );
    // The interactive session: a screenshot of session 0 would be black, and
    // the target's windows live on the visible desktop.
    let (code, log) = exec_capture(handle, &cmd, RunAs::ExistingLogin)?;
    if host_out.exists() {
        return Ok(host_out);
    }
    let tail = tail_lines(&log, 12);
    Err(format!(
        "guest UI role ({}) produced no output (exit code {code}){}",
        mode.name(),
        if tail.is_empty() { String::new() } else { format!(":\n{tail}") }
    ))
}

/// Read and delete a result file the guest wrote into the share.
fn take_result(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()));
    let _ = std::fs::remove_file(path);
    bytes
}

/// Capture the guest's whole virtual screen as PNG. With `host_out` the file is
/// moved there; otherwise it stays in the io share and that path is returned.
pub fn screenshot(handle: &SandboxHandle, host_out: Option<&Path>) -> Result<PathBuf, String> {
    let produced = run_mode(handle, UiMode::Screenshot)?;
    match host_out {
        Some(dest) => {
            if let Some(parent) = dest.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::rename(&produced, dest).is_err() {
                std::fs::copy(&produced, dest).map_err(|e| format!("copy screenshot to {}: {e}", dest.display()))?;
                let _ = std::fs::remove_file(&produced);
            }
            Ok(dest.to_path_buf())
        }
        None => Ok(produced),
    }
}

/// Every window in the interactive session (top-level windows first, each
/// followed by its children).
pub fn list_windows(handle: &SandboxHandle) -> Result<Vec<GuestWindow>, String> {
    let bytes = take_result(&run_mode(handle, UiMode::Windows)?)?;
    serde_json::from_slice::<Vec<GuestWindow>>(&bytes).map_err(|e| format!("parse guest window list: {e}"))
}

/// `WM_GETTEXT` of one window or control (by hwnd from [`list_windows`]).
pub fn window_text(handle: &SandboxHandle, hwnd: u64) -> Result<String, String> {
    let bytes = take_result(&run_mode(handle, UiMode::Text { hwnd })?)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
