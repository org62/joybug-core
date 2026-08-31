//! Map the user's host mounts to guest paths and rewrite the launch command's
//! executable (and working directory) from host paths to the guest paths they
//! appear at inside the sandbox.
//!
//! The user configures host folders to mount and a host launch command; the
//! target must live under one of the mounted folders. Each mount appears in the
//! guest at `C:\mounts\<basename>` (deduped), and the target's host path is
//! translated to that location.

use super::config::MountSpec;

/// A host mount resolved to its guest mount point.
pub struct ResolvedMount {
    pub host: std::path::PathBuf,
    /// Guest path, e.g. `C:\mounts\app`.
    pub guest: String,
    pub read_only: bool,
}

/// Assign each mount a `C:\mounts\<basename>` guest path, deduping basename
/// collisions with a numeric suffix. Order is preserved.
pub fn resolve_mounts(mounts: &[MountSpec]) -> Vec<ResolvedMount> {
    let mut used: Vec<String> = Vec::new(); // lowercased guest basenames already taken
    let mut out = Vec::with_capacity(mounts.len());
    for m in mounts {
        let host = std::path::PathBuf::from(&m.host_path);
        let base = host
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "mount".to_string());

        let mut name = base.clone();
        let mut n = 2;
        while used.iter().any(|u| u.eq_ignore_ascii_case(&name)) {
            name = format!("{base}-{n}");
            n += 1;
        }
        used.push(name.clone());

        out.push(ResolvedMount {
            host,
            guest: format!(r"C:\mounts\{name}"),
            read_only: m.read_only,
        });
    }
    out
}

/// Rewrite `launch_command` (host) and `working_directory` (host) to guest paths.
/// Returns `(guest_launch_command, guest_working_directory)`.
///
/// Errors if the target executable is not located under any mounted folder — the
/// caller is expected to have added the exe's folder as a mount.
pub fn rewrite_command(
    launch_command: &str,
    working_directory: Option<&str>,
    mounts: &[ResolvedMount],
) -> Result<(String, Option<String>), String> {
    let (exe, rest) = split_launch_exe(launch_command);
    if exe.is_empty() {
        return Err("empty launch command".to_string());
    }

    // Prefer a user mount. Failing that, a target that already exists *inside*
    // the guest — a bare command resolved via PATH (`cmd.exe`), or an absolute
    // path under the guest's own Windows directory (`C:\Windows\System32\...`) —
    // runs as-is; only a host-specific path the guest can't reach is an error.
    // This is what makes the default `cmd.exe /c echo ...` smoke test work with
    // no mounts configured.
    let guest_exe = match host_to_guest(&exe, mounts) {
        Some(g) => g,
        None if is_guest_resident(&exe) => exe.clone(),
        None => {
            return Err(format!(
                "the target executable ({exe}) is not inside any mounted folder — \
                 add its folder to the sandbox mounts"
            ));
        }
    };

    // Reassemble. Quote the exe token ONLY when it contains a space: joybug-core
    // derives the main module's fallback name from the launch command's first
    // whitespace-delimited token (`command.split_whitespace().next()`), which does
    // NOT strip quotes — so an always-quoted `"cmd.exe"` becomes a module named
    // literally `"cmd.exe"` that can't be read as a file (os error 123). A bare,
    // space-free exe needs no quotes and yields a clean module name.
    let needs_quotes = guest_exe.contains(' ');
    let exe_token = if needs_quotes { format!("\"{guest_exe}\"") } else { guest_exe.clone() };
    let guest_cmd = if rest.trim().is_empty() {
        exe_token
    } else {
        format!("{exe_token} {}", rest.trim_start())
    };

    // Working directory: translate if under a mount, else default to the exe's
    // guest folder.
    let guest_cwd = working_directory
        .and_then(|w| host_to_guest(w, mounts))
        .or_else(|| guest_parent(&guest_exe));

    Ok((guest_cmd, guest_cwd))
}

/// Split a command line into its leading executable token and the remainder.
/// Honors a double-quoted first token (CreateProcess-style).
pub fn split_launch_exe(cmd: &str) -> (String, String) {
    let s = cmd.trim_start();
    if let Some(stripped) = s.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            let exe = stripped[..end].to_string();
            let rest = stripped[end + 1..].to_string();
            return (exe, rest);
        }
        // Unterminated quote: treat the whole thing as the exe.
        return (stripped.to_string(), String::new());
    }
    match s.find(char::is_whitespace) {
        Some(i) => (s[..i].to_string(), s[i..].to_string()),
        None => (s.to_string(), String::new()),
    }
}

/// Translate a host path to its guest path if it lies under a mount root.
/// Case-insensitive, separator-normalized (Windows).
fn host_to_guest(host_path: &str, mounts: &[ResolvedMount]) -> Option<String> {
    let target = normalize(host_path);
    for m in mounts {
        let root = normalize(&m.host.to_string_lossy());
        if target == root {
            return Some(m.guest.clone());
        }
        let root_prefix = format!("{root}\\");
        if target.starts_with(&root_prefix) {
            let rel = &host_path[root_prefix.len().min(host_path.len())..];
            // Rebuild from the original (preserve original-case relative part).
            let rel = rel.trim_start_matches(['\\', '/']);
            return Some(format!(r"{}\{}", m.guest, rel.replace('/', "\\")));
        }
    }
    None
}

/// Whether `exe` names a binary that already exists inside every sandbox guest,
/// so it can be launched without being mapped in from the host: a bare command
/// name (resolved via the guest PATH) or an absolute path under `C:\Windows`.
fn is_guest_resident(exe: &str) -> bool {
    if !exe.contains('\\') && !exe.contains('/') {
        return true; // bare name, e.g. `cmd.exe` — guest PATH resolves it
    }
    normalize(exe).starts_with(r"c:\windows\")
}

/// Guest parent directory of a guest path (for defaulting the working directory).
fn guest_parent(guest_path: &str) -> Option<String> {
    let p = guest_path.trim_end_matches('\\');
    p.rfind('\\').map(|i| p[..i].to_string())
}

/// Lowercase + backslash-normalize + strip a trailing separator, for comparison.
fn normalize(p: &str) -> String {
    let mut s = p.replace('/', "\\").to_ascii_lowercase();
    while s.ends_with('\\') {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(host: &str, ro: bool) -> MountSpec {
        MountSpec { host_path: host.to_string(), read_only: ro }
    }

    #[test]
    fn dedupes_basenames() {
        let r = resolve_mounts(&[mount(r"C:\a\app", true), mount(r"D:\b\app", false)]);
        assert_eq!(r[0].guest, r"C:\mounts\app");
        assert_eq!(r[1].guest, r"C:\mounts\app-2");
    }

    #[test]
    fn rewrites_exe_and_defaults_cwd() {
        let mounts = resolve_mounts(&[mount(r"C:\proj\app", true)]);
        let (cmd, cwd) =
            rewrite_command(r"C:\proj\app\target.exe --flag x", None, &mounts).unwrap();
        // Space-free guest path → unquoted, so the module name stays clean.
        assert_eq!(cmd, r"C:\mounts\app\target.exe --flag x");
        assert_eq!(cwd.as_deref(), Some(r"C:\mounts\app"));
    }

    #[test]
    fn handles_quoted_exe_and_subdir() {
        let mounts = resolve_mounts(&[mount(r"C:\proj\app", true)]);
        let (cmd, _) =
            rewrite_command(r#""C:\proj\app\bin\t.exe" a b"#, None, &mounts).unwrap();
        assert_eq!(cmd, r"C:\mounts\app\bin\t.exe a b");
    }

    #[test]
    fn quotes_only_when_guest_path_has_spaces() {
        // A spaced mount basename yields a spaced guest path; the user quotes the
        // (spaced) host path, and the spaced guest path is re-quoted on output.
        let mounts = resolve_mounts(&[mount(r"C:\x\my app", true)]);
        let (cmd, _) =
            rewrite_command(r#""C:\x\my app\t.exe" a"#, None, &mounts).unwrap();
        assert_eq!(cmd, r#""C:\mounts\my app\t.exe" a"#);
    }

    #[test]
    fn errors_when_target_not_mounted() {
        let mounts = resolve_mounts(&[mount(r"C:\proj\data", true)]);
        assert!(rewrite_command(r"C:\other\t.exe", None, &mounts).is_err());
    }

    #[test]
    fn bare_command_passes_through_without_mounts() {
        // The default smoke-test launch: no mounts, a guest-resident command.
        let (cmd, cwd) =
            rewrite_command("cmd.exe /c echo Hello World!", None, &[]).unwrap();
        assert_eq!(cmd, r"cmd.exe /c echo Hello World!");
        assert_eq!(cwd, None);
    }

    #[test]
    fn windows_system_path_passes_through_without_mounts() {
        let (cmd, _) =
            rewrite_command(r"C:\Windows\System32\notepad.exe", None, &[]).unwrap();
        assert_eq!(cmd, r"C:\Windows\System32\notepad.exe");
    }
}
