//! Check a staged guest executable BEFORE booting a VM for it (RETRO B3/F12).
//!
//! The marker read here is described in [`crate::guest_marker`]: its presence
//! proves the file is a joybug build that provides both guest roles (server +
//! collector), its fingerprint proves it speaks this build's protocol. The two
//! silent failures this replaces were an empty capture from a binary with no
//! collector role, and a first request that hung against a server built from
//! another revision.

use std::path::Path;

use crate::guest_marker::find_marker;
use crate::protocol::PROTOCOL_FINGERPRINT;

/// Validate `path` as a guest binary for this build (it carries a guest marker
/// with this build's protocol fingerprint). Cheap: the file is memory-mapped
/// and scanned once (tens of milliseconds for a 60 MB exe).
pub fn preflight_guest_exe(path: &Path) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| {
        format!(
            "guest exe {} cannot be opened: {e}. `guest_bin_dir` must hold the guest executable \
             named by `guest_exe` (joybug-core.exe, jlua.exe or the Joybug app exe)",
            path.display()
        )
    })?;
    // SAFETY: read-only mapping of a file we do not write; a concurrent
    // truncation would at worst fault this process, which is the caller's own
    // staging folder.
    let map = unsafe { memmap2::Mmap::map(&file) }
        .map_err(|e| format!("guest exe {} cannot be mapped: {e}", path.display()))?;
    let marker = find_marker(&map).ok_or_else(|| {
        format!(
            "{} is not a joybug guest binary (no guest marker found): it provides neither the \
             debug-server nor the ETW-collector role. Stage joybug-core.exe, jlua.exe or the \
             Joybug app exe from this build",
            path.display()
        )
    })?;
    if marker.fingerprint != PROTOCOL_FINGERPRINT {
        return Err(format!(
            "{} was built from a different joybug-core revision (protocol fingerprint \
             {:016x}; this build is {:016x}) — the guest server would not decode our requests. \
             Re-stage the guest binary from this build",
            path.display(),
            marker.fingerprint,
            PROTOCOL_FINGERPRINT
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_exe_passes() {
        crate::guest_marker::touch();
        let exe = std::env::current_exe().unwrap();
        preflight_guest_exe(&exe).expect("this binary carries the marker");
    }

    #[test]
    fn a_foreign_exe_and_a_missing_file_are_rejected_with_reasons() {
        let mut p = std::env::temp_dir();
        p.push(format!("joybug-preflight-{}.exe", std::process::id()));
        std::fs::write(&p, b"MZ this is not joybug").unwrap();
        let err = preflight_guest_exe(&p).unwrap_err();
        assert!(err.contains("not a joybug guest binary"), "{err}");
        let _ = std::fs::remove_file(&p);
        let err = preflight_guest_exe(Path::new(r"C:\does\not\exist\joybug.exe")).unwrap_err();
        assert!(err.contains("cannot be opened"), "{err}");
    }

    #[test]
    fn a_different_revision_is_rejected() {
        // Forge a marker with another fingerprint inside a fake image. The
        // prefix is assembled at runtime (see `guest_marker::needle`) so this
        // fixture's bytes are not planted as a contiguous marker literal in the
        // test binary that `guest_marker`'s own scan reads.
        let mut blob = b"MZ".to_vec();
        blob.extend_from_slice(&crate::guest_marker::needle());
        blob.extend_from_slice(b"v1\0deadbeefcafef00d\0");
        let mut p = std::env::temp_dir();
        p.push(format!("joybug-preflight-old-{}.exe", std::process::id()));
        std::fs::write(&p, &blob).unwrap();
        let err = preflight_guest_exe(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        assert!(err.contains("different joybug-core revision"), "{err}");
        assert!(err.contains("deadbeefcafef00d"), "{err}");
    }
}
