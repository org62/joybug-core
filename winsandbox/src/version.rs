//! OS build detection via a real Windows API call.
//!
//! The Windows Sandbox CLI (`wsb.exe`) exists only on Windows 11, version 24H2
//! (build 26100) and later. Rather than discover this by a confusing spawn
//! failure, we query the build number up front with `RtlGetVersion`.
//!
//! `RtlGetVersion` is used instead of `GetVersionEx` because the latter is
//! subject to application-manifest shimming and lies about the version on
//! unmanifested processes; `RtlGetVersion` always reports the true build.

use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

use crate::Error;

/// Minimum Windows build that ships the Windows Sandbox CLI (24H2).
pub const MIN_BUILD: u32 = 26100;

/// Return the current OS build number (e.g. `26200`).
pub fn os_build() -> u32 {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a valid, correctly-sized OSVERSIONINFOW. RtlGetVersion
    // only writes into it and returns STATUS_SUCCESS.
    unsafe {
        let _ = RtlGetVersion(&mut info);
    }
    info.dwBuildNumber
}

/// Error out if the running OS is too old to have the Windows Sandbox CLI.
pub fn ensure_supported() -> Result<(), Error> {
    let build = os_build();
    if build < MIN_BUILD {
        Err(Error::Unsupported { found: build })
    } else {
        Ok(())
    }
}
