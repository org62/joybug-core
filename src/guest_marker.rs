//! A build identity stamped into every executable that can serve as a sandbox
//! guest, and the reader `sandbox::provision` uses to check a staged binary
//! BEFORE booting a VM (RETRO B3/F12).
//!
//! The guest side of a sandbox session is whatever exe the caller stages —
//! `joybug-core.exe`, `jlua.exe`, the Joybug app — launched with `--listen`
//! (debug server) or `--out` (ETW collector). Two things used to go wrong
//! silently: staging a binary that has no collector role at all produced an
//! empty capture and a clean exit, and staging one built from another revision
//! hung the first request. Both are now caught by reading the file on disk:
//!
//! * [`GUEST_MARKER`] is a `#[used]` static of the form
//!   `JOYBUG-GUEST\0v1\0<16 hex digits of PROTOCOL_FINGERPRINT>\0`. Its
//!   presence says "this is a joybug guest with both roles"; the fingerprint
//!   says which protocol revision it speaks.
//! * [`find_marker`] scans an executable image for that record. The needle is
//!   assembled at runtime so the *searcher's* own string literal can never be
//!   mistaken for a marker, and each candidate is validated by shape.
//!
//! `#[used]` keeps the static in the object file, but a library object that
//! nothing references can still be dropped by the linker — so [`touch`] is
//! called from `guest_roles::from_argv`, the role dispatch every guest-capable
//! binary runs first.

use crate::protocol::PROTOCOL_FINGERPRINT;

const PREFIX: &[u8; 12] = b"JOYBUG-GUEST";
const VERSION: &[u8; 2] = b"v1";
/// `PREFIX \0 VERSION \0 <16 hex> \0`
pub const MARKER_LEN: usize = PREFIX.len() + 1 + VERSION.len() + 1 + 16 + 1;

const fn build() -> [u8; MARKER_LEN] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; MARKER_LEN];
    let mut i = 0;
    while i < PREFIX.len() {
        out[i] = PREFIX[i];
        i += 1;
    }
    let mut o = PREFIX.len() + 1; // NUL after the prefix
    let mut j = 0;
    while j < VERSION.len() {
        out[o] = VERSION[j];
        o += 1;
        j += 1;
    }
    o += 1; // NUL after the version
    let mut k = 0;
    while k < 16 {
        let nibble = (PROTOCOL_FINGERPRINT >> (60 - 4 * k)) & 0xf;
        out[o] = HEX[nibble as usize];
        o += 1;
        k += 1;
    }
    out // trailing NUL is the zero-initialised last byte
}

/// The record embedded in this binary.
#[used]
pub static GUEST_MARKER: [u8; MARKER_LEN] = build();

/// Reference the marker so the linker keeps it. Called from
/// `guest_roles::from_argv`, the one entry point every guest-capable binary
/// passes through.
#[inline(never)]
pub fn touch() {
    std::hint::black_box(&GUEST_MARKER);
}

/// A marker record found in an executable image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMarker {
    pub version: String,
    pub fingerprint: u64,
}

/// Find the first well-formed marker record in `bytes`.
pub fn find_marker(bytes: &[u8]) -> Option<GuestMarker> {
    let needle = needle();
    let finder = memchr::memmem::Finder::new(&needle);
    finder.find_iter(bytes).find_map(|pos| parse_record(&bytes[pos + needle.len()..]))
}

/// Parse `<version>\0<16 hex>\0` at the start of `rest`.
fn parse_record(rest: &[u8]) -> Option<GuestMarker> {
    let vend = rest.iter().take(8).position(|&b| b == 0)?;
    let version = std::str::from_utf8(&rest[..vend]).ok()?;
    if !version.starts_with('v') || version.len() < 2 {
        return None;
    }
    let hex = rest.get(vend + 1..vend + 1 + 16)?;
    if rest.get(vend + 1 + 16) != Some(&0) {
        return None;
    }
    let fingerprint = u64::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
    Some(GuestMarker { version: version.to_string(), fingerprint })
}

/// `JOYBUG-GUEST\0`, assembled at runtime so the contiguous prefix literal is
/// never emitted into the image that carries this code. Otherwise scanning
/// that very binary (as `provision` and the tests do) could match the
/// searcher's own needle — or a test's forged fixture — ahead of the real
/// [`GUEST_MARKER`]. The one source of the needle for [`find_marker`] and for
/// tests that forge a marker.
pub(crate) fn needle() -> Vec<u8> {
    let mut v = Vec::with_capacity(PREFIX.len() + 1);
    v.extend_from_slice(&PREFIX[..7]);
    v.extend_from_slice(&PREFIX[7..]);
    v.push(0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_marker_round_trips() {
        let m = find_marker(&GUEST_MARKER).expect("marker parses");
        assert_eq!(m.version, "v1");
        assert_eq!(m.fingerprint, PROTOCOL_FINGERPRINT);
        assert_eq!(GUEST_MARKER[MARKER_LEN - 1], 0);
    }

    #[test]
    fn a_marker_is_found_inside_surrounding_bytes() {
        let mut blob = vec![0x90u8; 1000];
        blob.extend_from_slice(&GUEST_MARKER);
        blob.extend_from_slice(b"trailing");
        assert_eq!(find_marker(&blob).unwrap().fingerprint, PROTOCOL_FINGERPRINT);
    }

    #[test]
    fn malformed_candidates_are_skipped_and_nothing_is_none() {
        assert_eq!(find_marker(b"no marker here"), None);
        // Prefix followed by junk (what a stray string literal would look like).
        let mut blob = needle();
        blob.extend_from_slice(b"v9\0notsixteenhexdigits");
        assert_eq!(find_marker(&blob), None);
        // ...followed by a real one: the real one wins.
        blob.extend_from_slice(&GUEST_MARKER);
        assert_eq!(find_marker(&blob).unwrap().version, "v1");
    }

    #[test]
    fn this_test_binary_carries_the_marker() {
        // The reader must find the record in a real linked image — the very
        // check `provision` performs on a staged guest.
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&exe).unwrap();
        touch();
        let m = find_marker(&bytes).expect("marker linked into the test binary");
        assert_eq!(m.fingerprint, PROTOCOL_FINGERPRINT);
    }
}
