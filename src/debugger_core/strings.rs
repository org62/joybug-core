//! String readers: UTF-16LE decoding shared by the live `read_wide_string`
//! and the offline `static_pe` string reader.

use crate::interfaces::PlatformError;
use tracing::warn;

/// Byte offset of the first NUL *character* (a `[0, 0]` pair on a u16 boundary)
/// in a UTF-16LE buffer. A byte-pair search (`windows(2)`) is wrong here: it also
/// matches the high byte of the last ASCII character followed by the low byte
/// of the terminator, which sits on an odd offset and cuts that character off.
pub fn wide_nul_position(bytes: &[u8]) -> Option<usize> {
    bytes.chunks_exact(2).position(|c| c == [0, 0]).map(|i| i * 2)
}

/// Decode a UTF-16LE buffer up to (not including) its first NUL character. A
/// trailing odd byte is ignored; whitespace is data and is preserved.
pub fn decode_wide_until_nul(bytes: &[u8]) -> String {
    let end = wide_nul_position(bytes).unwrap_or(bytes.len());
    let wide_chars: Vec<u16> = bytes[..end]
        .chunks_exact(2)
        .map(|a| u16::from_le_bytes([a[0], a[1]]))
        .collect();
    String::from_utf16_lossy(&wide_chars)
}

/// Read a NUL-terminated UTF-16 string from the tracee through `read`.
/// `max_len` is a character count; when known, exactly that many characters
/// are read (a NUL inside the window still terminates the string).
pub fn read_wide_string(
    read: impl Fn(u64, usize) -> Result<Vec<u8>, PlatformError>,
    address: u64,
    max_len: Option<usize>, // Number of characters
) -> Result<String, PlatformError> {
    let mut buffer = Vec::new();

    if let Some(len) = max_len {
        // Length is known: read exactly that many characters; a NUL inside the
        // window still terminates the string (decode_wide_until_nul).
        let bytes_to_read = len * 2;
        buffer = read(address, bytes_to_read)?;
    } else {
        // Length is unknown, read in chunks until the null terminator. The chunk
        // size is even, so every chunk starts on a character boundary and the
        // u16-aligned scan below never sees a torn character.
        const CHUNK_SIZE: usize = 64; // read 64 bytes at a time
        let mut total_read_bytes = 0;
        const MAX_TOTAL_READ: usize = 4096 * 2; // safety break at 8KB

        loop {
            let chunk = read(address + total_read_bytes as u64, CHUNK_SIZE)?;
            if chunk.is_empty() {
                break; // End of memory
            }

            // Only the new chunk needs scanning (it starts on a character
            // boundary); the decode below cuts at the terminator.
            let terminated = wide_nul_position(&chunk).is_some();
            buffer.extend_from_slice(&chunk);
            if terminated {
                break;
            }

            total_read_bytes += chunk.len();
            if total_read_bytes >= MAX_TOTAL_READ {
                warn!("read_wide_string reached max read limit of {} bytes without finding a null terminator.", MAX_TOTAL_READ);
                break;
            }
        }
    }

    // Trim surrounding whitespace at the public boundary (long-standing
    // behavior; some callers pass a length-counted buffer that includes a
    // trailing CRLF). The terminator handling lives in `decode_wide_until_nul`,
    // which is orthogonal to trimming.
    Ok(decode_wide_until_nul(&buffer).trim().to_string())
}

#[cfg(test)]
mod wide_string_tests {
    use super::decode_wide_until_nul;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn keeps_the_last_character_before_the_terminator() {
        // "UnholyDragon\0": the retro's B1 — the old byte-pair scan matched the
        // `00 00` straddling 'n' and the NUL and returned "UnholyDrago".
        let mut bytes = utf16("UnholyDragon");
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(decode_wide_until_nul(&bytes), "UnholyDragon");
    }

    #[test]
    fn stops_at_the_first_nul_and_ignores_what_follows() {
        let mut bytes = utf16("a.ex");
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend(utf16("junk"));
        assert_eq!(decode_wide_until_nul(&bytes), "a.ex");
    }

    #[test]
    fn no_terminator_decodes_everything_and_drops_a_torn_byte() {
        let mut bytes = utf16("abc");
        bytes.push(0x41); // half of a character
        assert_eq!(decode_wide_until_nul(&bytes), "abc");
    }

    #[test]
    fn whitespace_is_preserved() {
        let mut bytes = utf16("  padded  ");
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(decode_wide_until_nul(&bytes), "  padded  ");
    }

    #[test]
    fn a_nul_low_byte_inside_a_character_is_not_a_terminator() {
        // U+0100 is `00 01` on the wire: its low byte is zero, and the character
        // before it ends in `00` too — a byte-pair scan would stop here.
        let mut bytes = utf16("aĀb");
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(decode_wide_until_nul(&bytes), "aĀb");
    }
}
