//! Masked byte-pattern search (`"ff 15 ?? ?? 69 00"`).

/// A parsed pattern: the bytes to match and, per position, whether the byte
/// is fixed (`true`) or a wildcard (`false`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<bool>,
}

impl BytePattern {
    /// Parse `"ff 15 ?? ?? 69 00"`. Tokens are whitespace-separated hex bytes;
    /// `??` or `?` is a wildcard. A single token without spaces is read as a
    /// contiguous hex string (`"ff15????6900"`). At least one byte must be fixed.
    pub fn parse(text: &str) -> Result<Self, String> {
        let tokens: Vec<&str> = text.split_whitespace().collect();
        let tokens: Vec<String> = if tokens.len() == 1 && tokens[0].len() > 2 {
            let t = tokens[0];
            if t.len() % 2 != 0 {
                return Err(format!("odd-length hex pattern {:?}", t));
            }
            (0..t.len()).step_by(2).map(|i| t[i..i + 2].to_string()).collect()
        } else {
            tokens.into_iter().map(str::to_string).collect()
        };
        if tokens.is_empty() {
            return Err("empty pattern".into());
        }
        let mut bytes = Vec::with_capacity(tokens.len());
        let mut mask = Vec::with_capacity(tokens.len());
        for tok in &tokens {
            if tok == "??" || tok == "?" {
                bytes.push(0);
                mask.push(false);
            } else {
                let b = u8::from_str_radix(tok.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad byte {:?} in pattern", tok))?;
                bytes.push(b);
                mask.push(true);
            }
        }
        if !mask.iter().any(|&m| m) {
            return Err("pattern needs at least one fixed byte".into());
        }
        Ok(Self { bytes, mask })
    }

    /// Whether the pattern matches `hay` at its start.
    fn matches_at(&self, hay: &[u8]) -> bool {
        hay.len() >= self.bytes.len()
            && self.bytes.iter().zip(&self.mask).zip(hay).all(|((b, m), h)| !m || b == h)
    }

    /// Every offset in `hay` where the pattern matches, at most `max` of them.
    /// Anchors on the first fixed byte with `memchr`, then verifies the rest.
    pub fn find_all(&self, hay: &[u8], max: usize) -> Vec<usize> {
        let mut out = Vec::new();
        if hay.len() < self.bytes.len() || max == 0 {
            return out;
        }
        let anchor = self.mask.iter().position(|&m| m).unwrap_or(0);
        let anchor_byte = self.bytes[anchor];
        let last_start = hay.len() - self.bytes.len();
        let mut search_from = anchor;
        while let Some(pos) = memchr::memchr(anchor_byte, &hay[search_from..]) {
            let hit = search_from + pos;
            let start = match hit.checked_sub(anchor) {
                Some(s) if s <= last_start => s,
                _ => {
                    search_from = hit + 1;
                    if search_from > hay.len() { break; }
                    continue;
                }
            };
            if self.matches_at(&hay[start..]) {
                out.push(start);
                if out.len() >= max {
                    break;
                }
            }
            search_from = hit + 1;
            if search_from > hay.len() {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spaced_and_contiguous() {
        let a = BytePattern::parse("ff 15 ?? ?? 69 00").unwrap();
        let b = BytePattern::parse("ff15????6900").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.bytes, vec![0xff, 0x15, 0, 0, 0x69, 0]);
        assert_eq!(a.mask, vec![true, true, false, false, true, true]);
    }

    #[test]
    fn rejects_all_wildcards_and_junk() {
        assert!(BytePattern::parse("?? ??").is_err());
        assert!(BytePattern::parse("zz").is_err());
        assert!(BytePattern::parse("").is_err());
    }

    #[test]
    fn finds_with_wildcards_and_leading_wildcard() {
        let hay = [0x00u8, 0xff, 0x15, 0xd0, 0x0d, 0x69, 0x00, 0xff, 0x15, 0x11, 0x22, 0x69, 0x00, 0xff];
        let p = BytePattern::parse("ff 15 ?? ?? 69 00").unwrap();
        assert_eq!(p.find_all(&hay, 10), vec![1, 7]);
        assert_eq!(p.find_all(&hay, 1), vec![1]);
        // Leading wildcard: anchor is the second byte.
        let q = BytePattern::parse("?? 15 d0").unwrap();
        assert_eq!(q.find_all(&hay, 10), vec![1]);
        // No match past the end.
        let r = BytePattern::parse("69 00 ff 15 11 22 33").unwrap();
        assert!(r.find_all(&hay, 10).is_empty());
    }
}
