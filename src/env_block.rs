//! Environment block construction for launching debuggees.
//!
//! `CreateProcessW` either inherits the caller's environment (`lpEnvironment ==
//! NULL`) or takes a complete replacement block. We never want the caller to
//! re-specify the whole environment, so a launch request carries only *extra*
//! variables; this module merges them over the debugger's own environment and
//! produces the UTF-16 block `CreateProcessW` expects.

use std::collections::BTreeMap;
use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;

/// An `lpEnvironment` argument for `CreateProcessW`, owning the block it points
/// at. Keep the value alive across the call — [`as_ptr`](Self::as_ptr) borrows
/// from it — and OR [`create_flags`](Self::create_flags) into the creation
/// flags: a UTF-16 block passed without `CREATE_UNICODE_ENVIRONMENT` is read as
/// ANSI and silently garbles the child's environment, so the two always travel
/// together.
pub struct EnvironmentBlock(Option<Vec<u16>>);

impl EnvironmentBlock {
    /// Build the block from the current process environment with `extra` merged
    /// in (override by name, case-insensitively — Windows variable names are).
    /// No extras means no block: the child inherits through a null pointer, as
    /// it did before environments were configurable.
    ///
    /// Layout: `NAME=VALUE\0 ... NAME=VALUE\0\0`, sorted by name like the block
    /// the loader builds itself.
    pub fn new(extra: Option<&[(String, String)]>) -> Self {
        let extra = match extra {
            Some(extra) if !extra.is_empty() => extra,
            _ => return Self(None),
        };

        // Keyed by uppercased name so the merge overrides case-insensitively
        // and the ordering falls out of the map — the value keeps the
        // inherited variable's original casing.
        let mut vars: BTreeMap<String, (OsString, OsString)> = std::env::vars_os()
            .map(|(name, value)| (name.to_string_lossy().to_uppercase(), (name, value)))
            .collect();
        for (name, value) in extra {
            vars.entry(name.to_uppercase())
                .and_modify(|slot| slot.1 = OsString::from(value))
                .or_insert_with(|| (OsString::from(name), OsString::from(value)));
        }

        let mut block: Vec<u16> = Vec::new();
        for (name, value) in vars.values() {
            block.extend(name.encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        block.push(0);
        Self(Some(block))
    }

    /// Creation flags this block requires; zero when there is no block.
    pub fn create_flags(&self) -> u32 {
        if self.0.is_some() { CREATE_UNICODE_ENVIRONMENT } else { 0 }
    }

    /// `lpEnvironment`: null when the child should inherit unchanged.
    pub fn as_ptr(&self) -> *const c_void {
        self.0.as_ref().map_or(std::ptr::null(), |b| b.as_ptr().cast())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(env: &EnvironmentBlock) -> Vec<String> {
        String::from_utf16_lossy(env.0.as_ref().unwrap())
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn empty_extra_inherits() {
        for env in [EnvironmentBlock::new(None), EnvironmentBlock::new(Some(&[]))] {
            assert!(env.0.is_none());
            assert!(env.as_ptr().is_null());
            assert_eq!(env.create_flags(), 0);
        }
    }

    #[test]
    fn merges_and_overrides_case_insensitively() {
        let env = EnvironmentBlock::new(Some(&[
            ("JOYBUG_ENV_TEST_NEW".into(), "1".into()),
            ("systemroot".into(), r"X:\fake".into()),
        ]));
        assert_eq!(env.create_flags(), CREATE_UNICODE_ENVIRONMENT);
        let block = env.0.as_ref().unwrap();
        assert_eq!(&block[block.len() - 2..], &[0, 0]);
        let entries = decode(&env);
        assert!(entries.iter().any(|e| e == "JOYBUG_ENV_TEST_NEW=1"));
        // Overridden in place: exactly one SystemRoot entry, with our value.
        let roots: Vec<_> = entries
            .iter()
            .filter(|e| e.to_uppercase().starts_with("SYSTEMROOT="))
            .collect();
        assert_eq!(roots.len(), 1);
        assert!(roots[0].ends_with(r"=X:\fake"));
        // Everything else is still inherited.
        assert!(entries.iter().any(|e| e.to_uppercase().starts_with("PATH=")));
    }
}
