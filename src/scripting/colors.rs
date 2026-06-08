//! ANSI color support for the REPL.
//!
//! All color output goes through this module. Colors can be disabled globally
//! via `set_enabled(false)` (controlled by `--no-color` flag or `NO_COLOR` env var).

use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

// ANSI escape codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[90m";      // bright black (gray)
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[37m";
const BOLD_WHITE: &str = "\x1b[1;37m";
const BOLD_CYAN: &str = "\x1b[1;36m";

fn wrap<'a>(code: &str, s: &'a str) -> std::borrow::Cow<'a, str> {
    if ENABLED.load(Ordering::Relaxed) {
        std::borrow::Cow::Owned(format!("{}{}{}", code, s, RESET))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// Cyan — addresses (0x7FF8...)
pub fn addr(s: &str) -> std::borrow::Cow<'_, str> { wrap(CYAN, s) }

/// Yellow — symbol names (ntdll!NtClose)
pub fn sym(s: &str) -> std::borrow::Cow<'_, str> { wrap(YELLOW, s) }

/// Green — register names, strings
pub fn green(s: &str) -> std::borrow::Cow<'_, str> { wrap(GREEN, s) }

/// Bold white — mnemonics (mov, call, ret)
pub fn mnem(s: &str) -> std::borrow::Cow<'_, str> { wrap(BOLD_WHITE, s) }

/// White — operands, values
pub fn val(s: &str) -> std::borrow::Cow<'_, str> { wrap(WHITE, s) }

/// Gray/dim — comments, arrows, secondary info
pub fn dim(s: &str) -> std::borrow::Cow<'_, str> { wrap(DIM, s) }

/// Red — errors
pub fn red(s: &str) -> std::borrow::Cow<'_, str> { wrap(RED, s) }

/// Bold — headers
pub fn bold(s: &str) -> std::borrow::Cow<'_, str> { wrap(BOLD, s) }

/// Bold cyan — headers, prompts
pub fn bold_cyan(s: &str) -> std::borrow::Cow<'_, str> { wrap(BOLD_CYAN, s) }

/// Build a plain prompt string (coloring done by rustyline Highlighter).
pub fn prompt_break(location: &str) -> String {
    format!("break {}> ", location)
}

pub fn prompt_top() -> String {
    "jlua> ".to_string()
}
