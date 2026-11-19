// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Automatic ANSI color detection for console output.
//!
//! `tracing_subscriber`'s formatter turns ANSI on unless `NO_COLOR` is set. It
//! does not check whether the output stream is a terminal, so a gateway or
//! driver running in a container writes escape sequences into its collected
//! logs. Long-running binaries pass [`stdout_ansi`] or [`stderr_ansi`] to
//! `with_ansi` so console logs are colored only on a terminal that can render
//! them.
//!
//! Resolution order, highest precedence first:
//!
//! 1. `NO_COLOR`, set and non-empty, disables color (<https://no-color.org>).
//! 2. `FORCE_COLOR`, set and non-empty, forces color on (<https://force-color.org>).
//! 3. Otherwise the stream is colored only when it is a terminal *and* that
//!    terminal renders ANSI.

use std::ffi::OsStr;
use std::io::IsTerminal;

/// Whether console output written to stdout should carry ANSI escapes.
#[must_use]
pub fn stdout_ansi() -> bool {
    stream_ansi(std::io::stdout().is_terminal())
}

/// Whether console output written to stderr should carry ANSI escapes.
#[must_use]
pub fn stderr_ansi() -> bool {
    stream_ansi(std::io::stderr().is_terminal())
}

fn stream_ansi(stream_is_terminal: bool) -> bool {
    let term = std::env::var_os("TERM");
    auto(
        std::env::var_os("NO_COLOR").as_deref(),
        std::env::var_os("FORCE_COLOR").as_deref(),
        terminal_supports_ansi(stream_is_terminal, term.as_deref()),
    )
}

/// Decide whether one stream may carry escapes when no explicit color choice
/// was made. Pure so the precedence rules are testable without process state.
#[must_use]
pub fn auto(
    no_color: Option<&OsStr>,
    force_color: Option<&OsStr>,
    stream_supports_ansi: bool,
) -> bool {
    // Both conventions key on presence rather than value: set and non-empty
    // means yes, regardless of what the value is.
    if is_set(no_color) {
        return false;
    }
    if is_set(force_color) {
        return true;
    }
    stream_supports_ansi
}

/// Whether this output stream's terminal renders ANSI escapes.
///
/// Being attached to a terminal is not the same as that terminal rendering
/// ANSI. `TERM` is the unix signal for it; Windows consoles enable virtual
/// terminal processing instead and do not set `TERM`, so the check does not
/// apply there.
#[must_use]
pub fn terminal_supports_ansi(stream_is_terminal: bool, term: Option<&OsStr>) -> bool {
    stream_is_terminal
        && if cfg!(unix) {
            term_supports_ansi(term)
        } else {
            true
        }
}

/// Whether the terminal named by `TERM` renders ANSI escapes on Unix.
///
/// Follows the rule `console` applies on unix: `dumb` means no, and an unset
/// `TERM` means no because nothing identifies a capable terminal.
///
/// Empty is treated as unset, which is a deliberate divergence: `console` reads
/// `TERM=""` as `Ok("")`, and since that is not `"dumb"` it counts as capable.
/// An empty value names no terminal type, and every other variable here already
/// treats empty as unset, so it is handled the same way.
fn term_supports_ansi(term: Option<&OsStr>) -> bool {
    is_set(term) && term != Some(OsStr::new("dumb"))
}

/// Whether an environment variable counts as set: present and not empty.
fn is_set(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(value: &str) -> &OsStr {
        OsStr::new(value)
    }

    #[test]
    fn no_color_disables_when_set_and_non_empty() {
        assert!(!auto(Some(env("1")), None, true));
        // Presence is what counts; a value that reads as falsy still disables.
        assert!(!auto(Some(env("0")), None, true));
        // NO_COLOR outranks FORCE_COLOR.
        assert!(!auto(Some(env("1")), Some(env("1")), true));
        // An empty value is not "set" for the purposes of the convention.
        assert!(auto(Some(env("")), None, true));
    }

    #[test]
    fn force_color_enables_when_set_and_non_empty() {
        assert!(auto(None, Some(env("1")), false));
        assert!(auto(None, Some(env("0")), false));
        assert!(!auto(None, Some(env("")), false));
    }

    #[test]
    fn otherwise_follows_the_stream() {
        assert!(auto(None, None, true));
        // A container log stream is not a terminal, so it stays plain.
        assert!(!auto(None, None, false));
    }

    #[test]
    fn redirected_stream_is_never_capable() {
        assert!(!terminal_supports_ansi(false, Some(env("xterm-256color"))));
    }

    #[cfg(unix)]
    #[test]
    fn terminal_capability_follows_term() {
        assert!(terminal_supports_ansi(true, Some(env("xterm-256color"))));
        assert!(!terminal_supports_ansi(true, Some(env("dumb"))));
        assert!(!terminal_supports_ansi(true, None));
    }

    #[test]
    fn term_capability_follows_the_console_rule() {
        assert!(term_supports_ansi(Some(env("xterm-256color"))));
        assert!(term_supports_ansi(Some(env("screen"))));
        assert!(!term_supports_ansi(Some(env("dumb"))));
        // Nothing to suggest a capable terminal, so assume none.
        assert!(!term_supports_ansi(None));
        // Empty names no terminal type; treated as unset, unlike `console`.
        assert!(!term_supports_ansi(Some(env(""))));
        // Only an exact match counts; `dumb-something` is a different terminal.
        assert!(term_supports_ansi(Some(env("dumb-but-color"))));
    }
}
