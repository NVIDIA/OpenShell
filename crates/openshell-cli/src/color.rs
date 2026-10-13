// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime color control for CLI output.
//!
//! The CLI styles its human-readable tables and status lines with ANSI escape
//! sequences. Those sequences must not appear when the output is being consumed
//! by another program, or callers end up writing brittle patterns against bytes
//! they cannot see.
//!
//! `owo_colors::OwoColorize` emits escapes unconditionally, so this module wraps
//! it with a process-wide switch resolved once at startup by [`init`]. Command
//! modules import [`Colorize`] instead of `OwoColorize`; the method names match,
//! so call sites are unchanged, but each one now checks the switch when it
//! renders.
//!
//! Styling is not confined to `owo-colors`, and the other paths each carry
//! their own default, so [`init`] brings them under the same setting:
//!
//! - `tracing_subscriber` formats with ANSI on, does no terminal detection, and
//!   writes to stdout. Left alone, `openshell -v ... | ...` leaks escapes into a
//!   pipe exactly like the styled tables did. `main` passes [`stdout_enabled`]
//!   to `with_ansi`.
//! - `indicatif` and `dialoguer` both style through `console`, which has its own
//!   detection and honors `NO_COLOR` but cannot know about `--color`. [`init`]
//!   overrides it globally, which covers every progress bar and prompt rather
//!   than the specific ones the CLI happens to construct today.
//! - `miette` renders errors to stderr with its own detection, likewise unaware
//!   of `--color`. [`init`] installs a report handler built from
//!   [`stderr_enabled`].
//!
//! Resolution order, highest precedence first:
//!
//! 1. `--color always|never` on the command line.
//! 2. `NO_COLOR`, set and non-empty, disables color (<https://no-color.org>).
//! 3. `FORCE_COLOR`, set and non-empty, forces color on (<https://force-color.org>).
//! 4. Otherwise the stream is styled only when that stream is a terminal *and*
//!    that terminal renders ANSI.
//!
//! Attachment and capability are separate questions. `TERM=dumb` is a terminal
//! that does not interpret escapes, so `auto` must not style it — and neither
//! `console` nor `miette` can apply their own `TERM` checks any more, because
//! [`init`] overrides both. Capability is consulted only under `auto`, so
//! `--color always` and `FORCE_COLOR` still force styling on a `dumb` terminal
//! for anyone who wants it.
//!
//! Step 4 is resolved per stream. Redirecting one must not decide for the other:
//! `openshell ... 2> build.log` from a terminal should keep a styled stdout and
//! write a plain-text log, and `openshell ... | grep` should keep styled
//! diagnostics on the terminal while feeding the pipe clean bytes. [`init`]
//! therefore stores one answer per stream and hands each library the one for the
//! stream it writes to.
//!
//! The `owo-colors` wrapper is the exception, because its call sites are split
//! across `println!` and `eprintln!` and a [`Painted`] value cannot tell which
//! macro will consume it. It styles only when both streams accept escapes, which
//! errs toward plain text rather than risk writing escapes to a redirected
//! stream.

use std::ffi::OsStr;
use std::fmt::{self, Display};
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

use owo_colors::{OwoColorize, Style};

/// Whether stdout may carry escapes. Consulted for `tracing` and console's
/// stdout switch.
///
/// Defaults to disabled so that any output produced before [`init`] runs — and
/// output from unit tests, which never call `init` — stays free of escapes.
static STDOUT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether stderr may carry escapes. Consulted for `miette` and console's stderr
/// switch.
static STDERR_ENABLED: AtomicBool = AtomicBool::new(false);

/// When to colorize CLI output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    /// Colorize a stream only when that stream is a terminal and no environment
    /// override applies.
    #[default]
    Auto,
    /// Always colorize, even when output is redirected.
    Always,
    /// Never colorize.
    Never,
}

/// Resolve the color setting and store it for the rest of the process.
///
/// Call once, as early as possible after argument parsing and before any output
/// is written.
pub fn init(choice: ColorChoice) {
    let no_color = std::env::var_os("NO_COLOR");
    let force_color = std::env::var_os("FORCE_COLOR");
    let term = std::env::var_os("TERM");

    // Under `auto` each stream answers for itself. Redirecting one must not
    // decide for the other: `openshell ... 2> build.log` from a terminal has a
    // styled stdout and a plain-text stderr, and vice versa for `| grep`.
    let stdout_enabled = resolve(
        choice,
        no_color.as_deref(),
        force_color.as_deref(),
        terminal_supports_ansi(std::io::stdout().is_terminal(), term.as_deref()),
    );
    let stderr_enabled = resolve(
        choice,
        no_color.as_deref(),
        force_color.as_deref(),
        terminal_supports_ansi(std::io::stderr().is_terminal(), term.as_deref()),
    );
    STDOUT_ENABLED.store(stdout_enabled, Ordering::Relaxed);
    STDERR_ENABLED.store(stderr_enabled, Ordering::Relaxed);

    // `indicatif` and `dialoguer` both style through `console`, which keeps its
    // own detection. Override it so progress bars and prompts follow the same
    // setting as everything else — including `--color`, which console has no way
    // to learn about on its own.
    console::set_colors_enabled(stdout_enabled);
    console::set_colors_enabled_stderr(stderr_enabled);

    // miette renders errors to stderr. The hook can only be installed once per
    // process; a failure means something already installed one, and error
    // rendering is not worth aborting the command over.
    let _ = miette::set_hook(Box::new(move |_| {
        Box::new(
            miette::MietteHandlerOpts::new()
                .color(stderr_enabled)
                .build(),
        )
    }));
}

/// Whether stdout may carry ANSI escapes.
///
/// [`init`] configures `console` and `miette` directly; `tracing` is wired up by
/// the caller, which writes to stdout and passes this to `with_ansi`.
#[must_use]
pub fn stdout_enabled() -> bool {
    STDOUT_ENABLED.load(Ordering::Relaxed)
}

/// Whether stderr may carry ANSI escapes.
#[must_use]
pub fn stderr_enabled() -> bool {
    STDERR_ENABLED.load(Ordering::Relaxed)
}

/// Whether a [`Painted`] value should render styled.
///
/// The `owo-colors` call sites are split across `println!` and `eprintln!` and
/// the wrapper cannot tell which one will consume it, so it styles only when
/// *both* streams accept escapes. Erring toward plain text keeps a redirected
/// stream clean, which is the whole point of the switch; the cost is that
/// `openshell ... 2>/dev/null` from a terminal prints an uncolored table.
/// `--color always` overrides it.
#[must_use]
fn painted_enabled() -> bool {
    stdout_enabled() && stderr_enabled()
}

/// Decide whether one stream may carry escapes. Split out from [`init`] so the
/// precedence rules are testable without mutating process state.
fn resolve(
    choice: ColorChoice,
    no_color: Option<&OsStr>,
    force_color: Option<&OsStr>,
    stream_supports_ansi: bool,
) -> bool {
    match choice {
        ColorChoice::Always => return true,
        ColorChoice::Never => return false,
        ColorChoice::Auto => {}
    }

    // Both conventions key on presence rather than value: set and non-empty
    // means yes, regardless of what the value is. <https://no-color.org> and
    // <https://force-color.org>.
    if is_set(no_color) {
        return false;
    }
    if is_set(force_color) {
        return true;
    }

    // Only `auto` consults the terminal. An explicit request above has already
    // returned, so `--color always` and `FORCE_COLOR` still win on a terminal
    // that reports no ANSI support.
    stream_supports_ansi
}

/// Whether this output stream's terminal renders ANSI escapes.
///
/// Being attached to a terminal is not the same as that terminal rendering
/// ANSI. `TERM` is the unix signal for it; Windows consoles enable virtual
/// terminal processing instead and do not set `TERM`, so the check does not
/// apply there.
fn terminal_supports_ansi(stream_is_terminal: bool, term: Option<&OsStr>) -> bool {
    stream_is_terminal
        && if cfg!(unix) {
            term_supports_ansi(term)
        } else {
            true
        }
}

/// Whether the terminal named by `TERM` renders ANSI escapes on Unix.
///
/// Follows the rule `console` applies on unix, which this module overrides:
/// `dumb` means no, and an unset `TERM` means no because nothing identifies a
/// capable terminal.
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

/// A value tagged with a style, rendered only when color is enabled.
///
/// Borrows its value and forwards the caller's format specification to the
/// inner `Display`, so width and alignment apply to the text rather than to the
/// text plus escapes.
pub struct Painted<'a, T: ?Sized> {
    value: &'a T,
    style: Style,
}

impl<T: Display + ?Sized> Display for Painted<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !painted_enabled() {
            return Display::fmt(&self.value, f);
        }
        // Hand the whole style to owo-colors in one go. `Styled` writes the
        // prefix, forwards `f` to the inner `Display` so padding still measures
        // the text, then writes the reset.
        Display::fmt(&OwoColorize::style(&self.value, self.style), f)
    }
}

/// Style-combining methods, so `x.green().bold()` renders as one escape
/// sequence rather than nesting two.
///
/// These are inherent so they take precedence over the [`Colorize`] blanket
/// impl, which would otherwise wrap a `Painted` in another `Painted`.
impl<T: ?Sized> Painted<'_, T> {
    /// Add bold to the current style.
    #[must_use]
    pub fn bold(self) -> Self {
        Self {
            style: self.style.bold(),
            ..self
        }
    }
    /// Add cyan to the current style.
    #[must_use]
    pub fn cyan(self) -> Self {
        Self {
            style: self.style.cyan(),
            ..self
        }
    }
    /// Add dimmed to the current style.
    #[must_use]
    pub fn dimmed(self) -> Self {
        Self {
            style: self.style.dimmed(),
            ..self
        }
    }
    /// Add green to the current style.
    #[must_use]
    pub fn green(self) -> Self {
        Self {
            style: self.style.green(),
            ..self
        }
    }
    /// Add red to the current style.
    #[must_use]
    pub fn red(self) -> Self {
        Self {
            style: self.style.red(),
            ..self
        }
    }
    /// Add yellow to the current style.
    #[must_use]
    pub fn yellow(self) -> Self {
        Self {
            style: self.style.yellow(),
            ..self
        }
    }
}

/// Styling methods mirroring the `owo_colors::OwoColorize` surface the CLI uses.
///
/// Import this instead of `OwoColorize` so styled output honors [`init`]. The
/// two traits have colliding method names on purpose: importing both in one
/// module is an ambiguity error, which keeps unconditional coloring from
/// creeping back in.
pub trait Colorize {
    /// Render in bold.
    fn bold(&self) -> Painted<'_, Self>;
    /// Render in cyan.
    fn cyan(&self) -> Painted<'_, Self>;
    /// Render dimmed.
    fn dimmed(&self) -> Painted<'_, Self>;
    /// Render in green.
    fn green(&self) -> Painted<'_, Self>;
    /// Render in red.
    fn red(&self) -> Painted<'_, Self>;
    /// Render in yellow.
    fn yellow(&self) -> Painted<'_, Self>;
}

impl<T: ?Sized> Colorize for T {
    fn bold(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            style: Style::new().bold(),
        }
    }
    fn cyan(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            style: Style::new().cyan(),
        }
    }
    fn dimmed(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            style: Style::new().dimmed(),
        }
    }
    fn green(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            style: Style::new().green(),
        }
    }
    fn red(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            style: Style::new().red(),
        }
    }
    fn yellow(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            style: Style::new().yellow(),
        }
    }
}

#[cfg(test)]
mod tests {
    // Deliberately not `use super::*`: that would also pull in `OwoColorize`
    // and make every `.green()` below ambiguous.
    use super::{
        ColorChoice, Colorize, Ordering, STDERR_ENABLED, STDOUT_ENABLED, Style, painted_enabled,
        resolve, term_supports_ansi,
    };
    use std::ffi::OsStr;

    /// Serializes tests that flip the process-wide switches.
    static SWITCH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set both stream switches, since [`Painted`] requires both.
    fn with_color<R>(on: bool, body: impl FnOnce() -> R) -> R {
        with_streams(on, on, body)
    }

    fn with_streams<R>(stdout: bool, stderr: bool, body: impl FnOnce() -> R) -> R {
        let _guard = SWITCH_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_out = STDOUT_ENABLED.swap(stdout, Ordering::Relaxed);
        let prev_err = STDERR_ENABLED.swap(stderr, Ordering::Relaxed);
        let result = body();
        STDOUT_ENABLED.store(prev_out, Ordering::Relaxed);
        STDERR_ENABLED.store(prev_err, Ordering::Relaxed);
        result
    }

    /// Helper so the `resolve` cases read as plain strings.
    fn env(value: &str) -> &OsStr {
        OsStr::new(value)
    }

    #[test]
    fn disabled_output_has_no_escapes() {
        with_color(false, || {
            assert_eq!("running".green().to_string(), "running");
            assert_eq!("dead".red().to_string(), "dead");
            assert_eq!("STATUS".bold().to_string(), "STATUS");
        });
    }

    #[test]
    fn enabled_output_is_wrapped_in_the_expected_escapes() {
        with_color(true, || {
            // The styling the bug report observed from `forward list`.
            assert_eq!("running".green().to_string(), "\u{1b}[32mrunning\u{1b}[0m");
            // Delegation is to owo-colors, so the bytes match what it would
            // produce for the same style.
            assert_eq!(
                "running".green().to_string(),
                owo_colors::OwoColorize::style(&"running", Style::new().green()).to_string()
            );
            assert_eq!(
                "x".dimmed().to_string(),
                owo_colors::OwoColorize::style(&"x", Style::new().dimmed()).to_string()
            );
        });
    }

    #[test]
    fn format_width_applies_to_text_not_escapes() {
        // Padding must measure the value, so columns line up identically whether
        // or not color is on.
        let plain = with_color(false, || format!("[{:<10}]", "running".green()));
        let colored = with_color(true, || format!("[{:<10}]", "running".green()));

        assert_eq!(plain, "[running   ]");
        assert_eq!(colored, "[\u{1b}[32mrunning   \u{1b}[0m]");
    }

    #[test]
    fn styles_merge_into_one_escape_sequence() {
        with_color(true, || {
            // Chaining combines into a single style rather than nesting two
            // wrappers, so there is one prefix and one reset.
            assert_eq!("hi".green().bold().to_string(), "\u{1b}[32;1mhi\u{1b}[0m");
            assert_eq!(
                "hi".green().bold().to_string(),
                owo_colors::OwoColorize::style(&"hi", Style::new().green().bold()).to_string()
            );
            // Order of the calls does not change the resulting style.
            assert_eq!(
                "hi".green().bold().to_string(),
                "hi".bold().green().to_string()
            );
        });
        with_color(false, || {
            assert_eq!("hi".green().bold().to_string(), "hi");
        });
    }

    #[test]
    fn non_string_values_render() {
        with_color(false, || {
            assert_eq!(8443.green().to_string(), "8443");
            assert_eq!(true.yellow().to_string(), "true");
        });
    }

    /// Render a `dialoguer` confirm prompt, which styles through `console`.
    ///
    /// Asserting on emitted bytes rather than on `console::colors_enabled()`
    /// keeps this honest about what a user would actually see.
    fn rendered_prompt() -> String {
        use dialoguer::theme::Theme as _;

        let mut out = String::new();
        dialoguer::theme::ColorfulTheme::default()
            .format_confirm_prompt(&mut out, "Continue?", Some(false))
            .expect("format confirm prompt");
        out
    }

    #[test]
    fn console_override_governs_indicatif_and_dialoguer_styling() {
        let _guard = SWITCH_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Prompts and progress bars draw to stderr, so their styles consult
        // console's stderr switch. `init` sets both; so does this test.
        let previous = console::colors_enabled_stderr();

        console::set_colors_enabled_stderr(true);
        let styled = rendered_prompt();
        console::set_colors_enabled_stderr(false);
        let plain = rendered_prompt();

        console::set_colors_enabled_stderr(previous);

        // Positive control first: without it, the plain assertion could pass
        // simply because dialoguer stopped emitting anything at all.
        assert!(
            styled.contains('\u{1b}'),
            "console override should permit styling, got: {styled:?}"
        );
        assert!(
            !plain.contains('\u{1b}'),
            "console override should suppress styling, got: {plain:?}"
        );
        assert!(plain.contains("Continue?"), "got: {plain:?}");
    }

    #[test]
    fn explicit_choice_overrides_environment_and_terminal() {
        assert!(resolve(ColorChoice::Always, Some(env("1")), None, false));
        assert!(!resolve(ColorChoice::Never, None, Some(env("1")), true));
    }

    #[test]
    fn no_color_disables_when_set_and_non_empty() {
        assert!(!resolve(ColorChoice::Auto, Some(env("1")), None, true));
        // Presence is what counts; the value is not interpreted, so a value that
        // reads as falsy still disables color.
        assert!(!resolve(ColorChoice::Auto, Some(env("0")), None, true));
        // NO_COLOR outranks FORCE_COLOR.
        assert!(!resolve(
            ColorChoice::Auto,
            Some(env("1")),
            Some(env("1")),
            true
        ));
        // An empty value is not "set" for the purposes of the convention.
        assert!(resolve(ColorChoice::Auto, Some(env("")), None, true));
    }

    #[test]
    fn force_color_enables_when_set_and_non_empty() {
        assert!(resolve(ColorChoice::Auto, None, Some(env("1")), false));
        // Same presence rule as NO_COLOR: `0` is a value, not an opt-out.
        // <https://force-color.org> keys on presence and non-emptiness only.
        assert!(resolve(ColorChoice::Auto, None, Some(env("0")), false));
        assert!(!resolve(ColorChoice::Auto, None, Some(env("")), false));
    }

    #[test]
    fn term_capability_follows_the_console_rule() {
        assert!(term_supports_ansi(Some(OsStr::new("xterm-256color"))));
        assert!(term_supports_ansi(Some(OsStr::new("screen"))));
        assert!(!term_supports_ansi(Some(OsStr::new("dumb"))));
        // Nothing to suggest a capable terminal, so assume none.
        assert!(!term_supports_ansi(None));
        // Empty names no terminal type; treated as unset, unlike `console`.
        assert!(!term_supports_ansi(Some(OsStr::new(""))));
        // Only an exact match counts; `dumb-something` is a different terminal.
        assert!(term_supports_ansi(Some(OsStr::new("dumb-but-color"))));
    }

    #[test]
    fn auto_does_not_style_an_incapable_terminal() {
        // A `dumb` terminal is still a terminal, so `is_terminal()` alone would
        // wrongly enable color.
        assert!(!resolve(ColorChoice::Auto, None, None, false));
        assert!(resolve(ColorChoice::Auto, None, None, true));
    }

    #[test]
    fn explicit_requests_outrank_terminal_capability() {
        // `--color always` and FORCE_COLOR are for callers who know better than
        // the detection, so an incapable terminal must not veto them.
        assert!(resolve(ColorChoice::Always, None, None, false));
        assert!(resolve(ColorChoice::Auto, None, Some(env("1")), false));
        // The negative direction still wins over capability too.
        assert!(!resolve(ColorChoice::Never, None, None, true));
        assert!(!resolve(ColorChoice::Auto, Some(env("1")), None, true));
    }

    #[test]
    fn capability_does_not_rescue_a_redirected_stream() {
        // Capability is an additional requirement, not an alternative one.
        assert!(!resolve(ColorChoice::Auto, None, None, false));
    }

    #[test]
    fn auto_resolves_each_stream_independently() {
        // `openshell ... 2> build.log` from a terminal: stdout is styled, the
        // log file is not. Resolving both from stdout's answer would put escapes
        // in the log.
        assert!(resolve(ColorChoice::Auto, None, None, true));
        assert!(!resolve(ColorChoice::Auto, None, None, false));
    }

    #[test]
    fn painted_requires_both_streams() {
        // A `Painted` value cannot tell whether it is bound for stdout or
        // stderr, so it stays plain unless both streams accept escapes.
        assert!(with_streams(true, true, painted_enabled));
        assert!(!with_streams(true, false, painted_enabled));
        assert!(!with_streams(false, true, painted_enabled));
        assert!(!with_streams(false, false, painted_enabled));

        // The rendered consequence: stderr redirected to a file leaves the
        // styled text plain rather than writing escapes into it.
        assert_eq!(
            with_streams(true, false, || "running".green().to_string()),
            "running"
        );
    }

    #[test]
    fn auto_follows_the_terminal() {
        assert!(resolve(ColorChoice::Auto, None, None, true));
        assert!(!resolve(ColorChoice::Auto, None, None, false));
    }
}
