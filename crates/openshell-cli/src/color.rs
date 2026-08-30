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
//!   pipe exactly like the styled tables did. `main` passes [`enabled`] to
//!   `with_ansi`.
//! - `indicatif` and `dialoguer` both style through `console`, which has its own
//!   detection and honors `NO_COLOR` but cannot know about `--color`. [`init`]
//!   overrides it globally, which covers every progress bar and prompt rather
//!   than the specific ones the CLI happens to construct today.
//! - `miette` renders errors to stderr with its own detection, likewise unaware
//!   of `--color`. [`init`] installs a report handler built from the same
//!   setting.
//!
//! Resolution order, highest precedence first:
//!
//! 1. `--color always|never` on the command line.
//! 2. `NO_COLOR` set to any non-empty value disables color (<https://no-color.org>).
//! 3. `CLICOLOR_FORCE` set to a non-empty value other than `0` forces color on.
//! 4. Otherwise color is on only when stdout is a terminal.
//!
//! The decision is made against stdout even for text written to stderr. A single
//! switch keeps every call site consistent without each one having to declare
//! its destination stream, and stdout is the stream that gets parsed. Users who
//! redirect stdout but still want styled diagnostics can pass `--color always`.

use std::ffi::OsString;
use std::fmt::{self, Display};
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

use owo_colors::OwoColorize;

/// Process-wide switch consulted by every [`Painted`] value when it renders.
///
/// Defaults to disabled so that any output produced before [`init`] runs — and
/// output from unit tests, which never call `init` — stays free of escapes.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// When to colorize CLI output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    /// Colorize only when stdout is a terminal and no environment override applies.
    #[default]
    Auto,
    /// Always colorize, even when stdout is redirected.
    Always,
    /// Never colorize.
    Never,
}

/// Resolve the color setting and store it for the rest of the process.
///
/// Call once, as early as possible after argument parsing and before any output
/// is written.
pub fn init(choice: ColorChoice) {
    let enabled = resolve(
        choice,
        std::env::var_os("NO_COLOR"),
        std::env::var_os("CLICOLOR_FORCE"),
        std::io::stdout().is_terminal(),
    );
    ENABLED.store(enabled, Ordering::Relaxed);

    // `indicatif` and `dialoguer` both style through `console`, which keeps its
    // own detection. Override it so progress bars and prompts follow the same
    // setting as everything else — including `--color always`, which console
    // has no way to learn about on its own. Both switches matter: prompts and
    // progress bars draw to stderr.
    console::set_colors_enabled(enabled);
    console::set_colors_enabled_stderr(enabled);

    // miette renders errors to stderr with its own color detection. The hook can
    // only be installed once per process; a failure means something already
    // installed one, and error rendering is not worth aborting the command over.
    let _ = miette::set_hook(Box::new(move |_| {
        Box::new(miette::MietteHandlerOpts::new().color(enabled).build())
    }));
}

/// Whether ANSI escapes should be emitted.
///
/// [`init`] configures `console` and `miette` directly; `tracing` is wired up by
/// the caller, which passes this to `with_ansi`.
#[must_use]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Decide whether to colorize. Split out from [`init`] so the precedence rules
/// are testable without mutating process state.
fn resolve(
    choice: ColorChoice,
    no_color: Option<OsString>,
    clicolor_force: Option<OsString>,
    stdout_is_terminal: bool,
) -> bool {
    match choice {
        ColorChoice::Always => return true,
        ColorChoice::Never => return false,
        ColorChoice::Auto => {}
    }

    // no-color.org: any non-empty value disables color, regardless of content.
    if no_color.is_some_and(|value| !value.is_empty()) {
        return false;
    }

    // CLICOLOR_FORCE is the companion convention for forcing color on in
    // pipelines. `0` is the documented opt-out and falls through to detection.
    let forced = clicolor_force.is_some_and(|value| {
        let value = value.to_string_lossy();
        !value.is_empty() && value != "0"
    });
    if forced {
        return true;
    }

    stdout_is_terminal
}

/// The styles the CLI actually uses.
#[derive(Clone, Copy)]
enum Paint {
    Bold,
    Cyan,
    Dimmed,
    Green,
    Red,
    Yellow,
}

/// A value tagged with a style, rendered only when color is enabled.
///
/// Borrows its value and forwards the caller's format specification to the
/// inner `Display`, so width and alignment apply to the text rather than to the
/// text plus escapes.
pub struct Painted<'a, T: ?Sized> {
    value: &'a T,
    paint: Paint,
}

impl<T: Display + ?Sized> Display for Painted<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !enabled() {
            return Display::fmt(&self.value, f);
        }
        // Delegate to owo-colors so the escape sequences stay identical to what
        // the CLI emitted before this switch existed. These calls must be
        // fully qualified: `Colorize` below is also in scope and shadows the
        // same method names, which would recurse instead of emitting anything.
        match self.paint {
            Paint::Bold => Display::fmt(&OwoColorize::bold(&self.value), f),
            Paint::Cyan => Display::fmt(&OwoColorize::cyan(&self.value), f),
            Paint::Dimmed => Display::fmt(&OwoColorize::dimmed(&self.value), f),
            Paint::Green => Display::fmt(&OwoColorize::green(&self.value), f),
            Paint::Red => Display::fmt(&OwoColorize::red(&self.value), f),
            Paint::Yellow => Display::fmt(&OwoColorize::yellow(&self.value), f),
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
            paint: Paint::Bold,
        }
    }
    fn cyan(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            paint: Paint::Cyan,
        }
    }
    fn dimmed(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            paint: Paint::Dimmed,
        }
    }
    fn green(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            paint: Paint::Green,
        }
    }
    fn red(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            paint: Paint::Red,
        }
    }
    fn yellow(&self) -> Painted<'_, Self> {
        Painted {
            value: self,
            paint: Paint::Yellow,
        }
    }
}

#[cfg(test)]
mod tests {
    // Deliberately not `use super::*`: that would also pull in `OwoColorize`
    // and make every `.green()` below ambiguous.
    use super::{ColorChoice, Colorize, ENABLED, Ordering, OsString, resolve};

    /// Serializes tests that flip the process-wide switch.
    static SWITCH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_color<R>(on: bool, body: impl FnOnce() -> R) -> R {
        let _guard = SWITCH_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = ENABLED.swap(on, Ordering::Relaxed);
        let result = body();
        ENABLED.store(previous, Ordering::Relaxed);
        result
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
    fn enabled_output_matches_owo_colors_bytes() {
        with_color(true, || {
            // The exact sequence the bug report observed from `forward list`.
            assert_eq!("running".green().to_string(), "\u{1b}[32mrunning\u{1b}[39m");
            assert_eq!(
                "running".green().to_string(),
                owo_colors::OwoColorize::green(&"running").to_string()
            );
            assert_eq!(
                "x".dimmed().to_string(),
                owo_colors::OwoColorize::dimmed(&"x").to_string()
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
        assert_eq!(colored, "[\u{1b}[32mrunning   \u{1b}[39m]");
    }

    #[test]
    fn styles_compose() {
        with_color(true, || {
            assert_eq!(
                "hi".green().bold().to_string(),
                "\u{1b}[1m\u{1b}[32mhi\u{1b}[39m\u{1b}[0m"
            );
            // Nesting must stay byte-identical to owo-colors composing directly.
            assert_eq!(
                "hi".green().bold().to_string(),
                owo_colors::OwoColorize::bold(&owo_colors::OwoColorize::green(&"hi")).to_string()
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
        assert!(resolve(ColorChoice::Always, Some("1".into()), None, false));
        assert!(!resolve(ColorChoice::Never, None, Some("1".into()), true));
    }

    #[test]
    fn no_color_disables_when_non_empty() {
        assert!(!resolve(ColorChoice::Auto, Some("1".into()), None, true));
        // Any value counts, including ones that look falsy.
        assert!(!resolve(ColorChoice::Auto, Some("0".into()), None, true));
        assert!(!resolve(
            ColorChoice::Auto,
            Some("1".into()),
            Some("1".into()),
            true
        ));
        // An empty value is not "set" for the purposes of the convention.
        assert!(resolve(
            ColorChoice::Auto,
            Some(OsString::new()),
            None,
            true
        ));
    }

    #[test]
    fn clicolor_force_enables_without_a_terminal() {
        assert!(resolve(ColorChoice::Auto, None, Some("1".into()), false));
        // `0` is the documented opt-out; fall through to terminal detection.
        assert!(!resolve(ColorChoice::Auto, None, Some("0".into()), false));
        assert!(resolve(ColorChoice::Auto, None, Some("0".into()), true));
    }

    #[test]
    fn auto_follows_the_terminal() {
        assert!(resolve(ColorChoice::Auto, None, None, true));
        assert!(!resolve(ColorChoice::Auto, None, None, false));
    }
}
