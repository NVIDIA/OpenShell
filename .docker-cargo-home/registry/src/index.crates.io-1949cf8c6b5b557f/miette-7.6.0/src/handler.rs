use crate::highlighters::Highlighter;
use crate::highlighters::MietteHighlighter;
use crate::protocol::Diagnostic;
use crate::GraphicalReportHandler;
use crate::GraphicalTheme;
use crate::NarratableReportHandler;
use crate::ReportHandler;
use crate::ThemeCharacters;
use crate::ThemeStyles;
use cfg_if::cfg_if;
use std::fmt;

/// Settings to control the color format used for graphical rendering.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum RgbColors {
    /// Use RGB colors even if the terminal does not support them
    Always,
    /// Use RGB colors instead of ANSI if the terminal supports RGB
    Preferred,
    /// Always use ANSI, regardless of terminal support for RGB
    #[default]
    Never,
}

/**
Create a custom [`MietteHandler`] from options.

## Example

```no_run
miette::set_hook(Box::new(|_| {
    Box::new(miette::MietteHandlerOpts::new()
        .terminal_links(true)
        .unicode(false)
        .context_lines(3)
        .build())
}))
# .unwrap();
```
*/
#[derive(Default, Debug, Clone)]
pub struct MietteHandlerOpts {
    pub(crate) linkify: Option<bool>,
    pub(crate) width: Option<usize>,
    pub(crate) theme: Option<GraphicalTheme>,
    pub(crate) force_graphical: Option<bool>,
    pub(crate) force_narrated: Option<bool>,
    pub(crate) rgb_colors: RgbColors,
    pub(crate) color: Option<bool>,
    pub(crate) unicode: Option<bool>,
    pub(crate) footer: Option<String>,
    pub(crate) context_lines: Option<usize>,
    pub(crate) tab_width: Option<usize>,
    pub(crate) with_cause_chain: Option<bool>,
    pub(crate) break_words: Option<bool>,
    pub(crate) wrap_lines: Option<bool>,
    pub(crate) word_separator: Option<textwrap::WordSeparator>,
    pub(crate) word_splitter: Option<textwrap::WordSplitter>,
    pub(crate) highlighter: Option<MietteHighlighter>,
    pub(crate) show_related_as_nested: Option<bool>,
}

impl MietteHandlerOpts {
    /// Create a new `MietteHandlerOpts`.
    pub fn new() -> Self {
        Default::default()
    }

    /// If true, specify whether the graphical handler will make codes be
    /// clickable links in supported terminals. Defaults to auto-detection
    /// based on known supported terminals.
    pub fn terminal_links(mut self, linkify: bool) -> Self {
        self.linkify = Some(linkify);
        self
    }

    /// Set a graphical theme for the handler when rendering in graphical mode.
    /// Use [`force_graphical()`](`MietteHandlerOpts::force_graphical) to force
    /// graphical mode. This option overrides
    /// [`color()`](`MietteHandlerOpts::color).
    pub fn graphical_theme(mut self, theme: GraphicalTheme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Set a syntax highlighter when rendering in graphical mode.
    /// Use [`force_graphical()`](MietteHandlerOpts::force_graphical()) to
    /// force graphical mode.
    ///
    /// Syntax highlighting is disabled by default unless the
    /// `syntect-highlighter` feature is enabled. Call this method
    /// to override the default and use a custom highlighter
    /// implementation instead.
    ///
    /// Use
    /// [`without_syntax_highlighting()`](MietteHandlerOpts::without_syntax_highlighting())
    /// To disable highlighting completely.
    ///
    /// Setting this option will not force color output. In all cases, the
    /// current color configuration via
    /// [`color()`](MietteHandlerOpts::color()) takes precedence over
    /// highlighter configuration. However, this option does take precedence over
    /// [`rgb_colors()`](MietteHandlerOpts::rgb_colors()) (meaning syntax highlighting will be
    /// enabled regardless of the value of [`MietteHandlerOpts::rgb_colors`]).
    pub fn with_syntax_highlighting(
        mut self,
        highlighter: impl Highlighter + Send + Sync + 'static,
    ) -> Self {
        self.highlighter = Some(MietteHighlighter::from(highlighter));
        self
    }

    /// Disables syntax highlighting when rendering in graphical mode.
    /// Use [`force_graphical()`](MietteHandlerOpts::force_graphical()) to
    /// force graphical mode.
    ///
    /// Syntax highlighting is disabled by default unless the
    /// `syntect-highlighter` feature is enabled. Call this method if you want
    /// to disable highlighting when building with this feature.
    pub fn without_syntax_highlighting(mut self) -> Self {
        self.highlighter = Some(MietteHighlighter::nocolor());
        self
    }

    /// Sets the width to wrap the report at. Defaults to 80.
    pub fn width(mut self, width: usize) -> Self {
        self.width = Some(width);
        self
    }

    /// If true, long lines can be wrapped.
    ///
    /// If false, long lines will not be broken when they exceed the width.
    ///
    /// Defaults to true.
    pub fn wrap_lines(mut self, wrap_lines: bool) -> Self {
        self.wrap_lines = Some(wrap_lines);
        self
    }

    /// If true, long words can be broken when wrapping.
    ///
    /// If false, long words will not be broken when they exceed the width.
    ///
    /// Defaults to true.
    pub fn break_words(mut self, break_words: bool) -> Self {
        self.break_words = Some(break_words);
        self
    }
    /// Sets the `textwrap::WordSeparator` to use when determining wrap points.
    pub fn word_separator(mut self, word_separator: textwrap::WordSeparator) -> Self {
        self.word_separator = Some(word_separator);
        self
    }

    /// Sets the `textwrap::WordSplitter` to use when determining wrap points.
    pub fn word_splitter(mut self, word_splitter: textwrap::WordSplitter) -> Self {
        self.word_splitter = Some(word_splitter);
        self
    }
    /// Include the cause chain of the top-level error in the report.
    pub fn with_cause_chain(mut self) -> Self {
        self.with_cause_chain = Some(true);
        self
    }

    /// Do not include the cause chain of the top-level error in the report.
    pub fn without_cause_chain(mut self) -> Self {
        self.with_cause_chain = Some(false);
        self
    }

    /// Show related errors as siblings.
    pub fn show_related_errors_as_siblings(mut self) -> Self {
        self.show_related_as_nested = Some(false);
        self
    }

    /// Show related errors as nested errors.
    pub fn show_related_errors_as_nested(mut self) -> Self {
        self.show_related_as_nested = Some(true);
        self
    }

    /// If true, colors will be used during graphical rendering, regardless
    /// of whether or not the terminal supports them.
    ///
    /// If false, colors will never be used.
    ///
    /// If unspecified, colors will be used only if the terminal supports them.
    ///
    /// The actual format depends on the value of
    /// [`MietteHandlerOpts::rgb_colors`].
    pub fn color(mut self, color: bool) -> Self {
        self.color = Some(color);
        self
    }

    /// Controls which color format to use if colors are used in graphical
    /// rendering.
    ///
    /// The default is `Never`.
    ///
    /// This value does not control whether or not colors are being used in the
    /// first place. That is handled by the [`MietteHandlerOpts::color`]
    /// setting. If colors are not being used, the value of `rgb_colors` has
    /// no effect.
    ///
    /// It also does not control colors when a syntax highlighter is in use.
    pub fn rgb_colors(mut self, color: RgbColors) -> Self {
        self.rgb_colors = color;
        self
    }

    /// If true, forces unicode display for graphical output. If set to false,
    /// forces ASCII art display.
    pub fn unicode(mut self, unicode: bool) -> Self {
        self.unicode = Some(unicode);
        self
    }

    /// If true, graphical rendering will be used regardless of terminal
    /// detection.
    pub fn force_graphical(mut self, force: bool) -> Self {
        self.force_graphical = Some(force);
        self
    }

    /// If true, forces use of the narrated renderer.
    pub fn force_narrated(mut self, force: bool) -> Self {
        self.force_narrated = Some(force);
        self
    }

    /// Set a footer to be displayed at the bottom of the report.
    pub fn footer(mut self, footer: String) -> Self {
        self.footer = Some(footer);
        self
    }

    /// Sets the number of context lines before and after a span to display.
    pub fn context_lines(mut self, context_lines: usize) -> Self {
        self.context_lines = Some(context_lines);
        self
    }

    /// Set the displayed tab width in spaces.
    pub fn tab_width(mut self, width: usize) -> Self {
        self.tab_width = Some(width);
        self
    }

    /// Builds a [`MietteHandler`] from this builder.
    pub fn build(self) -> MietteHandler {
        let graphical = self.is_graphical();
        let width = self.get_width();
        if !graphical {
            let mut handler = NarratableReportHandler::new();
            if let Some(footer) = self.footer {
                handler = handler.with_footer(footer);
            }
            if let Some(context_lines) = self.context_lines {
                handler = handler.with_context_lines(context_lines);
            }
            if let Some(with_cause_chain) = self.with_cause_chain {
                if with_cause_chain {
                    handler = handler.with_cause_chain();
                } else {
                    handler = handler.without_cause_chain();
                }
            }
            MietteHandler {
                inner: Box::new(handler),
            }
        } else {
            let linkify = self.use_links();
            let characters = match self.unicode {
                Some(true) => ThemeCharacters::unicode(),
                Some(false) => ThemeCharacters::ascii(),
                None if syscall::supports_unicode() => ThemeCharacters::unicode(),
                None => ThemeCharacters::ascii(),
            };
            let styles = if self.color == Some(false) {
                ThemeStyles::none()
            } else if let Some(color_has_16m) = syscall::supports_color_has_16m() {
                match self.rgb_colors {
                    RgbColors::Always => ThemeStyles::rgb(),
                    RgbColors::Preferred if color_has_16m => ThemeStyles::rgb(),
                    _ => ThemeStyles::ansi(),
                }
            } else if self.color == Some(true) {
                match self.rgb_colors {
                    RgbColors::Always => ThemeStyles::rgb(),
                    _ => ThemeStyles::ansi(),
                }
            } else {
                ThemeStyles::none()
            };
            let highlighter_opt =
                HighlighterOption::select(self.color, self.highlighter, syscall::supports_color());
            let theme = self.theme.unwrap_or(GraphicalTheme { characters, styles });
            let mut handler = GraphicalReportHandler::new_themed(theme)
                .with_width(width)
                .with_links(linkify);
            handler.highlighter = highlighter_opt.into();
            if let Some(with_cause_chain) = self.with_cause_chain {
                if with_cause_chain {
                    handler = handler.with_cause_chain();
                } else {
                    handler = handler.without_cause_chain();
                }
            }
            if let Some(footer) = self.footer {
                handler = handler.with_footer(footer);
            }
            if let Some(context_lines) = self.context_lines {
                handler = handler.with_context_lines(context_lines);
            }
            if let Some(w) = self.tab_width {
                handler = handler.tab_width(w);
            }
            if let Some(b) = self.break_words {
                handler = handler.with_break_words(b)
            }
            if let Some(b) = self.wrap_lines {
                handler = handler.with_wrap_lines(b)
            }
            if let Some(s) = self.word_separator {
                handler = handler.with_word_separator(s)
            }
            if let Some(s) = self.word_splitter {
                handler = handler.with_word_splitter(s)
            }
            if let Some(b) = self.show_related_as_nested {
                handler = handler.with_show_related_as_nested(b)
            }

            MietteHandler {
                inner: Box::new(handler),
            }
        }
    }

    pub(crate) fn is_graphical(&self) -> bool {
        if let Some(force_narrated) = self.force_narrated {
            !force_narrated
        } else if let Some(force_graphical) = self.force_graphical {
            force_graphical
        } else if let Ok(env) = std::env::var("NO_GRAPHICS") {
            env == "0"
        } else {
            true
        }
    }

    // Detects known terminal apps based on env variables and returns true if
    // they support rendering links.
    pub(crate) fn use_links(&self) -> bool {
        if let Some(linkify) = self.linkify {
            linkify
        } else {
            syscall::supports_hyperlinks()
        }
    }

    pub(crate) fn get_width(&self) -> usize {
        self.width
            .unwrap_or_else(|| syscall::terminal_width().unwrap_or(80))
    }
}

/**
A [`ReportHandler`] that displays a given [`Report`](crate::Report) in a
quasi-graphical way, using terminal colors, unicode drawing characters, and
other such things.

This is the default reporter bundled with `miette`.

This printer can be customized by using
[`GraphicalReportHandler::new_themed()`] and handing it a [`GraphicalTheme`] of
your own creation (or using one of its own defaults).

See [`set_hook`](crate::set_hook) for more details on customizing your global
printer.
*/
#[allow(missing_debug_implementations)]
pub struct MietteHandler {
    inner: Box<dyn ReportHandler + Send + Sync>,
}

impl MietteHandler {
    /// Creates a new [`MietteHandler`] with default settings.
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for MietteHandler {
    fn default() -> Self {
        MietteHandlerOpts::new().build()
    }
}

impl ReportHandler for MietteHandler {
    fn debug(&self, diagnostic: &(dyn Diagnostic), f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            return fmt::Debug::fmt(diagnostic, f);
        }

        self.inner.debug(diagnostic, f)
    }
}

enum HighlighterOption {
    Disable,
    EnableCustom(MietteHighlighter),
    #[cfg(feature = "syntect-highlighter")]
    EnableSyntect,
}

impl HighlighterOption {
    fn select(
        color: Option<bool>,
        highlighter: Option<MietteHighlighter>,
        supports_color: bool,
    ) -> HighlighterOption {
        if color == Some(false) || (color.is_none() && !supports_color) {
            return HighlighterOption::Disable;
        }
        highlighter
            .map(HighlighterOption::EnableCustom)
            .unwrap_or_default()
    }
}

// NOTE: This is manually implemented so that it's clearer what's going on with
// the conditional compilation — clippy isn't picking up the `cfg` stuff here
#[allow(clippy::derivable_impls)]
impl Default for HighlighterOption {
    fn default() -> Self {
        cfg_if! {
            if #[cfg(feature = "syntect-highlighter")] {
                // Because the syntect highlighter currently only supports 24-bit truecolor,
                // it supersedes and ignores the `rgb_colors` config.
                // TODO: In the future, if we find a way to convert the RGB syntect theme
                // into an ANSI color theme, we can take `rgb_colors` into account.
                HighlighterOption::EnableSyntect
            } else {
                HighlighterOption::Disable
            }
        }
    }
}

impl From<HighlighterOption> for MietteHighlighter {
    fn from(opt: HighlighterOption) -> Self {
        match opt {
            HighlighterOption::Disable => MietteHighlighter::nocolor(),
            HighlighterOption::EnableCustom(highlighter) => highlighter,
            #[cfg(feature = "syntect-highlighter")]
            HighlighterOption::EnableSyntect => MietteHighlighter::syntect_truecolor(),
        }
    }
}

mod syscall {
    use cfg_if::cfg_if;

    #[inline]
    pub(super) fn terminal_width() -> Option<usize> {
        cfg_if! {
            if #[cfg(any(feature = "fancy-no-syscall", miri))] {
                None
            } else {
                terminal_size::terminal_size().map(|size| size.0 .0 as usize)
            }
        }
    }

    #[inline]
    pub(super) fn supports_hyperlinks() -> bool {
        cfg_if! {
            if #[cfg(feature = "fancy-no-syscall")] {
                false
            } else {
                supports_hyperlinks::on(supports_hyperlinks::Stream::Stderr)
            }
        }
    }

    #[inline]
    pub(super) fn supports_color() -> bool {
        cfg_if! {
            if #[cfg(feature = "fancy-no-syscall")] {
                false
            } else {
                supports_color::on(supports_color::Stream::Stderr).is_some()
            }
        }
    }

    #[inline]
    pub(super) fn supports_color_has_16m() -> Option<bool> {
        cfg_if! {
            if #[cfg(feature = "fancy-no-syscall")] {
                None
            } else {
                supports_color::on(supports_color::Stream::Stderr).map(|color| color.has_16m)
            }
        }
    }

    #[inline]
    pub(super) fn supports_unicode() -> bool {
        cfg_if! {
            if #[cfg(feature = "fancy-no-syscall")] {
                false
            } else {
                supports_unicode::on(supports_unicode::Stream::Stderr)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::highlighters::BlankHighlighter;
    use cfg_if::cfg_if;

    #[test]
    fn test_highlighter_option() {
        // Syntax highlighting is enabled depending on several variables:
        // - The `color` config
        // - The `highlighter` config
        // - Whether the `syntect-highlighter` feature is enabled
        // - Whether the terminal supports color
        //
        // This test asserts the expected highlighter depending on combinations of those variables.

        macro_rules! assert_highlighter_opt {
            (opts = $opts:expr, supports_color = $sup_color:literal, expected = $expected:pat $(,)?) => {
                assert_highlighter_opt!(
                    opts = $opts,
                    supports_color = $sup_color,
                    expected_with_syntect = $expected,
                    expected_without_syntect = $expected,
                );
            };

            (
                opts = $opts:expr,
                supports_color = $sup_color:literal,
                expected_with_syntect = $expected_with:pat,
                expected_without_syntect = $expected_without:pat $(,)?
            ) => {{
                let highlighter_opt =
                    HighlighterOption::select($opts.color, $opts.highlighter, $sup_color);
                cfg_if! {
                    if #[cfg(feature = "syntect-highlighter")] {
                        assert!(matches!(highlighter_opt, $expected_with));
                    } else {
                        assert!(matches!(highlighter_opt, $expected_without));
                    }
                }
            }};
        }

        // When color is explicitly disabled, highlighting is also always disabled.
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new().color(false),
            supports_color = true,
            expected = HighlighterOption::Disable,
        );

        // When color is unset and the terminal doesn't support color, highlighting is disabled.
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new(),
            supports_color = false,
            expected = HighlighterOption::Disable,
        );

        // With explicit or implicit color support, highlighting is automatically enabled when
        // `syntect-highlighter` is enabled.
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new().color(true),
            supports_color = false,
            expected_with_syntect = HighlighterOption::EnableSyntect,
            expected_without_syntect = HighlighterOption::Disable,
        );
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new(),
            supports_color = true,
            expected_with_syntect = HighlighterOption::EnableSyntect,
            expected_without_syntect = HighlighterOption::Disable,
        );

        // With explicit or implicit color support, if custom highlighting is set, it's enabled.
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new()
                .color(true)
                .with_syntax_highlighting(BlankHighlighter),
            supports_color = false,
            expected = HighlighterOption::EnableCustom(_),
        );
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new().with_syntax_highlighting(BlankHighlighter),
            supports_color = true,
            expected = HighlighterOption::EnableCustom(_),
        );

        // Setting `RgbColors::Never` has no effect when syntax highlighting is enabled.
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new()
                .color(true)
                .rgb_colors(RgbColors::Never),
            supports_color = false,
            expected_with_syntect = HighlighterOption::EnableSyntect,
            expected_without_syntect = HighlighterOption::Disable,
        );
        assert_highlighter_opt!(
            opts = MietteHandlerOpts::new().rgb_colors(RgbColors::Never),
            supports_color = true,
            expected_with_syntect = HighlighterOption::EnableSyntect,
            expected_without_syntect = HighlighterOption::Disable,
        );
    }
}
