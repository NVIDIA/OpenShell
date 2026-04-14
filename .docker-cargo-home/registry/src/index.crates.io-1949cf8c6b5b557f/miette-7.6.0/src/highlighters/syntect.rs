use std::path::Path;

// all syntect imports are explicitly qualified, but their paths are shortened for convenience
#[allow(clippy::module_inception)]
mod syntect {
    pub(super) use syntect::{
        highlighting::{
            Color, HighlightIterator, HighlightState, Highlighter, Style, Theme, ThemeSet,
        },
        parsing::{ParseState, ScopeStack, SyntaxReference, SyntaxSet},
    };
}

use owo_colors::{Rgb, Style, Styled};

use crate::{
    highlighters::{Highlighter, HighlighterState},
    SpanContents,
};

use super::BlankHighlighterState;

/// Highlights miette [`SpanContents`] with the [syntect](https://docs.rs/syntect/latest/syntect/) highlighting crate.
///
/// Currently only 24-bit truecolor output is supported due to syntect themes
/// representing color as RGBA.
#[derive(Debug, Clone)]
pub struct SyntectHighlighter {
    theme: syntect::Theme,
    syntax_set: syntect::SyntaxSet,
    use_bg_color: bool,
}

impl Default for SyntectHighlighter {
    fn default() -> Self {
        let theme_set = syntect::ThemeSet::load_defaults();
        let theme = theme_set.themes["base16-ocean.dark"].clone();
        Self::new_themed(theme, false)
    }
}

impl Highlighter for SyntectHighlighter {
    fn start_highlighter_state<'h>(
        &'h self,
        source: &dyn SpanContents<'_>,
    ) -> Box<dyn HighlighterState + 'h> {
        if let Some(syntax) = self.detect_syntax(source) {
            let highlighter = syntect::Highlighter::new(&self.theme);
            let parse_state = syntect::ParseState::new(syntax);
            let highlight_state =
                syntect::HighlightState::new(&highlighter, syntect::ScopeStack::new());
            Box::new(SyntectHighlighterState {
                syntax_set: &self.syntax_set,
                highlighter,
                parse_state,
                highlight_state,
                use_bg_color: self.use_bg_color,
            })
        } else {
            Box::new(BlankHighlighterState)
        }
    }
}

impl SyntectHighlighter {
    /// Create a syntect highlighter with the given theme and syntax set.
    pub fn new(syntax_set: syntect::SyntaxSet, theme: syntect::Theme, use_bg_color: bool) -> Self {
        Self {
            theme,
            syntax_set,
            use_bg_color,
        }
    }

    /// Create a syntect highlighter with the given theme and the default syntax set.
    pub fn new_themed(theme: syntect::Theme, use_bg_color: bool) -> Self {
        Self::new(
            syntect::SyntaxSet::load_defaults_nonewlines(),
            theme,
            use_bg_color,
        )
    }

    /// Determine syntect [`SyntaxReference`] to use for given [`SpanContents`].
    fn detect_syntax(&self, contents: &dyn SpanContents<'_>) -> Option<&syntect::SyntaxReference> {
        // use language if given
        if let Some(language) = contents.language() {
            return self.syntax_set.find_syntax_by_name(language);
        }
        // otherwise try to use any file extension provided in the name
        if let Some(name) = contents.name() {
            if let Some(ext) = Path::new(name).extension() {
                return self
                    .syntax_set
                    .find_syntax_by_extension(ext.to_string_lossy().as_ref());
            }
        }
        // finally, attempt to guess syntax based on first line
        self.syntax_set.find_syntax_by_first_line(
            std::str::from_utf8(contents.data())
                .ok()?
                .split('\n')
                .next()?,
        )
    }
}

/// Stateful highlighting iterator for [`SyntectHighlighter`].
#[derive(Debug)]
pub(crate) struct SyntectHighlighterState<'h> {
    syntax_set: &'h syntect::SyntaxSet,
    highlighter: syntect::Highlighter<'h>,
    parse_state: syntect::ParseState,
    highlight_state: syntect::HighlightState,
    use_bg_color: bool,
}

impl HighlighterState for SyntectHighlighterState<'_> {
    fn highlight_line<'s>(&mut self, line: &'s str) -> Vec<Styled<&'s str>> {
        if let Ok(ops) = self.parse_state.parse_line(line, self.syntax_set) {
            let use_bg_color = self.use_bg_color;
            syntect::HighlightIterator::new(
                &mut self.highlight_state,
                &ops,
                line,
                &self.highlighter,
            )
            .map(|(style, str)| (convert_style(style, use_bg_color).style(str)))
            .collect()
        } else {
            vec![Style::default().style(line)]
        }
    }
}

/// Convert syntect [`syntect::Style`] into `owo_colors` [`Style`]
#[inline]
fn convert_style(syntect_style: syntect::Style, use_bg_color: bool) -> Style {
    if use_bg_color {
        let fg = blend_fg_color(syntect_style);
        let bg = convert_color(syntect_style.background);
        Style::new().color(fg).on_color(bg)
    } else {
        let fg = convert_color(syntect_style.foreground);
        Style::new().color(fg)
    }
}

/// Blend foreground RGB into background RGB according to alpha channel
#[inline]
fn blend_fg_color(syntect_style: syntect::Style) -> Rgb {
    let fg = syntect_style.foreground;
    if fg.a == 0xff {
        return convert_color(fg);
    }
    let bg = syntect_style.background;
    let ratio = fg.a as u32;
    let r = (fg.r as u32 * ratio + bg.r as u32 * (255 - ratio)) / 255;
    let g = (fg.g as u32 * ratio + bg.g as u32 * (255 - ratio)) / 255;
    let b = (fg.b as u32 * ratio + bg.b as u32 * (255 - ratio)) / 255;
    Rgb(r as u8, g as u8, b as u8)
}

/// Convert syntect color into owo color.
///
/// Note: ignores alpha channel. use [`blend_fg_color`] if you need that
///
#[inline]
fn convert_color(color: syntect::Color) -> Rgb {
    Rgb(color.r, color.g, color.b)
}
