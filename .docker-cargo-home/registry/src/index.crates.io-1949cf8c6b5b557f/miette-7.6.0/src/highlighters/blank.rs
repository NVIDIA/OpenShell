use owo_colors::Style;

use crate::SpanContents;

use super::{Highlighter, HighlighterState};

/// The default syntax highlighter. It applies `Style::default()` to input text.
/// This is used by default when no syntax highlighting features are enabled.
#[derive(Debug, Clone)]
pub struct BlankHighlighter;

impl Highlighter for BlankHighlighter {
    fn start_highlighter_state<'h>(
        &'h self,
        _source: &dyn SpanContents<'_>,
    ) -> Box<dyn super::HighlighterState + 'h> {
        Box::new(BlankHighlighterState)
    }
}

impl Default for BlankHighlighter {
    fn default() -> Self {
        BlankHighlighter
    }
}

/// The default highlighter state. It applies `Style::default()` to input text.
/// This is used by default when no syntax highlighting features are enabled.
#[derive(Debug, Clone)]
pub struct BlankHighlighterState;

impl HighlighterState for BlankHighlighterState {
    fn highlight_line<'s>(&mut self, line: &'s str) -> Vec<owo_colors::Styled<&'s str>> {
        vec![Style::default().style(line)]
    }
}
