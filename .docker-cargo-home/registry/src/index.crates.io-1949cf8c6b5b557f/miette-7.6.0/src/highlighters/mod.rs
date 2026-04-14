//! This module provides a trait for creating custom syntax highlighters that
//! highlight [`Diagnostic`](crate::Diagnostic) source code with ANSI escape
//! sequences when rendering with the [`GraphicalReportHighlighter`](crate::GraphicalReportHandler).
//!
//! It also provides built-in highlighter implementations that you can use out of the box.
//! By default, there are no syntax highlighters exported by miette
//! (except for the no-op [`BlankHighlighter`]).
//! To enable support for specific highlighters, you should enable their associated feature flag.
//!
//! Currently supported syntax highlighters and their feature flags:
//! * `syntect-highlighter` - Enables [`syntect`](https://docs.rs/syntect/latest/syntect/) syntax highlighting support via the [`SyntectHighlighter`]
//!

use std::{ops::Deref, sync::Arc};

use crate::SpanContents;
use owo_colors::Styled;

#[cfg(feature = "syntect-highlighter")]
pub use self::syntect::*;
pub use blank::*;

mod blank;
#[cfg(feature = "syntect-highlighter")]
mod syntect;

/// A syntax highlighter for highlighting miette [`SourceCode`](crate::SourceCode) snippets.
pub trait Highlighter {
    ///  Creates a new [`HighlighterState`] to begin parsing and highlighting
    /// a [`SpanContents`].
    ///
    /// The [`GraphicalReportHandler`](crate::GraphicalReportHandler) will call
    /// this method at the start of rendering a [`SpanContents`].
    ///
    /// The [`SpanContents`] is provided as input only so that the [`Highlighter`]
    /// can detect language syntax and make other initialization decisions prior
    /// to highlighting, but it is not intended that the Highlighter begin
    /// highlighting at this point. The returned [`HighlighterState`] is
    /// responsible for the actual rendering.
    fn start_highlighter_state<'h>(
        &'h self,
        source: &dyn SpanContents<'_>,
    ) -> Box<dyn HighlighterState + 'h>;
}

/// A stateful highlighter that incrementally highlights lines of a particular
/// source code.
///
/// The [`GraphicalReportHandler`](crate::GraphicalReportHandler)
/// will create a highlighter state by calling
/// [`start_highlighter_state`](Highlighter::start_highlighter_state) at the
/// start of rendering, then it will iteratively call
/// [`highlight_line`](HighlighterState::highlight_line) to render individual
/// highlighted lines. This allows [`Highlighter`] implementations to maintain
/// mutable parsing and highlighting state.
pub trait HighlighterState {
    /// Highlight an individual line from the source code by returning a vector of [Styled]
    /// regions.
    fn highlight_line<'s>(&mut self, line: &'s str) -> Vec<Styled<&'s str>>;
}

/// Arcified trait object for Highlighter. Used internally by [`GraphicalReportHandler`]
///
/// Wrapping the trait object in this way allows us to implement `Debug` and `Clone`.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct MietteHighlighter(Arc<dyn Highlighter + Send + Sync>);

impl MietteHighlighter {
    pub(crate) fn nocolor() -> Self {
        Self::from(BlankHighlighter)
    }

    #[cfg(feature = "syntect-highlighter")]
    pub(crate) fn syntect_truecolor() -> Self {
        Self::from(SyntectHighlighter::default())
    }
}

impl Default for MietteHighlighter {
    #[cfg(feature = "syntect-highlighter")]
    fn default() -> Self {
        use std::io::IsTerminal;
        match std::env::var("NO_COLOR") {
            _ if !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal() => {
                //TODO: should use ANSI styling instead of 24-bit truecolor here
                Self(Arc::new(SyntectHighlighter::default()))
            }
            Ok(string) if string != "0" => MietteHighlighter::nocolor(),
            _ => Self(Arc::new(SyntectHighlighter::default())),
        }
    }
    #[cfg(not(feature = "syntect-highlighter"))]
    fn default() -> Self {
        MietteHighlighter::nocolor()
    }
}

impl<T: Highlighter + Send + Sync + 'static> From<T> for MietteHighlighter {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

impl std::fmt::Debug for MietteHighlighter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MietteHighlighter(...)")
    }
}

impl Deref for MietteHighlighter {
    type Target = dyn Highlighter + Send + Sync;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}
