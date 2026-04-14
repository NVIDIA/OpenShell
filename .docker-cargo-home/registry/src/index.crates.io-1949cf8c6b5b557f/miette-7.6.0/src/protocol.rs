/*!
This module defines the core of the miette protocol: a series of types and
traits that you can implement to get access to miette's (and related library's)
full reporting and such features.
*/
use std::{
    fmt::{self, Display},
    fs,
    panic::Location,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{DiagnosticError, MietteError};

/// Adds rich metadata to your Error that can be used by
/// [`Report`](crate::Report) to print really nice and human-friendly error
/// messages.
pub trait Diagnostic: std::error::Error {
    /// Unique diagnostic code that can be used to look up more information
    /// about this `Diagnostic`. Ideally also globally unique, and documented
    /// in the toplevel crate's documentation for easy searching. Rust path
    /// format (`foo::bar::baz`) is recommended, but more classic codes like
    /// `E0123` or enums will work just fine.
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        None
    }

    /// Diagnostic severity. This may be used by
    /// [`ReportHandler`](crate::ReportHandler)s to change the display format
    /// of this diagnostic.
    ///
    /// If `None`, reporters should treat this as [`Severity::Error`].
    fn severity(&self) -> Option<Severity> {
        None
    }

    /// Additional help text related to this `Diagnostic`. Do you have any
    /// advice for the poor soul who's just run into this issue?
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        None
    }

    /// URL to visit for a more detailed explanation/help about this
    /// `Diagnostic`.
    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        None
    }

    /// Source code to apply this `Diagnostic`'s [`Diagnostic::labels`] to.
    fn source_code(&self) -> Option<&dyn SourceCode> {
        None
    }

    /// Labels to apply to this `Diagnostic`'s [`Diagnostic::source_code`]
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        None
    }

    /// Additional related `Diagnostic`s.
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        None
    }

    /// The cause of the error.
    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        None
    }
}

macro_rules! box_error_impls {
    ($($box_type:ty),*) => {
        $(
            impl std::error::Error for $box_type {
                fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                    (**self).source()
                }

                fn cause(&self) -> Option<&dyn std::error::Error> {
                    self.source()
                }
            }
        )*
    }
}

box_error_impls! {
    Box<dyn Diagnostic>,
    Box<dyn Diagnostic + Send>,
    Box<dyn Diagnostic + Send + Sync>
}

macro_rules! box_borrow_impls {
    ($($box_type:ty),*) => {
        $(
            impl std::borrow::Borrow<dyn Diagnostic> for $box_type {
                fn borrow(&self) -> &(dyn Diagnostic + 'static) {
                    self.as_ref()
                }
            }
        )*
    }
}

box_borrow_impls! {
    Box<dyn Diagnostic + Send>,
    Box<dyn Diagnostic + Send + Sync>
}

impl<T: Diagnostic + Send + Sync + 'static> From<T>
    for Box<dyn Diagnostic + Send + Sync + 'static>
{
    fn from(diag: T) -> Self {
        Box::new(diag)
    }
}

impl<T: Diagnostic + Send + Sync + 'static> From<T> for Box<dyn Diagnostic + Send + 'static> {
    fn from(diag: T) -> Self {
        Box::<dyn Diagnostic + Send + Sync>::from(diag)
    }
}

impl<T: Diagnostic + Send + Sync + 'static> From<T> for Box<dyn Diagnostic + 'static> {
    fn from(diag: T) -> Self {
        Box::<dyn Diagnostic + Send + Sync>::from(diag)
    }
}

impl From<&str> for Box<dyn Diagnostic> {
    fn from(s: &str) -> Self {
        From::from(String::from(s))
    }
}

impl From<&str> for Box<dyn Diagnostic + Send + Sync + '_> {
    fn from(s: &str) -> Self {
        From::from(String::from(s))
    }
}

impl From<String> for Box<dyn Diagnostic> {
    fn from(s: String) -> Self {
        let err1: Box<dyn Diagnostic + Send + Sync> = From::from(s);
        let err2: Box<dyn Diagnostic> = err1;
        err2
    }
}

impl From<String> for Box<dyn Diagnostic + Send + Sync> {
    fn from(s: String) -> Self {
        struct StringError(String);

        impl std::error::Error for StringError {}
        impl Diagnostic for StringError {}

        impl Display for StringError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Display::fmt(&self.0, f)
            }
        }

        // Purposefully skip printing "StringError(..)"
        impl fmt::Debug for StringError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.0, f)
            }
        }

        Box::new(StringError(s))
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for Box<dyn Diagnostic + Send + Sync> {
    fn from(s: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Box::new(DiagnosticError(s))
    }
}

/**
[`Diagnostic`] severity. Intended to be used by
[`ReportHandler`](crate::ReportHandler)s to change the way different
[`Diagnostic`]s are displayed. Defaults to [`Severity::Error`].
*/
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default)]
pub enum Severity {
    /// Just some help. Here's how you could be doing it better.
    Advice,
    /// Warning. Please take note.
    Warning,
    /// Critical failure. The program cannot continue.
    /// This is the default severity, if you don't specify another one.
    #[default]
    Error,
}

#[cfg(feature = "serde")]
#[test]
fn test_serialize_severity() {
    use serde_json::json;

    assert_eq!(json!(Severity::Advice), json!("Advice"));
    assert_eq!(json!(Severity::Warning), json!("Warning"));
    assert_eq!(json!(Severity::Error), json!("Error"));
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_severity() {
    use serde_json::json;

    let severity: Severity = serde_json::from_value(json!("Advice")).unwrap();
    assert_eq!(severity, Severity::Advice);

    let severity: Severity = serde_json::from_value(json!("Warning")).unwrap();
    assert_eq!(severity, Severity::Warning);

    let severity: Severity = serde_json::from_value(json!("Error")).unwrap();
    assert_eq!(severity, Severity::Error);
}

/**
Represents readable source code of some sort.

This trait is able to support simple `SourceCode` types like [`String`]s, as
well as more involved types like indexes into centralized `SourceMap`-like
types, file handles, and even network streams.

If you can read it, you can source it, and it's not necessary to read the
whole thing--meaning you should be able to support `SourceCode`s which are
gigabytes or larger in size.
*/
pub trait SourceCode: Send + Sync {
    /// Read the bytes for a specific span from this `SourceCode`, keeping a
    /// certain number of lines before and after the span as context.
    fn read_span<'a>(
        &'a self,
        span: &SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn SpanContents<'a> + 'a>, MietteError>;
}

/// A labeled [`SourceSpan`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LabeledSpan {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    label: Option<String>,
    span: SourceSpan,
    primary: bool,
}

impl LabeledSpan {
    /// Makes a new labeled span.
    pub const fn new(label: Option<String>, offset: ByteOffset, len: usize) -> Self {
        Self {
            label,
            span: SourceSpan::new(SourceOffset(offset), len),
            primary: false,
        }
    }

    /// Makes a new labeled span using an existing span.
    pub fn new_with_span(label: Option<String>, span: impl Into<SourceSpan>) -> Self {
        Self {
            label,
            span: span.into(),
            primary: false,
        }
    }

    /// Makes a new labeled primary span using an existing span.
    pub fn new_primary_with_span(label: Option<String>, span: impl Into<SourceSpan>) -> Self {
        Self {
            label,
            span: span.into(),
            primary: true,
        }
    }

    /// Change the text of the label
    pub fn set_label(&mut self, label: Option<String>) {
        self.label = label;
    }

    /// Makes a new label at specified span
    ///
    /// # Examples
    /// ```
    /// use miette::LabeledSpan;
    ///
    /// let source = "Cpp is the best";
    /// let label = LabeledSpan::at(0..3, "should be Rust");
    /// assert_eq!(
    ///     label,
    ///     LabeledSpan::new(Some("should be Rust".to_string()), 0, 3)
    /// )
    /// ```
    pub fn at(span: impl Into<SourceSpan>, label: impl Into<String>) -> Self {
        Self::new_with_span(Some(label.into()), span)
    }

    /// Makes a new label that points at a specific offset.
    ///
    /// # Examples
    /// ```
    /// use miette::LabeledSpan;
    ///
    /// let source = "(2 + 2";
    /// let label = LabeledSpan::at_offset(4, "expected a closing parenthesis");
    /// assert_eq!(
    ///     label,
    ///     LabeledSpan::new(Some("expected a closing parenthesis".to_string()), 4, 0)
    /// )
    /// ```
    pub fn at_offset(offset: ByteOffset, label: impl Into<String>) -> Self {
        Self::new(Some(label.into()), offset, 0)
    }

    /// Makes a new label without text, that underlines a specific span.
    ///
    /// # Examples
    /// ```
    /// use miette::LabeledSpan;
    ///
    /// let source = "You have an eror here";
    /// let label = LabeledSpan::underline(12..16);
    /// assert_eq!(label, LabeledSpan::new(None, 12, 4))
    /// ```
    pub fn underline(span: impl Into<SourceSpan>) -> Self {
        Self::new_with_span(None, span)
    }

    /// Gets the (optional) label string for this `LabeledSpan`.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns a reference to the inner [`SourceSpan`].
    pub const fn inner(&self) -> &SourceSpan {
        &self.span
    }

    /// Returns the 0-based starting byte offset.
    pub const fn offset(&self) -> usize {
        self.span.offset()
    }

    /// Returns the number of bytes this `LabeledSpan` spans.
    pub const fn len(&self) -> usize {
        self.span.len()
    }

    /// True if this `LabeledSpan` is empty.
    pub const fn is_empty(&self) -> bool {
        self.span.is_empty()
    }

    /// True if this `LabeledSpan` is a primary span.
    pub const fn primary(&self) -> bool {
        self.primary
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_serialize_labeled_span() {
    use serde_json::json;

    assert_eq!(
        json!(LabeledSpan::new(None, 0, 0)),
        json!({
            "span": { "offset": 0, "length": 0, },
            "primary": false,
        })
    );

    assert_eq!(
        json!(LabeledSpan::new(Some("label".to_string()), 0, 0)),
        json!({
            "label": "label",
            "span": { "offset": 0, "length": 0, },
            "primary": false,
        })
    );
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_labeled_span() {
    use serde_json::json;

    let span: LabeledSpan = serde_json::from_value(json!({
        "label": null,
        "span": { "offset": 0, "length": 0, },
        "primary": false,
    }))
    .unwrap();
    assert_eq!(span, LabeledSpan::new(None, 0, 0));

    let span: LabeledSpan = serde_json::from_value(json!({
        "span": { "offset": 0, "length": 0, },
        "primary": false
    }))
    .unwrap();
    assert_eq!(span, LabeledSpan::new(None, 0, 0));

    let span: LabeledSpan = serde_json::from_value(json!({
        "label": "label",
        "span": { "offset": 0, "length": 0, },
        "primary": false
    }))
    .unwrap();
    assert_eq!(span, LabeledSpan::new(Some("label".to_string()), 0, 0));
}

/**
Contents of a [`SourceCode`] covered by [`SourceSpan`].

Includes line and column information to optimize highlight calculations.
*/
pub trait SpanContents<'a> {
    /// Reference to the data inside the associated span, in bytes.
    fn data(&self) -> &'a [u8];
    /// [`SourceSpan`] representing the span covered by this `SpanContents`.
    fn span(&self) -> &SourceSpan;
    /// An optional (file?) name for the container of this `SpanContents`.
    fn name(&self) -> Option<&str> {
        None
    }
    /// The 0-indexed line in the associated [`SourceCode`] where the data
    /// begins.
    fn line(&self) -> usize;
    /// The 0-indexed column in the associated [`SourceCode`] where the data
    /// begins, relative to `line`.
    fn column(&self) -> usize;
    /// Total number of lines covered by this `SpanContents`.
    fn line_count(&self) -> usize;

    /// Optional method. The language name for this source code, if any.
    /// This is used to drive syntax highlighting.
    ///
    /// Examples: Rust, TOML, C
    ///
    fn language(&self) -> Option<&str> {
        None
    }
}

/**
Basic implementation of the [`SpanContents`] trait, for convenience.
*/
#[derive(Clone, Debug)]
pub struct MietteSpanContents<'a> {
    // Data from a [`SourceCode`], in bytes.
    data: &'a [u8],
    // span actually covered by this SpanContents.
    span: SourceSpan,
    // The 0-indexed line where the associated [`SourceSpan`] _starts_.
    line: usize,
    // The 0-indexed column where the associated [`SourceSpan`] _starts_.
    column: usize,
    // Number of line in this snippet.
    line_count: usize,
    // Optional filename
    name: Option<String>,
    // Optional language
    language: Option<String>,
}

impl<'a> MietteSpanContents<'a> {
    /// Make a new [`MietteSpanContents`] object.
    pub const fn new(
        data: &'a [u8],
        span: SourceSpan,
        line: usize,
        column: usize,
        line_count: usize,
    ) -> MietteSpanContents<'a> {
        MietteSpanContents {
            data,
            span,
            line,
            column,
            line_count,
            name: None,
            language: None,
        }
    }

    /// Make a new [`MietteSpanContents`] object, with a name for its 'file'.
    pub const fn new_named(
        name: String,
        data: &'a [u8],
        span: SourceSpan,
        line: usize,
        column: usize,
        line_count: usize,
    ) -> MietteSpanContents<'a> {
        MietteSpanContents {
            data,
            span,
            line,
            column,
            line_count,
            name: Some(name),
            language: None,
        }
    }

    /// Sets the [`language`](SpanContents::language) for syntax highlighting.
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }
}

impl<'a> SpanContents<'a> for MietteSpanContents<'a> {
    fn data(&self) -> &'a [u8] {
        self.data
    }
    fn span(&self) -> &SourceSpan {
        &self.span
    }
    fn line(&self) -> usize {
        self.line
    }
    fn column(&self) -> usize {
        self.column
    }
    fn line_count(&self) -> usize {
        self.line_count
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }
}

/// Span within a [`SourceCode`]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SourceSpan {
    /// The start of the span.
    offset: SourceOffset,
    /// The total length of the span
    length: usize,
}

impl SourceSpan {
    /// Create a new [`SourceSpan`].
    pub const fn new(start: SourceOffset, length: usize) -> Self {
        Self {
            offset: start,
            length,
        }
    }

    /// The absolute offset, in bytes, from the beginning of a [`SourceCode`].
    pub const fn offset(&self) -> usize {
        self.offset.offset()
    }

    /// Total length of the [`SourceSpan`], in bytes.
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Whether this [`SourceSpan`] has a length of zero. It may still be useful
    /// to point to a specific point.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl From<(ByteOffset, usize)> for SourceSpan {
    fn from((start, len): (ByteOffset, usize)) -> Self {
        Self {
            offset: start.into(),
            length: len,
        }
    }
}

impl From<(SourceOffset, usize)> for SourceSpan {
    fn from((start, len): (SourceOffset, usize)) -> Self {
        Self::new(start, len)
    }
}

impl From<std::ops::Range<ByteOffset>> for SourceSpan {
    fn from(range: std::ops::Range<ByteOffset>) -> Self {
        Self {
            offset: range.start.into(),
            length: range.len(),
        }
    }
}

impl From<std::ops::RangeInclusive<ByteOffset>> for SourceSpan {
    /// # Panics
    ///
    /// Panics if the total length of the inclusive range would overflow a
    /// `usize`. This will only occur with the range `0..=usize::MAX`.
    fn from(range: std::ops::RangeInclusive<ByteOffset>) -> Self {
        let (start, end) = range.clone().into_inner();
        Self {
            offset: start.into(),
            length: if range.is_empty() {
                0
            } else {
                // will not overflow because `is_empty() == false` guarantees
                // that `start <= end`
                (end - start)
                    .checked_add(1)
                    .expect("length of inclusive range should fit in a usize")
            },
        }
    }
}

impl From<SourceOffset> for SourceSpan {
    fn from(offset: SourceOffset) -> Self {
        Self { offset, length: 0 }
    }
}

impl From<ByteOffset> for SourceSpan {
    fn from(offset: ByteOffset) -> Self {
        Self {
            offset: offset.into(),
            length: 0,
        }
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_serialize_source_span() {
    use serde_json::json;

    assert_eq!(
        json!(SourceSpan::from(0)),
        json!({ "offset": 0, "length": 0})
    );
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_source_span() {
    use serde_json::json;

    let span: SourceSpan = serde_json::from_value(json!({ "offset": 0, "length": 0})).unwrap();
    assert_eq!(span, SourceSpan::from(0));
}

/**
"Raw" type for the byte offset from the beginning of a [`SourceCode`].
*/
pub type ByteOffset = usize;

/**
Newtype that represents the [`ByteOffset`] from the beginning of a [`SourceCode`]
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SourceOffset(ByteOffset);

impl SourceOffset {
    /// Actual byte offset.
    pub const fn offset(&self) -> ByteOffset {
        self.0
    }

    /// Little utility to help convert 1-based line/column locations into
    /// miette-compatible Spans
    ///
    /// This function is infallible: Giving an out-of-range line/column pair
    /// will return the offset of the last byte in the source.
    pub fn from_location(source: impl AsRef<str>, loc_line: usize, loc_col: usize) -> Self {
        let mut line = 0usize;
        let mut col = 0usize;
        let mut offset = 0usize;
        for char in source.as_ref().chars() {
            if line + 1 >= loc_line && col + 1 >= loc_col {
                break;
            }
            if char == '\n' {
                col = 0;
                line += 1;
            } else {
                col += 1;
            }
            offset += char.len_utf8();
        }

        SourceOffset(offset)
    }

    /// Returns an offset for the _file_ location of wherever this function is
    /// called. If you want to get _that_ caller's location, mark this
    /// function's caller with `#[track_caller]` (and so on and so forth).
    ///
    /// Returns both the filename that was given and the offset of the caller
    /// as a [`SourceOffset`].
    ///
    /// Keep in mind that this fill only work if the file your Rust source
    /// file was compiled from is actually available at that location. If
    /// you're shipping binaries for your application, you'll want to ignore
    /// the Err case or otherwise report it.
    #[track_caller]
    pub fn from_current_location() -> Result<(String, Self), MietteError> {
        let loc = Location::caller();
        Ok((
            loc.file().into(),
            fs::read_to_string(loc.file())
                .map(|txt| Self::from_location(txt, loc.line() as usize, loc.column() as usize))?,
        ))
    }
}

impl From<ByteOffset> for SourceOffset {
    fn from(bytes: ByteOffset) -> Self {
        SourceOffset(bytes)
    }
}

#[test]
fn test_source_offset_from_location() {
    let source = "f\n\noo\r\nbar";

    assert_eq!(SourceOffset::from_location(source, 1, 1).offset(), 0);
    assert_eq!(SourceOffset::from_location(source, 1, 2).offset(), 1);
    assert_eq!(SourceOffset::from_location(source, 2, 1).offset(), 2);
    assert_eq!(SourceOffset::from_location(source, 3, 1).offset(), 3);
    assert_eq!(SourceOffset::from_location(source, 3, 2).offset(), 4);
    assert_eq!(SourceOffset::from_location(source, 3, 3).offset(), 5);
    assert_eq!(SourceOffset::from_location(source, 3, 4).offset(), 6);
    assert_eq!(SourceOffset::from_location(source, 4, 1).offset(), 7);
    assert_eq!(SourceOffset::from_location(source, 4, 2).offset(), 8);
    assert_eq!(SourceOffset::from_location(source, 4, 3).offset(), 9);
    assert_eq!(SourceOffset::from_location(source, 4, 4).offset(), 10);

    // Out-of-range
    assert_eq!(
        SourceOffset::from_location(source, 5, 1).offset(),
        source.len()
    );
}

#[cfg(feature = "serde")]
#[test]
fn test_serialize_source_offset() {
    use serde_json::json;

    assert_eq!(json!(SourceOffset::from(0)), 0);
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_source_offset() {
    let offset: SourceOffset = serde_json::from_str("0").unwrap();
    assert_eq!(offset, SourceOffset::from(0));
}
