use crate::{
    libyml::{emitter, error as libyml},
    modules::path::Path,
};
use serde::{de, ser};
use std::{
    error::Error as StdError,
    fmt::{self, Debug, Display},
    io, result, string,
    sync::Arc,
};

/// Represents a position in the YAML input.
#[derive(Debug)]
pub struct Pos {
    /// The mark representing the position.
    mark: libyml::Mark,
    /// The path to the position.
    path: String,
}

/// The input location where an error occurred.
#[derive(Clone, Copy, Debug)]
pub struct Location {
    /// The byte index of the error.
    index: usize,
    /// The line of the error.
    line: usize,
    /// The column of the error.
    column: usize,
}

impl Location {
    /// Returns the byte index where the error occurred.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the line number where the error occurred.
    pub fn line(&self) -> usize {
        self.line
    }

    /// Returns the column number where the error occurred.
    pub fn column(&self) -> usize {
        self.column
    }

    // This function is intended for internal use only to maintain decoupling with the yaml crate.
    #[doc(hidden)]
    fn from_mark(mark: libyml::Mark) -> Self {
        Location {
            index: mark.index() as usize,
            // `line` and `column` returned from libyml are 0-indexed but all error messages add +1 to this value.
            line: mark.line() as usize + 1,
            column: mark.column() as usize + 1,
        }
    }
}

/// An error that occurred during YAML serialization or deserialization.
///
/// This struct wraps an internal error representation, `ErrorImpl`, and provides methods for
/// accessing the error's location and a shared reference to the internal error.
pub struct Error(Box<ErrorImpl>);

/// Alias for a `Result` with the error type `serde_yml::Error`.
pub type Result<T> = result::Result<T, Error>;

/// The internal representation of an error.
///
/// This enum represents various errors that can occur during YAML serialization or deserialization,
/// including I/O errors, UTF-8 conversion errors, and errors originating from the `libyml` library.
#[derive(Debug)]
pub enum ErrorImpl {
    /// A generic error message with an optional position.
    Message(String, Option<Pos>),
    /// An error originating from the `libyml` library.
    Libyml(libyml::Error),
    /// An I/O error.
    IoError(io::Error),
    /// An error encountered while converting a byte slice to a string using UTF-8 encoding.
    FromUtf8(string::FromUtf8Error),
    /// An error indicating that the end of the YAML stream was reached unexpectedly.
    EndOfStream,
    /// An error indicating that more than one YAML document was encountered.
    MoreThanOneDocument,
    /// An error indicating that the recursion limit was exceeded.
    RecursionLimitExceeded(libyml::Mark),
    /// An error indicating that the repetition limit was exceeded.
    RepetitionLimitExceeded,
    /// An error indicating that byte-based YAML is unsupported.
    BytesUnsupported,
    /// An error indicating that an unknown anchor was encountered.
    UnknownAnchor(libyml::Mark),
    /// An error indicating that serializing a nested enum is not supported.
    SerializeNestedEnum,
    /// An error indicating that a scalar value was encountered in a merge operation.
    ScalarInMerge,
    /// An error indicating that a tagged value was encountered in a merge operation.
    TaggedInMerge,
    /// An error indicating that a scalar value was encountered in a merge element.
    ScalarInMergeElement,
    /// An error indicating that a sequence was encountered in a merge element.
    SequenceInMergeElement,
    /// An error indicating that an empty tag was encountered.
    EmptyTag,
    /// An error indicating that parsing a number failed.
    FailedToParseNumber,
    /// A shared error implementation.
    Shared(Arc<ErrorImpl>),
}

impl Display for ErrorImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorImpl::Message(msg, _) => write!(f, "Error: {}", msg),
            ErrorImpl::Libyml(_) => write!(f, "Error: An error occurred in the Libyml library"),
            ErrorImpl::IoError(err) => write!(f, "I/O Error: {}", err),
            ErrorImpl::FromUtf8(err) => write!(f, "UTF-8 Conversion Error: {}", err),
            ErrorImpl::EndOfStream => write!(f, "Unexpected End of YAML Stream: The YAML stream ended unexpectedly while parsing a value"),
            ErrorImpl::MoreThanOneDocument => write!(f, "Multiple YAML Documents Error: Deserializing from YAML containing more than one document is not supported"),
            ErrorImpl::RecursionLimitExceeded(_) => write!(f, "Recursion Limit Exceeded: The recursive depth limit was exceeded while parsing the YAML"),
            ErrorImpl::RepetitionLimitExceeded => write!(f, "Repetition Limit Exceeded: The repetition limit was exceeded while parsing the YAML"),
            ErrorImpl::BytesUnsupported => write!(f, "Unsupported Bytes Error: Serialization and deserialization of bytes in YAML is not implemented"),
            ErrorImpl::UnknownAnchor(_) => write!(f, "Unknown Anchor Error: An unknown anchor was encountered in the YAML"),
            ErrorImpl::SerializeNestedEnum => write!(f, "Nested Enum Serialization Error: Serializing nested enums in YAML is not supported"),
            ErrorImpl::ScalarInMerge => write!(f, "Invalid Merge Error: Expected a mapping or list of mappings for merging, but found a scalar value"),
            ErrorImpl::TaggedInMerge => write!(f, "Invalid Merge Error: Unexpected tagged value encountered in a merge operation"),
            ErrorImpl::ScalarInMergeElement => write!(f, "Invalid Merge Element Error: Expected a mapping for merging, but found a scalar value"),
            ErrorImpl::SequenceInMergeElement => write!(f, "Invalid Merge Element Error: Expected a mapping for merging, but found a sequence"),
            ErrorImpl::EmptyTag => write!(f, "Empty Tag Error: Empty YAML tags are not allowed"),
            ErrorImpl::FailedToParseNumber => write!(f, "Number Parsing Error: Failed to parse the YAML number"),
            ErrorImpl::Shared(_) => write!(f, "Shared Error: An error occurred in the shared error implementation"),
        }
    }
}

impl Error {
    /// Returns the I/O error that caused this error, if available.
    pub fn io_error(&self) -> Option<&io::Error> {
        if let ErrorImpl::IoError(err) = &*self.0 {
            Some(err)
        } else {
            None
        }
    }

    /// Returns the location where the error occurred, if available.
    pub fn location(&self) -> Option<Location> {
        self.0.location()
    }

    /// Returns a shared reference to the internal error representation.
    ///
    /// This method is useful when you need to share an error between multiple threads or for
    /// other use cases where a shared reference is required.
    pub fn shared(self) -> Arc<ErrorImpl> {
        if let ErrorImpl::Shared(err) = *self.0 {
            err
        } else {
            Arc::from(self.0)
        }
    }
}

/// Creates a new `Error` from the given `ErrorImpl`.
pub fn new(inner: ErrorImpl) -> Error {
    Error(Box::new(inner))
}

/// Creates a new `Error` from a shared `ErrorImpl`.
pub fn shared(shared: Arc<ErrorImpl>) -> Error {
    Error(Box::new(ErrorImpl::Shared(shared)))
}

/// Fixes the mark and path in an error.
pub fn fix_mark(
    mut error: Error,
    mark: libyml::Mark,
    path: Path<'_>,
) -> Error {
    if let ErrorImpl::Message(_, none @ None) = error.0.as_mut() {
        *none = Some(Pos {
            mark,
            path: path.to_string(),
        });
    }
    error
}

impl From<libyml::Error> for Error {
    fn from(err: libyml::Error) -> Self {
        Error(Box::new(ErrorImpl::Libyml(err)))
    }
}

impl From<emitter::Error> for Error {
    fn from(err: emitter::Error) -> Self {
        match err {
            emitter::Error::Libyml(err) => Self::from(err),
            emitter::Error::Io(err) => new(ErrorImpl::IoError(err)),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.0.source()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display(f)
    }
}

// Remove two layers of verbosity from the debug representation. Humans often
// end up seeing this representation because it is what unwrap() shows.
impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.debug(f)
    }
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error(Box::new(ErrorImpl::Message(msg.to_string(), None)))
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error(Box::new(ErrorImpl::Message(msg.to_string(), None)))
    }
}

impl ErrorImpl {
    fn location(&self) -> Option<Location> {
        self.mark().map(Location::from_mark)
    }

    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ErrorImpl::IoError(err) => err.source(),
            ErrorImpl::FromUtf8(err) => err.source(),
            ErrorImpl::Shared(err) => err.source(),
            _ => None,
        }
    }

    fn mark(&self) -> Option<libyml::Mark> {
        match self {
            ErrorImpl::Message(_, Some(Pos { mark, path: _ }))
            | ErrorImpl::RecursionLimitExceeded(mark)
            | ErrorImpl::UnknownAnchor(mark) => Some(*mark),
            ErrorImpl::Libyml(err) => Some(err.mark()),
            ErrorImpl::Shared(err) => err.mark(),
            _ => None,
        }
    }

    fn message(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorImpl::Message(description, None) => f.write_str(description),
            ErrorImpl::Message(description, Some(Pos { mark: _, path })) => {
                if path != "." {
                    write!(f, "{}: ", path)?;
                }
                f.write_str(description)
            }
            ErrorImpl::Libyml(_) => unreachable!(),
            ErrorImpl::IoError(err) => Display::fmt(err, f),
            ErrorImpl::FromUtf8(err) => Display::fmt(err, f),
            ErrorImpl::EndOfStream => f.write_str("EOF while parsing a value"),
            ErrorImpl::MoreThanOneDocument => f.write_str(
                "deserializing from YAML containing more than one document is not supported",
            ),
            ErrorImpl::RecursionLimitExceeded(_mark) => {
                f.write_str("recursion limit exceeded")
            }
            ErrorImpl::RepetitionLimitExceeded => {
                f.write_str("repetition limit exceeded")
            }
            ErrorImpl::BytesUnsupported => {
                f.write_str("serialization and deserialization of bytes in YAML is not implemented")
            }
            ErrorImpl::UnknownAnchor(_mark) => f.write_str("unknown anchor"),
            ErrorImpl::SerializeNestedEnum => {
                f.write_str("serializing nested enums in YAML is not supported yet")
            }
            ErrorImpl::ScalarInMerge => {
                f.write_str("expected a mapping or list of mappings for merging, but found scalar")
            }
            ErrorImpl::TaggedInMerge => {
                f.write_str("unexpected tagged value in merge")
            }
            ErrorImpl::ScalarInMergeElement => {
                f.write_str("expected a mapping for merging, but found scalar")
            }
            ErrorImpl::SequenceInMergeElement => {
                f.write_str("expected a mapping for merging, but found sequence")
            }
            ErrorImpl::EmptyTag => f.write_str("empty YAML tag is not allowed"),
            ErrorImpl::FailedToParseNumber => {
                f.write_str("failed to parse YAML number")
            }
            ErrorImpl::Shared(_) => unreachable!(),
        }
    }

    fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorImpl::Libyml(err) => Display::fmt(err, f),
            ErrorImpl::Shared(err) => err.display(f),
            _ => {
                self.message(f)?;
                if let Some(location) = self.mark() {
                    if location.line() != 0 || location.column() != 0 {
                        write!(f, " at {}", location)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorImpl::Libyml(err) => Debug::fmt(err, f),
            ErrorImpl::Shared(err) => err.debug(f),
            _ => {
                f.write_str("Error(")?;
                struct MessageNoMark<'a>(&'a ErrorImpl);
                impl Display for MessageNoMark<'_> {
                    fn fmt(
                        &self,
                        f: &mut fmt::Formatter<'_>,
                    ) -> fmt::Result {
                        self.0.message(f)
                    }
                }
                let msg = MessageNoMark(self).to_string();
                Debug::fmt(&msg, f)?;
                if let Some(mark) = self.mark() {
                    write!(
                        f,
                        ", line: {}, column: {}",
                        mark.line() + 1,
                        mark.column() + 1,
                    )?;
                }
                f.write_str(")")
            }
        }
    }
}
