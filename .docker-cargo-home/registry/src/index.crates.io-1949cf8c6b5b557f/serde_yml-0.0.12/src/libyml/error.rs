use crate::libyml::safe_cstr::CStr;
#[allow(clippy::unsafe_removed_from_name)]
use libyml as sys;
use std::{
    fmt::{self, Debug, Display},
    mem::MaybeUninit,
    ptr::NonNull,
};

/// A type alias for a `Result` with an `Error` as the error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Represents an error that occurred during YAML processing.
#[derive(Clone, Copy)]
pub struct Error {
    /// The kind of error that occurred.
    ///
    /// This field uses the `yaml_error_type_t` type from the `libyml` crate,
    /// which represents different types of errors.
    pub kind: sys::YamlErrorTypeT,

    /// A null-terminated string describing the problem that caused the error.
    ///
    /// The `CStr<'static>` type represents a borrowed C-style string with a static lifetime.
    pub problem: CStr<'static>,

    /// The offset of the problem that caused the error.
    pub problem_offset: u64,

    /// The mark indicating the position of the problem that caused the error.
    ///
    /// The `Mark` type represents a position in the YAML input.
    pub problem_mark: Mark,

    /// An optional null-terminated string providing additional context for the error.
    ///
    /// The `CStr<'static>` type represents a borrowed C-style string with a static lifetime.
    pub context: Option<CStr<'static>>,

    /// The mark indicating the position of the context related to the error.
    ///
    /// The `Mark` type represents a position in the YAML input.
    pub context_mark: Mark,
}

impl Error {
    /// Constructs an `Error` from a `YamlParserT` pointer.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences raw pointers and assumes
    /// the validity of the `YamlParserT` pointer.
    pub unsafe fn parse_error(parser: *const sys::YamlParserT) -> Self {
        Error {
            kind: unsafe { (*parser).error },
            problem: match NonNull::new(unsafe {
                (*parser).problem as *mut _
            }) {
                Some(problem) => CStr::from_ptr(problem),
                None => CStr::from_bytes_with_nul(
                    b"libyml parser failed but there is no error\0",
                )
                .expect("Error creating CStr from bytes"),
            },
            problem_offset: unsafe { (*parser).problem_offset },
            problem_mark: Mark {
                sys: unsafe { (*parser).problem_mark },
            },
            #[allow(clippy::manual_map)]
            context: match NonNull::new(unsafe {
                (*parser).context as *mut _
            }) {
                Some(context) => Some(CStr::from_ptr(context)),
                None => None,
            },
            context_mark: Mark {
                sys: unsafe { (*parser).context_mark },
            },
        }
    }

    /// Constructs an `Error` from a `YamlEmitterT` pointer.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences raw pointers and assumes
    /// the validity of the `YamlEmitterT` pointer.
    pub unsafe fn emit_error(
        emitter: *const sys::YamlEmitterT,
    ) -> Self {
        Error {
            kind: unsafe { (*emitter).error },
            problem: match NonNull::new(unsafe {
                (*emitter).problem as *mut _
            }) {
                Some(problem) => CStr::from_ptr(problem),
                None => CStr::from_bytes_with_nul(
                    b"libyml emitter failed but there is no error\0",
                )
                .expect("Error creating CStr from bytes"),
            },
            problem_offset: 0,
            problem_mark: Mark {
                sys: unsafe {
                    MaybeUninit::<sys::YamlMarkT>::zeroed()
                        .assume_init()
                },
            },
            context: None,
            context_mark: Mark {
                sys: unsafe {
                    MaybeUninit::<sys::YamlMarkT>::zeroed()
                        .assume_init()
                },
            },
        }
    }

    /// Returns the mark indicating the position of the problem that caused the error.
    pub fn mark(&self) -> Mark {
        self.problem_mark
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.problem)?;
        if self.problem_mark.sys.line != 0
            || self.problem_mark.sys.column != 0
        {
            write!(formatter, " at {}", self.problem_mark)?;
        } else if self.problem_offset != 0 {
            write!(formatter, " at position {}", self.problem_offset)?;
        }
        if let Some(context) = &self.context {
            write!(formatter, ", {}", context)?;
            if (self.context_mark.sys.line != 0
                || self.context_mark.sys.column != 0)
                && (self.context_mark.sys.line
                    != self.problem_mark.sys.line
                    || self.context_mark.sys.column
                        != self.problem_mark.sys.column)
            {
                write!(formatter, " at {}", self.context_mark)?;
            }
        }
        Ok(())
    }
}

impl Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut formatter = formatter.debug_struct("Error");
        if let Some(kind) = match self.kind {
            sys::YamlMemoryError => Some("MEMORY"),
            sys::YamlReaderError => Some("READER"),
            sys::YamlScannerError => Some("SCANNER"),
            sys::YamlParserError => Some("PARSER"),
            sys::YamlComposerError => Some("COMPOSER"),
            sys::YamlWriterError => Some("WRITER"),
            sys::YamlEmitterError => Some("EMITTER"),
            _ => None,
        } {
            formatter.field("kind", &format_args!("{}", kind));
        }
        formatter.field("problem", &self.problem);
        if self.problem_mark.sys.line != 0
            || self.problem_mark.sys.column != 0
        {
            formatter.field("problem_mark", &self.problem_mark);
        } else if self.problem_offset != 0 {
            formatter.field("problem_offset", &self.problem_offset);
        }
        if let Some(context) = &self.context {
            formatter.field("context", context);
            if self.context_mark.sys.line != 0
                || self.context_mark.sys.column != 0
            {
                formatter.field("context_mark", &self.context_mark);
            }
        }
        formatter.finish()
    }
}

/// Represents a mark in a YAML document.
/// A mark indicates a specific position or location within the document.
#[derive(Copy, Clone)]
pub struct Mark {
    /// The underlying system representation of the mark.
    ///
    /// This field is marked as `pub(super)`, which means it is accessible within the current module
    /// and its parent module, but not from outside the crate.
    pub sys: sys::YamlMarkT,
}

impl Mark {
    /// Retrieves the index of the mark.
    ///
    /// The index represents the position of the mark within the YAML input.
    ///
    /// # Returns
    ///
    /// Returns the index of the mark as a `u64`.
    pub fn index(&self) -> u64 {
        self.sys.index
    }

    /// Retrieves the line number of the mark.
    ///
    /// The line number indicates the line in the YAML input where the mark is located.
    ///
    /// # Returns
    ///
    /// Returns the line number of the mark as a `u64`.
    pub fn line(&self) -> u64 {
        self.sys.line
    }

    /// Retrieves the column number of the mark.
    ///
    /// The column number indicates the column within the line where the mark is located.
    ///
    /// # Returns
    ///
    /// Returns the column number of the mark as a `u64`.
    pub fn column(&self) -> u64 {
        self.sys.column
    }
}

impl Display for Mark {
    /// Formats the mark for display purposes.
    ///
    /// If the line and column numbers are non-zero, the mark is formatted as "line X column Y".
    /// Otherwise, the mark is formatted as "position Z", where Z is the index.
    ///
    /// # Arguments
    ///
    /// * `formatter` - The formatter to write the display output to.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the formatting was successful, or an error otherwise.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sys.line != 0 || self.sys.column != 0 {
            write!(
                formatter,
                "line {} column {}",
                self.sys.line + 1,
                self.sys.column + 1,
            )
        } else {
            write!(formatter, "position {}", self.sys.index)
        }
    }
}

impl Debug for Mark {
    /// Formats the mark for debugging purposes.
    ///
    /// The mark is formatted as a debug struct with either the line and column numbers
    /// or the index, depending on their values.
    ///
    /// # Arguments
    ///
    /// * `formatter` - The formatter to write the debug output to.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the formatting was successful, or an error otherwise.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut formatter = formatter.debug_struct("Mark");
        if self.sys.line != 0 || self.sys.column != 0 {
            formatter.field("line", &(self.sys.line + 1));
            formatter.field("column", &(self.sys.column + 1));
        } else {
            formatter.field("index", &self.sys.index);
        }
        formatter.finish()
    }
}
