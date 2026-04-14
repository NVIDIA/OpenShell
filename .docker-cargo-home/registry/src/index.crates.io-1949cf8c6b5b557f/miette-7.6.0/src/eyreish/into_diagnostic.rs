use std::{error::Error, fmt::Display};

use crate::{Diagnostic, Report};

/// Convenience [`Diagnostic`] that can be used as an "anonymous" wrapper for
/// Errors. This is intended to be paired with [`IntoDiagnostic`].
#[derive(Debug)]
pub(crate) struct DiagnosticError(pub(crate) Box<dyn std::error::Error + Send + Sync + 'static>);

impl Display for DiagnosticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = &self.0;
        write!(f, "{msg}")
    }
}
impl Error for DiagnosticError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl Diagnostic for DiagnosticError {}

/**
Convenience trait that adds a [`.into_diagnostic()`](IntoDiagnostic::into_diagnostic) method that converts a type implementing
[`std::error::Error`] to a [`Result<T, Report>`].

## Warning

Calling this on a type implementing [`Diagnostic`] will reduce it to the common denominator of
[`std::error::Error`]. Meaning all extra information provided by [`Diagnostic`] will be
inaccessible. If you have a type implementing [`Diagnostic`] consider simply returning it or using
[`Into`] or the [`Try`](std::ops::Try) operator (`?`).
*/
pub trait IntoDiagnostic<T, E> {
    /// Converts [`Result`] types that return regular [`std::error::Error`]s
    /// into a [`Result`] that returns a [`Diagnostic`].
    fn into_diagnostic(self) -> Result<T, Report>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> IntoDiagnostic<T, E> for Result<T, E> {
    fn into_diagnostic(self) -> Result<T, Report> {
        self.map_err(|e| DiagnosticError(Box::new(e)).into())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, ErrorKind};

    use super::*;

    use crate::error::tests::TestError;

    #[test]
    fn diagnostic_error() {
        let inner_error = io::Error::new(ErrorKind::Other, "halt and catch fire");
        let outer_error: Result<(), _> = Err(TestError(inner_error));

        let diagnostic_error = outer_error.into_diagnostic().unwrap_err();

        assert_eq!(diagnostic_error.to_string(), "testing, testing...");
        assert_eq!(
            diagnostic_error.source().unwrap().to_string(),
            "halt and catch fire"
        );
    }
}
