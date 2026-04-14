use std::{
    error::Error,
    fmt::{self, Display},
    io,
};

use crate::Diagnostic;

/**
Error enum for miette. Used by certain operations in the protocol.
*/
#[derive(Debug)]
pub enum MietteError {
    /// Wrapper around [`std::io::Error`]. This is returned when something went
    /// wrong while reading a [`SourceCode`](crate::SourceCode).
    IoError(io::Error),

    /// Returned when a [`SourceSpan`](crate::SourceSpan) extends beyond the
    /// bounds of a given [`SourceCode`](crate::SourceCode).
    OutOfBounds,
}

impl Display for MietteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MietteError::IoError(error) => write!(f, "{error}"),
            MietteError::OutOfBounds => {
                write!(f, "The given offset is outside the bounds of its Source")
            }
        }
    }
}

impl Error for MietteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            MietteError::IoError(error) => error.source(),
            MietteError::OutOfBounds => None,
        }
    }
}

impl From<io::Error> for MietteError {
    fn from(value: io::Error) -> Self {
        Self::IoError(value)
    }
}

impl Diagnostic for MietteError {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            MietteError::IoError(_) => Some(Box::new("miette::io_error")),
            MietteError::OutOfBounds => Some(Box::new("miette::span_out_of_bounds")),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            MietteError::IoError(_) => None,
            MietteError::OutOfBounds => Some(Box::new(
                "Double-check your spans. Do you have an off-by-one error?",
            )),
        }
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        let crate_version = env!("CARGO_PKG_VERSION");
        let variant = match self {
            MietteError::IoError(_) => "#variant.IoError",
            MietteError::OutOfBounds => "#variant.OutOfBounds",
        };
        Some(Box::new(format!(
            "https://docs.rs/miette/{}/miette/enum.MietteError.html{}",
            crate_version, variant,
        )))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{error::Error, io::ErrorKind};

    use super::*;

    #[derive(Debug)]
    pub(crate) struct TestError(pub(crate) io::Error);

    impl Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "testing, testing...")
        }
    }

    impl Error for TestError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn io_error() {
        let inner_error = io::Error::new(ErrorKind::Other, "halt and catch fire");
        let outer_error = TestError(inner_error);
        let io_error = io::Error::new(ErrorKind::Other, outer_error);

        let miette_error = MietteError::from(io_error);

        assert_eq!(miette_error.to_string(), "testing, testing...");
        assert_eq!(
            miette_error.source().unwrap().to_string(),
            "halt and catch fire"
        );
    }

    #[test]
    fn out_of_bounds() {
        let miette_error = MietteError::OutOfBounds;

        assert_eq!(
            miette_error.to_string(),
            "The given offset is outside the bounds of its Source"
        );
        assert_eq!(miette_error.source().map(ToString::to_string), None);
    }
}
