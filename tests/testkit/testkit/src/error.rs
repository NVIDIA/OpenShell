// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test failures.

use std::fmt;

use openshell_sdk::SdkError;

/// A test failure: a message with the context it happened in.
#[derive(Debug)]
pub struct Error {
    message: String,
}

/// The result of a test or test step.
pub type Result<T = ()> = std::result::Result<T, Error>;

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn from_display(error: impl fmt::Display) -> Self {
        Self::msg(error.to_string())
    }

    /// An error with its sources, so a wrapper such as tonic's
    /// "transport error" still says what went wrong underneath.
    pub fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        let mut message = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            let cause_message = cause.to_string();
            // Some errors repeat their source's message in their own.
            if !message.ends_with(&cause_message) {
                message = format!("{message}: {cause_message}");
            }
            source = cause.source();
        }
        Self::msg(message)
    }

    #[must_use]
    pub fn context(self, context: impl fmt::Display) -> Self {
        Self::msg(format!("{context}: {}", self.message))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<SdkError> for Error {
    fn from(error: SdkError) -> Self {
        Self::from_error(&error)
    }
}

/// Add context to a failing step.
pub trait ResultExt<T> {
    fn context(self, context: impl fmt::Display) -> Result<T>;
}

impl<T, E: Into<Error>> ResultExt<T> for std::result::Result<T, E> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.map_err(|error| error.into().context(context))
    }
}

/// Fail the test unless `cond` holds.
///
/// ```ignore
/// testkit::ensure!(output.exit_code == 0, "exec exited with {}", output.exit_code);
/// ```
#[macro_export]
macro_rules! ensure {
    ($cond:expr $(,)?) => {
        if !$cond {
            return Err($crate::Error::msg(concat!("condition failed: ", stringify!($cond))));
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err($crate::Error::msg(format!($($arg)+)));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_prefixes_message() {
        let result: Result = Err(Error::msg("boom"));
        let err = result.context("step two").context("test").unwrap_err();
        assert_eq!(err.to_string(), "test: step two: boom");
    }

    #[derive(Debug)]
    struct Wrapper(Option<Box<dyn std::error::Error + 'static>>, &'static str);

    impl fmt::Display for Wrapper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.1)
        }
    }

    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.0.as_deref()
        }
    }

    #[test]
    fn from_error_includes_sources() {
        let refused = Wrapper(None, "connection refused");
        let transport = Wrapper(Some(Box::new(refused)), "transport error");
        assert_eq!(
            Error::from_error(&transport).to_string(),
            "transport error: connection refused"
        );
    }

    #[test]
    fn from_error_skips_repeated_source_messages() {
        let inner = Wrapper(None, "refused");
        let outer = Wrapper(Some(Box::new(inner)), "connect: refused");
        assert_eq!(Error::from_error(&outer).to_string(), "connect: refused");
    }

    #[test]
    fn ensure_returns_error_with_message() {
        fn check(value: i32) -> Result {
            ensure!(value == 1, "value was {value}");
            Ok(())
        }
        assert!(check(1).is_ok());
        assert_eq!(check(2).unwrap_err().to_string(), "value was 2");
    }

    #[test]
    fn ensure_without_message_names_condition() {
        fn check(value: i32) -> Result {
            ensure!(value == 1);
            Ok(())
        }
        assert_eq!(
            check(2).unwrap_err().to_string(),
            "condition failed: value == 1"
        );
    }
}
