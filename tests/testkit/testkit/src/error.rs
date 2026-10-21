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
