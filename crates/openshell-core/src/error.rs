// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common error types for `OpenShell`.

use miette::Diagnostic;
use thiserror::Error;

/// Result type alias using `OpenShell`'s error type.
pub type Result<T> = std::result::Result<T, Error>;

/// `OpenShell` error type.
#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    /// Configuration error.
    #[error("configuration error: {message}")]
    #[diagnostic(code(openshell::config))]
    Config {
        /// Error message.
        message: String,
    },

    /// I/O error.
    #[error("I/O error: {source}")]
    #[diagnostic(code(openshell::io))]
    Io {
        /// Underlying I/O error.
        #[from]
        source: std::io::Error,
    },

    /// TLS error.
    #[error("TLS error: {message}")]
    #[diagnostic(code(openshell::tls))]
    Tls {
        /// Error message.
        message: String,
    },

    /// gRPC transport error.
    #[error("transport error: {message}")]
    #[diagnostic(code(openshell::transport))]
    Transport {
        /// Error message.
        message: String,
    },

    /// Execution error.
    #[error("execution error: {message}")]
    #[diagnostic(code(openshell::execution))]
    Execution {
        /// Error message.
        message: String,
    },

    /// Process error.
    #[error("process error: {message}")]
    #[diagnostic(code(openshell::process))]
    Process {
        /// Error message.
        message: String,
    },

    /// Timeout error.
    #[error("operation timed out")]
    #[diagnostic(code(openshell::timeout))]
    Timeout,
}

impl Error {
    /// Create a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Create a TLS error.
    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls {
            message: message.into(),
        }
    }

    /// Create a transport error.
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
        }
    }

    /// Create an execution error.
    pub fn execution(message: impl Into<String>) -> Self {
        Self::Execution {
            message: message.into(),
        }
    }

    /// Create a process error.
    pub fn process(message: impl Into<String>) -> Self {
        Self::Process {
            message: message.into(),
        }
    }
}

/// Error type shared by all compute driver implementations.
///
/// Drivers map backend-specific errors into these variants before crossing
/// crate boundaries.
#[derive(Debug, Error)]
pub enum ComputeDriverError {
    /// The requested sandbox already exists.
    #[error("sandbox already exists")]
    AlreadyExists,
    /// The requested sandbox does not exist.
    #[error("sandbox not found")]
    NotFound,
    /// The request contains an invalid argument.
    #[error("{0}")]
    InvalidArgument(String),
    /// A precondition for the operation was not met.
    #[error("{0}")]
    Precondition(String),
    /// Generic error message.
    #[error("{0}")]
    Message(String),
}

impl From<ComputeDriverError> for tonic::Status {
    fn from(err: ComputeDriverError) -> Self {
        match err {
            ComputeDriverError::AlreadyExists => Self::already_exists("sandbox already exists"),
            ComputeDriverError::NotFound => Self::not_found("sandbox not found"),
            ComputeDriverError::InvalidArgument(m) => Self::invalid_argument(m),
            ComputeDriverError::Precondition(m) => Self::failed_precondition(m),
            ComputeDriverError::Message(m) => Self::internal(m),
        }
    }
}

/// Stable marker embedded in the gateway's rejection of relay-backed RPCs for
/// sandboxes whose topology has no in-sandbox process supervisor.
///
/// SSH, `exec`, port forwarding, and file transfer all travel over the
/// supervisor session, which such a topology never opens. The CLI matches on
/// this marker to explain the situation rather than surfacing a raw gRPC
/// error, so callers must keep the two in sync. It is deliberately a distinct
/// token rather than prose so rewording the message cannot break detection.
pub const NO_SUPERVISOR_SESSION_MARKER: &str = "openshell:no-supervisor-session";

/// Full message returned for relay-backed RPCs against such a sandbox.
#[must_use]
pub fn no_supervisor_session_message() -> String {
    format!(
        "this sandbox's topology runs no supervisor inside the sandbox, so SSH, exec, port \
         forwarding, and file transfer are unavailable. Policy-enforced network egress is \
         unaffected. Use the `combined`, `sidecar`, or `cni-sidecar` topology when interactive \
         sessions are required. [{NO_SUPERVISOR_SESSION_MARKER}]"
    )
}
