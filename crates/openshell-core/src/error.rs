// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common error types for OpenShell.

use miette::Diagnostic;
use thiserror::Error;

/// Result type alias using OpenShell's error type.
pub type Result<T> = std::result::Result<T, Error>;

/// OpenShell error type.
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
/// Both the Podman and Kubernetes drivers map their backend-specific
/// errors into these variants before crossing crate boundaries.
#[derive(Debug, Error)]
pub enum ComputeDriverError {
    /// The requested sandbox already exists.
    #[error("sandbox already exists")]
    AlreadyExists,
    /// A precondition for the operation was not met.
    #[error("{0}")]
    Precondition(String),
    /// Generic error message.
    #[error("{0}")]
    Message(String),
}
