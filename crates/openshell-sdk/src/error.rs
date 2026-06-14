// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SDK error type. Surfaces a discriminable variant set so consumers (CLI,
//! TUI, language bindings) can decide how to render or remap each kind.

use miette::Diagnostic;
use thiserror::Error;

/// SDK result type alias.
pub type Result<T> = std::result::Result<T, SdkError>;

/// Errors produced by `openshell-sdk`.
///
/// CLI consumers convert these to `miette::Report` at the call boundary;
/// future TS/Python bindings will map them to language-native exceptions
/// via the [`SdkError::code`] accessor.
#[derive(Debug, Error, Diagnostic)]
pub enum SdkError {
    /// Caller-supplied configuration is invalid (URL parse, missing field,
    /// illegal token characters).
    #[error("invalid configuration: {message}")]
    #[diagnostic(code(openshell::sdk::invalid_config))]
    InvalidConfig {
        /// Error message.
        message: String,
    },

    /// TLS material parse or rustls config build failure.
    #[error("TLS error: {message}")]
    #[diagnostic(code(openshell::sdk::tls))]
    Tls {
        /// Error message.
        message: String,
    },

    /// Failed to establish a connection to the gateway (TCP, TLS handshake,
    /// HTTP/2, WebSocket upgrade).
    #[error("connect error: {message}")]
    #[diagnostic(code(openshell::sdk::connect))]
    Connect {
        /// Error message.
        message: String,
    },

    /// Auth-related failure: OIDC discovery / refresh, token format invalid
    /// for header injection.
    #[error("auth error: {message}")]
    #[diagnostic(code(openshell::sdk::auth))]
    Auth {
        /// Error message.
        message: String,
    },

    /// Local IO failure (file read, listener bind, socket).
    #[error("I/O error: {source}")]
    #[diagnostic(code(openshell::sdk::io))]
    Io {
        /// Underlying I/O error.
        #[from]
        source: std::io::Error,
    },

    /// Gateway reported the requested object does not exist (gRPC `NotFound`).
    #[error("not found: {message}")]
    #[diagnostic(code(openshell::sdk::not_found))]
    NotFound {
        /// Error message.
        message: String,
    },

    /// Gateway reported the requested object already exists (gRPC `AlreadyExists`).
    #[error("already exists: {message}")]
    #[diagnostic(code(openshell::sdk::already_exists))]
    AlreadyExists {
        /// Error message.
        message: String,
    },

    /// Catch-all for gRPC errors not mapped to a more specific variant.
    #[error("gateway error ({code}): {message}")]
    #[diagnostic(code(openshell::sdk::rpc))]
    Rpc {
        /// Numeric gRPC status code (see [`tonic::Code`]).
        code: i32,
        /// Error message.
        message: String,
    },
}

impl SdkError {
    /// Create an `InvalidConfig` error.
    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            message: message.into(),
        }
    }

    /// Create a `Tls` error.
    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls {
            message: message.into(),
        }
    }

    /// Create a `Connect` error.
    pub fn connect(message: impl Into<String>) -> Self {
        Self::Connect {
            message: message.into(),
        }
    }

    /// Create an `Auth` error.
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth {
            message: message.into(),
        }
    }

    /// Stable string code for cross-language binding consumers.
    ///
    /// Returns one of: `invalid_config`, `tls`, `connect`, `auth`, `io`,
    /// `not_found`, `already_exists`, `rpc`. Phase 3 (napi binding) will
    /// surface this as the JS error's `code` field for discriminated-union
    /// ergonomics.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "invalid_config",
            Self::Tls { .. } => "tls",
            Self::Connect { .. } => "connect",
            Self::Auth { .. } => "auth",
            Self::Io { .. } => "io",
            Self::NotFound { .. } => "not_found",
            Self::AlreadyExists { .. } => "already_exists",
            Self::Rpc { .. } => "rpc",
        }
    }
}
