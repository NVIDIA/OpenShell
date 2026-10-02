// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform-owned failure causes, independent of service diagnostic text.

/// Retains why HTTP request processing failed across middleware and relay layers.
///
/// Explicit policy denials have no failure kind. Remote status codes are retained
/// without status messages or metadata, which may contain workload data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRequestFailureKind {
    StageTimeout,
    ChainTimeout,
    RequestBodyTimeout,
    RemoteStatus(tonic::Code),
    Unavailable,
    InvalidResult,
    Capacity,
    HeaderMutation,
    Io,
    Cancelled,
    PolicyEvaluation,
}

impl HttpRequestFailureKind {
    /// Returns a fixed category safe for operator diagnostics and span attributes.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::StageTimeout | Self::ChainTimeout | Self::RequestBodyTimeout => "timeout",
            Self::RemoteStatus(_) => "remote_status",
            Self::Unavailable => "unavailable",
            Self::InvalidResult => "protocol",
            Self::Capacity => "capacity",
            Self::HeaderMutation => "header_mutation",
            Self::Io => "io",
            Self::Cancelled => "cancelled",
            Self::PolicyEvaluation => "policy_evaluation",
        }
    }

    /// Identifies the platform deadline; a remote DEADLINE_EXCEEDED is a status.
    #[must_use]
    pub const fn deadline_scope(self) -> Option<&'static str> {
        match self {
            Self::StageTimeout => Some("stage"),
            Self::ChainTimeout => Some("chain"),
            Self::RequestBodyTimeout => Some("request_body"),
            _ => None,
        }
    }
}

impl std::fmt::Display for HttpRequestFailureKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for HttpRequestFailureKind {}
