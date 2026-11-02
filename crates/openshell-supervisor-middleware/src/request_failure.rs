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
    WholeBodyTimeout,
    StreamIdleTimeout,
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
    pub(crate) fn of_platform_reason(reason: &str) -> Self {
        match reason {
            "middleware_timeout" => Self::StageTimeout,
            "middleware_chain_timeout" => Self::ChainTimeout,
            "middleware_body_timeout" => Self::WholeBodyTimeout,
            "middleware_stall_timeout" => Self::StreamIdleTimeout,
            "binding_not_described" => Self::Unavailable,
            "head_input_over_capacity"
            | "buffered_input_over_capacity"
            | "buffered_output_over_capacity"
            | "request_output_over_capacity"
            | "session_capacity_exhausted"
            | "diagnostics_reason_over_capacity"
            | "diagnostics_findings_over_capacity"
            | "diagnostics_metadata_over_capacity"
            | "request_body_over_capacity"
            | "request_config_over_capacity"
            | "request_context_over_capacity"
            | "request_target_over_capacity"
            | "request_header_count_over_capacity"
            | "request_header_bytes_over_capacity"
            | "response_body_over_capacity"
            | "response_reason_over_capacity"
            | "header_mutation_count_over_capacity"
            | "header_mutation_bytes_over_capacity"
            | "response_findings_over_capacity"
            | "response_finding_over_capacity"
            | "response_metadata_count_over_capacity"
            | "response_metadata_bytes_over_capacity"
            | "response_envelope_over_capacity" => Self::Capacity,
            "middleware_stream_closed" | "middleware_result_stream_closed" => Self::Io,
            _ => Self::InvalidResult,
        }
    }

    /// Returns a fixed category safe for operator diagnostics and span attributes.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::StageTimeout
            | Self::ChainTimeout
            | Self::RequestBodyTimeout
            | Self::WholeBodyTimeout
            | Self::StreamIdleTimeout => "timeout",
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

    /// Identifies the platform deadline; a remote `DEADLINE_EXCEEDED` is a status.
    #[must_use]
    pub const fn deadline_scope(self) -> Option<&'static str> {
        match self {
            Self::StageTimeout => Some("stage"),
            Self::ChainTimeout => Some("chain"),
            Self::RequestBodyTimeout => Some("request_body"),
            Self::WholeBodyTimeout => Some("whole_body"),
            Self::StreamIdleTimeout => Some("stream_idle"),
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
