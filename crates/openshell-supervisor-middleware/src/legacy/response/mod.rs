// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy HTTP response protocol (0.1). Removed in 0.2.0.
//!
//! Legacy response entries run as [`adapter::LegacyResponseStage`]s on the
//! response stage pipeline. They report their 0.1.x invocation records as
//! [`HttpResponseInvocation`]s.

pub mod adapter;
mod validation;

use crate::ContractFailureKind;

/// Largest legacy body unit a stage exchanges.
pub const MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES: usize = 64 * 1024;
/// 0.1.x bound on the body bytes a response retained. A legacy stream stage
/// that holds its output until the body ends keeps to it.
pub const MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// What one step of a legacy response stage did, as 0.1.x recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpResponseInvocationOutcome {
    Skip,
    BlockDelivery,
    HeadersOnly,
    WholeBody,
    Stream,
    Trailers,
    PassThrough,
    Transform,
    SkipRemaining,
    FailOpen,
    FailClosed,
}

/// One 0.1.x invocation record of a legacy response stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: HttpResponseInvocationOutcome,
    pub sequence: Option<u64>,
    pub input_size: usize,
    pub output_size: Option<usize>,
    pub failed: bool,
    pub stage_disabled: bool,
    pub reason_code: Option<String>,
    pub failure_category: Option<String>,
}

/// Category of a failure reason, as 0.1.x reported a failed response stage
/// in its invocation records and `fail_open` findings.
pub fn failure_category(reason: &str) -> &'static str {
    if ContractFailureKind::from_reason(reason).is_some() {
        "contract_failure"
    } else if reason == "middleware_session_capacity_exhausted" {
        "session_capacity"
    } else if reason.contains("over_capacity") {
        "payload_capacity"
    } else if reason.contains("timeout") {
        "timeout"
    } else if reason.contains("stream_closed")
        || reason.contains("stream closed")
        || reason.contains("transport")
        || reason.contains("unavailable")
    {
        "transport"
    } else if matches!(
        reason,
        "bodyless_response"
            | "response_input_unrepresentable"
            | "partial_response"
            | "content_coding_not_identity"
            | "cache_control_no_transform"
    ) {
        "response_not_inspectable"
    } else {
        "invalid_result"
    }
}
