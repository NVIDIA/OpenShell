// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy HTTP response protocol (0.1). Removed in 0.2.0.
//!
//! Validation of legacy response results, and the 0.1.x body-mode offer.

use openshell_core::proto::{
    Finding, HttpHeader, HttpResponseBodyMode, HttpResponseBodyPassThrough,
    HttpResponseEventResult, http_response_body_result, http_response_body_skip_remaining,
    http_response_body_transform, http_response_event_result,
};
use prost::Message as _;

use crate::response::{HttpResponsePreflightInput, body_restriction, is_open_ended};
use crate::{
    DescribedChainEntry, MAX_MIDDLEWARE_FINDING_BYTES, MAX_MIDDLEWARE_FINDINGS_PER_STAGE,
    MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES, MAX_MIDDLEWARE_METADATA_BYTES,
    MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_REASON_BYTES, MAX_MIDDLEWARE_REASON_CODE_BYTES,
    headers, is_stable_reason_code, is_stale_http_response_integrity_header,
};

/// Body lifecycle a legacy stage selected at preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StageMode {
    HeadersOnly,
    WholeBody,
    Stream,
}

pub(super) enum BodyAction {
    PassThrough,
    Transform(Vec<u8>),
    BlockDelivery,
    SkipRemaining(CurrentBodyAction),
}

pub(super) enum CurrentBodyAction {
    PassThrough,
    Transform(Vec<u8>),
}

pub(super) struct BodyDecision {
    pub(super) action: BodyAction,
    pub(super) reason_code: String,
    pub(super) findings: Vec<Finding>,
    pub(super) metadata: std::collections::HashMap<String, String>,
}

pub(super) struct TrailersDecision {
    pub(super) headers: Vec<HttpHeader>,
    pub(super) reason_code: String,
    pub(super) findings: Vec<Finding>,
    pub(super) metadata: std::collections::HashMap<String, String>,
}

pub(super) fn validate_trailers_result(
    result: HttpResponseEventResult,
    trailers: &[HttpHeader],
    entry: &DescribedChainEntry,
    connection_nominated_headers: &[String],
) -> Result<TrailersDecision, String> {
    let Some(http_response_event_result::Result::TrailersResult(result)) = result.result else {
        return Err("unexpected_response_result".into());
    };
    validate_diagnostics(
        &result.reason,
        &result.reason_code,
        &result.findings,
        &result.metadata,
    )
    .map_err(str::to_string)?;
    if result.trailer_mutations.len() > headers::MAX_HEADER_MUTATIONS {
        return Err("header_mutation_count_over_capacity".into());
    }
    let encoded_mutations = result
        .trailer_mutations
        .iter()
        .fold(0usize, |total, mutation| {
            total.saturating_add(mutation.encoded_len())
        });
    if encoded_mutations > MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES {
        return Err("header_mutation_bytes_over_capacity".into());
    }
    let headers = headers::apply(
        headers::HeaderAuthority::ResponseTrailers,
        trailers,
        connection_nominated_headers,
        &result.trailer_mutations,
    )
    .map_err(|error| {
        entry.service.as_ref().map_or_else(
            || error.to_string(),
            |service| {
                service
                    .diagnostic_policy
                    .header_mutation_error_reason(&error)
            },
        )
    })?;
    Ok(TrailersDecision {
        headers,
        reason_code: result.reason_code,
        findings: result.findings,
        metadata: result.metadata,
    })
}

pub(super) fn encoded_header_bytes(headers: &[HttpHeader]) -> usize {
    headers.iter().fold(0usize, |total, header| {
        total.saturating_add(header.encoded_len())
    })
}

pub(super) fn validate_body_result(
    result: HttpResponseEventResult,
    sequence: u64,
    max_payload_bytes: usize,
) -> Result<BodyDecision, &'static str> {
    let Some(http_response_event_result::Result::BodyResult(body)) = result.result else {
        return Err("unexpected_response_result");
    };
    if body.sequence != sequence {
        return Err("response_body_sequence_mismatch");
    }
    validate_diagnostics(
        &body.reason,
        &body.reason_code,
        &body.findings,
        &body.metadata,
    )?;
    let action = match body.action {
        Some(http_response_body_result::Action::PassThrough(HttpResponseBodyPassThrough {})) => {
            BodyAction::PassThrough
        }
        Some(http_response_body_result::Action::Transform(transform)) => BodyAction::Transform(
            validate_replacement(transform.replacement, max_payload_bytes)?,
        ),
        Some(http_response_body_result::Action::BlockDelivery(_)) => BodyAction::BlockDelivery,
        Some(http_response_body_result::Action::SkipRemaining(skip)) => {
            let current = match skip.current {
                Some(http_response_body_skip_remaining::Current::PassThrough(
                    HttpResponseBodyPassThrough {},
                )) => CurrentBodyAction::PassThrough,
                Some(http_response_body_skip_remaining::Current::Transform(transform)) => {
                    CurrentBodyAction::Transform(validate_replacement(
                        transform.replacement,
                        max_payload_bytes,
                    )?)
                }
                None => return Err("invalid_response_body_skip_remaining_action"),
            };
            BodyAction::SkipRemaining(current)
        }
        None => return Err("invalid_response_body_decision"),
    };
    Ok(BodyDecision {
        action,
        reason_code: body.reason_code,
        findings: body.findings,
        metadata: body.metadata,
    })
}

fn validate_replacement(
    replacement: Option<http_response_body_transform::Replacement>,
    max_payload_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    let Some(http_response_body_transform::Replacement::Data(replacement)) = replacement else {
        return Err("response_body_replacement_missing");
    };
    if replacement.len() > max_payload_bytes {
        return Err("response_body_replacement_over_capacity");
    }
    Ok(replacement)
}

pub(super) fn validate_inspect(
    entry: &DescribedChainEntry,
    inspect: &openshell_core::proto::HttpResponsePreflightInspect,
    permitted_modes: &[i32],
) -> Result<StageMode, String> {
    let mode = match HttpResponseBodyMode::try_from(inspect.body_mode) {
        Ok(HttpResponseBodyMode::HeadersOnly) => StageMode::HeadersOnly,
        Ok(HttpResponseBodyMode::WholeBodyBytes) => StageMode::WholeBody,
        Ok(HttpResponseBodyMode::StreamBytes) => StageMode::Stream,
        Ok(HttpResponseBodyMode::Unspecified) | Err(_) => {
            return Err("invalid_response_body_mode".into());
        }
    };
    if !permitted_modes.contains(&inspect.body_mode) {
        return Err("response_body_mode_not_permitted".into());
    }
    if inspect.header_mutations.len() > headers::MAX_HEADER_MUTATIONS {
        return Err("header_mutation_count_over_capacity".into());
    }
    let encoded_mutations = inspect
        .header_mutations
        .iter()
        .fold(0usize, |total, mutation| {
            total.saturating_add(mutation.encoded_len())
        });
    if encoded_mutations > MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES {
        return Err("header_mutation_bytes_over_capacity".into());
    }
    if entry.max_payload_bytes == 0 && mode != StageMode::HeadersOnly {
        return Err("response_payload_limit_invalid".into());
    }
    Ok(mode)
}

pub(super) fn validate_diagnostics(
    reason: &str,
    reason_code: &str,
    findings: &[Finding],
    metadata: &std::collections::HashMap<String, String>,
) -> Result<(), &'static str> {
    if reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err("response_reason_over_capacity");
    }
    if !reason_code.is_empty()
        && (reason_code.len() > MAX_MIDDLEWARE_REASON_CODE_BYTES
            || !is_stable_reason_code(reason_code))
    {
        return Err("response_reason_code_invalid");
    }
    if findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE {
        return Err("response_findings_over_capacity");
    }
    if findings
        .iter()
        .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err("response_finding_over_capacity");
    }
    if metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES {
        return Err("response_metadata_count_over_capacity");
    }
    if metadata.iter().fold(0usize, |total, (key, value)| {
        total.saturating_add(key.len()).saturating_add(value.len())
    }) > MAX_MIDDLEWARE_METADATA_BYTES
    {
        return Err("response_metadata_bytes_over_capacity");
    }
    Ok(())
}

/// Body modes 0.1.x offered a stage: `HEADERS_ONLY` always, and unless the
/// response body cannot be inspected, `WHOLE_BODY_BYTES` for a closed-ended
/// body within the stage limit and `STREAM_BYTES` for a non-zero limit.
pub(super) fn permitted_body_modes(
    input: &HttpResponsePreflightInput,
    entry: &DescribedChainEntry,
) -> Vec<i32> {
    let mut modes = vec![HttpResponseBodyMode::HeadersOnly as i32];
    if body_restriction(input).is_some() {
        return modes;
    }
    if input
        .declared_body_length
        .is_none_or(|length| length <= entry.max_payload_bytes as u64)
        && !is_open_ended(input)
    {
        modes.push(HttpResponseBodyMode::WholeBodyBytes as i32);
    }
    if entry.max_payload_bytes > 0 {
        modes.push(HttpResponseBodyMode::StreamBytes as i32);
    }
    modes
}

pub(super) fn strip_stale_integrity(headers: &mut Vec<HttpHeader>) {
    headers.retain(|header| !is_stale_http_response_integrity_header(&header.name));
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{ChainEntry, OnError};

    fn input() -> HttpResponsePreflightInput {
        HttpResponsePreflightInput {
            context: openshell_core::proto::RequestContext::default(),
            target: openshell_core::proto::HttpRequestTarget {
                method: "GET".into(),
                ..Default::default()
            },
            status_code: 200,
            declared_body_length: None,
            headers: vec![HttpHeader {
                name: "content-type".into(),
                value: "text/plain".into(),
            }],
            connection_nominated_headers: Vec::new(),
        }
    }

    #[test]
    fn stream_mode_requires_only_one_byte_of_payload_capacity() {
        let mut described = DescribedChainEntry {
            entry: ChainEntry {
                name: "response".into(),
                implementation: "test/response".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            service: None,
            binding: None,
            max_payload_bytes: 1,
            timeout: Duration::from_millis(500),
        };

        let modes = permitted_body_modes(&input(), &described);
        assert!(modes.contains(&(HttpResponseBodyMode::StreamBytes as i32)));

        described.max_payload_bytes = 0;
        let modes = permitted_body_modes(&input(), &described);
        assert!(!modes.contains(&(HttpResponseBodyMode::StreamBytes as i32)));
    }
}
