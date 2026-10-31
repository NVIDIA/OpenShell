// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP hooks (`HttpHooks.EvaluateRequest` and `HttpHooks.EvaluateResponse`).
//!
//! Legacy HTTP hooks keep their own engines. A chain runs on exactly one hook
//! version: every selected entry for one HTTP message must use the same
//! version, and a chain that mixes them fails closed with
//! [`MIDDLEWARE_HOOK_VERSIONS_MIXED`].

mod pipeline;
mod request;
mod response;
#[cfg(test)]
mod tests;

use openshell_core::proto::{HttpHeader, HttpRequestTarget, RequestContext};
use prost::Message as _;

pub use pipeline::{
    HTTP_STREAM_IDLE_TIMEOUT, HTTP_WHOLE_BODY_TIMEOUT, HttpBodyInput, HttpBodyOutput,
    HttpFailureCode, HttpMiddlewareFailure, HttpPipelineFinish, HttpStageDiagnostics,
    HttpStageInvocation, HttpStageOutcome, MAX_HTTP_STREAM_UNIT_BYTES, MIDDLEWARE_CANNOT_INSPECT,
    MIDDLEWARE_HOOK_VERSIONS_MIXED, MiddlewareFailureDetail,
};
pub use request::{
    HttpRequestPipeline, HttpRequestPreflightInput, HttpRequestPreflightOutcome,
    MAX_HTTP_REQUEST_WITHHELD_BYTES,
};
pub use response::{HttpResponseDelivery, HttpResponsePipeline, HttpResponsePipelinePreflight};

use crate::{
    DescribedChainEntry, HttpHookVersion, MAX_MIDDLEWARE_CONTEXT_BYTES,
    MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS, MAX_MIDDLEWARE_TARGET_BYTES,
};

/// HTTP hook version a described chain runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainHttpHookVersion {
    /// Every resolved entry uses legacy HTTP hooks, or the chain is empty. The
    /// chain runs on the legacy HTTP hook engines, unchanged.
    Legacy,
    /// At least one entry uses HTTP hooks and none uses legacy HTTP
    /// hooks.
    Current,
    /// Resolved entries of both HTTP hook versions select the same
    /// message. The message fails closed with [`MIDDLEWARE_HOOK_VERSIONS_MIXED`].
    Mixed,
}

/// Classify a chain described for one HTTP operation by its resolved
/// entries. An unresolved entry follows its `on_error` on either path.
#[must_use]
pub fn chain_http_hook_version(entries: &[DescribedChainEntry]) -> ChainHttpHookVersion {
    let current = entries
        .iter()
        .any(|entry| entry.http_hook_version() == Some(HttpHookVersion::Current));
    let legacy = entries
        .iter()
        .any(|entry| entry.http_hook_version() == Some(HttpHookVersion::Legacy));
    match (legacy, current) {
        (true, true) => ChainHttpHookVersion::Mixed,
        (false, true) => ChainHttpHookVersion::Current,
        _ => ChainHttpHookVersion::Legacy,
    }
}

/// True when an HTTP hook stage of a described response chain may inspect bodies.
///
/// No body mode is offered for an encoded response, so the relay then asks the
/// upstream for an identity-coded one.
#[must_use]
pub fn chain_inspects_http_response_bodies(entries: &[DescribedChainEntry]) -> bool {
    entries.iter().any(|entry| {
        entry.http_hook_version() == Some(HttpHookVersion::Current) && entry.max_payload_bytes() > 0
    })
}

/// True when `headers` declare a content coding other than `identity`.
/// Middleware would only see the encoded body.
fn has_content_coding(headers: &[HttpHeader]) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .any(|header| {
            header
                .value
                .split(',')
                .any(|coding| !coding.trim().eq_ignore_ascii_case("identity"))
        })
}

/// Platform limits on the head shown to every stage.
fn validate_head_input(
    context: &RequestContext,
    target: &HttpRequestTarget,
    headers: &[HttpHeader],
) -> Result<(), &'static str> {
    if context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES
        || target.encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES
    {
        return Err("head_input_over_capacity");
    }
    validate_header_input(headers)
}

/// Platform limits on one header list shown to every stage.
fn validate_header_input(headers: &[HttpHeader]) -> Result<(), &'static str> {
    if headers.len() > MAX_MIDDLEWARE_HEADERS
        || headers
            .iter()
            .map(prost::Message::encoded_len)
            .fold(0usize, usize::saturating_add)
            > MAX_MIDDLEWARE_HEADER_BYTES
    {
        return Err("head_input_over_capacity");
    }
    Ok(())
}
