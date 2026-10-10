// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP session hooks (`EvaluateHttpRequestSession` and `EvaluateHttpResponseSession`).
//!
//! v1 HTTP hooks keep their own engines. A chain runs on exactly one hook
//! version: every selected entry for one HTTP message must use the same
//! version, and a chain that mixes them fails closed with
//! [`MIDDLEWARE_HOOK_VERSIONS_MIXED`].

mod pipeline;
mod request;
mod response;
#[cfg(test)]
mod tests;
mod uninspectable;

use openshell_core::proto::{HttpHeader, HttpRequestTarget, RequestContext};
use prost::Message as _;

pub use pipeline::{
    HTTP_BUFFERED_BODY_TIMEOUT, HTTP_STREAM_IDLE_TIMEOUT, HttpBodyInput, HttpBodyOutput,
    HttpMiddlewareFailure, HttpPipelineFinish, HttpStageDiagnostics, HttpStageInvocation,
    HttpStageOutcome, MAX_HTTP_STREAM_UNIT_BYTES, MIDDLEWARE_CANNOT_INSPECT,
    MIDDLEWARE_HOOK_VERSIONS_MIXED,
};
pub use request::{
    HttpRequestPreflightInput, HttpRequestPreflightOutcome, HttpRequestSession,
    MAX_HTTP_REQUEST_WITHHELD_BYTES,
};
pub use response::{
    HttpResponseDelivery, HttpResponsePipelinePreflight, HttpResponsePipelineSession,
};
pub use uninspectable::{UninspectableInvocation, UninspectableOutcome, UninspectableTrafficInput};

use crate::{
    DescribedChainEntry, HttpHookVersion, MAX_MIDDLEWARE_CONTEXT_BYTES,
    MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS, MAX_MIDDLEWARE_TARGET_BYTES,
};

/// HTTP hook version a described chain runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainHttpHookVersion {
    /// Every resolved entry uses v1 HTTP hooks, or the chain is empty. The
    /// chain runs on the v1 HTTP hook engines, unchanged.
    V1,
    /// At least one entry uses HTTP session hooks and none uses v1 HTTP
    /// hooks.
    Session,
    /// Resolved v1 HTTP hook and HTTP session hook entries select the same
    /// message. The message fails closed with [`MIDDLEWARE_HOOK_VERSIONS_MIXED`].
    Mixed,
}

/// Classify a chain described for one HTTP operation by its resolved
/// entries. An unresolved entry follows its `on_error` on either path.
#[must_use]
pub fn chain_http_hook_version(entries: &[DescribedChainEntry]) -> ChainHttpHookVersion {
    let session = entries
        .iter()
        .any(|entry| entry.http_hook_version() == Some(HttpHookVersion::Session));
    let v1 = entries
        .iter()
        .any(|entry| entry.http_hook_version() == Some(HttpHookVersion::V1));
    match (v1, session) {
        (true, true) => ChainHttpHookVersion::Mixed,
        (false, true) => ChainHttpHookVersion::Session,
        _ => ChainHttpHookVersion::V1,
    }
}

/// Platform limits on the head shown to every stage.
fn validate_head_input(
    context: &RequestContext,
    target: &HttpRequestTarget,
    headers: &[HttpHeader],
) -> Result<(), &'static str> {
    if context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES
        || target.encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES
        || headers.len() > MAX_MIDDLEWARE_HEADERS
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
