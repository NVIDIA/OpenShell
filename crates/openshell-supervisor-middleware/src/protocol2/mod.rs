// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP middleware protocol 2 (`EvaluateHttp`).
//!
//! HTTP protocol 1 keeps its own engines. A chain runs on exactly one
//! protocol: every selected entry for one HTTP message must use the same
//! protocol, and a chain that mixes them fails closed with
//! [`MIDDLEWARE_PROTOCOL_MIXED`].

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
    MIDDLEWARE_PROTOCOL_MIXED,
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
    DescribedChainEntry, HttpProtocol, MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_HEADER_BYTES,
    MAX_MIDDLEWARE_HEADERS, MAX_MIDDLEWARE_TARGET_BYTES,
};

/// HTTP protocol a described chain runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainHttpProtocol {
    /// Every resolved entry uses HTTP protocol 1, or the chain is empty. The
    /// chain runs on the HTTP protocol 1 engines, unchanged.
    V1,
    /// At least one entry uses HTTP protocol 2 and none uses HTTP protocol 1.
    V2,
    /// Resolved HTTP protocol 1 and HTTP protocol 2 entries select the same
    /// message. The message fails closed with [`MIDDLEWARE_PROTOCOL_MIXED`].
    Mixed,
}

/// Classify a chain described for one HTTP operation.
///
/// An unresolved entry counts as HTTP protocol 2 only when the gateway
/// described its service as such; any other unresolved entry follows its
/// `on_error` on either path.
#[must_use]
pub fn chain_http_protocol(entries: &[DescribedChainEntry]) -> ChainHttpProtocol {
    let v2 = entries
        .iter()
        .any(|entry| entry.http_protocol() == Some(HttpProtocol::V2));
    let v1 = entries
        .iter()
        .any(|entry| entry.is_resolved() && entry.http_protocol() == Some(HttpProtocol::V1));
    match (v1, v2) {
        (true, true) => ChainHttpProtocol::Mixed,
        (false, true) => ChainHttpProtocol::V2,
        _ => ChainHttpProtocol::V1,
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
