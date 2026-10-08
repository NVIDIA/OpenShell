// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Constructors for v0.1.2 results that scripts commonly return.

use crate::proto::middleware::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestResult, HttpResponseBlockDelivery,
    HttpResponseBodyMode, HttpResponseBodyPassThrough, HttpResponseBodyResult,
    HttpResponseBodySkipRemaining, HttpResponseBodyTransform, HttpResponsePreflightInspect,
    HttpResponsePreflightResult, HttpResponsePreflightSkip, HttpResponseTrailersResult,
    RemoveHeader, WebSocketMessageResult, WebSocketPreflightAction, WebSocketPreflightDecision,
    WriteHeader, header_mutation, http_response_body_result, http_response_body_skip_remaining,
    http_response_body_transform, http_response_preflight_result, web_socket_message_result,
};

/// Allow the request unchanged.
#[must_use]
pub fn allow() -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Allow as i32,
        ..Default::default()
    }
}

/// Allow the request with a replacement body.
#[must_use]
pub fn replace_body(body: impl Into<Vec<u8>>) -> HttpRequestResult {
    HttpRequestResult {
        body: body.into(),
        has_body: true,
        ..allow()
    }
}

/// Allow the request and apply ordered header mutations.
#[must_use]
pub fn mutate_headers(header_mutations: Vec<HeaderMutation>) -> HttpRequestResult {
    HttpRequestResult {
        header_mutations,
        ..allow()
    }
}

/// Deny the request with a stable reason code.
#[must_use]
pub fn deny(reason_code: &str) -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Deny as i32,
        reason: "fixture denial".into(),
        reason_code: reason_code.into(),
        ..Default::default()
    }
}

/// Write one header with the given collision behavior.
#[must_use]
pub fn write_header(name: &str, value: &str, on_existing: ExistingHeaderAction) -> HeaderMutation {
    HeaderMutation {
        operation: Some(header_mutation::Operation::Write(WriteHeader {
            name: name.into(),
            value: value.into(),
            on_existing: on_existing as i32,
        })),
    }
}

/// Remove every value of one header.
#[must_use]
pub fn remove_header(name: &str) -> HeaderMutation {
    HeaderMutation {
        operation: Some(header_mutation::Operation::Remove(RemoveHeader {
            name: name.into(),
        })),
    }
}

/// Decline response inspection.
#[must_use]
pub fn preflight_skip() -> HttpResponsePreflightResult {
    HttpResponsePreflightResult {
        action: Some(http_response_preflight_result::Action::Skip(
            HttpResponsePreflightSkip {},
        )),
        ..Default::default()
    }
}

/// Inspect the response in `mode`, applying head mutations first.
#[must_use]
pub fn preflight_inspect(
    mode: HttpResponseBodyMode,
    header_mutations: Vec<HeaderMutation>,
) -> HttpResponsePreflightResult {
    HttpResponsePreflightResult {
        action: Some(http_response_preflight_result::Action::Inspect(
            HttpResponsePreflightInspect {
                body_mode: mode as i32,
                header_mutations,
            },
        )),
        ..Default::default()
    }
}

/// Block delivery at preflight.
#[must_use]
pub fn preflight_block(reason_code: &str) -> HttpResponsePreflightResult {
    HttpResponsePreflightResult {
        action: Some(http_response_preflight_result::Action::BlockDelivery(
            HttpResponseBlockDelivery {},
        )),
        reason_code: reason_code.into(),
        ..Default::default()
    }
}

fn body_result(sequence: u64, action: http_response_body_result::Action) -> HttpResponseBodyResult {
    HttpResponseBodyResult {
        sequence,
        action: Some(action),
        ..Default::default()
    }
}

/// Forward body unit `sequence` unchanged.
#[must_use]
pub fn body_pass_through(sequence: u64) -> HttpResponseBodyResult {
    body_result(
        sequence,
        http_response_body_result::Action::PassThrough(HttpResponseBodyPassThrough {}),
    )
}

/// Replace body unit `sequence`.
#[must_use]
pub fn body_transform(sequence: u64, data: impl Into<Vec<u8>>) -> HttpResponseBodyResult {
    body_result(
        sequence,
        http_response_body_result::Action::Transform(HttpResponseBodyTransform {
            replacement: Some(http_response_body_transform::Replacement::Data(data.into())),
        }),
    )
}

/// Block delivery at body unit `sequence`.
#[must_use]
pub fn body_block(sequence: u64, reason_code: &str) -> HttpResponseBodyResult {
    HttpResponseBodyResult {
        reason_code: reason_code.into(),
        ..body_result(
            sequence,
            http_response_body_result::Action::BlockDelivery(HttpResponseBlockDelivery {}),
        )
    }
}

/// Finalize unit `sequence`, optionally replacing it, and stop inspecting.
#[must_use]
pub fn body_skip_remaining(sequence: u64, replacement: Option<Vec<u8>>) -> HttpResponseBodyResult {
    let current = replacement.map_or(
        http_response_body_skip_remaining::Current::PassThrough(HttpResponseBodyPassThrough {}),
        |data| {
            http_response_body_skip_remaining::Current::Transform(HttpResponseBodyTransform {
                replacement: Some(http_response_body_transform::Replacement::Data(data)),
            })
        },
    );
    body_result(
        sequence,
        http_response_body_result::Action::SkipRemaining(HttpResponseBodySkipRemaining {
            current: Some(current),
        }),
    )
}

/// Keep the current trailers.
#[must_use]
pub fn trailers_unchanged() -> HttpResponseTrailersResult {
    HttpResponseTrailersResult::default()
}

/// Apply ordered trailer mutations.
#[must_use]
pub fn trailers_mutated(trailer_mutations: Vec<HeaderMutation>) -> HttpResponseTrailersResult {
    HttpResponseTrailersResult {
        trailer_mutations,
        ..Default::default()
    }
}

fn websocket_preflight(action: WebSocketPreflightAction) -> WebSocketPreflightDecision {
    WebSocketPreflightDecision {
        action: action as i32,
        ..Default::default()
    }
}

/// Inspect the WebSocket session.
#[must_use]
pub fn websocket_inspect() -> WebSocketPreflightDecision {
    websocket_preflight(WebSocketPreflightAction::Inspect)
}

/// Decline WebSocket inspection.
#[must_use]
pub fn websocket_skip() -> WebSocketPreflightDecision {
    websocket_preflight(WebSocketPreflightAction::Skip)
}

/// Deny the WebSocket upgrade.
#[must_use]
pub fn websocket_deny(reason_code: &str) -> WebSocketPreflightDecision {
    WebSocketPreflightDecision {
        reason_code: reason_code.into(),
        ..websocket_preflight(WebSocketPreflightAction::Deny)
    }
}

/// Allow WebSocket message `sequence` unchanged.
#[must_use]
pub fn message_allow(sequence: u64) -> WebSocketMessageResult {
    WebSocketMessageResult {
        sequence,
        decision: Decision::Allow as i32,
        ..Default::default()
    }
}

/// Allow WebSocket message `sequence` with a text replacement.
#[must_use]
pub fn message_replace_text(sequence: u64, text: &str) -> WebSocketMessageResult {
    WebSocketMessageResult {
        replacement: Some(web_socket_message_result::Replacement::Text(text.into())),
        ..message_allow(sequence)
    }
}

/// Deny WebSocket message `sequence`.
#[must_use]
pub fn message_deny(sequence: u64, reason_code: &str) -> WebSocketMessageResult {
    WebSocketMessageResult {
        sequence,
        decision: Decision::Deny as i32,
        reason_code: reason_code.into(),
        ..Default::default()
    }
}
