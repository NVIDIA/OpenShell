// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy `EvaluateWebSocketSession` behavior over the v0.1.2 wire.
//!
//! WebSocket bindings keep `on_error` after the HTTP protocol moves to v2, so
//! these expectations hold across every cutover.

use openshell_core::proto::{MiddlewareSessionEndReason, SupervisorMiddlewarePhase};
use openshell_supervisor_middleware_wire_fixture::proto::middleware::{
    WebSocketMessage, WebSocketMessageResult, web_socket_message, web_socket_session_event,
};
use openshell_supervisor_middleware_wire_fixture::{
    LegacyMiddlewareFixture, LegacyRpc, Reply, RunningFixture, results, websocket_binding,
};
use tonic::Status;

use super::harness::{connect, entry, registration};
use crate::{ChainRunner, OnError, WebSocketPreflightInput};

const GUARD: &str = "legacy-websocket-guard";
const LIMIT: u64 = 4096;

async fn guard(fixture: LegacyMiddlewareFixture) -> (RunningFixture, ChainRunner) {
    let fixture = fixture
        .with_binding(websocket_binding(LIMIT))
        .spawn()
        .await
        .expect("spawn WebSocket fixture");
    let runner = connect(vec![registration(GUARD, &fixture, LIMIT)]).await;
    (fixture, runner)
}

fn preflight_input() -> WebSocketPreflightInput {
    WebSocketPreflightInput {
        session_id: "compat-ws".into(),
        request_id: "compat-request".into(),
        sandbox_id: "compat-sandbox-id".into(),
        sandbox_name: "compat-sandbox".into(),
        workspace: "compat-workspace".into(),
        scheme: "wss".into(),
        host: "api.example.test".into(),
        port: 443,
        path: "/v1/realtime".into(),
        requested_subprotocols: vec!["json".into()],
    }
}

fn text(message: &WebSocketMessage) -> &str {
    match message.payload.as_ref() {
        Some(web_socket_message::Payload::Text(text)) => text,
        _ => "",
    }
}

fn redact_or_deny(message: &WebSocketMessage) -> Reply<WebSocketMessageResult> {
    let payload = text(message);
    if payload.contains("forbidden") {
        results::message_deny(message.sequence, "content_match").into()
    } else if payload.contains("secret") {
        results::message_replace_text(message.sequence, &payload.replace("secret", "[FILTERED]"))
            .into()
    } else {
        results::message_allow(message.sequence).into()
    }
}

#[tokio::test]
async fn websocket_messages_round_trip_over_the_v0_1_2_wire() {
    let (fixture, runner) = guard(
        LegacyMiddlewareFixture::new("compat/websocket").on_websocket_message(redact_or_deny),
    )
    .await;
    let chain = [entry("ws-guard", GUARD, 10, OnError::FailClosed)];

    let preflight = runner
        .preflight_websocket(&chain, preflight_input())
        .await
        .expect("WebSocket preflight");
    assert!(preflight.allowed);
    let mut session = preflight.session.expect("the fixture inspects the session");
    assert!(session.start("json").await.allowed);

    let redacted = session.evaluate_text("a secret value".into()).await;
    assert!(redacted.allowed);
    assert_eq!(redacted.payload, "a [FILTERED] value");

    let clean = session.evaluate_text("plain".into()).await;
    assert!(clean.allowed);
    assert_eq!(clean.payload, "plain");

    let denied = session.evaluate_text("forbidden".into()).await;
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "middleware_denied:ws-guard:content_match");
    assert_eq!(
        denied.denial.and_then(|denial| denial.reason_code),
        Some("content_match".into())
    );
    session.end(MiddlewareSessionEndReason::Normal).await;

    let events = &fixture.websocket_sessions()[0];
    let Some(web_socket_session_event::Event::Preflight(preflight)) = events[0].event.clone()
    else {
        panic!("the first WebSocket event is preflight");
    };
    assert_eq!(preflight.session_id, "compat-ws");
    assert_eq!(
        preflight.phase,
        SupervisorMiddlewarePhase::PreCredentials as i32
    );
    assert_eq!(preflight.middleware_name, GUARD);
    assert_eq!(preflight.requested_subprotocols, vec!["json".to_string()]);
    let target = preflight.target.expect("upgrade target");
    assert_eq!(
        (
            target.scheme.as_str(),
            target.method.as_str(),
            target.path.as_str()
        ),
        ("wss", "GET", "/v1/realtime")
    );
    let Some(web_socket_session_event::Event::SessionStart(start)) = events[1].event.clone() else {
        panic!("session_start follows preflight");
    };
    assert_eq!(start.selected_subprotocol, "json");
    let sequences: Vec<u64> = events
        .iter()
        .filter_map(|event| match &event.event {
            Some(web_socket_session_event::Event::Message(message)) => Some(message.sequence),
            _ => None,
        })
        .collect();
    assert_eq!(sequences, [1, 2, 3]);
}

#[tokio::test]
async fn websocket_message_failures_follow_on_error() {
    for on_error in [OnError::FailOpen, OnError::FailClosed] {
        let (fixture, runner) = guard(
            LegacyMiddlewareFixture::new("compat/websocket-failing")
                .on_websocket_message(|_| Reply::Fail(Status::internal("guard crashed"))),
        )
        .await;
        let chain = [entry("ws-guard", GUARD, 10, on_error)];
        let preflight = runner
            .preflight_websocket(&chain, preflight_input())
            .await
            .expect("WebSocket preflight");
        let mut session = preflight.session.expect("inspected session");
        assert!(session.start("").await.allowed);

        let first = session.evaluate_text("payload".into()).await;
        match on_error {
            OnError::FailOpen => {
                assert!(first.allowed, "fail_open delivers the original message");
                assert_eq!(first.payload, "payload");
                assert!(first.invocations[0].failed);
                assert!(first.invocations[0].stage_disabled);

                let second = session.evaluate_text("next".into()).await;
                assert!(second.allowed);
                assert!(
                    second.invocations.is_empty(),
                    "the failed stage is bypassed for the rest of the session"
                );
            }
            OnError::FailClosed => {
                assert!(!first.allowed, "fail_closed terminates the session");
                assert!(first.reason.starts_with("middleware_failed: "));
                assert!(first.denial.is_none());
            }
        }
        session.end(MiddlewareSessionEndReason::Normal).await;
        assert_eq!(fixture.websocket_sessions().len(), 1, "{on_error:?}");
    }
}

/// `UNIMPLEMENTED` when opening the WebSocket stream follows `on_error` in
/// 0.1.x. WebSocket bindings keep `on_error`, so the fail-closed rule for HTTP
/// contract failures does not apply to them.
#[tokio::test]
async fn unimplemented_websocket_stream_follows_on_error() {
    let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/websocket-swapped")).await;
    fixture.set_unimplemented(LegacyRpc::EvaluateWebSocketSession, true);

    let open = runner
        .preflight_websocket(
            &[entry("ws-guard", GUARD, 10, OnError::FailOpen)],
            preflight_input(),
        )
        .await
        .expect("WebSocket preflight");
    assert!(open.allowed);
    assert!(open.session.is_none());
    assert!(open.invocations[0].failed);

    let closed = runner
        .preflight_websocket(
            &[entry("ws-guard", GUARD, 10, OnError::FailClosed)],
            preflight_input(),
        )
        .await
        .expect("WebSocket preflight");
    assert!(!closed.allowed);
    assert_eq!(
        closed.terminal_reason,
        Some(MiddlewareSessionEndReason::MiddlewareFailure)
    );
    assert!(closed.reason.starts_with("middleware_failed: "));
    assert!(fixture.websocket_sessions().is_empty());
}
