// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! First-party in-process supervisor middleware implementations.

mod regex;

use std::sync::Arc;

use miette::{Result, miette};
use openshell_core::middleware::{HttpRequestView, InProcessMiddleware, WebSocketResponseStream};
use openshell_core::proto::{
    HttpRequestResult, MiddlewareManifest, SupervisorMiddlewarePhase, WebSocketPreflightAction,
    WebSocketPreflightDecision, WebSocketSessionEvent, WebSocketSessionEventResult,
    web_socket_message, web_socket_session_event, web_socket_session_event_result,
};
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

pub use regex::{NAME as BUILTIN_REGEX, RegexConfig, RegexMode};

/// Return the first-party services that the gateway and supervisor install.
pub fn services() -> Vec<Arc<dyn InProcessMiddleware>> {
    vec![Arc::new(BuiltinMiddlewareService)]
}

/// Resolve and validate a first-party config before the supervisor has selected
/// its service endpoint.
pub fn validate_config(implementation: &str, config: &prost_types::Struct) -> Result<()> {
    match implementation {
        BUILTIN_REGEX => regex::validate_config(config),
        other => Err(miette!(
            "middleware implementation '{other}' is not a registered OpenShell built-in"
        )),
    }
}

fn evaluate_http_request(request: HttpRequestView<'_>) -> Result<HttpRequestResult> {
    match request.middleware_name() {
        BUILTIN_REGEX => regex::evaluate_http_request(request.config(), request.body()),
        other => Err(miette!(
            "middleware implementation '{other}' is not a registered OpenShell built-in"
        )),
    }
}

/// Aggregate service exposing first-party middleware through the borrowed in-process contract.
#[derive(Debug, Default)]
pub struct BuiltinMiddlewareService;

impl BuiltinMiddlewareService {
    fn websocket_stream<S>(mut requests: S) -> WebSocketResponseStream
    where
        S: Stream<Item = std::result::Result<WebSocketSessionEvent, Status>>
            + Send
            + Unpin
            + 'static,
    {
        let (responses_tx, responses_rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut config = None;
            let mut started = false;
            let mut sequence_lower_bound = Some(1u64);

            while let Some(request) = requests.next().await {
                let request = match request {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = responses_tx.send(Err(error)).await;
                        break;
                    }
                };
                let response = match request.event {
                    Some(web_socket_session_event::Event::Preflight(preflight))
                        if config.is_none() && !started =>
                    {
                        if preflight.phase == SupervisorMiddlewarePhase::PreCredentials as i32 {
                            let selected_config = preflight.config.unwrap_or_default();
                            match regex::validate_config(&selected_config) {
                                Ok(()) => {
                                    config = Some(selected_config);
                                    Ok(Some(WebSocketSessionEventResult {
                                        result: Some(
                                            web_socket_session_event_result::Result::PreflightDecision(
                                                WebSocketPreflightDecision {
                                                    action: WebSocketPreflightAction::Inspect
                                                        as i32,
                                                    ..Default::default()
                                                },
                                            ),
                                        ),
                                    }))
                                }
                                Err(error) => Err(Status::invalid_argument(error.to_string())),
                            }
                        } else {
                            Err(Status::invalid_argument(
                                "unsupported built-in WebSocket binding",
                            ))
                        }
                    }
                    Some(web_socket_session_event::Event::SessionStart(_))
                        if config.is_some() && !started =>
                    {
                        started = true;
                        Ok(None)
                    }
                    Some(web_socket_session_event::Event::Message(message)) if started => {
                        if let Err(error) = advance_sequence_lower_bound(
                            &mut sequence_lower_bound,
                            message.sequence,
                        ) {
                            Err(error)
                        } else {
                            match message.payload {
                                Some(web_socket_message::Payload::Text(payload)) => {
                                    let selected_config =
                                        config.as_ref().expect("started stream has config");
                                    match regex::evaluate_websocket_text(
                                        message.sequence,
                                        &payload,
                                        selected_config,
                                    ) {
                                        Ok(result) => Ok(Some(WebSocketSessionEventResult {
                                            result: Some(
                                                web_socket_session_event_result::Result::MessageResult(
                                                    result,
                                                ),
                                            ),
                                        })),
                                        Err(error) => {
                                            Err(Status::invalid_argument(error.to_string()))
                                        }
                                    }
                                }
                                Some(web_socket_message::Payload::Binary(_)) | None => {
                                    Err(Status::invalid_argument(
                                        "openshell/regex supports only client-to-upstream WebSocket text messages",
                                    ))
                                }
                            }
                        }
                    }
                    Some(web_socket_session_event::Event::SessionEnd(_)) if config.is_some() => {
                        break;
                    }
                    _ => Err(Status::failed_precondition(
                        "invalid built-in WebSocket session lifecycle",
                    )),
                };

                match response {
                    Ok(Some(response)) => {
                        if responses_tx.send(Ok(response)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = responses_tx.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
        Box::pin(tokio_stream::wrappers::ReceiverStream::new(responses_rx))
    }
}

fn advance_sequence_lower_bound(
    lower_bound: &mut Option<u64>,
    sequence: u64,
) -> std::result::Result<(), Status> {
    let Some(current_lower_bound) = *lower_bound else {
        return Err(Status::invalid_argument(
            "WebSocket message sequence must be strictly increasing",
        ));
    };
    if sequence < current_lower_bound {
        return Err(Status::invalid_argument(
            "WebSocket message sequence must be strictly increasing",
        ));
    }
    *lower_bound = sequence.checked_add(1);
    Ok(())
}

#[tonic::async_trait]
impl InProcessMiddleware for BuiltinMiddlewareService {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: BUILTIN_REGEX.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: regex::describe(),
            expected_audience: String::new(),
        }
    }

    async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> Result<()> {
        validate_config(middleware_name, config)
    }

    async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        evaluate_http_request(request)
    }

    async fn open_websocket_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, Status> {
        Ok(Self::websocket_stream(
            tokio_stream::wrappers::ReceiverStream::new(receiver).map(Ok),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        Decision, HttpRequestTarget, RequestContext, SupervisorMiddlewareOperation,
        SupervisorMiddlewarePhase, WebSocketPreflight,
    };

    fn string_config(key: &str, value: &str) -> prost_types::Struct {
        prost_types::Struct {
            fields: std::iter::once((
                key.to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(value.into())),
                },
            ))
            .collect(),
        }
    }

    fn evaluate_body(body: &[u8], config: &prost_types::Struct) -> Result<HttpRequestResult> {
        let context = RequestContext::default();
        let target = HttpRequestTarget::default();
        evaluate_http_request(HttpRequestView::new(
            SupervisorMiddlewarePhase::PreCredentials,
            &context,
            config,
            &target,
            &[],
            body,
            BUILTIN_REGEX,
        ))
    }

    #[tokio::test]
    async fn service_describes_regex_binding() {
        let manifest = InProcessMiddleware::describe(&BuiltinMiddlewareService).await;
        assert_eq!(manifest.bindings.len(), 2);
        assert_eq!(
            manifest.bindings[0].operation,
            SupervisorMiddlewareOperation::HttpRequest as i32
        );
        assert_eq!(
            manifest.bindings[0].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(manifest.bindings[0].max_payload_bytes, 256 * 1024);
        assert_eq!(
            manifest.bindings[1].operation,
            SupervisorMiddlewareOperation::WebsocketMessage as i32
        );
        assert_eq!(
            manifest.bindings[1].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(manifest.bindings[1].max_payload_bytes, 256 * 1024);
    }

    #[test]
    fn regex_config_defaults_to_redact() {
        let config = RegexConfig::from_struct(&prost_types::Struct::default()).unwrap();
        assert_eq!(config.mode, RegexMode::Redact);
    }

    #[test]
    fn regex_config_accepts_explicit_redact() {
        let config = RegexConfig::from_struct(&string_config("mode", "redact")).unwrap();
        assert_eq!(config.mode, RegexMode::Redact);
    }

    #[test]
    fn regex_config_rejects_unsupported_or_malformed_values() {
        for config in [
            string_config("mode", "allow"),
            string_config("patterns", "password"),
            prost_types::Struct {
                fields: std::iter::once((
                    "mode".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::NumberValue(42.0)),
                    },
                ))
                .collect(),
            },
        ] {
            assert!(validate_config(BUILTIN_REGEX, &config).is_err());
        }
    }

    #[test]
    fn registry_rejects_unknown_builtin_name() {
        let error = validate_config("openshell/unknown", &prost_types::Struct::default())
            .expect_err("unknown built-in");
        assert!(
            error
                .to_string()
                .contains("is not a registered OpenShell built-in")
        );
    }

    #[test]
    fn regex_replacement_evaluates_through_binding() {
        let result = evaluate_body(
            br#"{"password":"top-secret","token":"sk-ABCDEFGHIJKLMNOP"}"#,
            &prost_types::Struct::default(),
        )
        .expect("evaluate regex binding");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(result.has_body);
        let body = String::from_utf8(result.body).unwrap();
        assert!(body.contains("top-secret"));
        assert!(!body.contains("sk-ABCDEFGHIJKLMNOP"));
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.r#type != "regex.keyword")
        );
    }

    #[tokio::test]
    async fn service_validates_builtin_config() {
        InProcessMiddleware::validate_config(
            &BuiltinMiddlewareService,
            BUILTIN_REGEX,
            &prost_types::Struct::default(),
        )
        .await
        .expect("validate config");
    }

    #[tokio::test]
    async fn websocket_preflight_does_not_dispatch_on_registration_name() {
        let requests = tokio_stream::iter([Ok::<_, Status>(WebSocketSessionEvent {
            event: Some(web_socket_session_event::Event::Preflight(
                WebSocketPreflight {
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    middleware_name: "operator-assigned-name".into(),
                    config: Some(prost_types::Struct::default()),
                    ..Default::default()
                },
            )),
        })]);
        let mut responses = BuiltinMiddlewareService::websocket_stream(requests);
        let response = responses
            .next()
            .await
            .expect("preflight response")
            .expect("valid preflight");

        assert!(matches!(
            response.result,
            Some(web_socket_session_event_result::Result::PreflightDecision(
                WebSocketPreflightDecision { action, .. }
            )) if action == WebSocketPreflightAction::Inspect as i32
        ));
    }

    #[test]
    fn regex_replacement_does_not_parse_keyword_assignments() {
        let body = concat!(
            r#"{"password":"alpha beta","secret":"alpha,beta","api_key":"alpha\"beta"}"#,
            "\npassword=alpha\nnotpassword=omega"
        );
        let result = evaluate_body(body.as_bytes(), &prost_types::Struct::default())
            .expect("evaluate regex binding");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(!result.has_body);
        assert!(result.body.is_empty());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn regex_websocket_text_reuses_findings_and_metadata_semantics() {
        let payload =
            r#"{"type":"response.create","input":"sk-ABCDEFGHIJKLMNOP sk-QRSTUVWXYZabcdef"}"#;
        let result = regex::evaluate_websocket_text(7, payload, &prost_types::Struct::default())
            .expect("evaluate WebSocket text");

        assert_eq!(result.sequence, 7);
        assert_eq!(result.decision, Decision::Allow as i32);
        assert_eq!(
            result.replacement,
            Some(
                openshell_core::proto::web_socket_message_result::Replacement::Text(
                    r#"{"type":"response.create","input":"[REDACTED] [REDACTED]"}"#.into()
                )
            )
        );
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].r#type, "regex.openai");
        assert_eq!(result.findings[0].count, 2);
        assert_eq!(
            result.metadata.get("regex_matches_replaced"),
            Some(&"2".to_string())
        );
    }

    #[test]
    fn regex_websocket_no_match_returns_no_replacement_or_findings() {
        let result = regex::evaluate_websocket_text(
            1,
            r#"{"type":"response.create","input":"public"}"#,
            &prost_types::Struct::default(),
        )
        .expect("evaluate WebSocket text");

        assert!(result.replacement.is_none());
        assert!(result.findings.is_empty());
        assert!(result.metadata.is_empty());
    }

    #[test]
    fn regex_websocket_rejects_oversize_messages() {
        assert!(
            regex::evaluate_websocket_text(
                1,
                &"a".repeat(256 * 1024 + 1),
                &prost_types::Struct::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn websocket_sequence_lower_bound_accepts_gaps_and_rejects_reuse() {
        let mut lower_bound = Some(1);
        advance_sequence_lower_bound(&mut lower_bound, 2).expect("first delivered sequence");
        assert_eq!(lower_bound, Some(3));
        assert!(advance_sequence_lower_bound(&mut lower_bound, 2).is_err());
        assert!(advance_sequence_lower_bound(&mut lower_bound, 1).is_err());

        advance_sequence_lower_bound(&mut lower_bound, 7).expect("forward gap");
        assert_eq!(lower_bound, Some(8));

        advance_sequence_lower_bound(&mut lower_bound, u64::MAX).expect("last sequence");
        assert_eq!(lower_bound, None);
        assert!(advance_sequence_lower_bound(&mut lower_bound, u64::MAX).is_err());
    }

    #[test]
    fn regex_rejects_non_utf8_borrowed_body() {
        let error =
            evaluate_body(&[0xff], &prost_types::Struct::default()).expect_err("non-UTF-8 body");
        assert!(error.to_string().contains("requires UTF-8 request bodies"));
    }
}
