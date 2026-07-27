// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! First-party in-process supervisor middleware implementations.

mod regex;

use std::sync::Arc;

use miette::{Result, miette};
use openshell_core::middleware::{SupervisorMiddlewareEndpoint, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareManifest, SupervisorMiddlewarePhase,
    ValidateConfigRequest, ValidateConfigResponse, WebSocketDirection, WebSocketEvaluationRequest,
    WebSocketEvaluationResponse, WebSocketMessageType, WebSocketPreflightAction,
    WebSocketPreflightDecision, web_socket_evaluation_request, web_socket_evaluation_response,
};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

pub use regex::{NAME as BUILTIN_REGEX, RegexConfig, RegexMode};

/// Return the first-party services that the gateway and supervisor install.
pub fn services() -> Vec<Arc<dyn SupervisorMiddlewareEndpoint>> {
    vec![Arc::new(BuiltinMiddlewareService)]
}

/// Validate configuration for a first-party binding.
pub fn validate_config(implementation: &str, config: &prost_types::Struct) -> Result<()> {
    match implementation {
        BUILTIN_REGEX => regex::validate_config(config),
        other => Err(miette!(
            "middleware implementation '{other}' is not a registered OpenShell built-in"
        )),
    }
}

fn evaluate_http_request(evaluation: &HttpRequestEvaluation) -> Result<HttpRequestResult> {
    match evaluation.middleware_name.as_str() {
        BUILTIN_REGEX => regex::evaluate_http_request(evaluation),
        other => Err(miette!(
            "middleware implementation '{other}' is not a registered OpenShell built-in"
        )),
    }
}

/// Built-in regex service exposed through the standard middleware contract.
#[derive(Debug, Default)]
pub struct BuiltinMiddlewareService;

impl BuiltinMiddlewareService {
    fn websocket_stream<S>(mut requests: S) -> WebSocketResponseStream
    where
        S: Stream<Item = std::result::Result<WebSocketEvaluationRequest, Status>>
            + Send
            + Unpin
            + 'static,
    {
        let (responses_tx, responses_rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut config = None;
            let mut started = false;
            let mut next_sequence = 1u64;

            while let Some(request) = requests.next().await {
                let request = match request {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = responses_tx.send(Err(error)).await;
                        break;
                    }
                };
                let response = match request.request {
                    Some(web_socket_evaluation_request::Request::Preflight(preflight))
                        if config.is_none() && !started =>
                    {
                        if preflight.middleware_name != BUILTIN_REGEX {
                            Err(Status::invalid_argument(
                                "unknown built-in WebSocket middleware",
                            ))
                        } else if preflight.phase
                            != SupervisorMiddlewarePhase::PreCredentials as i32
                            || preflight.direction != WebSocketDirection::ClientToUpstream as i32
                        {
                            Err(Status::invalid_argument(
                                "unsupported built-in WebSocket binding",
                            ))
                        } else {
                            let selected_config = preflight.config.unwrap_or_default();
                            match regex::validate_config(&selected_config) {
                                Ok(()) => {
                                    config = Some(selected_config);
                                    Ok(Some(WebSocketEvaluationResponse {
                                        response: Some(
                                            web_socket_evaluation_response::Response::PreflightDecision(
                                                WebSocketPreflightDecision {
                                                    action: WebSocketPreflightAction::Inspect as i32,
                                                },
                                            ),
                                        ),
                                    }))
                                }
                                Err(error) => Err(Status::invalid_argument(error.to_string())),
                            }
                        }
                    }
                    Some(web_socket_evaluation_request::Request::SessionStart(_))
                        if config.is_some() && !started =>
                    {
                        started = true;
                        Ok(None)
                    }
                    Some(web_socket_evaluation_request::Request::Message(message)) if started => {
                        if message.sequence != next_sequence {
                            Err(Status::invalid_argument(
                                "WebSocket message sequence is not monotonic",
                            ))
                        } else if message.direction != WebSocketDirection::ClientToUpstream as i32
                            || message.message_type != WebSocketMessageType::Text as i32
                        {
                            Err(Status::invalid_argument(
                                "openshell/regex supports only client-to-upstream WebSocket text messages",
                            ))
                        } else {
                            let selected_config =
                                config.as_ref().expect("started stream has config");
                            match regex::evaluate_websocket_text(
                                message.sequence,
                                &message.payload,
                                selected_config,
                            ) {
                                Ok(result) => {
                                    next_sequence = next_sequence.saturating_add(1);
                                    Ok(Some(WebSocketEvaluationResponse {
                                        response: Some(
                                            web_socket_evaluation_response::Response::MessageResult(
                                                result,
                                            ),
                                        ),
                                    }))
                                }
                                Err(error) => Err(Status::invalid_argument(error.to_string())),
                            }
                        }
                    }
                    Some(web_socket_evaluation_request::Request::SessionEnd(_))
                        if config.is_some() =>
                    {
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

#[tonic::async_trait]
impl SupervisorMiddleware for BuiltinMiddlewareService {
    type EvaluateWebSocketStream = WebSocketResponseStream;

    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: BUILTIN_REGEX.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: regex::describe(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let config = request.config.unwrap_or_default();
        Ok(Response::new(
            match validate_config(&request.middleware_name, &config) {
                Ok(()) => ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
                Err(error) => ValidateConfigResponse {
                    valid: false,
                    reason: error.to_string(),
                },
            },
        ))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        evaluate_http_request(&request.into_inner())
            .map(Response::new)
            .map_err(|error| Status::invalid_argument(error.to_string()))
    }

    async fn evaluate_web_socket(
        &self,
        request: Request<tonic::Streaming<WebSocketEvaluationRequest>>,
    ) -> Result<Response<Self::EvaluateWebSocketStream>, Status> {
        Ok(Response::new(Self::websocket_stream(request.into_inner())))
    }
}

#[tonic::async_trait]
impl SupervisorMiddlewareEndpoint for BuiltinMiddlewareService {
    async fn describe(&self, request: Request<()>) -> Result<Response<MiddlewareManifest>, Status> {
        SupervisorMiddleware::describe(self, request).await
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        SupervisorMiddleware::validate_config(self, request).await
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        SupervisorMiddleware::evaluate_http_request(self, request).await
    }

    async fn open_websocket(
        &self,
        receiver: tokio::sync::mpsc::Receiver<WebSocketEvaluationRequest>,
    ) -> Result<WebSocketResponseStream, Status> {
        Ok(Self::websocket_stream(
            tokio_stream::wrappers::ReceiverStream::new(receiver).map(Ok),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        Decision, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
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

    #[tokio::test]
    async fn service_describes_regex_binding() {
        let manifest = SupervisorMiddleware::describe(&BuiltinMiddlewareService, Request::new(()))
            .await
            .expect("describe")
            .into_inner();
        assert_eq!(manifest.bindings.len(), 2);
        assert_eq!(
            manifest.bindings[0].operation,
            SupervisorMiddlewareOperation::HttpRequest as i32
        );
        assert_eq!(
            manifest.bindings[0].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(manifest.bindings[0].max_body_bytes, 256 * 1024);
        assert_eq!(manifest.bindings[0].max_message_bytes, 0);
        assert_eq!(
            manifest.bindings[1].operation,
            SupervisorMiddlewareOperation::WebsocketMessage as i32
        );
        assert_eq!(
            manifest.bindings[1].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(manifest.bindings[1].max_body_bytes, 0);
        assert_eq!(manifest.bindings[1].max_message_bytes, 256 * 1024);
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
    fn regex_replacement_evaluates_through_binding() {
        let result = evaluate_http_request(&HttpRequestEvaluation {
            middleware_name: BUILTIN_REGEX.into(),
            body: br#"{"password":"top-secret","token":"sk-ABCDEFGHIJKLMNOP"}"#.to_vec(),
            config: Some(prost_types::Struct::default()),
            ..Default::default()
        })
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

    #[test]
    fn regex_replacement_does_not_parse_keyword_assignments() {
        let body = concat!(
            r#"{"password":"alpha beta","secret":"alpha,beta","api_key":"alpha\"beta"}"#,
            "\npassword=alpha\nnotpassword=omega"
        );
        let result = evaluate_http_request(&HttpRequestEvaluation {
            middleware_name: BUILTIN_REGEX.into(),
            body: body.as_bytes().to_vec(),
            config: Some(prost_types::Struct::default()),
            ..Default::default()
        })
        .expect("evaluate regex binding");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(!result.has_body);
        assert_eq!(result.body, body.as_bytes());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn regex_websocket_text_reuses_findings_and_metadata_semantics() {
        let payload =
            br#"{"type":"response.create","input":"sk-ABCDEFGHIJKLMNOP sk-QRSTUVWXYZabcdef"}"#;
        let result = regex::evaluate_websocket_text(7, payload, &prost_types::Struct::default())
            .expect("evaluate WebSocket text");

        assert_eq!(result.sequence, 7);
        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(result.has_replacement);
        assert_eq!(
            String::from_utf8(result.replacement).expect("replacement UTF-8"),
            r#"{"type":"response.create","input":"[REDACTED] [REDACTED]"}"#
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
            br#"{"type":"response.create","input":"public"}"#,
            &prost_types::Struct::default(),
        )
        .expect("evaluate WebSocket text");

        assert!(!result.has_replacement);
        assert!(result.replacement.is_empty());
        assert!(result.findings.is_empty());
        assert!(result.metadata.is_empty());
    }

    #[test]
    fn regex_websocket_rejects_invalid_utf8_and_oversize_messages() {
        assert!(
            regex::evaluate_websocket_text(1, &[0xff], &prost_types::Struct::default()).is_err()
        );
        assert!(
            regex::evaluate_websocket_text(
                1,
                &vec![b'a'; 256 * 1024 + 1],
                &prost_types::Struct::default(),
            )
            .is_err()
        );
    }
}
