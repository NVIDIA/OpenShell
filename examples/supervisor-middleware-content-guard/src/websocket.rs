// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `SupervisorMiddleware.EvaluateWebSocketSession`. The HTTP protocol version
//! does not affect WebSocket bindings.

use openshell_core::middleware::WebSocketResponseStream;
use openshell_core::proto::{
    Decision, WebSocketMessage, WebSocketMessageResult, WebSocketPreflightAction,
    WebSocketPreflightDecision, WebSocketSessionEvent, WebSocketSessionEventResult,
    web_socket_message, web_socket_message_result, web_socket_session_event,
    web_socket_session_event_result,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

use crate::guard::{GuardConfig, MAX_PAYLOAD_BYTES, inspect};

pub(crate) fn session_stream<S>(mut events: S) -> WebSocketResponseStream
where
    S: Stream<Item = Result<WebSocketSessionEvent, Status>> + Send + Unpin + 'static,
{
    let (results_tx, results_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut config = None;
        let mut started = false;
        let mut sequence_lower_bound = Some(1_u64);

        while let Some(event) = events.next().await {
            let event = match event {
                Ok(event) => event,
                Err(error) => {
                    let _ = results_tx.send(Err(error)).await;
                    break;
                }
            };
            let result = match event.event {
                Some(web_socket_session_event::Event::Preflight(preflight))
                    if config.is_none() && !started =>
                {
                    if let Err(error) = crate::validate_phase(preflight.phase) {
                        Err(Status::invalid_argument(error))
                    } else {
                        match GuardConfig::parse(preflight.config.as_ref()) {
                            Ok(selected_config) => {
                                config = Some(selected_config);
                                Ok(Some(WebSocketSessionEventResult {
                                    result: Some(
                                        web_socket_session_event_result::Result::PreflightDecision(
                                            WebSocketPreflightDecision {
                                                action: WebSocketPreflightAction::Inspect as i32,
                                                ..Default::default()
                                            },
                                        ),
                                    ),
                                }))
                            }
                            Err(error) => Err(Status::invalid_argument(error)),
                        }
                    }
                }
                Some(web_socket_session_event::Event::SessionStart(_))
                    if config.is_some() && !started =>
                {
                    started = true;
                    Ok(None)
                }
                Some(web_socket_session_event::Event::Message(message)) if started => {
                    if let Err(error) =
                        advance_sequence_lower_bound(&mut sequence_lower_bound, message.sequence)
                    {
                        Err(error)
                    } else {
                        let selected_config = config.as_ref().expect("started stream has config");
                        evaluate_message(selected_config, &message).map(|result| {
                            Some(WebSocketSessionEventResult {
                                result: Some(
                                    web_socket_session_event_result::Result::MessageResult(result),
                                ),
                            })
                        })
                    }
                }
                Some(web_socket_session_event::Event::SessionEnd(_)) if config.is_some() => {
                    break;
                }
                _ => Err(Status::failed_precondition(
                    "invalid content guard WebSocket session lifecycle",
                )),
            };

            match result {
                Ok(Some(result)) => {
                    if results_tx.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = results_tx.send(Err(error)).await;
                    break;
                }
            }
        }
    });
    Box::pin(ReceiverStream::new(results_rx))
}

fn evaluate_message(
    config: &GuardConfig,
    message: &WebSocketMessage,
) -> Result<WebSocketMessageResult, Status> {
    let Some(web_socket_message::Payload::Text(payload)) = message.payload.as_ref() else {
        return Err(Status::invalid_argument(
            "content guard supports only WebSocket text messages",
        ));
    };
    let payload_bytes = u64::try_from(payload.len()).map_err(|_| {
        Status::invalid_argument("WebSocket text message length is not representable")
    })?;
    if payload_bytes > MAX_PAYLOAD_BYTES {
        return Err(Status::invalid_argument(format!(
            "WebSocket text message exceeds {MAX_PAYLOAD_BYTES} bytes"
        )));
    }
    let result = inspect(config, payload);
    Ok(WebSocketMessageResult {
        sequence: message.sequence,
        decision: if result.denied {
            Decision::Deny
        } else {
            Decision::Allow
        } as i32,
        replacement: result
            .replacement
            .map(web_socket_message_result::Replacement::Text),
        reason: result.reason,
        reason_code: result.reason_code,
        findings: result.findings,
        metadata: result.metadata,
    })
}

fn advance_sequence_lower_bound(
    lower_bound: &mut Option<u64>,
    sequence: u64,
) -> Result<(), Status> {
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

#[cfg(test)]
mod tests {
    use openshell_core::proto::{MiddlewareSessionEnd, WebSocketPreflight, WebSocketSessionStart};

    use super::*;
    use crate::PHASE;
    use crate::guard::test_support::config;

    fn event(event: web_socket_session_event::Event) -> Result<WebSocketSessionEvent, Status> {
        Ok(WebSocketSessionEvent { event: Some(event) })
    }

    #[tokio::test]
    async fn websocket_stream_redacts_text_messages() {
        let events = tokio_stream::iter([
            event(web_socket_session_event::Event::Preflight(
                WebSocketPreflight {
                    phase: PHASE as i32,
                    config: Some(config("redact", &["prototype-secret"], Some("[FILTERED]"))),
                    ..Default::default()
                },
            )),
            event(web_socket_session_event::Event::SessionStart(
                WebSocketSessionStart::default(),
            )),
            event(web_socket_session_event::Event::Message(WebSocketMessage {
                sequence: 1,
                payload: Some(web_socket_message::Payload::Text(
                    "contains prototype-secret".into(),
                )),
            })),
            event(web_socket_session_event::Event::SessionEnd(
                MiddlewareSessionEnd::default(),
            )),
        ]);
        let mut results = session_stream(events);

        let preflight = results
            .next()
            .await
            .expect("preflight result")
            .expect("valid preflight result");
        assert!(matches!(
            preflight.result,
            Some(web_socket_session_event_result::Result::PreflightDecision(
                WebSocketPreflightDecision { action, .. }
            )) if action == WebSocketPreflightAction::Inspect as i32
        ));

        let message = results
            .next()
            .await
            .expect("message result")
            .expect("valid message result");
        let Some(web_socket_session_event_result::Result::MessageResult(message)) = message.result
        else {
            panic!("expected message result");
        };
        assert_eq!(message.decision, Decision::Allow as i32);
        assert_eq!(
            message.replacement,
            Some(web_socket_message_result::Replacement::Text(
                "contains [FILTERED]".into()
            ))
        );
        assert_eq!(message.findings[0].count, 1);
        assert!(results.next().await.is_none());
    }

    #[test]
    fn websocket_deny_preserves_safe_diagnostics() {
        let config = GuardConfig::parse(Some(&config("deny", &["prototype-secret"], None)))
            .expect("valid config");
        let result = evaluate_message(
            &config,
            &WebSocketMessage {
                sequence: 7,
                payload: Some(web_socket_message::Payload::Text(
                    "contains prototype-secret".into(),
                )),
            },
        )
        .expect("message result");

        assert_eq!(result.sequence, 7);
        assert_eq!(result.decision, Decision::Deny as i32);
        assert_eq!(result.reason_code, "content_match");
        assert!(!result.reason.contains("prototype-secret"));
        assert!(result.replacement.is_none());
    }
}
