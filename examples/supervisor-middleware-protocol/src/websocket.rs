// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) fn stream<S>(mut events: S) -> WebSocketResponseStream
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
                    if preflight.phase != PHASE as i32 {
                        Err(Status::invalid_argument("expected PRE_CREDENTIALS"))
                    } else {
                        config = Some(());
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
                        evaluate_message(&message).map(|result| {
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
                    "invalid protocol demo WebSocket session lifecycle",
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
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(results_rx))
}

fn evaluate_message(message: &WebSocketMessage) -> Result<WebSocketMessageResult, Status> {
    let Some(web_socket_message::Payload::Text(text)) = message.payload.as_ref() else {
        return Err(Status::invalid_argument("expected text message"));
    };
    Ok(WebSocketMessageResult {
        sequence: message.sequence,
        decision: Decision::Allow as i32,
        replacement: Some(web_socket_message_result::Replacement::Text(
            text.to_ascii_uppercase(),
        )),
        ..Default::default()
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
    use super::*;
    #[tokio::test]
    async fn lifecycle_transforms_a_complete_message() {
        tokio::time::timeout(std::time::Duration::from_secs(5), check_lifecycle())
            .await
            .expect("WebSocket lifecycle completes");
    }

    async fn check_lifecycle() {
        use openshell_core::proto::{
            MiddlewareSessionEnd, WebSocketPreflight, WebSocketSessionStart,
        };
        let events = [
            web_socket_session_event::Event::Preflight(WebSocketPreflight {
                phase: PHASE as i32,
                ..Default::default()
            }),
            web_socket_session_event::Event::SessionStart(WebSocketSessionStart::default()),
            web_socket_session_event::Event::Message(WebSocketMessage {
                sequence: 1,
                payload: Some(web_socket_message::Payload::Text("hello".into())),
            }),
            web_socket_session_event::Event::SessionEnd(MiddlewareSessionEnd::default()),
        ];
        let mut results = stream(tokio_stream::iter(
            events.map(|event| Ok(WebSocketSessionEvent { event: Some(event) })),
        ));
        assert!(results.next().await.unwrap().is_ok());
        let result = results.next().await.unwrap().unwrap();
        let Some(web_socket_session_event_result::Result::MessageResult(message)) = result.result
        else {
            panic!("message result")
        };
        assert_eq!(
            message.replacement,
            Some(web_socket_message_result::Replacement::Text("HELLO".into()))
        );
        assert!(results.next().await.is_none());
    }
}
