// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP request pre-credentials stream adapter for remote middleware.

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt as _;
use tokio::sync::mpsc;

use openshell_core::middleware::{HttpRequestResultStream, HttpRequestView};
use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpRequestBodyEnd, HttpRequestBodyMode,
    HttpRequestBodyUnit, HttpRequestEvent, HttpRequestEventResult, HttpRequestPreflight,
    HttpRequestResult, MiddlewareExchangeProtocolError, MiddlewareSessionEnd,
    MiddlewareSessionEndReason, MiddlewareSessionProtocolError, http_request_body_result,
    http_request_body_transform, http_request_body_unit, http_request_event,
    http_request_event_result, http_request_preflight_result, middleware_session_protocol_error,
};

use crate::remote::GrpcMiddlewareService;

const STREAM_CHANNEL_CAPACITY: usize = 1;
const MAX_STREAM_UNIT_BYTES: usize = 64 * 1024;
const MAX_STAGE_FINDINGS: usize = 32;
const MAX_STAGE_METADATA_ENTRIES: usize = 64;

pub async fn evaluate_remote_request(
    service: &GrpcMiddlewareService,
    request: HttpRequestView<'_>,
    max_payload_bytes: usize,
) -> Result<tonic::Response<HttpRequestResult>, tonic::Status> {
    let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
    let mut responses = service.open_http_request_pre_credentials(receiver).await?;
    send(
        &sender,
        HttpRequestEvent {
            event: Some(http_request_event::Event::Preflight(HttpRequestPreflight {
                context: Some(request.context().clone()),
                target: Some(request.target().clone()),
                headers: request.headers().to_vec(),
                middleware_name: request.middleware_name().to_string(),
                config: Some(request.config().clone()),
                max_payload_bytes: max_payload_bytes as u64,
            })),
        },
    )
    .await?;

    let Some(http_request_event_result::Result::PreflightResult(preflight)) =
        next_result(&mut responses).await?.result
    else {
        return protocol_failure(&sender, "expected preflight result").await;
    };
    let Ok(mut diagnostics) = Diagnostics::new(
        preflight.reason,
        preflight.reason_code,
        preflight.findings,
        preflight.metadata,
    ) else {
        return protocol_failure(&sender, "invalid preflight diagnostics").await;
    };
    let Ok(decision) = Decision::try_from(preflight.decision) else {
        return protocol_failure(&sender, "invalid preflight decision").await;
    };

    match decision {
        Decision::Deny => {
            if preflight.action.is_some() {
                return protocol_failure(&sender, "denied preflight must not select an action")
                    .await;
            }
            end(&sender, MiddlewareSessionEndReason::MiddlewareDenial).await;
            return Ok(tonic::Response::new(diagnostics.into_result(
                Decision::Deny,
                Vec::new(),
                false,
                Vec::new(),
            )));
        }
        Decision::Allow => {}
        Decision::Unspecified => {
            return protocol_failure(&sender, "preflight decision is required").await;
        }
    }

    let Some(action) = preflight.action else {
        return protocol_failure(&sender, "allowed preflight requires an action").await;
    };
    let inspect = match action {
        http_request_preflight_result::Action::Skip(_) => {
            end(&sender, MiddlewareSessionEndReason::StageSkipped).await;
            return Ok(tonic::Response::new(diagnostics.into_result(
                Decision::Allow,
                Vec::new(),
                false,
                Vec::new(),
            )));
        }
        http_request_preflight_result::Action::Inspect(inspect) => inspect,
    };
    let Ok(body_mode) = HttpRequestBodyMode::try_from(inspect.body_mode) else {
        return protocol_failure(&sender, "invalid request body mode").await;
    };
    if body_mode == HttpRequestBodyMode::Unspecified {
        return protocol_failure(&sender, "request body mode is required").await;
    }
    let header_mutations = inspect.header_mutations;

    if body_mode == HttpRequestBodyMode::HeadersOnly {
        end(&sender, MiddlewareSessionEndReason::Normal).await;
        return Ok(tonic::Response::new(diagnostics.into_result(
            Decision::Allow,
            Vec::new(),
            false,
            header_mutations,
        )));
    }

    let mut output = Vec::new();
    let mut transformed = false;
    let mut final_sequence = 0;
    match body_mode {
        HttpRequestBodyMode::WholeBodyBytes => {
            final_sequence = 1;
            match exchange_body(
                &sender,
                &mut responses,
                1,
                request.body().to_vec(),
                max_payload_bytes,
                &mut diagnostics,
            )
            .await?
            {
                BodyOutcome::Continue {
                    data,
                    transformed: unit_transformed,
                } => {
                    transformed |= unit_transformed;
                    if !append_output(&mut output, data, max_payload_bytes) {
                        return protocol_failure(
                            &sender,
                            "transformed request body exceeds payload limit",
                        )
                        .await;
                    }
                }
                BodyOutcome::Deny => {
                    end(&sender, MiddlewareSessionEndReason::MiddlewareDenial).await;
                    return Ok(tonic::Response::new(diagnostics.into_result(
                        Decision::Deny,
                        Vec::new(),
                        false,
                        Vec::new(),
                    )));
                }
            }
        }
        HttpRequestBodyMode::StreamBytes => {
            let unit_limit = max_payload_bytes.clamp(1, MAX_STREAM_UNIT_BYTES);
            for (index, unit) in request.body().chunks(unit_limit).enumerate() {
                let sequence = index as u64 + 1;
                final_sequence = sequence;
                match exchange_body(
                    &sender,
                    &mut responses,
                    sequence,
                    unit.to_vec(),
                    max_payload_bytes,
                    &mut diagnostics,
                )
                .await?
                {
                    BodyOutcome::Continue {
                        data,
                        transformed: unit_transformed,
                    } => {
                        transformed |= unit_transformed;
                        if !append_output(&mut output, data, max_payload_bytes) {
                            return protocol_failure(
                                &sender,
                                "transformed request body exceeds payload limit",
                            )
                            .await;
                        }
                    }
                    BodyOutcome::Deny => {
                        end(&sender, MiddlewareSessionEndReason::MiddlewareDenial).await;
                        return Ok(tonic::Response::new(diagnostics.into_result(
                            Decision::Deny,
                            Vec::new(),
                            false,
                            Vec::new(),
                        )));
                    }
                }
            }
        }
        HttpRequestBodyMode::HeadersOnly | HttpRequestBodyMode::Unspecified => unreachable!(),
    }

    send(
        &sender,
        HttpRequestEvent {
            event: Some(http_request_event::Event::BodyEnd(HttpRequestBodyEnd {
                final_sequence,
            })),
        },
    )
    .await?;
    end(&sender, MiddlewareSessionEndReason::Normal).await;
    Ok(tonic::Response::new(diagnostics.into_result(
        Decision::Allow,
        output,
        transformed,
        header_mutations,
    )))
}

async fn exchange_body(
    sender: &mpsc::Sender<HttpRequestEvent>,
    responses: &mut HttpRequestResultStream,
    sequence: u64,
    input: Vec<u8>,
    max_payload_bytes: usize,
    diagnostics: &mut Diagnostics,
) -> Result<BodyOutcome, tonic::Status> {
    send(
        sender,
        HttpRequestEvent {
            event: Some(http_request_event::Event::Body(HttpRequestBodyUnit {
                sequence,
                payload: Some(http_request_body_unit::Payload::Data(input.clone())),
            })),
        },
    )
    .await?;
    let Some(http_request_event_result::Result::BodyResult(result)) =
        next_result(responses).await?.result
    else {
        return protocol_failure(sender, "expected body result").await;
    };
    if result.sequence != sequence {
        return protocol_failure(sender, "body result sequence mismatch").await;
    }
    if diagnostics
        .extend(
            result.reason,
            result.reason_code,
            result.findings,
            result.metadata,
        )
        .is_err()
    {
        return protocol_failure(sender, "invalid body diagnostics").await;
    }
    let Ok(decision) = Decision::try_from(result.decision) else {
        return protocol_failure(sender, "invalid body decision").await;
    };
    match decision {
        Decision::Deny => {
            if result.action.is_some() {
                return protocol_failure(sender, "denied body result must not select an action")
                    .await;
            }
            Ok(BodyOutcome::Deny)
        }
        Decision::Allow => match result.action {
            Some(http_request_body_result::Action::PassThrough(_)) => Ok(BodyOutcome::Continue {
                data: input,
                transformed: false,
            }),
            Some(http_request_body_result::Action::Transform(transform)) => {
                let Some(http_request_body_transform::Replacement::Data(replacement)) =
                    transform.replacement
                else {
                    return protocol_failure(sender, "transform replacement is required").await;
                };
                if replacement.len() > max_payload_bytes {
                    return protocol_failure(sender, "body replacement exceeds payload limit")
                        .await;
                }
                Ok(BodyOutcome::Continue {
                    data: replacement,
                    transformed: true,
                })
            }
            None => protocol_failure(sender, "allowed body result requires an action").await,
        },
        Decision::Unspecified => protocol_failure(sender, "body decision is required").await,
    }
}

enum BodyOutcome {
    Continue { data: Vec<u8>, transformed: bool },
    Deny,
}

struct Diagnostics {
    reason: String,
    reason_code: String,
    findings: Vec<Finding>,
    metadata: HashMap<String, String>,
}

impl Diagnostics {
    fn new(
        reason: String,
        reason_code: String,
        findings: Vec<Finding>,
        metadata: HashMap<String, String>,
    ) -> Result<Self, tonic::Status> {
        let diagnostics = Self {
            reason,
            reason_code,
            findings,
            metadata,
        };
        diagnostics.validate()?;
        Ok(diagnostics)
    }

    fn extend(
        &mut self,
        reason: String,
        reason_code: String,
        findings: Vec<Finding>,
        metadata: HashMap<String, String>,
    ) -> Result<(), tonic::Status> {
        if !reason.is_empty() {
            self.reason = reason;
        }
        if !reason_code.is_empty() {
            self.reason_code = reason_code;
        }
        self.findings.extend(findings);
        self.metadata.extend(metadata);
        self.validate()
    }

    fn validate(&self) -> Result<(), tonic::Status> {
        if self.findings.len() > MAX_STAGE_FINDINGS {
            return Err(tonic::Status::invalid_argument(
                "request stage returned too many findings",
            ));
        }
        if self.metadata.len() > MAX_STAGE_METADATA_ENTRIES {
            return Err(tonic::Status::invalid_argument(
                "request stage returned too many metadata entries",
            ));
        }
        Ok(())
    }

    fn into_result(
        self,
        decision: Decision,
        body: Vec<u8>,
        has_body: bool,
        header_mutations: Vec<HeaderMutation>,
    ) -> HttpRequestResult {
        HttpRequestResult {
            decision: decision as i32,
            reason: self.reason,
            body,
            has_body,
            header_mutations,
            findings: self.findings,
            metadata: self.metadata,
            reason_code: self.reason_code,
        }
    }
}

fn append_output(output: &mut Vec<u8>, data: Vec<u8>, max_payload_bytes: usize) -> bool {
    if output.len().saturating_add(data.len()) > max_payload_bytes {
        return false;
    }
    output.extend_from_slice(&data);
    true
}

async fn next_result(
    responses: &mut HttpRequestResultStream,
) -> Result<HttpRequestEventResult, tonic::Status> {
    match responses.next().await {
        Some(Ok(result)) => Ok(result),
        Some(Err(status)) => Err(status),
        None => Err(tonic::Status::unavailable(
            "middleware closed request result stream before replying",
        )),
    }
}

async fn send(
    sender: &mpsc::Sender<HttpRequestEvent>,
    event: HttpRequestEvent,
) -> Result<(), tonic::Status> {
    sender
        .send(event)
        .await
        .map_err(|_| tonic::Status::unavailable("middleware closed request event stream"))
}

async fn end(sender: &mpsc::Sender<HttpRequestEvent>, reason: MiddlewareSessionEndReason) {
    let event = HttpRequestEvent {
        event: Some(http_request_event::Event::SessionEnd(
            MiddlewareSessionEnd {
                reason: reason as i32,
                protocol_error: None,
            },
        )),
    };
    let _ = tokio::time::timeout(Duration::from_millis(10), sender.send(event)).await;
}

async fn protocol_failure<T>(
    sender: &mpsc::Sender<HttpRequestEvent>,
    message: &'static str,
) -> Result<T, tonic::Status> {
    let event = HttpRequestEvent {
        event: Some(http_request_event::Event::SessionEnd(
            MiddlewareSessionEnd {
                reason: MiddlewareSessionEndReason::ProtocolError as i32,
                protocol_error: Some(MiddlewareSessionProtocolError {
                    domain: Some(
                        middleware_session_protocol_error::Domain::MiddlewareExchange(
                            MiddlewareExchangeProtocolError {},
                        ),
                    ),
                }),
            },
        )),
    };
    let _ = tokio::time::timeout(Duration::from_millis(10), sender.send(event)).await;
    Err(tonic::Status::invalid_argument(message))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openshell_core::middleware::{
        HttpRequestResultStream, SupervisorMiddlewareEndpoint, WebSocketResponseStream,
    };
    use openshell_core::proto::{
        HttpRequestBodyPassThrough, HttpRequestBodyResult, HttpRequestBodyTransform,
        HttpRequestEventResult, HttpRequestPreflightInspect, HttpRequestPreflightResult,
        HttpRequestResult, MiddlewareManifest, RequestContext, SupervisorMiddlewarePhase,
        ValidateConfigRequest, ValidateConfigResponse, http_request_body_result,
        http_request_body_transform, http_request_event, http_request_event_result,
        http_request_preflight_result,
    };

    use super::*;

    #[derive(Clone, Copy)]
    enum Script {
        Whole,
        Stream,
        PassThrough,
        Deny,
    }

    struct ScriptedEndpoint {
        script: Script,
    }

    #[tonic::async_trait]
    impl SupervisorMiddlewareEndpoint for ScriptedEndpoint {
        async fn describe(
            &self,
            _request: tonic::Request<()>,
        ) -> Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest::default()))
        }

        async fn validate_config(
            &self,
            _request: tonic::Request<ValidateConfigRequest>,
        ) -> Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_http_request(
            &self,
            _request: tonic::Request<openshell_core::proto::HttpRequestEvaluation>,
        ) -> Result<tonic::Response<HttpRequestResult>, tonic::Status> {
            Err(tonic::Status::unimplemented("stream-only test service"))
        }

        async fn open_websocket_session(
            &self,
            _requests: mpsc::Receiver<openshell_core::proto::WebSocketSessionEvent>,
        ) -> Result<WebSocketResponseStream, tonic::Status> {
            Err(tonic::Status::unimplemented("request-only test service"))
        }

        async fn open_http_request_pre_credentials(
            &self,
            mut requests: mpsc::Receiver<HttpRequestEvent>,
        ) -> Result<HttpRequestResultStream, tonic::Status> {
            let script = self.script;
            let (sender, receiver) = mpsc::channel(1);
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let result = match event.event {
                        Some(http_request_event::Event::Preflight(_)) => {
                            let (decision, action) = match script {
                                Script::Deny => (Decision::Deny, None),
                                Script::Whole | Script::PassThrough => (
                                    Decision::Allow,
                                    Some(http_request_preflight_result::Action::Inspect(
                                        HttpRequestPreflightInspect {
                                            body_mode: HttpRequestBodyMode::WholeBodyBytes as i32,
                                            header_mutations: Vec::new(),
                                        },
                                    )),
                                ),
                                Script::Stream => (
                                    Decision::Allow,
                                    Some(http_request_preflight_result::Action::Inspect(
                                        HttpRequestPreflightInspect {
                                            body_mode: HttpRequestBodyMode::StreamBytes as i32,
                                            header_mutations: Vec::new(),
                                        },
                                    )),
                                ),
                            };
                            Some(HttpRequestEventResult {
                                result: Some(http_request_event_result::Result::PreflightResult(
                                    HttpRequestPreflightResult {
                                        decision: decision as i32,
                                        action,
                                        reason_code: if decision == Decision::Deny {
                                            "blocked".to_string()
                                        } else {
                                            String::new()
                                        },
                                        ..Default::default()
                                    },
                                )),
                            })
                        }
                        Some(http_request_event::Event::Body(body)) => {
                            let Some(http_request_body_unit::Payload::Data(mut data)) =
                                body.payload
                            else {
                                let _ = sender
                                    .send(Err(tonic::Status::invalid_argument("missing data")))
                                    .await;
                                break;
                            };
                            let action = match script {
                                Script::Whole => {
                                    data.reverse();
                                    http_request_body_result::Action::Transform(
                                        HttpRequestBodyTransform {
                                            replacement: Some(
                                                http_request_body_transform::Replacement::Data(
                                                    data,
                                                ),
                                            ),
                                        },
                                    )
                                }
                                Script::Stream => {
                                    data.make_ascii_uppercase();
                                    http_request_body_result::Action::Transform(
                                        HttpRequestBodyTransform {
                                            replacement: Some(
                                                http_request_body_transform::Replacement::Data(
                                                    data,
                                                ),
                                            ),
                                        },
                                    )
                                }
                                Script::PassThrough => {
                                    http_request_body_result::Action::PassThrough(
                                        HttpRequestBodyPassThrough {},
                                    )
                                }
                                Script::Deny => http_request_body_result::Action::PassThrough(
                                    HttpRequestBodyPassThrough {},
                                ),
                            };
                            Some(HttpRequestEventResult {
                                result: Some(http_request_event_result::Result::BodyResult(
                                    HttpRequestBodyResult {
                                        sequence: body.sequence,
                                        decision: Decision::Allow as i32,
                                        action: Some(action),
                                        ..Default::default()
                                    },
                                )),
                            })
                        }
                        Some(http_request_event::Event::SessionEnd(_)) => break,
                        Some(http_request_event::Event::BodyEnd(_)) | None => None,
                    };
                    if let Some(result) = result
                        && sender.send(Ok(result)).await.is_err()
                    {
                        break;
                    }
                }
            });
            Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
        }
    }

    async fn run(script: Script, body: &[u8], max_payload_bytes: usize) -> HttpRequestResult {
        let service = GrpcMiddlewareService::from_service(Arc::new(ScriptedEndpoint { script }));
        let context = RequestContext::default();
        let config = prost_types::Struct::default();
        let target = openshell_core::proto::HttpRequestTarget::default();
        evaluate_remote_request(
            &service,
            HttpRequestView::new(
                SupervisorMiddlewarePhase::PreCredentials,
                &context,
                &config,
                &target,
                &[],
                body,
                "scripted",
            ),
            max_payload_bytes,
        )
        .await
        .unwrap()
        .into_inner()
    }

    #[tokio::test]
    async fn whole_body_mode_transforms_one_unit() {
        let result = run(Script::Whole, b"abcdef", 64).await;
        assert_eq!(result.decision, Decision::Allow as i32);
        assert_eq!(result.body, b"fedcba");
        assert!(result.has_body);
    }

    #[tokio::test]
    async fn stream_mode_transforms_lockstep_units() {
        let body = vec![b'a'; MAX_STREAM_UNIT_BYTES + 1];
        let result = run(Script::Stream, &body, body.len()).await;
        assert_eq!(result.decision, Decision::Allow as i32);
        assert_eq!(result.body, vec![b'A'; body.len()]);
        assert!(result.has_body);
    }

    #[tokio::test]
    async fn pass_through_does_not_report_a_body_replacement() {
        let result = run(Script::PassThrough, b"unchanged", 64).await;
        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(!result.has_body);
    }

    #[tokio::test]
    async fn preflight_denial_needs_no_processing_action() {
        let result = run(Script::Deny, b"secret", 64).await;
        assert_eq!(result.decision, Decision::Deny as i32);
        assert_eq!(result.reason_code, "blocked");
        assert!(!result.has_body);
    }
}
