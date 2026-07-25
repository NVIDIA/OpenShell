// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Forward-direction WebSocket middleware session runner.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::time::Instant;

use openshell_core::proto::{
    Decision, RequestContext, SupervisorMiddlewarePhase, WebSocketDirection,
    WebSocketEvaluationRequest, WebSocketMessage, WebSocketMessageResult, WebSocketMessageType,
    WebSocketPreflight, WebSocketPreflightAction, WebSocketSessionEnd, WebSocketSessionEndReason,
    WebSocketSessionStart, web_socket_evaluation_request, web_socket_evaluation_response,
};

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_BODY_BYTES,
    MAX_MIDDLEWARE_CHAIN_TIMEOUT, MAX_MIDDLEWARE_CONFIG_BYTES, MAX_MIDDLEWARE_CONTEXT_BYTES,
    MAX_MIDDLEWARE_FINDING_BYTES, MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_METADATA_BYTES,
    MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT, MAX_MIDDLEWARE_REASON_BYTES,
    MIDDLEWARE_GRPC_MESSAGE_BYTES, MiddlewareDenial, NamespacedFinding, OnError,
    is_stable_reason_code, middleware_denial_reason,
};

const STREAM_CHANNEL_CAPACITY: usize = 4;
const MAX_REQUESTED_SUBPROTOCOLS: usize = 32;
const MAX_SUBPROTOCOL_BYTES: usize = 4 * 1024;
const MAX_SELECTED_SUBPROTOCOL_BYTES: usize = 256;
#[derive(Debug, Clone)]
pub struct WebSocketPreflightInput {
    pub session_id: String,
    pub request_id: String,
    pub sandbox_id: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Raw request path without a query string.
    pub path: String,
    pub requested_subprotocols: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketInvocationOutcome {
    Inspect,
    Skip,
    Allow,
    Deny,
    FailOpen,
    FailClosed,
}

#[derive(Debug, Clone)]
pub struct WebSocketInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: WebSocketInvocationOutcome,
    pub sequence: Option<u64>,
    pub original_size: usize,
    pub replacement_size: Option<usize>,
    pub transformed: bool,
    pub failed: bool,
    /// The stage stream became unusable and will be bypassed for the rest of
    /// this session when its policy is `fail_open`.
    pub stage_disabled: bool,
    pub reason_code: Option<String>,
}

pub struct WebSocketPreflightResult {
    pub allowed: bool,
    pub reason: String,
    pub session: Option<WebSocketSession>,
    pub invocations: Vec<WebSocketInvocation>,
    pub saturated: bool,
}

#[derive(Debug)]
pub struct WebSocketSessionStartOutcome {
    pub allowed: bool,
    pub reason: String,
    pub invocations: Vec<WebSocketInvocation>,
}

#[derive(Debug)]
pub struct WebSocketMessageOutcome {
    pub allowed: bool,
    pub reason: String,
    pub payload: Vec<u8>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<WebSocketInvocation>,
    pub denial: Option<MiddlewareDenial>,
    pub saturated: bool,
    pub platform_oversize: bool,
}

struct WebSocketStage {
    entry: DescribedChainEntry,
    sender: mpsc::Sender<WebSocketEvaluationRequest>,
    responses: tonic::Streaming<openshell_core::proto::WebSocketEvaluationResponse>,
    active: bool,
}

pub struct WebSocketSession {
    runner: ChainRunner,
    stages: Vec<WebSocketStage>,
    next_sequence: u64,
}

enum OpenStage {
    Inspect(Box<WebSocketStage>, WebSocketInvocation),
    Skip(WebSocketInvocation),
    Failed(DescribedChainEntry, &'static str),
}

impl ChainRunner {
    pub async fn reserve_middleware_work(&self) -> miette::Result<super::MiddlewareAdmission> {
        if let Ok(permit) = Arc::clone(&self.registry.admission).try_acquire_owned() {
            Ok(super::MiddlewareAdmission {
                _work: permit,
                saturated: false,
            })
        } else {
            let waiter = Arc::clone(&self.registry.admission_waiters)
                .try_acquire_owned()
                .map_err(|_| {
                    miette::miette!(
                        "middleware admission queue is full; refusing additional buffered work"
                    )
                })?;
            let permit = Arc::clone(&self.registry.admission)
                .acquire_owned()
                .await
                .map_err(|_| miette::miette!("middleware admission semaphore closed"))?;
            drop(waiter);
            Ok(super::MiddlewareAdmission {
                _work: permit,
                saturated: true,
            })
        }
    }

    pub async fn preflight_websocket(
        &self,
        entries: &[ChainEntry],
        input: WebSocketPreflightInput,
    ) -> miette::Result<WebSocketPreflightResult> {
        validate_preflight_input(&input)?;
        let described = self.describe_websocket_chain(entries).await?;
        if described.is_empty() {
            return Ok(WebSocketPreflightResult {
                allowed: true,
                reason: String::new(),
                session: None,
                invocations: Vec::new(),
                saturated: false,
            });
        }

        // One permit covers the complete concurrent preflight fan-out. Permit
        // wait is deliberate backpressure and is excluded from every deadline.
        let permit = self.reserve_middleware_work().await?;
        let saturated = permit.saturated();
        let opened = join_all(
            described
                .into_iter()
                .map(|entry| open_stage(entry, input.clone())),
        )
        .await;

        let mut stages = Vec::new();
        let mut invocations = Vec::new();
        let mut fail_closed_reason = None;
        for result in opened {
            match result {
                OpenStage::Inspect(stage, invocation) => {
                    stages.push(*stage);
                    invocations.push(invocation);
                }
                OpenStage::Skip(invocation) => invocations.push(invocation),
                OpenStage::Failed(entry, reason) => {
                    let invocation = failure_invocation(&entry, None, 0, reason);
                    if entry.entry.on_error == OnError::FailClosed {
                        fail_closed_reason
                            .get_or_insert_with(|| format!("middleware_failed: {reason}"));
                    }
                    invocations.push(invocation);
                }
            }
        }

        if let Some(reason) = fail_closed_reason {
            end_stages(&mut stages, WebSocketSessionEndReason::MiddlewareFailure).await;
            return Ok(WebSocketPreflightResult {
                allowed: false,
                reason,
                session: None,
                invocations,
                saturated,
            });
        }

        Ok(WebSocketPreflightResult {
            allowed: true,
            reason: String::new(),
            session: (!stages.is_empty()).then_some(WebSocketSession {
                runner: self.clone(),
                stages,
                next_sequence: 1,
            }),
            invocations,
            saturated,
        })
    }
}

impl WebSocketSession {
    pub async fn reserve_message(&self) -> miette::Result<super::MiddlewareAdmission> {
        self.runner.reserve_middleware_work().await
    }

    pub async fn start(&mut self, selected_subprotocol: &str) -> WebSocketSessionStartOutcome {
        if selected_subprotocol.len() > MAX_SELECTED_SUBPROTOCOL_BYTES {
            return WebSocketSessionStartOutcome {
                allowed: false,
                reason: "middleware_failed: selected_subprotocol_over_capacity".to_string(),
                invocations: Vec::new(),
            };
        }
        let mut invocations = Vec::new();
        let mut fail_closed = None;
        for stage in &mut self.stages {
            if !stage.active {
                continue;
            }
            let request = WebSocketEvaluationRequest {
                request: Some(web_socket_evaluation_request::Request::SessionStart(
                    WebSocketSessionStart {
                        selected_subprotocol: selected_subprotocol.to_string(),
                    },
                )),
            };
            let sent = tokio::time::timeout(stage.entry.timeout, stage.sender.send(request)).await;
            if !matches!(sent, Ok(Ok(()))) {
                stage.active = false;
                let reason = "session_start_send_failed";
                let mut invocation = failure_invocation(&stage.entry, None, 0, reason);
                invocation.stage_disabled = true;
                if stage.entry.entry.on_error == OnError::FailClosed {
                    fail_closed.get_or_insert_with(|| format!("middleware_failed: {reason}"));
                }
                invocations.push(invocation);
            }
        }
        WebSocketSessionStartOutcome {
            allowed: fail_closed.is_none(),
            reason: fail_closed.unwrap_or_default(),
            invocations,
        }
    }

    pub async fn evaluate_text(&mut self, payload: Vec<u8>) -> WebSocketMessageOutcome {
        let admission = self.reserve_message().await.ok();
        self.evaluate_text_admitted(payload, admission).await
    }

    pub async fn evaluate_text_admitted(
        &mut self,
        payload: Vec<u8>,
        admission: Option<super::MiddlewareAdmission>,
    ) -> WebSocketMessageOutcome {
        if payload.len() > MAX_MIDDLEWARE_BODY_BYTES {
            return WebSocketMessageOutcome {
                allowed: false,
                reason: "websocket_message_over_platform_capacity".to_string(),
                payload,
                findings: Vec::new(),
                metadata: BTreeMap::new(),
                invocations: Vec::new(),
                denial: None,
                saturated: false,
                platform_oversize: true,
            };
        }

        let Some(permit) = admission else {
            return WebSocketMessageOutcome {
                allowed: false,
                reason: "middleware_admission_over_capacity".to_string(),
                payload,
                findings: Vec::new(),
                metadata: BTreeMap::new(),
                invocations: Vec::new(),
                denial: None,
                saturated: true,
                platform_oversize: false,
            };
        };
        let saturated = permit.saturated();
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let mut current = payload;
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut invocations = Vec::new();

        for stage in &mut self.stages {
            if !stage.active {
                continue;
            }
            let original_size = current.len();
            if original_size > stage.entry.max_message_bytes {
                let reason = "request_message_over_capacity";
                let invocation =
                    failure_invocation(&stage.entry, Some(sequence), original_size, reason);
                let fail_closed = stage.entry.entry.on_error == OnError::FailClosed;
                invocations.push(invocation);
                if fail_closed {
                    return denied_message_outcome(
                        current,
                        findings,
                        metadata,
                        invocations,
                        format!("middleware_failed: {reason}"),
                        None,
                        saturated,
                    );
                }
                continue;
            }

            let remaining = chain_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let reason = "middleware_chain_timeout";
                let mut invocation =
                    failure_invocation(&stage.entry, Some(sequence), original_size, reason);
                let fail_closed = stage.entry.entry.on_error == OnError::FailClosed;
                stage.active = false;
                invocation.stage_disabled = true;
                invocations.push(invocation);
                if fail_closed {
                    return denied_message_outcome(
                        current,
                        findings,
                        metadata,
                        invocations,
                        format!("middleware_failed: {reason}"),
                        None,
                        saturated,
                    );
                }
                continue;
            }
            let stage_timeout = stage.entry.timeout.min(remaining);
            let request = WebSocketEvaluationRequest {
                request: Some(web_socket_evaluation_request::Request::Message(
                    WebSocketMessage {
                        sequence,
                        direction: WebSocketDirection::ClientToUpstream as i32,
                        message_type: WebSocketMessageType::Text as i32,
                        payload: current.clone(),
                    },
                )),
            };
            let response = tokio::time::timeout(stage_timeout, async {
                stage
                    .sender
                    .send(request)
                    .await
                    .map_err(|_| tonic::Status::unavailable("request stream closed"))?;
                stage.responses.message().await
            })
            .await;
            let result = match response {
                Ok(Ok(Some(response))) => match response.response {
                    Some(web_socket_evaluation_response::Response::MessageResult(result)) => result,
                    Some(web_socket_evaluation_response::Response::PreflightDecision(_)) | None => {
                        if let Some(outcome) = handle_stage_failure(
                            stage,
                            sequence,
                            original_size,
                            "unexpected_websocket_response",
                            &current,
                            &findings,
                            &metadata,
                            &mut invocations,
                            saturated,
                        ) {
                            return outcome;
                        }
                        continue;
                    }
                },
                Ok(Ok(None)) => {
                    if let Some(outcome) = handle_stage_failure(
                        stage,
                        sequence,
                        original_size,
                        "missing_message_result",
                        &current,
                        &findings,
                        &metadata,
                        &mut invocations,
                        saturated,
                    ) {
                        return outcome;
                    }
                    continue;
                }
                Ok(Err(_)) => {
                    if let Some(outcome) = handle_stage_failure(
                        stage,
                        sequence,
                        original_size,
                        "external_service_error",
                        &current,
                        &findings,
                        &metadata,
                        &mut invocations,
                        saturated,
                    ) {
                        return outcome;
                    }
                    continue;
                }
                Err(_) => {
                    if let Some(outcome) = handle_stage_failure(
                        stage,
                        sequence,
                        original_size,
                        "middleware_timeout",
                        &current,
                        &findings,
                        &metadata,
                        &mut invocations,
                        saturated,
                    ) {
                        return outcome;
                    }
                    continue;
                }
            };

            let result =
                match validate_message_result(result, sequence, stage.entry.max_message_bytes) {
                    Ok(result) => result,
                    Err(reason) => {
                        if let Some(outcome) = handle_stage_failure(
                            stage,
                            sequence,
                            original_size,
                            reason,
                            &current,
                            &findings,
                            &metadata,
                            &mut invocations,
                            saturated,
                        ) {
                            return outcome;
                        }
                        continue;
                    }
                };

            let decision = Decision::try_from(result.decision).expect("validated decision");
            let reason_code = (!result.reason_code.is_empty()).then(|| result.reason_code.clone());
            for finding in result.findings {
                findings.push(NamespacedFinding {
                    middleware: stage.entry.entry.name.clone(),
                    finding,
                });
            }
            if !result.metadata.is_empty() {
                metadata.insert(
                    stage.entry.entry.name.clone(),
                    result.metadata.into_iter().collect(),
                );
            }
            if decision == Decision::Deny {
                let denial = MiddlewareDenial {
                    config_name: stage.entry.entry.name.clone(),
                    reason_code,
                };
                invocations.push(success_invocation(
                    &stage.entry,
                    WebSocketInvocationOutcome::Deny,
                    sequence,
                    original_size,
                    None,
                    false,
                    denial.reason_code.clone(),
                ));
                return denied_message_outcome(
                    current,
                    findings,
                    metadata,
                    invocations,
                    middleware_denial_reason(&denial.config_name, denial.reason_code.as_deref()),
                    Some(denial),
                    saturated,
                );
            }

            let replacement_size = result.has_replacement.then_some(result.replacement.len());
            if result.has_replacement {
                current = result.replacement;
            }
            invocations.push(success_invocation(
                &stage.entry,
                WebSocketInvocationOutcome::Allow,
                sequence,
                original_size,
                replacement_size,
                result.has_replacement,
                reason_code,
            ));
        }

        WebSocketMessageOutcome {
            allowed: true,
            reason: String::new(),
            payload: current,
            findings,
            metadata,
            invocations,
            denial: None,
            saturated,
            platform_oversize: false,
        }
    }

    pub async fn end(mut self, reason: WebSocketSessionEndReason) {
        end_stages(&mut self.stages, reason).await;
    }
}

async fn open_stage(entry: DescribedChainEntry, input: WebSocketPreflightInput) -> OpenStage {
    let Some(service) = entry.service.as_ref() else {
        return OpenStage::Failed(entry, "binding_not_described");
    };
    let Some(remote) = service.remote.clone() else {
        return OpenStage::Failed(entry, "websocket_stream_not_available");
    };
    let preflight = WebSocketPreflight {
        session_id: input.session_id,
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        direction: WebSocketDirection::ClientToUpstream as i32,
        context: Some(RequestContext {
            request_id: input.request_id,
            sandbox_id: input.sandbox_id,
            originating_process: None,
        }),
        scheme: input.scheme,
        host: input.host,
        port: u32::from(input.port),
        path: input.path,
        requested_subprotocols: input.requested_subprotocols,
        middleware_name: entry.entry.implementation.clone(),
        config_name: entry.entry.name.clone(),
        config: Some(entry.entry.config.clone()),
    };
    if validate_preflight_envelope(&preflight).is_err() {
        return OpenStage::Failed(entry, "preflight_envelope_over_capacity");
    }

    let timeout = entry.timeout.min(MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT);
    let opened = tokio::time::timeout(timeout, async {
        let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        sender
            .send(WebSocketEvaluationRequest {
                request: Some(web_socket_evaluation_request::Request::Preflight(preflight)),
            })
            .await
            .map_err(|_| tonic::Status::unavailable("request stream closed"))?;
        let mut responses = remote.open_websocket(receiver).await?;
        let response = responses.message().await?;
        Ok::<_, tonic::Status>((sender, responses, response))
    })
    .await;

    let (sender, responses, response) = match opened {
        Ok(Ok(opened)) => opened,
        Ok(Err(_)) => return OpenStage::Failed(entry, "external_service_error"),
        Err(_) => return OpenStage::Failed(entry, "middleware_timeout"),
    };
    let Some(response) = response else {
        return OpenStage::Failed(entry, "missing_preflight_decision");
    };
    let Some(web_socket_evaluation_response::Response::PreflightDecision(decision)) =
        response.response
    else {
        return OpenStage::Failed(entry, "invalid_preflight_decision");
    };
    match WebSocketPreflightAction::try_from(decision.action) {
        Ok(WebSocketPreflightAction::Inspect) => {
            let invocation = success_invocation(
                &entry,
                WebSocketInvocationOutcome::Inspect,
                0,
                0,
                None,
                false,
                None,
            );
            OpenStage::Inspect(
                Box::new(WebSocketStage {
                    entry,
                    sender,
                    responses,
                    active: true,
                }),
                invocation,
            )
        }
        Ok(WebSocketPreflightAction::Skip) => {
            let invocation = success_invocation(
                &entry,
                WebSocketInvocationOutcome::Skip,
                0,
                0,
                None,
                false,
                None,
            );
            let _ = sender.try_send(session_end_request(WebSocketSessionEndReason::Cancellation));
            OpenStage::Skip(invocation)
        }
        Ok(WebSocketPreflightAction::Unspecified) | Err(_) => {
            OpenStage::Failed(entry, "invalid_preflight_decision")
        }
    }
}

fn validate_preflight_input(input: &WebSocketPreflightInput) -> miette::Result<()> {
    if input.session_id.is_empty() || input.session_id.len() > 128 {
        return Err(miette::miette!("invalid WebSocket middleware session id"));
    }
    if input.path.len() > super::MAX_MIDDLEWARE_TARGET_BYTES {
        return Err(miette::miette!(
            "WebSocket middleware preflight path exceeds platform capacity"
        ));
    }
    if input.path.contains('?') {
        return Err(miette::miette!(
            "WebSocket middleware preflight path must not contain a query string"
        ));
    }
    if input.requested_subprotocols.len() > MAX_REQUESTED_SUBPROTOCOLS
        || input
            .requested_subprotocols
            .iter()
            .map(String::len)
            .sum::<usize>()
            > MAX_SUBPROTOCOL_BYTES
    {
        return Err(miette::miette!(
            "WebSocket middleware requested subprotocols exceed platform capacity"
        ));
    }
    Ok(())
}

fn validate_preflight_envelope(preflight: &WebSocketPreflight) -> Result<(), &'static str> {
    if preflight
        .config
        .as_ref()
        .is_some_and(|config| config.encoded_len() > MAX_MIDDLEWARE_CONFIG_BYTES)
    {
        return Err("preflight_config_over_capacity");
    }
    if preflight
        .context
        .as_ref()
        .is_some_and(|context| context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES)
    {
        return Err("preflight_context_over_capacity");
    }
    if preflight.encoded_len() > MIDDLEWARE_GRPC_MESSAGE_BYTES {
        return Err("preflight_envelope_over_capacity");
    }
    Ok(())
}

fn validate_message_result(
    result: WebSocketMessageResult,
    sequence: u64,
    stage_limit: usize,
) -> Result<WebSocketMessageResult, &'static str> {
    if result.sequence != sequence {
        return Err("message_result_sequence_mismatch");
    }
    if !matches!(
        Decision::try_from(result.decision),
        Ok(Decision::Allow | Decision::Deny)
    ) {
        return Err("invalid_response_decision");
    }
    if result.reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err("response_reason_over_capacity");
    }
    if !result.reason_code.is_empty() && !is_stable_reason_code(&result.reason_code) {
        return Err("response_reason_code_invalid");
    }
    if !result.has_replacement && !result.replacement.is_empty() {
        return Err("unsolicited_replacement");
    }
    if result.has_replacement {
        if result.replacement.len() > MAX_MIDDLEWARE_BODY_BYTES {
            return Err("response_message_over_platform_capacity");
        }
        if result.replacement.len() > stage_limit {
            return Err("response_message_over_capacity");
        }
        if std::str::from_utf8(&result.replacement).is_err() {
            return Err("text_replacement_invalid_utf8");
        }
    }
    if result.findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE
        || result
            .findings
            .iter()
            .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err("response_findings_over_capacity");
    }
    if result.metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES {
        return Err("response_metadata_count_over_capacity");
    }
    let metadata_bytes = result.metadata.iter().fold(0usize, |total, (key, value)| {
        total.saturating_add(key.len()).saturating_add(value.len())
    });
    if metadata_bytes > MAX_MIDDLEWARE_METADATA_BYTES {
        return Err("response_metadata_bytes_over_capacity");
    }
    if result.encoded_len() > MIDDLEWARE_GRPC_MESSAGE_BYTES {
        return Err("response_envelope_over_capacity");
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn handle_stage_failure(
    stage: &mut WebSocketStage,
    sequence: u64,
    original_size: usize,
    reason: &'static str,
    current: &[u8],
    findings: &[NamespacedFinding],
    metadata: &BTreeMap<String, BTreeMap<String, String>>,
    invocations: &mut Vec<WebSocketInvocation>,
    saturated: bool,
) -> Option<WebSocketMessageOutcome> {
    stage.active = false;
    let mut invocation = failure_invocation(&stage.entry, Some(sequence), original_size, reason);
    invocation.stage_disabled = true;
    invocations.push(invocation);
    (stage.entry.entry.on_error == OnError::FailClosed).then(|| {
        denied_message_outcome(
            current.to_vec(),
            findings.to_vec(),
            metadata.clone(),
            invocations.clone(),
            format!("middleware_failed: {reason}"),
            None,
            saturated,
        )
    })
}

fn denied_message_outcome(
    payload: Vec<u8>,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<WebSocketInvocation>,
    reason: String,
    denial: Option<MiddlewareDenial>,
    saturated: bool,
) -> WebSocketMessageOutcome {
    WebSocketMessageOutcome {
        allowed: false,
        reason,
        payload,
        findings,
        metadata,
        invocations,
        denial,
        saturated,
        platform_oversize: false,
    }
}

fn success_invocation(
    entry: &DescribedChainEntry,
    outcome: WebSocketInvocationOutcome,
    sequence: u64,
    original_size: usize,
    replacement_size: Option<usize>,
    transformed: bool,
    reason_code: Option<String>,
) -> WebSocketInvocation {
    WebSocketInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome,
        sequence: (sequence != 0).then_some(sequence),
        original_size,
        replacement_size,
        transformed,
        failed: false,
        stage_disabled: false,
        reason_code,
    }
}

fn failure_invocation(
    entry: &DescribedChainEntry,
    sequence: Option<u64>,
    original_size: usize,
    _reason: &'static str,
) -> WebSocketInvocation {
    let outcome = match entry.entry.on_error {
        OnError::FailOpen => WebSocketInvocationOutcome::FailOpen,
        OnError::FailClosed => WebSocketInvocationOutcome::FailClosed,
    };
    WebSocketInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome,
        sequence,
        original_size,
        replacement_size: None,
        transformed: false,
        failed: true,
        stage_disabled: false,
        reason_code: None,
    }
}

async fn end_stages(stages: &mut [WebSocketStage], reason: WebSocketSessionEndReason) {
    for stage in stages {
        if stage.active {
            let _ = tokio::time::timeout(
                Duration::from_millis(10),
                stage.sender.send(session_end_request(reason)),
            )
            .await;
            stage.active = false;
        }
    }
}

fn session_end_request(reason: WebSocketSessionEndReason) -> WebSocketEvaluationRequest {
    WebSocketEvaluationRequest {
        request: Some(web_socket_evaluation_request::Request::SessionEnd(
            WebSocketSessionEnd {
                reason: reason as i32,
            },
        )),
    }
}
