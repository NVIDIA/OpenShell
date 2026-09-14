// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Forward-direction WebSocket middleware session runner.

use std::collections::BTreeMap;
use std::time::Duration;

use futures::{StreamExt, future::join_all};
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::time::Instant;

use openshell_core::proto::{
    Decision, HttpRequestTarget, RequestContext, SupervisorMiddlewarePhase, WebSocketMessage,
    WebSocketMessageResult, WebSocketPreflight, WebSocketPreflightAction,
    WebSocketPreflightDecision, WebSocketSessionEnd, WebSocketSessionEndReason,
    WebSocketSessionEvent, WebSocketSessionStart, web_socket_message, web_socket_message_result,
    web_socket_session_event, web_socket_session_event_result,
};

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_CONFIG_BYTES, MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_FINDING_BYTES,
    MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_METADATA_BYTES,
    MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_PAYLOAD_BYTES,
    MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT, MAX_MIDDLEWARE_REASON_BYTES, MIDDLEWARE_GRPC_MESSAGE_BYTES,
    MiddlewareDenial, MiddlewareSessionAdmission, MiddlewareSessionPermit, MiddlewareWorkAdmission,
    NamespacedFinding, OnError, is_stable_reason_code, middleware_denial_reason,
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
    pub sandbox_name: String,
    pub workspace: String,
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

/// Coverage of a selected policy attachment that did not result in a
/// WebSocket middleware invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketCoverageState {
    /// The attached implementation did not advertise the exact
    /// `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` binding.
    BindingNotSelected,
    /// The binding was selected, but the V1 relay does not expose this message
    /// class to middleware.
    UnsupportedMessageType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketMessageType {
    Text,
    Binary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketCoverage {
    pub config_name: String,
    pub implementation: String,
    pub state: WebSocketCoverageState,
    pub sequence: Option<u64>,
    pub message_type: Option<WebSocketMessageType>,
    pub original_size: usize,
}

pub struct WebSocketPreflightResult {
    pub allowed: bool,
    /// Typed terminal reason when preflight denied the upgrade. `None` means
    /// the request may continue, including voluntary skip and fail-open.
    pub terminal_reason: Option<WebSocketSessionEndReason>,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    pub session: Option<WebSocketSession>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<WebSocketInvocation>,
    pub coverage: Vec<WebSocketCoverage>,
    pub saturated: bool,
    pub session_capacity_exhausted: bool,
}

#[derive(Debug)]
pub struct WebSocketSessionStartOutcome {
    pub allowed: bool,
    /// Typed terminal reason when session start cannot continue.
    pub terminal_reason: Option<WebSocketSessionEndReason>,
    pub reason: String,
    pub invocations: Vec<WebSocketInvocation>,
}

#[derive(Debug)]
pub struct WebSocketMessageOutcome {
    pub allowed: bool,
    pub reason: String,
    pub payload: String,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<WebSocketInvocation>,
    pub denial: Option<MiddlewareDenial>,
    pub saturated: bool,
    pub platform_oversize: bool,
}

struct WebSocketStageTransport {
    sender: mpsc::Sender<WebSocketSessionEvent>,
    responses: super::WebSocketResponseStream,
}

struct WebSocketStage {
    entry: DescribedChainEntry,
    transport: Option<WebSocketStageTransport>,
}

impl WebSocketStage {
    fn is_active(&self) -> bool {
        self.transport.is_some()
    }

    async fn disable(&mut self) {
        self.end(WebSocketSessionEndReason::MiddlewareFailure).await;
    }

    async fn end(&mut self, reason: WebSocketSessionEndReason) {
        if let Some(transport) = self.transport.take() {
            let _ = tokio::time::timeout(
                Duration::from_millis(10),
                transport.sender.send(session_end_request(reason)),
            )
            .await;
        }
    }
}

pub struct WebSocketSession {
    runner: ChainRunner,
    stages: Vec<WebSocketStage>,
    next_sequence: u64,
    session_admission: Option<MiddlewareSessionPermit>,
}

/// Whether a WebSocket text message needs the shared short-lived work budget.
///
/// A fully disabled fail-open session returns `Bypass` without touching the
/// work semaphore. Other parsed WebSocket features may continue processing the
/// original payload independently.
#[derive(Debug)]
pub enum WebSocketMessageAdmission {
    Bypass,
    Inspect(MiddlewareWorkAdmission),
}

enum OpenStage {
    Inspect(Box<WebSocketStage>, PreflightStageOutcome),
    Deny(Box<WebSocketStage>, PreflightStageOutcome),
    Skip(PreflightStageOutcome),
    Failed(DescribedChainEntry, String),
}

struct PreflightStageOutcome {
    invocation: WebSocketInvocation,
    findings: Vec<NamespacedFinding>,
    metadata: Option<(String, BTreeMap<String, String>)>,
}

impl ChainRunner {
    pub async fn preflight_websocket(
        &self,
        entries: &[ChainEntry],
        input: WebSocketPreflightInput,
    ) -> miette::Result<WebSocketPreflightResult> {
        if entries.is_empty() {
            return Ok(empty_preflight_result());
        }
        let description = self
            .describe_chain_for(
                entries,
                openshell_core::proto::SupervisorMiddlewareOperation::WebsocketMessage,
                SupervisorMiddlewarePhase::PreCredentials,
            )
            .await?;
        let coverage = description
            .unbound
            .iter()
            .map(binding_not_selected_coverage)
            .collect::<Vec<_>>();
        let described = description.entries;
        if described.is_empty() {
            let mut result = empty_preflight_result();
            result.coverage = coverage;
            return Ok(result);
        }
        validate_preflight_input(&input)?;

        // One permit covers the complete concurrent preflight fan-out. Permit
        // wait is deliberate backpressure and is excluded from every deadline.
        let preflight_work = self.reserve_middleware_work_admission().await?;
        let saturated = preflight_work.saturated();
        let session_admission = match self.try_reserve_middleware_session() {
            MiddlewareSessionAdmission::Admitted(admission) => admission,
            MiddlewareSessionAdmission::AtCapacity => {
                return Ok(session_capacity_exhausted(described, coverage, saturated));
            }
        };
        let opened = join_all(
            described
                .into_iter()
                .map(|entry| open_stage(entry, input.clone())),
        )
        .await;

        let mut stages = Vec::new();
        let mut invocations = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut denial = None;
        let mut fail_closed_reason = None;
        for result in opened {
            match result {
                OpenStage::Inspect(stage, outcome) => {
                    stages.push(*stage);
                    collect_preflight_outcome(
                        outcome,
                        &mut invocations,
                        &mut findings,
                        &mut metadata,
                    );
                }
                OpenStage::Deny(stage, outcome) => {
                    denial.get_or_insert_with(|| MiddlewareDenial {
                        config_name: stage.entry.entry.name.clone(),
                        reason_code: outcome.invocation.reason_code.clone(),
                    });
                    stages.push(*stage);
                    collect_preflight_outcome(
                        outcome,
                        &mut invocations,
                        &mut findings,
                        &mut metadata,
                    );
                }
                OpenStage::Skip(outcome) => collect_preflight_outcome(
                    outcome,
                    &mut invocations,
                    &mut findings,
                    &mut metadata,
                ),
                OpenStage::Failed(entry, reason) => {
                    let invocation = failure_invocation(&entry, None, 0, &reason);
                    if entry.entry.on_error == OnError::FailClosed {
                        fail_closed_reason
                            .get_or_insert_with(|| format!("middleware_failed: {reason}"));
                    }
                    invocations.push(invocation);
                }
            }
        }

        if let Some(denial) = denial {
            end_stages(&mut stages, WebSocketSessionEndReason::MiddlewareDenial).await;
            return Ok(WebSocketPreflightResult {
                allowed: false,
                terminal_reason: Some(WebSocketSessionEndReason::MiddlewareDenial),
                reason: middleware_denial_reason(
                    &denial.config_name,
                    denial.reason_code.as_deref(),
                ),
                denial: Some(denial),
                session: None,
                findings,
                metadata,
                invocations,
                coverage,
                saturated,
                session_capacity_exhausted: false,
            });
        }

        if let Some(reason) = fail_closed_reason {
            end_stages(&mut stages, WebSocketSessionEndReason::MiddlewareFailure).await;
            return Ok(WebSocketPreflightResult {
                allowed: false,
                terminal_reason: Some(WebSocketSessionEndReason::MiddlewareFailure),
                reason,
                denial: None,
                session: None,
                findings,
                metadata,
                invocations,
                coverage,
                saturated,
                session_capacity_exhausted: false,
            });
        }

        if stages.is_empty() {
            drop(session_admission);
            return Ok(WebSocketPreflightResult {
                allowed: true,
                terminal_reason: None,
                reason: String::new(),
                denial: None,
                session: None,
                findings,
                metadata,
                invocations,
                coverage,
                saturated,
                session_capacity_exhausted: false,
            });
        }

        Ok(WebSocketPreflightResult {
            allowed: true,
            terminal_reason: None,
            reason: String::new(),
            denial: None,
            session: Some(WebSocketSession {
                runner: self.clone(),
                stages,
                next_sequence: 1,
                session_admission: Some(session_admission),
            }),
            findings,
            metadata,
            invocations,
            coverage,
            saturated,
            session_capacity_exhausted: false,
        })
    }
}

fn empty_preflight_result() -> WebSocketPreflightResult {
    WebSocketPreflightResult {
        allowed: true,
        terminal_reason: None,
        reason: String::new(),
        denial: None,
        session: None,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        coverage: Vec::new(),
        saturated: false,
        session_capacity_exhausted: false,
    }
}

fn session_capacity_exhausted(
    described: Vec<DescribedChainEntry>,
    coverage: Vec<WebSocketCoverage>,
    saturated: bool,
) -> WebSocketPreflightResult {
    let reason = "middleware_session_capacity_exhausted";
    let mut fail_closed = false;
    let invocations = described
        .iter()
        .map(|entry| {
            fail_closed |= entry.entry.on_error == OnError::FailClosed;
            failure_invocation(entry, None, 0, reason)
        })
        .collect();
    WebSocketPreflightResult {
        allowed: !fail_closed,
        terminal_reason: fail_closed.then_some(WebSocketSessionEndReason::MiddlewareFailure),
        reason: if fail_closed {
            format!("middleware_failed: {reason}")
        } else {
            String::new()
        },
        denial: None,
        session: None,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations,
        coverage,
        saturated,
        session_capacity_exhausted: true,
    }
}

impl WebSocketSession {
    fn has_active_stages(&self) -> bool {
        self.stages.iter().any(WebSocketStage::is_active)
    }

    fn reconcile_lifecycle(&mut self) {
        if !self.has_active_stages() {
            self.session_admission.take();
        }
    }

    pub async fn admit_message(&mut self) -> miette::Result<WebSocketMessageAdmission> {
        self.reconcile_lifecycle();
        if !self.has_active_stages() {
            return Ok(WebSocketMessageAdmission::Bypass);
        }
        self.runner
            .reserve_middleware_work_admission()
            .await
            .map(WebSocketMessageAdmission::Inspect)
    }

    pub async fn start(&mut self, selected_subprotocol: &str) -> WebSocketSessionStartOutcome {
        if selected_subprotocol.len() > MAX_SELECTED_SUBPROTOCOL_BYTES {
            return WebSocketSessionStartOutcome {
                allowed: false,
                terminal_reason: Some(WebSocketSessionEndReason::MiddlewareFailure),
                reason: "middleware_failed: selected_subprotocol_over_capacity".to_string(),
                invocations: Vec::new(),
            };
        }
        let mut invocations = Vec::new();
        let mut fail_closed = None;
        for stage in &mut self.stages {
            let Some(transport) = stage.transport.as_mut() else {
                continue;
            };
            let request = WebSocketSessionEvent {
                event: Some(web_socket_session_event::Event::SessionStart(
                    WebSocketSessionStart {
                        selected_subprotocol: selected_subprotocol.to_string(),
                    },
                )),
            };
            let sent =
                tokio::time::timeout(stage.entry.timeout, transport.sender.send(request)).await;
            if !matches!(sent, Ok(Ok(()))) {
                stage.disable().await;
                let reason = "session_start_send_failed";
                let mut invocation = failure_invocation(&stage.entry, None, 0, reason);
                invocation.stage_disabled = true;
                if stage.entry.entry.on_error == OnError::FailClosed {
                    fail_closed.get_or_insert_with(|| format!("middleware_failed: {reason}"));
                }
                invocations.push(invocation);
            }
        }
        self.reconcile_lifecycle();
        WebSocketSessionStartOutcome {
            allowed: fail_closed.is_none(),
            terminal_reason: fail_closed
                .as_ref()
                .map(|_| WebSocketSessionEndReason::MiddlewareFailure),
            reason: fail_closed.unwrap_or_default(),
            invocations,
        }
    }

    /// Record one logical message whose type the selected V1 WebSocket binding
    /// cannot inspect. This is a coverage state, not a middleware failure:
    /// `on_error` is not applied and active stages remain available for later
    /// text messages.
    pub fn observe_unsupported_message(
        &mut self,
        message_type: WebSocketMessageType,
        original_size: usize,
    ) -> Vec<WebSocketCoverage> {
        self.reconcile_lifecycle();
        if !self.has_active_stages() {
            return Vec::new();
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.stages
            .iter()
            .filter(|stage| stage.is_active())
            .map(|stage| WebSocketCoverage {
                config_name: stage.entry.entry.name.clone(),
                implementation: stage.entry.entry.implementation.clone(),
                state: WebSocketCoverageState::UnsupportedMessageType,
                sequence: Some(sequence),
                message_type: Some(message_type),
                original_size,
            })
            .collect()
    }

    pub async fn evaluate_text(&mut self, payload: String) -> WebSocketMessageOutcome {
        if payload.len() > MAX_MIDDLEWARE_PAYLOAD_BYTES {
            return platform_oversize_outcome(payload);
        }
        match self.admit_message().await {
            Ok(WebSocketMessageAdmission::Bypass) => bypassed_message_outcome(payload),
            Ok(WebSocketMessageAdmission::Inspect(admission)) => {
                self.evaluate_text_admitted(payload, admission).await
            }
            Err(_) => admission_failure_outcome(payload),
        }
    }

    pub async fn evaluate_text_admitted(
        &mut self,
        payload: String,
        admission: MiddlewareWorkAdmission,
    ) -> WebSocketMessageOutcome {
        let outcome = self.evaluate_text_admitted_inner(payload, admission).await;
        self.reconcile_lifecycle();
        outcome
    }

    async fn evaluate_text_admitted_inner(
        &mut self,
        payload: String,
        admission: MiddlewareWorkAdmission,
    ) -> WebSocketMessageOutcome {
        if payload.len() > MAX_MIDDLEWARE_PAYLOAD_BYTES {
            return platform_oversize_outcome(payload);
        }

        let saturated = admission.saturated();
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let mut current = payload;
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut invocations = Vec::new();

        for stage in &mut self.stages {
            if !stage.is_active() {
                continue;
            }
            let original_size = current.len();
            if original_size > stage.entry.max_payload_bytes {
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
                stage.disable().await;
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
            let request = WebSocketSessionEvent {
                event: Some(web_socket_session_event::Event::Message(WebSocketMessage {
                    sequence,
                    payload: Some(web_socket_message::Payload::Text(current.clone())),
                })),
            };
            let response = {
                let transport = stage
                    .transport
                    .as_mut()
                    .expect("active WebSocket stage has transport");
                tokio::time::timeout(stage_timeout, async {
                    transport
                        .sender
                        .send(request)
                        .await
                        .map_err(|_| tonic::Status::unavailable("request stream closed"))?;
                    transport.responses.next().await.transpose()
                })
                .await
            };
            let result = match response {
                Ok(Ok(Some(response))) => match response.result {
                    Some(web_socket_session_event_result::Result::MessageResult(result)) => result,
                    Some(web_socket_session_event_result::Result::PreflightDecision(_)) | None => {
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
                        )
                        .await
                        {
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
                    )
                    .await
                    {
                        return outcome;
                    }
                    continue;
                }
                Ok(Err(error)) => {
                    let reason = stage.entry.service.as_ref().map_or_else(
                        || "binding_not_described".to_string(),
                        |service| service.diagnostic_policy.error_reason(&error),
                    );
                    if let Some(outcome) = handle_stage_failure(
                        stage,
                        sequence,
                        original_size,
                        &reason,
                        &current,
                        &findings,
                        &metadata,
                        &mut invocations,
                        saturated,
                    )
                    .await
                    {
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
                    )
                    .await
                    {
                        return outcome;
                    }
                    continue;
                }
            };

            let result = match validate_message_result(
                result,
                sequence,
                WebSocketMessageType::Text,
                stage.entry.max_payload_bytes,
            ) {
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
                    )
                    .await
                    {
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

            let replacement_size = result.replacement.as_ref().map(websocket_replacement_len);
            let transformed = result.replacement.is_some();
            if let Some(web_socket_message_result::Replacement::Text(replacement)) =
                result.replacement
            {
                current = replacement;
            }
            invocations.push(success_invocation(
                &stage.entry,
                WebSocketInvocationOutcome::Allow,
                sequence,
                original_size,
                replacement_size,
                transformed,
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
        self.reconcile_lifecycle();
    }
}

impl Drop for WebSocketSession {
    fn drop(&mut self) {
        end_stages_now(&mut self.stages, WebSocketSessionEndReason::Cancellation);
        self.reconcile_lifecycle();
    }
}

fn platform_oversize_outcome(payload: String) -> WebSocketMessageOutcome {
    WebSocketMessageOutcome {
        allowed: false,
        reason: "websocket_message_over_platform_capacity".to_string(),
        payload,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        denial: None,
        saturated: false,
        platform_oversize: true,
    }
}

fn admission_failure_outcome(payload: String) -> WebSocketMessageOutcome {
    WebSocketMessageOutcome {
        allowed: false,
        reason: "middleware_admission_over_capacity".to_string(),
        payload,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        denial: None,
        saturated: true,
        platform_oversize: false,
    }
}

fn bypassed_message_outcome(payload: String) -> WebSocketMessageOutcome {
    WebSocketMessageOutcome {
        allowed: true,
        reason: String::new(),
        payload,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        denial: None,
        saturated: false,
        platform_oversize: false,
    }
}

fn binding_not_selected_coverage(entry: &ChainEntry) -> WebSocketCoverage {
    WebSocketCoverage {
        config_name: entry.name.clone(),
        implementation: entry.implementation.clone(),
        state: WebSocketCoverageState::BindingNotSelected,
        sequence: None,
        message_type: None,
        original_size: 0,
    }
}

fn preflight_stage_outcome(
    entry: &DescribedChainEntry,
    outcome: WebSocketInvocationOutcome,
    decision: WebSocketPreflightDecision,
) -> PreflightStageOutcome {
    let reason_code = (!decision.reason_code.is_empty()).then(|| decision.reason_code.clone());
    let findings = decision
        .findings
        .into_iter()
        .map(|finding| NamespacedFinding {
            middleware: entry.entry.name.clone(),
            finding,
        })
        .collect();
    let metadata = (!decision.metadata.is_empty()).then(|| {
        (
            entry.entry.name.clone(),
            decision.metadata.into_iter().collect(),
        )
    });
    PreflightStageOutcome {
        invocation: success_invocation(entry, outcome, 0, 0, None, false, reason_code),
        findings,
        metadata,
    }
}

fn collect_preflight_outcome(
    outcome: PreflightStageOutcome,
    invocations: &mut Vec<WebSocketInvocation>,
    findings: &mut Vec<NamespacedFinding>,
    metadata: &mut BTreeMap<String, BTreeMap<String, String>>,
) {
    invocations.push(outcome.invocation);
    findings.extend(outcome.findings);
    if let Some((middleware, values)) = outcome.metadata {
        metadata.insert(middleware, values);
    }
}

async fn open_stage(entry: DescribedChainEntry, input: WebSocketPreflightInput) -> OpenStage {
    let Some(service) = entry.service.as_ref() else {
        return OpenStage::Failed(entry, "binding_not_described".into());
    };
    let dispatch = service.service.clone();
    let diagnostic_policy = service.diagnostic_policy;
    let preflight = WebSocketPreflight {
        session_id: input.session_id,
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: input.request_id,
            sandbox_id: input.sandbox_id,
            sandbox_name: input.sandbox_name,
            workspace: input.workspace,
            originating_process: None,
        }),
        target: Some(HttpRequestTarget {
            scheme: input.scheme,
            host: input.host,
            port: u32::from(input.port),
            method: "GET".into(),
            path: input.path,
            query: String::new(),
        }),
        requested_subprotocols: input.requested_subprotocols,
        middleware_name: entry.entry.implementation.clone(),
        config: Some(entry.entry.config.clone()),
    };
    if validate_preflight_envelope(&preflight).is_err() {
        return OpenStage::Failed(entry, "preflight_envelope_over_capacity".into());
    }

    let timeout = entry.timeout.min(MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT);
    let opened = tokio::time::timeout(timeout, async {
        let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        sender
            .send(WebSocketSessionEvent {
                event: Some(web_socket_session_event::Event::Preflight(preflight)),
            })
            .await
            .map_err(|_| tonic::Status::unavailable("request stream closed"))?;
        let mut responses = dispatch.open_websocket_session(receiver).await?;
        let response = responses.next().await.transpose()?;
        Ok::<_, tonic::Status>((sender, responses, response))
    })
    .await;

    let (sender, responses, response) = match opened {
        Ok(Ok(opened)) => opened,
        Ok(Err(error)) => {
            return OpenStage::Failed(entry, diagnostic_policy.error_reason(&error));
        }
        Err(_) => return OpenStage::Failed(entry, "middleware_timeout".into()),
    };
    let Some(response) = response else {
        let _ = sender.try_send(session_end_request(
            WebSocketSessionEndReason::MiddlewareFailure,
        ));
        return OpenStage::Failed(entry, "missing_preflight_decision".into());
    };
    let Some(web_socket_session_event_result::Result::PreflightDecision(decision)) =
        response.result
    else {
        let _ = sender.try_send(session_end_request(
            WebSocketSessionEndReason::MiddlewareFailure,
        ));
        return OpenStage::Failed(entry, "invalid_preflight_decision".into());
    };
    let decision = match validate_preflight_decision(decision) {
        Ok(decision) => decision,
        Err(reason) => {
            let _ = sender.try_send(session_end_request(
                WebSocketSessionEndReason::MiddlewareFailure,
            ));
            return OpenStage::Failed(entry, reason.into());
        }
    };
    let action =
        WebSocketPreflightAction::try_from(decision.action).expect("validated preflight action");
    match action {
        WebSocketPreflightAction::Inspect => {
            let outcome =
                preflight_stage_outcome(&entry, WebSocketInvocationOutcome::Inspect, decision);
            OpenStage::Inspect(
                Box::new(WebSocketStage {
                    entry,
                    transport: Some(WebSocketStageTransport { sender, responses }),
                }),
                outcome,
            )
        }
        WebSocketPreflightAction::Deny => {
            let outcome =
                preflight_stage_outcome(&entry, WebSocketInvocationOutcome::Deny, decision);
            OpenStage::Deny(
                Box::new(WebSocketStage {
                    entry,
                    transport: Some(WebSocketStageTransport { sender, responses }),
                }),
                outcome,
            )
        }
        WebSocketPreflightAction::Skip => {
            let outcome =
                preflight_stage_outcome(&entry, WebSocketInvocationOutcome::Skip, decision);
            let _ = sender.try_send(session_end_request(WebSocketSessionEndReason::StageSkipped));
            OpenStage::Skip(outcome)
        }
        WebSocketPreflightAction::Unspecified => {
            unreachable!("validated preflight action cannot be unspecified")
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
    let Some(target) = preflight.target.as_ref() else {
        return Err("preflight_target_missing");
    };
    if target.method != "GET" {
        return Err("preflight_target_method_invalid");
    }
    if !target.query.is_empty() || target.path.contains('?') {
        return Err("preflight_target_query_present");
    }
    if target.encoded_len() > super::MAX_MIDDLEWARE_TARGET_BYTES {
        return Err("preflight_target_over_capacity");
    }
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

fn validate_preflight_decision(
    decision: WebSocketPreflightDecision,
) -> Result<WebSocketPreflightDecision, &'static str> {
    if !matches!(
        WebSocketPreflightAction::try_from(decision.action),
        Ok(WebSocketPreflightAction::Inspect
            | WebSocketPreflightAction::Skip
            | WebSocketPreflightAction::Deny)
    ) {
        return Err("invalid_preflight_decision");
    }
    if decision.reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err("response_reason_over_capacity");
    }
    if !decision.reason_code.is_empty() && !is_stable_reason_code(&decision.reason_code) {
        return Err("response_reason_code_invalid");
    }
    if decision.findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE
        || decision
            .findings
            .iter()
            .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err("response_findings_over_capacity");
    }
    if decision.metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES {
        return Err("response_metadata_count_over_capacity");
    }
    let metadata_bytes = decision
        .metadata
        .iter()
        .fold(0usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
    if metadata_bytes > MAX_MIDDLEWARE_METADATA_BYTES {
        return Err("response_metadata_bytes_over_capacity");
    }
    if decision.encoded_len() > MIDDLEWARE_GRPC_MESSAGE_BYTES {
        return Err("response_envelope_over_capacity");
    }
    Ok(decision)
}

fn validate_message_result(
    result: WebSocketMessageResult,
    sequence: u64,
    message_type: WebSocketMessageType,
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
    if let Some(replacement) = &result.replacement {
        if !matches!(
            (message_type, replacement),
            (
                WebSocketMessageType::Text,
                web_socket_message_result::Replacement::Text(_)
            ) | (
                WebSocketMessageType::Binary,
                web_socket_message_result::Replacement::Binary(_)
            )
        ) {
            return Err("replacement_type_mismatch");
        }
        let replacement_len = websocket_replacement_len(replacement);
        if replacement_len > MAX_MIDDLEWARE_PAYLOAD_BYTES {
            return Err("response_message_over_platform_capacity");
        }
        if replacement_len > stage_limit {
            return Err("response_message_over_capacity");
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

fn websocket_replacement_len(replacement: &web_socket_message_result::Replacement) -> usize {
    match replacement {
        web_socket_message_result::Replacement::Text(text) => text.len(),
        web_socket_message_result::Replacement::Binary(binary) => binary.len(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_stage_failure(
    stage: &mut WebSocketStage,
    sequence: u64,
    original_size: usize,
    reason: &str,
    current: &str,
    findings: &[NamespacedFinding],
    metadata: &BTreeMap<String, BTreeMap<String, String>>,
    invocations: &mut Vec<WebSocketInvocation>,
    saturated: bool,
) -> Option<WebSocketMessageOutcome> {
    stage.disable().await;
    let mut invocation = failure_invocation(&stage.entry, Some(sequence), original_size, reason);
    invocation.stage_disabled = true;
    invocations.push(invocation);
    (stage.entry.entry.on_error == OnError::FailClosed).then(|| {
        denied_message_outcome(
            current.to_owned(),
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
    payload: String,
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
    _reason: &str,
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
        stage.end(reason).await;
    }
}

fn end_stages_now(stages: &mut [WebSocketStage], reason: WebSocketSessionEndReason) {
    for stage in stages {
        if let Some(transport) = stage.transport.take() {
            let _ = transport.sender.try_send(session_end_request(reason));
        }
    }
}

fn session_end_request(reason: WebSocketSessionEndReason) -> WebSocketSessionEvent {
    WebSocketSessionEvent {
        event: Some(web_socket_session_event::Event::SessionEnd(
            WebSocketSessionEnd {
                reason: reason as i32,
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_rejects_invalid_utf8_text_payload() {
        let encoded_text_with_invalid_utf8 = [0x12, 0x01, 0xff];
        assert!(WebSocketMessage::decode(encoded_text_with_invalid_utf8.as_slice()).is_err());
    }

    #[test]
    fn replacement_presence_preserves_empty_text_and_rejects_type_changes() {
        let empty_text = WebSocketMessageResult {
            sequence: 7,
            decision: Decision::Allow as i32,
            replacement: Some(web_socket_message_result::Replacement::Text(String::new())),
            ..Default::default()
        };
        let validated = validate_message_result(
            empty_text,
            7,
            WebSocketMessageType::Text,
            MAX_MIDDLEWARE_PAYLOAD_BYTES,
        )
        .expect("empty text replacement must retain oneof presence");
        assert_eq!(
            validated.replacement,
            Some(web_socket_message_result::Replacement::Text(String::new()))
        );

        let binary_replacement = WebSocketMessageResult {
            sequence: 7,
            decision: Decision::Allow as i32,
            replacement: Some(web_socket_message_result::Replacement::Binary(Vec::new())),
            ..Default::default()
        };
        assert_eq!(
            validate_message_result(
                binary_replacement,
                7,
                WebSocketMessageType::Text,
                MAX_MIDDLEWARE_PAYLOAD_BYTES,
            ),
            Err("replacement_type_mismatch")
        );
    }

    #[tokio::test]
    async fn disabling_stage_sends_middleware_failure_once() {
        let (sender, mut requests) = mpsc::channel(1);
        let mut stage = WebSocketStage {
            entry: DescribedChainEntry {
                entry: ChainEntry {
                    name: "best-effort".into(),
                    implementation: "test/middleware".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailOpen,
                },
                service: None,
                binding: None,
                max_payload_bytes: 1024,
                timeout: Duration::from_secs(1),
            },
            transport: Some(WebSocketStageTransport {
                sender,
                responses: Box::pin(tokio_stream::empty()),
            }),
        };

        stage.disable().await;
        stage.disable().await;

        let event = requests.recv().await.expect("session end event");
        let Some(web_socket_session_event::Event::SessionEnd(end)) = event.event else {
            panic!("disabled stage must receive session end");
        };
        assert_eq!(
            WebSocketSessionEndReason::try_from(end.reason),
            Ok(WebSocketSessionEndReason::MiddlewareFailure)
        );
        assert!(
            requests.try_recv().is_err(),
            "disabled stage must receive at most one session end"
        );
    }
}
