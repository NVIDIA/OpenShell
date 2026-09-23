// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware application for L7 requests.

use crate::l7::relay::L7EvalContext;
use crate::opa::PolicyGenerationGuard;
use miette::{Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo,
    HttpActivityBuilder, HttpRequest, NetworkActivityBuilder, SeverityId, StatusId, Url as OcsfUrl,
    ocsf_emit,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{reason}")]
#[diagnostic(code(openshell::middleware::request_body_rejected))]
pub(super) struct RequestBodyMiddlewareError {
    pub(super) reason: String,
    pub(super) denial: Option<openshell_supervisor_middleware::MiddlewareDenial>,
}

/// Maximum wall-clock time spent receiving, evaluating, and processing one
/// request body before the supervisor cancels the middleware session.
// Keep `from_secs` while the workspace MSRV predates `Duration::from_mins`.
#[allow(clippy::duration_suboptimal_units)]
pub const DEFAULT_HTTP_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(120);

pub enum MiddlewareApplyResult {
    Allowed(crate::l7::provider::L7Request),
    Streamed {
        request: crate::l7::provider::L7Request,
        body: MiddlewareRequestBody,
    },
    Denied {
        denial: Option<openshell_supervisor_middleware::MiddlewareDenial>,
    },
    /// The platform's shared active-work and waiter capacities were both full.
    ///
    /// This is platform load shedding, not a selected middleware-stage failure,
    /// so callers must not apply a stage's `on_error` policy.
    AdmissionExhausted,
}

/// Bounded normalized body retained only when a later policy or credential
/// step requires the complete representation before upstream contact.
pub struct BufferedRequestBody {
    pub(crate) bytes: Vec<u8>,
    pub(crate) trailers: Vec<openshell_core::proto::HttpHeader>,
}

/// Body delivery selected after all request-middleware preflights complete.
pub enum MiddlewareRequestBody {
    /// A whole-body or ownership barrier completed before upstream contact.
    Buffered(BufferedRequestBody),
    /// Every active body stage selected unit-local streaming, so approved
    /// units can be released under network backpressure.
    Live(Box<RequestBodyStream>),
}

/// Whether otherwise incremental request middleware must retain the complete
/// representation for a later body-dependent policy or credential stage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RequestBodyDelivery {
    #[default]
    Incremental,
    Withhold,
}

pub struct RequestBodyStream {
    pub(crate) reader: crate::l7::rest::RequestBodyReader,
    session: Option<openshell_supervisor_middleware::HttpRequestSession>,
    preflight: openshell_supervisor_middleware::HttpRequestPreflightOutcome,
    request: crate::l7::provider::L7Request,
    context: L7EvalContext,
    generation_guard: PolicyGenerationGuard,
    deadline: tokio::time::Instant,
    terminal_emitted: bool,
}

/// One destination-selected middleware chain shared by an HTTP request and
/// its matching response. The request and response phases filter bindings
/// independently, so the full chain must remain available until relay ends.
#[derive(Clone)]
pub struct HttpMiddlewareExchange {
    request_id: String,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: openshell_supervisor_middleware::ChainRunner,
    generation_guard: PolicyGenerationGuard,
}

impl HttpMiddlewareExchange {
    pub fn new(
        request_id: String,
        chain: Vec<openshell_supervisor_middleware::ChainEntry>,
        runner: openshell_supervisor_middleware::ChainRunner,
        generation_guard: PolicyGenerationGuard,
    ) -> Self {
        Self {
            request_id,
            chain,
            runner,
            generation_guard,
        }
    }

    pub async fn apply_request<C>(
        &self,
        request: crate::l7::provider::L7Request,
        client: &mut C,
        ctx: &L7EvalContext,
        scheme: &str,
        transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
    ) -> Result<MiddlewareApplyResult>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        Box::pin(self.apply_request_with_delivery(
            request,
            client,
            ctx,
            scheme,
            transformed_body_policy,
            RequestBodyDelivery::Incremental,
        ))
        .await
    }

    pub async fn apply_request_with_delivery<C>(
        &self,
        request: crate::l7::provider::L7Request,
        client: &mut C,
        ctx: &L7EvalContext,
        scheme: &str,
        transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
        delivery: RequestBodyDelivery,
    ) -> Result<MiddlewareApplyResult>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        Box::pin(
            apply_middleware_chain_for_scheme_with_request_id_and_delivery(
                request,
                client,
                ctx,
                scheme,
                self.chain.clone(),
                &self.runner,
                &self.generation_guard,
                transformed_body_policy,
                &self.request_id,
                delivery,
            ),
        )
        .await
    }

    pub fn response_relay<'a>(
        &'a self,
        request: &crate::l7::provider::L7Request,
        ctx: &'a L7EvalContext,
        scheme: &str,
    ) -> crate::l7::rest::HttpResponseMiddlewareRelay<'a> {
        let sandbox = openshell_ocsf::ctx::ctx();
        crate::l7::rest::HttpResponseMiddlewareRelay {
            chain: &self.chain,
            runner: &self.runner,
            request_context: openshell_core::proto::RequestContext {
                request_id: self.request_id.clone(),
                sandbox_id: sandbox.sandbox_id.clone(),
                sandbox: sandbox.sandbox_name.clone(),
                workspace: ctx.workspace.clone(),
                originating_process: None,
            },
            target: openshell_core::proto::HttpRequestTarget {
                scheme: scheme.to_string(),
                host: ctx.host.clone(),
                port: u32::from(ctx.port),
                method: request.action.clone(),
                path: request.target.clone(),
                query: super::relay::policy_safe_response_query(&request.query_params),
            },
            policy_name: &ctx.policy_name,
            generation_guard: Some(&self.generation_guard),
            whole_body_timeout: super::rest::DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        }
    }
}

/// How traffic a middleware chain can never inspect (h2c, non-HTTP TCP,
/// protocols without an L7 relay) must be handled for a matching chain.
///
/// This is derived from each entry's `on_error` today. A future per-config
/// `on_uninspectable` knob could let an operator keep `fail_closed` error
/// handling for HTTP traffic while allowing uninspectable protocols through
/// without maintaining host excludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninspectableTrafficGate {
    /// No middleware matches this destination; raw relay is unaffected.
    Unrestricted,
    /// Every matching entry is `fail_open`: relay raw bytes but emit a bypass
    /// detection finding.
    BypassWithFinding,
    /// At least one matching entry is `fail_closed`: deny, the middleware
    /// must be able to see the traffic for it to flow.
    Deny,
}

pub fn uninspectable_traffic_gate(
    chain: &[openshell_supervisor_middleware::ChainEntry],
) -> UninspectableTrafficGate {
    if chain.is_empty() {
        return UninspectableTrafficGate::Unrestricted;
    }
    if chain
        .iter()
        .all(|entry| entry.on_error == openshell_supervisor_middleware::OnError::FailOpen)
    {
        UninspectableTrafficGate::BypassWithFinding
    } else {
        UninspectableTrafficGate::Deny
    }
}

/// Emit the detection finding for traffic a matching middleware chain cannot
/// inspect: denied under a fail-closed chain, bypassed under fail-open.
pub fn emit_middleware_uninspectable(ctx: &L7EvalContext, detail: &str, denied: bool) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(if denied {
            SeverityId::High
        } else {
            SeverityId::Medium
        })
        .finding_info(FindingInfo::new(
            "openshell.middleware.traffic_uninspectable",
            "Supervisor middleware cannot inspect this traffic",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("protocol", detail),
            ("disposition", if denied { "denied" } else { "fail_open" }),
        ])
        .message(if denied {
            "Uninspectable traffic to host with required middleware; denied"
        } else {
            "Uninspectable traffic bypassed middleware (fail_open)"
        })
        .build();
    ocsf_emit!(event);
}

pub fn emit_websocket_preflight_events(
    ctx: &L7EvalContext,
    outcome: &openshell_supervisor_middleware::WebSocketPreflightResult,
) {
    emit_websocket_invocations(ctx, &outcome.invocations);
    emit_websocket_coverage(ctx, &outcome.coverage);
    for event in websocket_preflight_finding_events(outcome) {
        ocsf_emit!(event);
    }
    if outcome.saturated {
        emit_websocket_saturation(ctx);
    }
    if outcome.session_capacity_exhausted {
        emit_middleware_session_capacity_exhausted(ctx);
    }
}

pub(super) fn emit_websocket_coverage(
    ctx: &L7EvalContext,
    coverage: &[openshell_supervisor_middleware::WebSocketCoverage],
) {
    for event in websocket_coverage_events(ctx, coverage) {
        ocsf_emit!(event);
    }
}

/// Build coverage events separately from the tracing pipeline so tests can
/// assert exact coverage telemetry without process-global callsite cache races.
pub(super) fn websocket_coverage_events(
    ctx: &L7EvalContext,
    coverage: &[openshell_supervisor_middleware::WebSocketCoverage],
) -> Vec<openshell_ocsf::OcsfEvent> {
    coverage
        .iter()
        .map(|coverage| {
            use openshell_supervisor_middleware::WebSocketCoverageState as State;

            let state = match coverage.state {
                State::BindingNotSelected => "binding_not_selected",
                State::UnsupportedMessageType => "unsupported_message_type",
            };
            let sequence = coverage
                .sequence
                .map_or_else(|| "-".to_string(), |sequence| sequence.to_string());
            let message_type = match coverage.message_type {
                Some(openshell_supervisor_middleware::WebSocketMessageType::Text) => "text",
                Some(openshell_supervisor_middleware::WebSocketMessageType::Binary) => "binary",
                None => "-",
            };
            NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .activity_name("WebSocket middleware coverage")
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "supervisor-middleware")
                .unmapped("middleware_config", coverage.config_name.as_str())
                .unmapped(
                    "middleware_implementation",
                    coverage.implementation.as_str(),
                )
                .unmapped("coverage_state", state)
                .unmapped("websocket_message_type", message_type)
                .unmapped("websocket_sequence", sequence.as_str())
                .unmapped("input_bytes", coverage.original_size)
                .message(format!(
                    "WEBSOCKET_MIDDLEWARE_COVERAGE state={state} config={} implementation={} sequence={sequence} message_type={message_type} input_bytes={}",
                    coverage.config_name, coverage.implementation, coverage.original_size,
                ))
                .build()
        })
        .collect()
}

pub(super) fn emit_websocket_session_start_events(
    ctx: &L7EvalContext,
    outcome: &openshell_supervisor_middleware::WebSocketSessionStartOutcome,
) {
    emit_websocket_invocations(ctx, &outcome.invocations);
}

pub(super) fn emit_websocket_message_events(
    ctx: &L7EvalContext,
    outcome: &openshell_supervisor_middleware::WebSocketMessageOutcome,
) {
    emit_websocket_invocations(ctx, &outcome.invocations);
    if outcome.saturated {
        emit_websocket_saturation(ctx);
    }
    for event in websocket_message_finding_events(outcome) {
        ocsf_emit!(event);
    }
}

pub(super) fn websocket_preflight_finding_events(
    outcome: &openshell_supervisor_middleware::WebSocketPreflightResult,
) -> Vec<openshell_ocsf::OcsfEvent> {
    middleware_finding_events(&outcome.findings)
}

pub(super) fn websocket_message_finding_events(
    outcome: &openshell_supervisor_middleware::WebSocketMessageOutcome,
) -> Vec<openshell_ocsf::OcsfEvent> {
    middleware_finding_events(&outcome.findings)
}

pub(super) fn middleware_finding_events(
    findings: &[openshell_supervisor_middleware::NamespacedFinding],
) -> Vec<openshell_ocsf::OcsfEvent> {
    findings
        .iter()
        .take(openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_FINDINGS)
        .map(|finding| {
            DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(match finding.finding.severity.as_str() {
                    "high" => SeverityId::High,
                    "low" => SeverityId::Low,
                    _ => SeverityId::Medium,
                })
                .finding_info(FindingInfo::new(
                    &finding.finding.r#type,
                    &finding.finding.label,
                ))
                .evidence_pairs(&[
                    ("middleware", &finding.middleware),
                    ("count", &finding.finding.count.to_string()),
                ])
                .unmapped("middleware", finding.middleware.as_str())
                .unmapped("count", finding.finding.count)
                .message(format!(
                    "Middleware finding {} count={}",
                    finding.finding.r#type, finding.finding.count
                ))
                .build()
        })
        .collect()
}

fn emit_websocket_invocations(
    ctx: &L7EvalContext,
    invocations: &[openshell_supervisor_middleware::WebSocketInvocation],
) {
    for invocation in invocations {
        use openshell_supervisor_middleware::WebSocketInvocationOutcome as Outcome;
        let (action, disposition, severity, status, outcome_name) = match invocation.outcome {
            Outcome::Inspect => (
                ActionId::Other,
                DispositionId::Allowed,
                SeverityId::Informational,
                StatusId::Success,
                "inspect",
            ),
            Outcome::Skip => (
                ActionId::Other,
                DispositionId::Other,
                SeverityId::Informational,
                StatusId::Success,
                "voluntary_skip",
            ),
            Outcome::Allow => (
                ActionId::Allowed,
                DispositionId::Allowed,
                SeverityId::Informational,
                StatusId::Success,
                "allow",
            ),
            Outcome::Deny => (
                ActionId::Denied,
                DispositionId::Blocked,
                SeverityId::Medium,
                StatusId::Failure,
                "deny",
            ),
            Outcome::FailOpen => (
                ActionId::Other,
                DispositionId::Allowed,
                SeverityId::Medium,
                StatusId::Failure,
                "fail_open",
            ),
            Outcome::FailClosed => (
                ActionId::Denied,
                DispositionId::Blocked,
                SeverityId::High,
                StatusId::Failure,
                "fail_closed",
            ),
        };
        let sequence = invocation
            .sequence
            .map_or_else(|| "-".to_string(), |sequence| sequence.to_string());
        let replacement_size = invocation
            .replacement_size
            .map_or_else(|| "-".to_string(), |size| size.to_string());
        let reason_code = invocation.reason_code.as_deref().unwrap_or("-");
        let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .activity_name("WebSocket middleware")
            .action(action)
            .disposition(disposition)
            .severity(severity)
            .status(status)
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "supervisor-middleware")
            .message(format!(
                "WEBSOCKET_MIDDLEWARE {outcome_name} config={} implementation={} sequence={sequence} input_bytes={} replacement_bytes={replacement_size} transformed={} reason_code={reason_code}",
                invocation.config_name,
                invocation.implementation,
                invocation.original_size,
                invocation.transformed,
            ))
            .build();
        ocsf_emit!(event);
        if invocation.failed {
            let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(if invocation.outcome == Outcome::FailClosed {
                    SeverityId::High
                } else {
                    SeverityId::Medium
                })
                .finding_info(FindingInfo::new(
                    "openshell.middleware.websocket_failure",
                    "WebSocket middleware processing failure",
                ))
                .evidence_pairs(&[
                    ("policy", ctx.policy_name.as_str()),
                    ("host", ctx.host.as_str()),
                    ("config", invocation.config_name.as_str()),
                    ("implementation", invocation.implementation.as_str()),
                    ("disposition", outcome_name),
                ])
                .message("WebSocket middleware stage failed")
                .build();
            ocsf_emit!(event);
        }
        if invocation.stage_disabled {
            let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Medium)
                .finding_info(FindingInfo::new(
                    "openshell.middleware.websocket_stage_disabled",
                    "WebSocket middleware stage disabled",
                ))
                .evidence_pairs(&[
                    ("policy", ctx.policy_name.as_str()),
                    ("host", ctx.host.as_str()),
                    ("config", invocation.config_name.as_str()),
                    ("implementation", invocation.implementation.as_str()),
                    ("disposition", outcome_name),
                ])
                .message(
                    "WebSocket middleware stage stream became unusable and was disabled for this session",
                )
                .build();
            ocsf_emit!(event);
        }
    }
}

fn emit_websocket_saturation(ctx: &L7EvalContext) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::Medium)
        .finding_info(FindingInfo::new(
            "openshell.middleware.admission_saturated",
            "Supervisor middleware admission saturated",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("operation", "websocket_message"),
        ])
        .message("WebSocket middleware work waited for admission capacity")
        .build();
    ocsf_emit!(event);
}

fn emit_middleware_session_capacity_exhausted(ctx: &L7EvalContext) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::Medium)
        .finding_info(FindingInfo::new(
            "openshell.middleware.session_capacity_exhausted",
            "Supervisor middleware session capacity exhausted",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("operation", "websocket_message"),
        ])
        .message("Persistent middleware session admission was refused at process capacity")
        .build();
    ocsf_emit!(event);
}

fn middleware_admission_exhausted_event(ctx: &L7EvalContext) -> openshell_ocsf::OcsfEvent {
    DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::Medium)
        .finding_info(FindingInfo::new(
            "openshell.middleware.admission_exhausted",
            "Supervisor middleware admission exhausted",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("operation", "http_request"),
            ("disposition", "shed"),
        ])
        .message("HTTP request shed because middleware work admission was exhausted")
        .build()
}

fn emit_middleware_admission_exhausted(ctx: &L7EvalContext) {
    ocsf_emit!(middleware_admission_exhausted_event(ctx));
}

/// Largest body-buffering limit across the entries that actually resolved to a
/// registered binding. Buffering for the most capable stage lets every stage
/// that can handle the body run; stages whose own limit is smaller are failed
/// individually with `request_body_over_capacity` through their `on_error`
/// policy in `evaluate_described`, instead of one undersized stage forcing the
/// whole chain onto the unbuffered path. Unresolved entries
/// (`is_resolved() == false`) report a zero limit and are excluded here: they
/// are handled by their `on_error` policy without inspecting the body.
/// Returns `None` when no entry resolved, so the caller can skip buffering.
pub(super) fn middleware_chain_body_limit(
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
) -> Option<usize> {
    chain
        .iter()
        .filter(|entry| entry.is_resolved())
        .map(|entry| {
            if entry.supports_http_body_mode(openshell_core::proto::HttpBodyMode::Stream) {
                openshell_supervisor_middleware::MAX_HTTP_REQUEST_DEFERRED_BYTES
            } else {
                entry.max_payload_bytes()
            }
        })
        .max()
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_middleware_chain_with_request_id<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
    transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
    request_id: &str,
) -> Result<MiddlewareApplyResult> {
    Box::pin(apply_middleware_chain_with_request_id_and_delivery(
        req,
        client,
        ctx,
        chain,
        runner,
        generation_guard,
        transformed_body_policy,
        request_id,
        RequestBodyDelivery::Incremental,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_middleware_chain_with_request_id_and_delivery<
    C: AsyncRead + AsyncWrite + Unpin + Send,
>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
    transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
    request_id: &str,
    delivery: RequestBodyDelivery,
) -> Result<MiddlewareApplyResult> {
    Box::pin(
        apply_middleware_chain_for_scheme_with_request_id_and_delivery(
            req,
            client,
            ctx,
            "https",
            chain,
            runner,
            generation_guard,
            transformed_body_policy,
            request_id,
            delivery,
        ),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_middleware_chain_for_scheme_with_request_id_and_delivery<
    C: AsyncRead + AsyncWrite + Unpin + Send,
>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    scheme: &str,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
    transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
    request_id: &str,
    delivery: RequestBodyDelivery,
) -> Result<MiddlewareApplyResult> {
    if chain.is_empty() {
        return Ok(MiddlewareApplyResult::Allowed(req));
    }
    let chain = runner.describe_chain(&chain).await?;
    if matches!(
        transformed_body_policy,
        openshell_supervisor_middleware::TransformedBodyPolicy::Reevaluate(_)
    ) {
        return apply_buffered_middleware_chain(
            req,
            client,
            ctx,
            scheme,
            chain,
            runner,
            generation_guard,
            transformed_body_policy,
            request_id,
        )
        .await;
    }

    Box::pin(apply_streaming_middleware_chain(
        req,
        client,
        ctx,
        scheme,
        chain,
        runner,
        generation_guard,
        request_id,
        delivery,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
async fn apply_buffered_middleware_chain<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    scheme: &str,
    chain: Vec<openshell_supervisor_middleware::DescribedChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
    transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
    request_id: &str,
) -> Result<MiddlewareApplyResult> {
    let admission = if chain.is_empty() {
        None
    } else {
        let work_admission = runner.reserve_middleware_work().await?;
        match work_admission {
            openshell_supervisor_middleware::MiddlewareWorkAdmissionOutcome::Admitted(
                admission,
            ) => Some(admission),
            openshell_supervisor_middleware::MiddlewareWorkAdmissionOutcome::QueueExhausted => {
                emit_middleware_admission_exhausted(ctx);
                return Ok(MiddlewareApplyResult::AdmissionExhausted);
            }
        }
    };
    let Some(max_body_bytes) = middleware_chain_body_limit(&chain) else {
        let input = middleware_request_input_with_id(
            openshell_ocsf::ctx::ctx(),
            scheme,
            &req,
            ctx,
            Vec::new(),
            Vec::new(),
            String::new(),
            Vec::new(),
            request_id,
        );
        let outcome = runner
            .evaluate_described_with_policy_admitted(
                &chain,
                input,
                openshell_supervisor_middleware::TransformedBodyPolicy::NotPolicyRelevant,
                admission,
            )
            .await?;
        emit_middleware_events(ctx, &req, &outcome);
        return Ok(if outcome.allowed {
            MiddlewareApplyResult::Allowed(req)
        } else {
            MiddlewareApplyResult::Denied {
                denial: outcome.denial,
            }
        });
    };
    let admission = admission.expect("resolved middleware chain reserved work admission");
    let buffer_result = crate::l7::rest::buffer_request_body_for_middleware(
        &req,
        client,
        Some(generation_guard),
        max_body_bytes,
    )
    .await?;
    let buffered = match buffer_result {
        crate::l7::rest::BufferResult::Buffered(buffered) => buffered,
        crate::l7::rest::BufferResult::OverCapacity => {
            return Ok(resolve_unbuffered_body(ctx));
        }
    };
    let headers = safe_middleware_headers(&buffered.headers)?;
    let query = raw_query_from_request_headers(&buffered.headers)?;
    let input = middleware_request_input_with_id(
        openshell_ocsf::ctx::ctx(),
        scheme,
        &req,
        ctx,
        headers.visible,
        headers.connection_nominated,
        query,
        buffered.body,
        request_id,
    );
    let outcome = runner
        .evaluate_described_with_policy_admitted(
            &chain,
            input,
            transformed_body_policy,
            Some(admission),
        )
        .await?;
    emit_middleware_events(ctx, &req, &outcome);
    if !outcome.allowed {
        return Ok(MiddlewareApplyResult::Denied {
            denial: outcome.denial,
        });
    }
    let rebuilt = crate::l7::rest::rebuild_request_with_buffered_body(
        &req,
        &buffered.headers,
        &outcome.body,
        &outcome.header_mutations,
    )?;
    Ok(MiddlewareApplyResult::Allowed(rebuilt))
}

#[allow(clippy::too_many_arguments)]
async fn apply_streaming_middleware_chain<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    scheme: &str,
    chain: Vec<openshell_supervisor_middleware::DescribedChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
    request_id: &str,
    delivery: RequestBodyDelivery,
) -> Result<MiddlewareApplyResult> {
    let header_end = req
        .raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(req.raw_header.len(), |position| position + 4);
    let original_headers = &req.raw_header[..header_end];
    let headers = safe_middleware_headers(original_headers)?;
    let query = raw_query_from_request_headers(original_headers)?;
    let sandbox = openshell_ocsf::ctx::ctx();
    let input = openshell_supervisor_middleware::HttpRequestPreflightInput {
        context: openshell_core::proto::RequestContext {
            request_id: request_id.to_string(),
            sandbox_id: sandbox.sandbox_id.clone(),
            sandbox: sandbox.sandbox_name.clone(),
            workspace: ctx.workspace.clone(),
            originating_process: None,
        },
        target: openshell_core::proto::HttpRequestTarget {
            scheme: scheme.to_string(),
            host: ctx.host.clone(),
            port: u32::from(ctx.port),
            method: req.action.clone(),
            path: req.target.clone(),
            query,
        },
        declared_body_length: match req.body_length {
            crate::l7::provider::BodyLength::ContentLength(length) => Some(length),
            crate::l7::provider::BodyLength::None => Some(0),
            crate::l7::provider::BodyLength::Chunked => None,
        },
        headers: headers
            .visible
            .into_iter()
            .map(|(name, value)| openshell_core::proto::HttpHeader { name, value })
            .collect(),
        connection_nominated_headers: headers.connection_nominated,
    };
    let mut preflight = runner
        .preflight_described_http_request(chain, input)
        .await?;
    if preflight.session_capacity_exhausted {
        emit_middleware_admission_exhausted(ctx);
        return Ok(MiddlewareApplyResult::AdmissionExhausted);
    }
    if !preflight.allowed {
        emit_streaming_middleware_events(
            ctx,
            &req,
            false,
            &preflight.reason,
            preflight.denial.as_ref(),
            &preflight.findings,
            &preflight.metadata,
            &preflight.invocations,
            false,
        );
        return Ok(MiddlewareApplyResult::Denied {
            denial: preflight.denial,
        });
    }

    let Some(session) = preflight.session.take() else {
        let rebuilt =
            crate::l7::rest::rebuild_request_headers_only(&req, &preflight.header_mutations)?;
        emit_streaming_middleware_events(
            ctx,
            &req,
            true,
            "",
            None,
            &preflight.findings,
            &preflight.metadata,
            &preflight.invocations,
            !preflight.header_mutations.is_empty(),
        );
        return Ok(MiddlewareApplyResult::Allowed(rebuilt));
    };

    let (prepared_headers, mut body_reader) =
        crate::l7::rest::prepare_request_body_stream(&req, client).await?;

    if delivery == RequestBodyDelivery::Incremental
        && !session.requires_withholding()
        && !matches!(req.body_length, crate::l7::provider::BodyLength::None)
        && req
            .raw_header
            .split(|byte| *byte == b'\n')
            .next()
            .is_some_and(|line| line.windows(8).any(|window| window == b"HTTP/1.1"))
    {
        let rebuilt = crate::l7::rest::rebuild_request_for_incremental_stream(
            &req,
            &prepared_headers,
            &preflight.header_mutations,
        )?;
        let request = crate::l7::provider::L7Request {
            action: req.action.clone(),
            target: req.target.clone(),
            query_params: req.query_params.clone(),
            raw_header: req.raw_header.clone(),
            body_length: req.body_length,
        };
        return Ok(MiddlewareApplyResult::Streamed {
            request: rebuilt,
            body: MiddlewareRequestBody::Live(Box::new(RequestBodyStream {
                reader: body_reader,
                session: Some(session),
                preflight,
                request,
                context: ctx.clone(),
                generation_guard: generation_guard.clone(),
                deadline: tokio::time::Instant::now() + DEFAULT_HTTP_REQUEST_BODY_TIMEOUT,
                terminal_emitted: false,
            })),
        });
    }

    let body_deadline = tokio::time::Instant::now() + DEFAULT_HTTP_REQUEST_BODY_TIMEOUT;
    let unit_limit = session.stream_unit_limit();
    let (input_tx, input_rx) = tokio::sync::mpsc::channel(4);
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(4);

    let feed = async move {
        loop {
            let unit = body_reader
                .next_unit(client, Some(generation_guard), unit_limit)
                .await?;
            let Some(unit) = unit else {
                break;
            };
            input_tx
                .send(openshell_supervisor_middleware::HttpRequestBodyInput::Chunk(unit))
                .await
                .map_err(|_| miette!("request middleware input closed"))?;
        }
        input_tx
            .send(openshell_supervisor_middleware::HttpRequestBodyInput::End(
                body_reader.take_trailers(),
            ))
            .await
            .map_err(|_| miette!("request middleware input closed"))
    };
    let collect = async move {
        let mut body = Vec::new();
        let mut trailers = Vec::new();
        let mut started = false;
        while let Some(event) = output_rx.recv().await {
            match event {
                openshell_supervisor_middleware::HttpRequestBodyOutput::Start { .. }
                    if !started =>
                {
                    started = true;
                }
                openshell_supervisor_middleware::HttpRequestBodyOutput::Chunk(unit) if started => {
                    if body.len().saturating_add(unit.len())
                        > openshell_supervisor_middleware::MAX_HTTP_REQUEST_DEFERRED_BYTES
                    {
                        return Err(miette!(
                            "middleware request output exceeds platform memory limit"
                        ));
                    }
                    body.extend_from_slice(&unit);
                }
                openshell_supervisor_middleware::HttpRequestBodyOutput::End { trailers: value }
                    if started =>
                {
                    trailers = value;
                    break;
                }
                _ => return Err(miette!("invalid request middleware output order")),
            }
        }
        if !started {
            return Err(miette!("request middleware output did not start"));
        }
        Ok::<_, miette::Report>((body, trailers))
    };
    let run = session.run(input_rx, output_tx);
    let completed = Box::pin(tokio::time::timeout_at(body_deadline, async {
        let (finish, feed, output) = tokio::join!(run, feed, collect);
        if finish.is_err() {
            return Ok::<_, miette::Report>((finish, (Vec::new(), Vec::new())));
        }
        feed?;
        let output = output?;
        Ok::<_, miette::Report>((finish, output))
    }))
    .await;
    let (finish, (body, trailers)) = match completed {
        Err(_) => {
            emit_request_body_timeout(
                ctx,
                &req,
                &preflight,
                openshell_supervisor_middleware::HttpRequestDiagnostics::default(),
            );
            return Ok(MiddlewareApplyResult::Denied { denial: None });
        }
        Ok(Err(error)) => return Err(error),
        Ok(Ok((Err(error), _))) => {
            let mut invocations = preflight.invocations;
            invocations.extend(error.diagnostics.invocations);
            let mut findings = preflight.findings;
            findings.extend(error.diagnostics.findings);
            let mut metadata = preflight.metadata;
            metadata.extend(error.diagnostics.metadata);
            emit_streaming_middleware_events(
                ctx,
                &req,
                false,
                &error.reason,
                error.denial.as_ref(),
                &findings,
                &metadata,
                &invocations,
                false,
            );
            return Ok(MiddlewareApplyResult::Denied {
                denial: error.denial,
            });
        }
        Ok(Ok((Ok(finish), output))) => (finish, output),
    };
    generation_guard.ensure_current()?;

    let rebuilt = crate::l7::rest::rebuild_request_with_streamed_body(
        &req,
        &prepared_headers,
        body.len() as u64,
        &trailers,
        &preflight.header_mutations,
    )?;
    let mut invocations = preflight.invocations;
    invocations.extend(finish.invocations);
    let mut findings = preflight.findings;
    findings.extend(finish.findings);
    let mut metadata = preflight.metadata;
    metadata.extend(finish.metadata);
    emit_streaming_middleware_events(
        ctx,
        &req,
        true,
        "",
        None,
        &findings,
        &metadata,
        &invocations,
        finish.body_transformed || !preflight.header_mutations.is_empty(),
    );
    Ok(MiddlewareApplyResult::Streamed {
        request: rebuilt,
        body: MiddlewareRequestBody::Buffered(BufferedRequestBody {
            bytes: body,
            trailers,
        }),
    })
}

impl RequestBodyStream {
    /// Run an incremental request session into a bounded output channel.
    ///
    /// The HTTP relay drains the channel directly into the upstream socket,
    /// so channel and socket backpressure bound supervisor memory without a
    /// whole-request storage cap.
    pub(crate) async fn run_to<C>(
        &mut self,
        client: &mut C,
        output: tokio::sync::mpsc::Sender<openshell_supervisor_middleware::HttpRequestBodyOutput>,
    ) -> Result<openshell_supervisor_middleware::HttpRequestFinish>
    where
        C: AsyncRead + Unpin,
    {
        let session = self
            .session
            .take()
            .ok_or_else(|| miette!("request middleware session is unavailable"))?;
        let unit_limit = session.stream_unit_limit();
        let (input_tx, input_rx) = tokio::sync::mpsc::channel(4);
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(4);
        let deadline = self.deadline;
        let reader = &mut self.reader;
        let generation_guard = &self.generation_guard;
        let feed = async move {
            loop {
                let unit = reader
                    .next_unit(client, Some(generation_guard), unit_limit)
                    .await?;
                let Some(unit) = unit else {
                    break;
                };
                input_tx
                    .send(openshell_supervisor_middleware::HttpRequestBodyInput::Chunk(unit))
                    .await
                    .map_err(|_| miette!("request middleware input closed"))?;
            }
            input_tx
                .send(openshell_supervisor_middleware::HttpRequestBodyInput::End(
                    reader.take_trailers(),
                ))
                .await
                .map_err(|_| miette!("request middleware input closed"))
        };
        let forward = async move {
            let mut started = false;
            while let Some(event) = event_rx.recv().await {
                match &event {
                    openshell_supervisor_middleware::HttpRequestBodyOutput::Start { .. }
                        if !started =>
                    {
                        started = true;
                    }
                    openshell_supervisor_middleware::HttpRequestBodyOutput::Chunk(_) if started => {
                    }
                    openshell_supervisor_middleware::HttpRequestBodyOutput::End { .. }
                        if started =>
                    {
                        output
                            .send(event)
                            .await
                            .map_err(|_| miette!("request middleware output consumer closed"))?;
                        return Ok::<(), miette::Report>(());
                    }
                    _ => return Err(miette!("invalid request middleware output order")),
                }
                output
                    .send(event)
                    .await
                    .map_err(|_| miette!("request middleware output consumer closed"))?;
            }
            Err(miette!("request middleware output ended early"))
        };
        let run = session.run(input_rx, event_tx);
        let completed = Box::pin(tokio::time::timeout_at(deadline, async {
            let (finish, feed, forward) = tokio::join!(run, feed, forward);
            if finish.is_err() {
                return Ok::<_, miette::Report>(finish);
            }
            feed?;
            forward?;
            Ok::<_, miette::Report>(finish)
        }))
        .await;
        match completed {
            Err(_) => {
                self.emit_failure(
                    "middleware_failed: request_body_timeout",
                    None,
                    openshell_supervisor_middleware::HttpRequestDiagnostics::default(),
                );
                Err(miette!("request middleware body deadline exceeded"))
            }
            Ok(Err(error)) => {
                self.emit_failure(
                    "middleware_failed: request_body_io_failed",
                    None,
                    openshell_supervisor_middleware::HttpRequestDiagnostics::default(),
                );
                Err(error)
            }
            Ok(Ok(Err(error))) => {
                let reason = error.reason.clone();
                let denial = error.denial.clone();
                self.emit_failure(&reason, denial.as_ref(), *error.diagnostics);
                Err(miette::Report::new(RequestBodyMiddlewareError {
                    reason,
                    denial,
                }))
            }
            Ok(Ok(Ok(finish))) => {
                self.emit_success(&finish);
                Ok(finish)
            }
        }
    }

    /// Terminate a live session after an upstream response wins the race with
    /// request upload. Unread client bytes make the downstream connection
    /// non-reusable, and no request replay is attempted.
    pub(crate) async fn cancel_for_early_response(&mut self) {
        let diagnostics = self
            .session
            .as_mut()
            .map(openshell_supervisor_middleware::HttpRequestSession::take_diagnostics)
            .unwrap_or_default();
        self.cancel_with_diagnostics("middleware_cancelled: upstream_response", diagnostics)
            .await;
    }

    async fn cancel_with_diagnostics(
        &mut self,
        reason: &str,
        diagnostics: openshell_supervisor_middleware::HttpRequestDiagnostics,
    ) {
        if let Some(session) = self.session.take() {
            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::Cancellation)
                .await;
        }
        self.emit_failure(reason, None, diagnostics);
    }

    fn emit_success(&mut self, finish: &openshell_supervisor_middleware::HttpRequestFinish) {
        if self.terminal_emitted {
            return;
        }
        let mut invocations = self.preflight.invocations.clone();
        invocations.extend(finish.invocations.clone());
        let mut findings = self.preflight.findings.clone();
        findings.extend(finish.findings.clone());
        let mut metadata = self.preflight.metadata.clone();
        metadata.extend(finish.metadata.clone());
        emit_streaming_middleware_events(
            &self.context,
            &self.request,
            true,
            "",
            None,
            &findings,
            &metadata,
            &invocations,
            finish.body_transformed || !self.preflight.header_mutations.is_empty(),
        );
        self.terminal_emitted = true;
    }

    fn emit_failure(
        &mut self,
        reason: &str,
        denial: Option<&openshell_supervisor_middleware::MiddlewareDenial>,
        diagnostics: openshell_supervisor_middleware::HttpRequestDiagnostics,
    ) {
        if self.terminal_emitted {
            return;
        }
        let mut invocations = self.preflight.invocations.clone();
        invocations.extend(diagnostics.invocations);
        let mut findings = self.preflight.findings.clone();
        findings.extend(diagnostics.findings);
        let mut metadata = self.preflight.metadata.clone();
        metadata.extend(diagnostics.metadata);
        emit_streaming_middleware_events(
            &self.context,
            &self.request,
            false,
            reason,
            denial,
            &findings,
            &metadata,
            &invocations,
            false,
        );
        self.terminal_emitted = true;
    }
}

fn emit_request_body_timeout(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    preflight: &openshell_supervisor_middleware::HttpRequestPreflightOutcome,
    diagnostics: openshell_supervisor_middleware::HttpRequestDiagnostics,
) {
    let mut invocations = preflight.invocations.clone();
    invocations.extend(diagnostics.invocations);
    let mut findings = preflight.findings.clone();
    findings.extend(diagnostics.findings);
    let mut metadata = preflight.metadata.clone();
    metadata.extend(diagnostics.metadata);
    emit_streaming_middleware_events(
        ctx,
        req,
        false,
        "middleware_failed: request_body_timeout",
        None,
        &findings,
        &metadata,
        &invocations,
        false,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_streaming_middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    allowed: bool,
    reason: &str,
    denial: Option<&openshell_supervisor_middleware::MiddlewareDenial>,
    findings: &[openshell_supervisor_middleware::NamespacedFinding],
    metadata: &std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    invocations: &[openshell_supervisor_middleware::HttpRequestInvocation],
    transformed: bool,
) {
    let mut applied = Vec::<openshell_supervisor_middleware::MiddlewareInvocation>::new();
    for invocation in invocations {
        if let Some(existing) = applied
            .iter_mut()
            .find(|existing| existing.name == invocation.config_name)
        {
            existing.failed |= invocation.failed;
            existing.transformed |= matches!(
                invocation.outcome,
                openshell_supervisor_middleware::HttpRequestInvocationOutcome::Replacement
            );
            if matches!(
                invocation.outcome,
                openshell_supervisor_middleware::HttpRequestInvocationOutcome::Reject
                    | openshell_supervisor_middleware::HttpRequestInvocationOutcome::FailClosed
            ) {
                existing.decision = openshell_core::proto::Decision::Deny;
            }
            continue;
        }
        applied.push(openshell_supervisor_middleware::MiddlewareInvocation {
            name: invocation.config_name.clone(),
            implementation: invocation.implementation.clone(),
            decision: if matches!(
                invocation.outcome,
                openshell_supervisor_middleware::HttpRequestInvocationOutcome::Reject
                    | openshell_supervisor_middleware::HttpRequestInvocationOutcome::FailClosed
            ) {
                openshell_core::proto::Decision::Deny
            } else {
                openshell_core::proto::Decision::Allow
            },
            transformed,
            failed: invocation.failed,
        });
    }
    let outcome = openshell_supervisor_middleware::ChainOutcome {
        allowed,
        reason: reason.to_string(),
        body: Vec::new(),
        header_mutations: Vec::new(),
        findings: findings.to_vec(),
        metadata: metadata.clone(),
        applied,
        denial: denial.cloned(),
    };
    emit_middleware_events(ctx, req, &outcome);
}

pub async fn send_middleware_rejection_response<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: &crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    denial: Option<&openshell_supervisor_middleware::MiddlewareDenial>,
    redacted_target: &str,
) -> Result<()> {
    let context = Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx));
    if let Some(denial) = denial {
        crate::l7::rest::send_middleware_deny_response(
            req,
            &ctx.policy_name,
            denial,
            client,
            Some(redacted_target),
            context,
        )
        .await
    } else {
        crate::l7::rest::send_middleware_failure_response(
            req,
            &ctx.policy_name,
            client,
            Some(redacted_target),
            context,
        )
        .await
    }
}

pub async fn send_middleware_admission_exhausted_response<
    C: AsyncRead + AsyncWrite + Unpin + Send,
>(
    req: &crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    redacted_target: &str,
) -> Result<()> {
    crate::l7::rest::send_middleware_unavailable_response(
        req,
        &ctx.policy_name,
        client,
        Some(redacted_target),
        Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn middleware_request_input_with_id(
    sandbox: &openshell_ocsf::EventContext,
    scheme: &str,
    req: &crate::l7::provider::L7Request,
    ctx: &L7EvalContext,
    headers: Vec<(String, String)>,
    connection_nominated_headers: Vec<String>,
    query: String,
    body: Vec<u8>,
    request_id: &str,
) -> openshell_supervisor_middleware::HttpRequestInput {
    openshell_supervisor_middleware::HttpRequestInput {
        request_id: request_id.to_string(),
        sandbox_id: sandbox.sandbox_id.clone(),
        sandbox_name: sandbox.sandbox_name.clone(),
        workspace: ctx.workspace.clone(),
        scheme: scheme.into(),
        host: ctx.host.clone(),
        port: ctx.port,
        method: req.action.clone(),
        path: req.target.clone(),
        query,
        headers,
        connection_nominated_headers,
        body,
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn middleware_request_input(
    sandbox: &openshell_ocsf::EventContext,
    scheme: &str,
    req: &crate::l7::provider::L7Request,
    ctx: &L7EvalContext,
    headers: Vec<(String, String)>,
    connection_nominated_headers: Vec<String>,
    query: String,
    body: Vec<u8>,
) -> openshell_supervisor_middleware::HttpRequestInput {
    let request_id = uuid::Uuid::new_v4().to_string();
    middleware_request_input_with_id(
        sandbox,
        scheme,
        req,
        ctx,
        headers,
        connection_nominated_headers,
        query,
        body,
        &request_id,
    )
}

pub(super) fn raw_query_from_request_headers(headers: &[u8]) -> Result<String> {
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let target = header_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| miette!("HTTP request line is missing a target"))?;
    Ok(target
        .split_once('?')
        .map_or_else(String::new, |(_, query)| query.to_string()))
}

/// Deny when the request body exceeds the bounded hold required by this path.
/// HTTP middleware never bypasses a selected stage on failure, even if invalid
/// policy state reaches this defensive runtime check.
pub(super) fn resolve_unbuffered_body(ctx: &L7EvalContext) -> MiddlewareApplyResult {
    emit_middleware_body_unavailable(ctx);
    MiddlewareApplyResult::Denied { denial: None }
}

fn emit_middleware_body_unavailable(ctx: &L7EvalContext) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::High)
        .finding_info(FindingInfo::new(
            "openshell.middleware.body_unavailable",
            "Supervisor middleware could not inspect request body",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("disposition", "denied"),
        ])
        .message("Request body exceeded middleware inspection cap; denied")
        .build();
    ocsf_emit!(event);
}

/// Parse the raw header block into middleware-visible headers, preserving
/// wire order and repeated names so middleware inspects every value the
/// upstream will receive. Credential-bearing and hop-by-hop headers are
/// omitted, while dynamically nominated names are retained separately for
/// mutation validation.
struct SafeMiddlewareHeaders {
    visible: Vec<(String, String)>,
    connection_nominated: Vec<String>,
}

fn safe_middleware_headers(headers: &[u8]) -> Result<SafeMiddlewareHeaders> {
    crate::l7::rest::validate_http_request_header_block(headers)?;
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let header_block = header_str
        .strip_suffix("\r\n\r\n")
        .expect("validated header block has terminator");
    let connection_nominated = crate::l7::rest::connection_nominated_header_names(headers)?;

    let visible = header_block
        .split("\r\n")
        .skip(1)
        .map(|line| {
            let (name, value) = line
                .split_once(':')
                .expect("validated header field contains colon");
            (name.to_ascii_lowercase(), value.trim().to_string())
        })
        .filter(|(name, _)| {
            !name.is_empty()
                && !matches!(
                    name.as_str(),
                    "authorization"
                        | "proxy-authorization"
                        | "proxy-authenticate"
                        | "cookie"
                        | "host"
                        | "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "proxy-connection"
                        | "keep-alive"
                        | "te"
                        | "trailer"
                        | "upgrade"
                )
                && !name.starts_with("x-amz-")
                && !name.starts_with("x-openshell-credential")
                && !connection_nominated.contains(name)
        })
        .collect();
    let mut connection_nominated: Vec<_> = connection_nominated.into_iter().collect();
    connection_nominated.sort();
    Ok(SafeMiddlewareHeaders {
        visible,
        connection_nominated,
    })
}

pub fn middleware_network_input(ctx: &L7EvalContext) -> crate::opa::NetworkInput {
    crate::opa::NetworkInput {
        host: ctx.host.clone(),
        port: ctx.port,
        binary_path: PathBuf::from(&ctx.binary_path),
        binary_sha256: String::new(),
        ancestors: ctx.ancestors.iter().map(PathBuf::from).collect(),
        cmdline_paths: ctx.cmdline_paths.iter().map(PathBuf::from).collect(),
    }
}

/// Build the OCSF events describing a middleware chain outcome, in emission
/// order. Separated from `emit_middleware_events` so tests can assert on the
/// events deterministically without routing through the global tracing pipeline,
/// whose callsite-interest cache is process-global and races under parallel
/// tests.
pub(super) fn middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    outcome: &openshell_supervisor_middleware::ChainOutcome,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = Vec::new();
    for invocation in &outcome.applied {
        let allowed = invocation.decision == openshell_core::proto::Decision::Allow;
        let mut event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .action(if allowed {
                ActionId::Allowed
            } else {
                ActionId::Denied
            })
            .disposition(if allowed {
                DispositionId::Allowed
            } else {
                DispositionId::Blocked
            })
            .severity(if allowed {
                SeverityId::Informational
            } else {
                SeverityId::Medium
            })
            .http_request(HttpRequest::new(
                &req.action,
                OcsfUrl::new("http", &ctx.host, &req.target, ctx.port),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "middleware")
            .unmapped("transformed", invocation.transformed)
            .unmapped("failed", invocation.failed)
            .message(format!(
                "MIDDLEWARE {} {} decision={:?}",
                invocation.name, invocation.implementation, invocation.decision
            ));
        if !allowed && !outcome.reason.is_empty() {
            event = event
                .status(StatusId::Failure)
                .status_detail(&outcome.reason);
        }
        let event = event.build();
        events.push(event);

        // A middleware that failed but was bypassed under `fail_open` is an
        // enforcement failure operators must be able to alert on, even though the
        // request proceeded.
        if invocation.failed && allowed {
            let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Medium)
                .finding_info(FindingInfo::new(
                    "openshell.middleware.failure",
                    "Supervisor middleware failed open",
                ))
                .evidence_pairs(&[
                    ("middleware", invocation.name.as_str()),
                    ("implementation", invocation.implementation.as_str()),
                ])
                .unmapped("middleware", invocation.name.as_str())
                .unmapped("implementation", invocation.implementation.as_str())
                .message(format!(
                    "Middleware {} failed and was bypassed (fail_open)",
                    invocation.name
                ))
                .build();
            events.push(event);
        }
    }
    if !outcome.allowed && outcome.reason.starts_with("middleware_failed:") {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new(
                "openshell.middleware.failure",
                "Supervisor middleware failure",
            ))
            .message("Required supervisor middleware failed closed")
            .build();
        events.push(event);
    }
    if !outcome.allowed
        && outcome
            .reason
            .starts_with("transformed_body_policy_evaluation_failed:")
    {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new(
                "openshell.middleware.policy_evaluation_failure",
                "Post-middleware policy evaluation failed",
            ))
            .evidence_pairs(&[
                ("policy", ctx.policy_name.as_str()),
                ("host", ctx.host.as_str()),
            ])
            .message("Transformed request denied because policy evaluation failed")
            .build();
        events.push(event);
    }
    // Each stage and the selected chain are independently bounded by the
    // runner. Keep the derived chain-wide emission bound as defense in depth
    // for manually constructed or future outcome producers.
    events.extend(middleware_finding_events(&outcome.findings));
    events
}

/// Emit the OCSF events describing a middleware chain outcome through the
/// tracing pipeline.
fn emit_middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    outcome: &openshell_supervisor_middleware::ChainOutcome,
) {
    for event in middleware_events(ctx, req, outcome) {
        ocsf_emit!(event);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        middleware_admission_exhausted_event, safe_middleware_headers,
        send_middleware_rejection_response, websocket_coverage_events,
        websocket_message_finding_events, websocket_preflight_finding_events,
    };
    use crate::l7::relay::L7EvalContext;
    use tokio::io::AsyncReadExt;

    #[test]
    fn admission_exhaustion_event_contains_only_platform_context() {
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            binary_path: "DO_NOT_LOG_BINARY".into(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&middleware_admission_exhausted_event(&ctx))
            .expect("serialize admission event");
        assert!(serialized.contains("openshell.middleware.admission_exhausted"));
        assert!(serialized.contains("api-policy"));
        assert!(serialized.contains("api.example.test"));
        assert!(serialized.contains("http_request"));
        assert!(serialized.contains("shed"));
        assert!(!serialized.contains("DO_NOT_LOG_BINARY"));
        assert!(!serialized.contains("middleware_config"));
        assert!(!serialized.contains("request_body"));
        assert!(!serialized.contains("query"));
    }

    #[test]
    fn websocket_coverage_events_distinguish_selection_from_message_support() {
        use openshell_ocsf::SeverityId;
        use openshell_supervisor_middleware::{
            WebSocketCoverage, WebSocketCoverageState as State, WebSocketMessageType,
        };

        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            ..Default::default()
        };
        let events = websocket_coverage_events(
            &ctx,
            &[
                WebSocketCoverage {
                    config_name: "http-guard".into(),
                    implementation: "example/http-only".into(),
                    state: State::BindingNotSelected,
                    sequence: None,
                    message_type: None,
                    original_size: 0,
                },
                WebSocketCoverage {
                    config_name: "text-guard".into(),
                    implementation: "example/websocket-text".into(),
                    state: State::UnsupportedMessageType,
                    sequence: Some(7),
                    message_type: Some(WebSocketMessageType::Binary),
                    original_size: 23,
                },
            ],
        );

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.class_uid() == 4001));
        assert!(
            events
                .iter()
                .all(|event| event.base().severity == SeverityId::Informational)
        );
        let serialized = serde_json::to_string(&events).expect("serialize coverage events");
        assert!(serialized.contains("binding_not_selected"));
        assert!(serialized.contains("unsupported_message_type"));
        assert!(serialized.contains("\"websocket_message_type\":\"binary\""));
        assert!(serialized.contains("\"websocket_sequence\":\"7\""));
        assert!(serialized.contains("\"input_bytes\":23"));
        assert!(!serialized.contains("fail_open"));
        assert!(!serialized.contains("fail_closed"));
    }

    #[test]
    fn websocket_preflight_findings_match_http_mapping() {
        let outcome = openshell_supervisor_middleware::WebSocketPreflightResult {
            allowed: true,
            terminal_reason: None,
            reason: "allowed".into(),
            denial: None,
            session: None,
            findings: vec![test_namespaced_finding()],
            metadata: std::collections::BTreeMap::new(),
            invocations: Vec::new(),
            coverage: Vec::new(),
            saturated: false,
            session_capacity_exhausted: false,
        };

        assert_middleware_finding_mapping(websocket_preflight_finding_events(&outcome));
    }

    #[test]
    fn websocket_message_findings_match_http_mapping() {
        let outcome = openshell_supervisor_middleware::WebSocketMessageOutcome {
            allowed: true,
            reason: "allowed".into(),
            payload: "hello".into(),
            findings: vec![test_namespaced_finding()],
            metadata: std::collections::BTreeMap::new(),
            invocations: Vec::new(),
            denial: None,
            saturated: false,
            platform_oversize: false,
        };

        assert_middleware_finding_mapping(websocket_message_finding_events(&outcome));
    }

    fn test_namespaced_finding() -> openshell_supervisor_middleware::NamespacedFinding {
        openshell_supervisor_middleware::NamespacedFinding {
            middleware: "content-guard".into(),
            finding: openshell_core::proto::Finding {
                r#type: "regex.api_key".into(),
                label: "API key".into(),
                count: 3,
                confidence: "high".into(),
                severity: "high".into(),
            },
        }
    }

    fn assert_middleware_finding_mapping(events: Vec<openshell_ocsf::OcsfEvent>) {
        use openshell_ocsf::SeverityId;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].class_uid(), 2004);
        assert_eq!(events[0].base().severity, SeverityId::High);
        let serialized = serde_json::to_string(&events[0]).expect("serialize finding event");
        assert!(serialized.contains("regex.api_key"));
        assert!(serialized.contains("API key"));
        assert!(serialized.contains("content-guard"));
        assert!(serialized.contains("\"count\":3"));
        assert!(serialized.contains("Middleware finding regex.api_key count=3"));
        assert!(!serialized.contains("openshell.middleware.websocket_finding"));
    }

    #[tokio::test]
    async fn direct_denial_uses_middleware_response_without_service_text() {
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            ..Default::default()
        };
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };
        let denial = openshell_supervisor_middleware::MiddlewareDenial {
            config_name: "prototype-content-guard".into(),
            reason_code: Some("content_match".into()),
        };
        let (mut client, mut server) = tokio::io::duplex(4096);

        send_middleware_rejection_response(&req, &mut server, &ctx, Some(&denial), "/v1/messages")
            .await
            .expect("send denial");
        drop(server);

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read denial");
        let response = String::from_utf8(response).expect("UTF-8 response");
        let (_, body) = response.split_once("\r\n\r\n").expect("HTTP response");
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON response");
        assert_eq!(body["error"], "middleware_denied");
        assert_eq!(body["middleware"], "prototype-content-guard");
        assert_eq!(body["reason_code"], "content_match");
        assert!(body.get("rule_missing").is_none());
        assert!(body.get("next_steps").is_none());
        assert!(!body.to_string().contains("secret-value"));
    }

    #[test]
    fn middleware_input_carries_real_sandbox_name() {
        let sandbox = openshell_ocsf::EventContext {
            sandbox_id: "sbx-123".into(),
            sandbox_name: "nightly-build".into(),
            container_image: String::new(),
            hostname: "h".into(),
            product_version: "0".into(),
            proxy_ip: [127, 0, 0, 1].into(),
            proxy_port: 3128,
        };

        let eval = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            workspace: "wrks-default".into(),
            policy_name: "api-policy".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            ..Default::default()
        };
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };

        let input = super::middleware_request_input_with_id(
            &sandbox,
            "https",
            &req,
            &eval,
            Vec::new(),
            Vec::new(),
            String::new(),
            Vec::new(),
            "exchange-123",
        );

        assert_eq!(input.sandbox_name, "nightly-build");
        assert_eq!(input.sandbox_id, "sbx-123");
        assert_eq!(input.workspace, "wrks-default");
        assert_eq!(input.request_id, "exchange-123");
    }

    #[tokio::test]
    async fn middleware_failure_uses_platform_response_without_policy_guidance() {
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            ..Default::default()
        };
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };
        let (mut client, mut server) = tokio::io::duplex(4096);

        send_middleware_rejection_response(&req, &mut server, &ctx, None, "/v1/messages")
            .await
            .expect("send failure");
        drop(server);

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read failure");
        let response = String::from_utf8(response).expect("UTF-8 response");
        let (_, body) = response.split_once("\r\n\r\n").expect("HTTP response");
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON response");
        assert_eq!(body["error"], "middleware_failed");
        assert_eq!(
            body["detail"],
            "Request could not be processed by configured middleware"
        );
        assert!(body.get("rule").is_none());
        assert!(body.get("rule_missing").is_none());
        assert!(body.get("next_steps").is_none());
        assert!(body.get("agent_guidance").is_none());
    }

    #[test]
    fn middleware_headers_exclude_origin_and_proxy_credentials() {
        let headers = safe_middleware_headers(
            b"GET http://api.example.test/v1 HTTP/1.1\r\n\
              Authorization: Bearer origin-secret\r\n\
              Proxy-Authorization: Basic proxy-secret\r\n\
              X-Request-ID: request-123\r\n\r\n",
        )
        .expect("headers should parse");

        assert_eq!(
            headers.visible,
            vec![("x-request-id".to_string(), "request-123".to_string())]
        );
    }

    #[test]
    fn middleware_headers_preserve_repeated_names_in_wire_order() {
        // Repeated header names must reach middleware as separate entries in
        // wire order: keeping only one value would let a request smuggle a
        // differently-positioned duplicate past inspection while the upstream
        // still receives every original value.
        let headers = safe_middleware_headers(
            b"POST /v1 HTTP/1.1\r\n\
              X-Api-Key: first-value\r\n\
              Accept: application/json\r\n\
              X-Api-Key: second-value\r\n\r\n",
        )
        .expect("headers should parse");

        assert_eq!(
            headers.visible,
            vec![
                ("x-api-key".to_string(), "first-value".to_string()),
                ("accept".to_string(), "application/json".to_string()),
                ("x-api-key".to_string(), "second-value".to_string()),
            ]
        );
    }

    #[test]
    fn middleware_headers_omit_standard_and_connection_nominated_hop_by_hop_fields() {
        let headers = safe_middleware_headers(
            b"GET /v1 HTTP/1.1\r\n\
              X-Hop: secret-hop-value\r\n\
              Connection: keep-alive, x-hop\r\n\
              Keep-Alive: timeout=5\r\n\
              TE: trailers\r\n\
              Trailer: X-Checksum\r\n\
              Upgrade: websocket\r\n\
              X-Visible: visible-value\r\n\r\n",
        )
        .expect("headers should parse");

        assert_eq!(
            headers.visible,
            vec![("x-visible".to_string(), "visible-value".to_string())]
        );
        assert_eq!(headers.connection_nominated, vec!["keep-alive", "x-hop"]);
    }

    #[test]
    fn middleware_headers_reject_malformed_fields_instead_of_dropping_them() {
        for headers in [
            b"GET /v1 HTTP/1.1\r\nX-Test: first\r\n continued\r\n\r\n".as_slice(),
            b"GET /v1 HTTP/1.1\r\nX-Test value\r\n\r\n".as_slice(),
            b"GET /v1 HTTP/1.1\r\nX-Test : value\r\n\r\n".as_slice(),
            b"GET /v1 HTTP/1.1\r\nX@Test: value\r\n\r\n".as_slice(),
        ] {
            assert!(
                safe_middleware_headers(headers).is_err(),
                "middleware must reject malformed header fields"
            );
        }
    }
}
