// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware application for L7 requests.

use crate::l7::relay::L7EvalContext;
use crate::opa::PolicyGenerationGuard;
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo,
    HttpActivityBuilder, HttpRequest, NetworkActivityBuilder, SeverityId, StatusId, Url as OcsfUrl,
    ocsf_emit,
};
use openshell_supervisor_middleware::{
    HttpBodyInput, HttpBodyOutput, HttpMiddlewareFailure, HttpPipelineFinish,
    HttpRequestPreflightInput, HttpRequestSession, HttpStageDiagnostics, HttpStageOutcome,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// How long the sandbox may stop sending a request body while a STREAM
/// request middleware session is held. STREAM has no total deadline, so this
/// bounds a paused upload; it matches the WebSocket message-assembly limit.
pub const REQUEST_CLIENT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);

pub enum MiddlewareApplyResult {
    Allowed(crate::l7::provider::L7Request),
    /// Request middleware streams the body. `request` holds only the head;
    /// the relay commits it on the middleware's final `Start`.
    Streamed {
        request: crate::l7::provider::L7Request,
        body: Box<RequestBodyStream>,
    },
    Denied {
        denial: Option<openshell_supervisor_middleware::MiddlewareDenial>,
    },
    /// The platform's shared active-work and waiter capacities were both full.
    ///
    /// This is platform load shedding, not a selected middleware-stage failure,
    /// so callers must not apply a stage's `on_error` policy.
    AdmissionExhausted,
    /// The sandbox stopped sending the request body. The caller answers 408
    /// and closes the connection.
    RequestTimeout,
}

/// Whether request middleware output may stream to the upstream while the
/// client uploads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RequestBodyDelivery {
    #[default]
    Incremental,
    /// A later step needs the complete body before upstream contact, so the
    /// output is withheld and inlined into the request (at most
    /// [`openshell_supervisor_middleware::MAX_HTTP_REQUEST_WITHHELD_BYTES`]).
    Withhold,
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
        emit_middleware_session_capacity_exhausted(ctx, "websocket_message");
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

fn emit_middleware_session_capacity_exhausted(ctx: &L7EvalContext, operation: &str) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::Medium)
        .finding_info(FindingInfo::new(
            "openshell.middleware.session_capacity_exhausted",
            "Supervisor middleware session capacity exhausted",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("operation", operation),
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
///
/// A version 2 stage on this path runs over the collected body: a STREAM stage
/// can take up to the platform payload maximum, and a preflight-only stage
/// needs no body.
pub(super) fn middleware_chain_body_limit(
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
) -> Option<usize> {
    chain
        .iter()
        .filter(|entry| entry.is_resolved())
        .map(|entry| {
            if entry.http_protocol() != Some(openshell_supervisor_middleware::HttpProtocol::V2) {
                entry.max_payload_bytes()
            } else if entry.supports_http_body_mode(openshell_core::proto::HttpBodyMode::Stream) {
                openshell_supervisor_middleware::MAX_HTTP_REQUEST_WITHHELD_BYTES
            } else if entry.supports_http_body_mode(openshell_core::proto::HttpBodyMode::Buffered) {
                entry.max_payload_bytes()
            } else {
                0
            }
        })
        .max()
}

/// True when the version 2 stage pipeline runs the chain. Chains with legacy
/// entries, and body-aware protocols whose stages can replace the body, run
/// on the collector, which re-evaluates policy after every replacement and
/// runs legacy and version 2 stages in chain order.
fn uses_request_pipeline(
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
    transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
) -> bool {
    use openshell_supervisor_middleware::HttpProtocol;
    if chain
        .iter()
        .any(|entry| entry.http_protocol() == Some(HttpProtocol::Legacy))
    {
        return false;
    }
    let has_v2 = chain
        .iter()
        .any(|entry| entry.http_protocol() == Some(HttpProtocol::V2));
    has_v2
        && (matches!(
            transformed_body_policy,
            openshell_supervisor_middleware::TransformedBodyPolicy::NotPolicyRelevant
        ) || !chain.iter().any(
            openshell_supervisor_middleware::DescribedChainEntry::supports_http_body_processing,
        ))
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
    apply_middleware_chain_for_scheme_with_request_id(
        req,
        client,
        ctx,
        "https",
        chain,
        runner,
        generation_guard,
        transformed_body_policy,
        request_id,
    )
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
pub async fn apply_middleware_chain_for_scheme_with_request_id<
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
) -> Result<MiddlewareApplyResult> {
    Box::pin(
        apply_middleware_chain_for_scheme_with_request_id_and_delivery(
            req,
            client,
            ctx,
            scheme,
            chain,
            runner,
            generation_guard,
            transformed_body_policy,
            request_id,
            RequestBodyDelivery::Incremental,
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
    if uses_request_pipeline(&chain, transformed_body_policy) {
        return Box::pin(apply_pipeline_middleware_chain(
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
        .await;
    }
    let admission = if chain.is_empty() {
        None
    } else {
        let outcome = runner.reserve_middleware_work().await?;
        match outcome {
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
        // No entry resolved to a registered binding, so nothing inspects the
        // body. Apply each entry's `on_error` policy without buffering (an
        // unresolved binding is handled before the body is read) and forward
        // the original request unchanged if the chain allows.
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
    // Admission was reserved above, before reading any request body. Keeping
    // the guard through evaluation bounds aggregate buffered input across HTTP
    // requests and WebSocket messages.
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
        crate::l7::rest::BufferResult::OverCapacity { recoverable } => {
            return Ok(resolve_unbuffered_body(ctx, req, &chain, recoverable));
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
    // The explicitly selected transformation policy either re-checks every
    // replacement or documents that this protocol's policy is body-independent.
    // An ALLOW outcome therefore means the final body is policy-compliant.
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

/// Run a chain of version 2 stages on the stage pipeline.
#[allow(clippy::too_many_arguments)]
async fn apply_pipeline_middleware_chain<C: AsyncRead + AsyncWrite + Unpin + Send>(
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
    let head = &req.raw_header[..request_header_end(&req.raw_header)];
    let headers = safe_middleware_headers(head)?;
    let sandbox = openshell_ocsf::ctx::ctx();
    let input = HttpRequestPreflightInput {
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
            query: raw_query_from_request_headers(head)?,
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
    if preflight.admission_exhausted {
        emit_middleware_admission_exhausted(ctx);
        return Ok(MiddlewareApplyResult::AdmissionExhausted);
    }
    if preflight.session_capacity_exhausted {
        emit_middleware_session_capacity_exhausted(ctx, "http_request");
        return Ok(MiddlewareApplyResult::AdmissionExhausted);
    }
    let mut events = RequestEvents {
        context: ctx.clone(),
        action: req.action.clone(),
        target: req.target.clone(),
        preflight: std::mem::take(&mut preflight.diagnostics),
        emitted: false,
    };
    if !preflight.allowed {
        events.emit(
            false,
            &preflight.reason,
            preflight.denial.as_ref(),
            HttpStageDiagnostics::default(),
        );
        return Ok(MiddlewareApplyResult::Denied {
            denial: preflight.denial,
        });
    }
    let Some(session) = preflight.session.take() else {
        let rebuilt =
            crate::l7::rest::rebuild_request_headers_only(&req, &preflight.header_mutations)?;
        events.emit(true, "", None, HttpStageDiagnostics::default());
        return Ok(MiddlewareApplyResult::Allowed(rebuilt));
    };

    let (prepared_headers, mut reader) =
        crate::l7::rest::prepare_request_body_stream(&req, client).await?;
    if delivery == RequestBodyDelivery::Incremental
        && !session.withholds_output()
        && !matches!(req.body_length, crate::l7::provider::BodyLength::None)
        && request_line_is_http11(head)
        && !crate::l7::rest::request_has_upgrade_header(head)
    {
        let request = crate::l7::rest::rebuild_request_for_live_body(
            &req,
            &prepared_headers,
            &preflight.header_mutations,
        )?;
        return Ok(MiddlewareApplyResult::Streamed {
            request,
            body: Box::new(RequestBodyStream {
                reader,
                session: Some(session),
                events,
                generation_guard: generation_guard.clone(),
                injected_headers: crate::l7::token_grant_injection::InjectedHeaders::default(),
            }),
        });
    }

    let progress = session.streams().then_some(REQUEST_CLIENT_PROGRESS_TIMEOUT);
    let (output, mut outputs) = mpsc::channel(4);
    let collect = async move {
        let mut late = Vec::new();
        let mut body = Vec::new();
        while let Some(event) = outputs.recv().await {
            match event {
                HttpBodyOutput::Start {
                    header_mutations, ..
                } => late = header_mutations,
                HttpBodyOutput::Chunk(data) => {
                    if body.len().saturating_add(data.len())
                        > openshell_supervisor_middleware::MAX_HTTP_REQUEST_WITHHELD_BYTES
                    {
                        return None;
                    }
                    body.extend_from_slice(&data);
                }
                HttpBodyOutput::End { .. } => {}
            }
        }
        Some((late, body))
    };
    let run = run_request_body(
        session,
        &mut reader,
        client,
        generation_guard,
        progress,
        output,
    );
    let (result, collected) = tokio::join!(run, collect);
    let (mut finish, (late, body)) = match (result, collected) {
        (_, None) => {
            events.emit(
                false,
                "middleware_failed: request_output_over_capacity",
                None,
                HttpStageDiagnostics::default(),
            );
            return Ok(MiddlewareApplyResult::Denied { denial: None });
        }
        (Err(error), _) => return events.body_failed(error),
        (Ok(finish), Some(collected)) => (finish, collected),
    };
    generation_guard.ensure_current()?;
    let mut header_mutations = preflight.header_mutations;
    header_mutations.extend(late);
    let rebuilt = crate::l7::rest::rebuild_request_with_middleware_body(
        &req,
        &prepared_headers,
        &body,
        &finish.trailers,
        &header_mutations,
    )?;
    events.emit(true, "", None, std::mem::take(&mut finish.diagnostics));
    Ok(MiddlewareApplyResult::Allowed(rebuilt))
}

fn request_header_end(raw_header: &[u8]) -> usize {
    raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(raw_header.len(), |position| position + 4)
}

fn request_line_is_http11(head: &[u8]) -> bool {
    head.split(|byte| *byte == b'\n')
        .next()
        .is_some_and(|line| line.trim_ascii_end().ends_with(b" HTTP/1.1"))
}

/// Why a request body run stopped.
enum BodyRunError {
    Middleware(HttpMiddlewareFailure),
    /// The sandbox sent no body bytes for [`REQUEST_CLIENT_PROGRESS_TIMEOUT`].
    ClientTimeout,
    /// Reading the client failed, or the policy generation changed.
    Client(miette::Report),
}

/// Feed a request body to `session` while it runs. Dropping the future
/// cancels every stage.
async fn run_request_body<C: AsyncRead + Unpin>(
    session: HttpRequestSession,
    reader: &mut crate::l7::rest::RequestBodyReader,
    client: &mut C,
    generation_guard: &PolicyGenerationGuard,
    progress: Option<Duration>,
    output: mpsc::Sender<HttpBodyOutput>,
) -> std::result::Result<HttpPipelineFinish, BodyRunError> {
    let limit = session.input_unit_limit();
    let (input, inputs) = mpsc::channel(4);
    let run = async {
        session
            .run(inputs, output)
            .await
            .map_err(BodyRunError::Middleware)
    };
    let feed = feed_request_body(reader, client, generation_guard, limit, progress, input);
    let (finish, ()) = tokio::try_join!(run, feed)?;
    Ok(finish)
}

async fn feed_request_body<C: AsyncRead + Unpin>(
    reader: &mut crate::l7::rest::RequestBodyReader,
    client: &mut C,
    generation_guard: &PolicyGenerationGuard,
    limit: usize,
    progress: Option<Duration>,
    input: mpsc::Sender<HttpBodyInput>,
) -> std::result::Result<(), BodyRunError> {
    let mut client = ClientProgress::new(client, progress);
    loop {
        client.restart();
        let unit = match reader
            .next_unit(&mut client, Some(generation_guard), limit)
            .await
        {
            Ok(unit) => unit,
            Err(_) if client.timed_out => return Err(BodyRunError::ClientTimeout),
            Err(error) => return Err(BodyRunError::Client(error)),
        };
        let Some(unit) = unit else {
            break;
        };
        // A closed input means the pipeline stopped; its result says why.
        if input.send(HttpBodyInput::Chunk(unit)).await.is_err() {
            return Ok(());
        }
    }
    let _ = input
        .send(HttpBodyInput::End {
            trailers: reader.take_trailers(),
        })
        .await;
    Ok(())
}

/// Client reader that fails when the sandbox sends nothing for `idle` while
/// the reader waits for it. Time spent not reading, such as under middleware
/// backpressure, does not count.
struct ClientProgress<'a, C> {
    inner: &'a mut C,
    idle: Option<Duration>,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
    waiting: bool,
    timed_out: bool,
}

impl<'a, C> ClientProgress<'a, C> {
    fn new(inner: &'a mut C, idle: Option<Duration>) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(Duration::ZERO)),
            waiting: false,
            timed_out: false,
        }
    }

    /// Start the next wait from zero.
    fn restart(&mut self) {
        self.waiting = false;
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for ClientProgress<'_, C> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut *this.inner).poll_read(cx, buf);
        if result.is_ready() {
            this.waiting = false;
            return result;
        }
        let Some(idle) = this.idle else {
            return result;
        };
        if !this.waiting {
            this.waiting = true;
            this.deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + idle);
        }
        if this.deadline.as_mut().poll(cx).is_ready() {
            this.timed_out = true;
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request body client progress timeout",
            )));
        }
        std::task::Poll::Pending
    }
}

/// Terminal OCSF events for one request through the stage pipeline, emitted
/// once.
struct RequestEvents {
    context: L7EvalContext,
    action: String,
    target: String,
    preflight: HttpStageDiagnostics,
    emitted: bool,
}

impl RequestEvents {
    fn emit(
        &mut self,
        allowed: bool,
        reason: &str,
        denial: Option<&openshell_supervisor_middleware::MiddlewareDenial>,
        body: HttpStageDiagnostics,
    ) {
        if std::mem::replace(&mut self.emitted, true) {
            return;
        }
        let mut diagnostics = std::mem::take(&mut self.preflight);
        diagnostics.extend(body);
        for event in request_middleware_events(
            &self.context,
            &self.action,
            &self.target,
            allowed,
            reason,
            denial,
            &diagnostics,
        ) {
            ocsf_emit!(event);
        }
    }

    /// Record a failed body run and return the result the relay acts on.
    fn body_failed(&mut self, error: BodyRunError) -> Result<MiddlewareApplyResult> {
        match error {
            BodyRunError::Middleware(failure) => {
                self.emit(
                    false,
                    &failure.reason,
                    failure.denial.as_ref(),
                    *failure.diagnostics,
                );
                Ok(MiddlewareApplyResult::Denied {
                    denial: failure.denial,
                })
            }
            BodyRunError::ClientTimeout => {
                ocsf_emit!(request_client_timeout_event(
                    &self.context,
                    &self.action,
                    &self.target
                ));
                self.emit(
                    false,
                    "middleware_cancelled: client_progress_timeout",
                    None,
                    HttpStageDiagnostics::default(),
                );
                Ok(MiddlewareApplyResult::RequestTimeout)
            }
            BodyRunError::Client(error) => {
                self.emit(
                    false,
                    "middleware_cancelled: request_body_read_failed",
                    None,
                    HttpStageDiagnostics::default(),
                );
                Err(error)
            }
        }
    }
}

/// A request body that request middleware streams to the upstream.
pub struct RequestBodyStream {
    reader: crate::l7::rest::RequestBodyReader,
    session: Option<HttpRequestSession>,
    events: RequestEvents,
    generation_guard: PolicyGenerationGuard,
    injected_headers: crate::l7::token_grant_injection::InjectedHeaders,
}

impl RequestBodyStream {
    /// Keep the platform's token grant headers over late header mutations
    /// when the head commits.
    pub(crate) fn reapply_injected_headers(
        &mut self,
        headers: crate::l7::token_grant_injection::InjectedHeaders,
    ) {
        self.injected_headers = headers;
    }

    pub(crate) fn take_injected_headers(
        &mut self,
    ) -> crate::l7::token_grant_injection::InjectedHeaders {
        std::mem::take(&mut self.injected_headers)
    }

    /// True when the client's body is chunked and so may end with trailers.
    pub(crate) fn input_is_chunked(&self) -> bool {
        matches!(self.reader, crate::l7::rest::RequestBodyReader::Chunked(_))
    }

    /// Run the middleware over the client's body, sending output to
    /// `output`. A middleware failure or client timeout is a
    /// [`crate::l7::rest::LiveRequestFailure`].
    pub(crate) async fn run_to<C: AsyncRead + Unpin>(
        &mut self,
        client: &mut C,
        output: mpsc::Sender<HttpBodyOutput>,
    ) -> Result<HttpPipelineFinish> {
        let session = self
            .session
            .take()
            .ok_or_else(|| miette!("request middleware body already ran"))?;
        let progress = session.streams().then_some(REQUEST_CLIENT_PROGRESS_TIMEOUT);
        let error = match run_request_body(
            session,
            &mut self.reader,
            client,
            &self.generation_guard,
            progress,
            output,
        )
        .await
        {
            Ok(mut finish) => {
                self.events
                    .emit(true, "", None, std::mem::take(&mut finish.diagnostics));
                return Ok(finish);
            }
            Err(error) => error,
        };
        let failure = match &error {
            BodyRunError::Middleware(failure) => crate::l7::rest::LiveRequestFailure::Middleware {
                reason: failure.reason.clone(),
                denial: failure.denial.clone(),
            },
            BodyRunError::ClientTimeout => crate::l7::rest::LiveRequestFailure::ClientTimeout,
            BodyRunError::Client(_) => {
                return self.events.body_failed(error).map(|_| unreachable!());
            }
        };
        self.events.body_failed(error)?;
        Err(miette::Report::new(failure))
    }

    /// Record that the middleware stages were cancelled for `reason`.
    pub(crate) fn cancelled(&mut self, reason: &str) {
        self.events.emit(
            false,
            &format!("middleware_cancelled: {reason}"),
            None,
            HttpStageDiagnostics::default(),
        );
    }
}

/// OCSF events for one request through the stage pipeline. Separated from
/// emission so tests can assert on them.
pub(super) fn request_middleware_events(
    ctx: &L7EvalContext,
    action: &str,
    target: &str,
    allowed: bool,
    reason: &str,
    denial: Option<&openshell_supervisor_middleware::MiddlewareDenial>,
    diagnostics: &HttpStageDiagnostics,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut applied = Vec::<openshell_supervisor_middleware::MiddlewareInvocation>::new();
    for invocation in &diagnostics.invocations {
        let denied = matches!(
            invocation.outcome,
            HttpStageOutcome::Reject | HttpStageOutcome::FailClosed
        );
        if let Some(existing) = applied
            .iter_mut()
            .find(|existing| existing.name == invocation.config_name)
        {
            existing.failed |= invocation.failed;
            existing.transformed |= invocation.transformed;
            if denied {
                existing.decision = openshell_core::proto::Decision::Deny;
            }
            continue;
        }
        applied.push(openshell_supervisor_middleware::MiddlewareInvocation {
            name: invocation.config_name.clone(),
            implementation: invocation.implementation.clone(),
            decision: if denied {
                openshell_core::proto::Decision::Deny
            } else {
                openshell_core::proto::Decision::Allow
            },
            transformed: invocation.transformed,
            failed: invocation.failed,
        });
    }
    // HTTP protocol 1 (0.1): a fail_open stage reports that it passed its
    // original input on, which 0.1.x records as a failed-open invocation.
    for (config_name, report) in &diagnostics.reports {
        if report.fail_open_reason().is_none() {
            continue;
        }
        if let Some(existing) = applied
            .iter_mut()
            .find(|existing| &existing.name == config_name)
        {
            existing.failed = true;
        }
    }
    let req = crate::l7::provider::L7Request {
        action: action.to_string(),
        target: target.to_string(),
        query_params: std::collections::HashMap::new(),
        raw_header: Vec::new(),
        body_length: crate::l7::provider::BodyLength::None,
    };
    middleware_events(
        ctx,
        &req,
        &openshell_supervisor_middleware::ChainOutcome {
            allowed,
            reason: reason.to_string(),
            body: Vec::new(),
            header_mutations: Vec::new(),
            findings: diagnostics.findings.clone(),
            metadata: diagnostics.metadata.clone(),
            applied,
            denial: denial.cloned(),
        },
    )
}

/// The sandbox stopped sending a request body that STREAM request
/// middleware was processing; the request was aborted.
pub(super) fn request_client_timeout_event(
    ctx: &L7EvalContext,
    action: &str,
    target: &str,
) -> openshell_ocsf::OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .status_detail("request_client_progress_timeout")
        .http_request(HttpRequest::new(
            action,
            OcsfUrl::new("http", &ctx.host, target, ctx.port),
        ))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&ctx.policy_name, "middleware")
        .message(format!(
            "MIDDLEWARE request body idle for {}s; request aborted",
            REQUEST_CLIENT_PROGRESS_TIMEOUT.as_secs()
        ))
        .build()
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

/// Answer 408 when the sandbox stops sending a request body that request
/// middleware is processing.
pub async fn send_request_timeout_response<C: AsyncWrite + Unpin>(
    action: &str,
    client: &mut C,
    ctx: &L7EvalContext,
    redacted_target: &str,
) -> Result<()> {
    let req = crate::l7::provider::L7Request {
        action: action.to_string(),
        target: redacted_target.to_string(),
        query_params: std::collections::HashMap::new(),
        raw_header: Vec::new(),
        body_length: crate::l7::provider::BodyLength::None,
    };
    crate::l7::rest::send_request_timeout_response(
        &req,
        &ctx.policy_name,
        client,
        Some(redacted_target),
        Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
    )
    .await?;
    client.shutdown().await.into_diagnostic()
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

/// Apply the chain's `on_error` policy when the request body exceeds every
/// stage's buffering limit. No stage can inspect such a body, so each stage
/// would individually fail with `request_body_over_capacity`; the aggregate is
/// a deny unless every attached middleware is `fail_open`, and passing the
/// body through is only safe when no bytes were consumed.
pub(super) fn resolve_unbuffered_body(
    ctx: &L7EvalContext,
    req: crate::l7::provider::L7Request,
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
    recoverable: bool,
) -> MiddlewareApplyResult {
    let all_fail_open = chain
        .iter()
        .all(|entry| entry.on_error() == openshell_supervisor_middleware::OnError::FailOpen);
    if recoverable && all_fail_open {
        emit_middleware_body_unavailable(ctx, false);
        return MiddlewareApplyResult::Allowed(req);
    }
    emit_middleware_body_unavailable(ctx, true);
    MiddlewareApplyResult::Denied { denial: None }
}

fn emit_middleware_body_unavailable(ctx: &L7EvalContext, denied: bool) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(if denied {
            SeverityId::High
        } else {
            SeverityId::Medium
        })
        .finding_info(FindingInfo::new(
            "openshell.middleware.body_unavailable",
            "Supervisor middleware could not inspect request body",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("disposition", if denied { "denied" } else { "fail_open" }),
        ])
        .message(if denied {
            "Request body exceeded middleware inspection cap; denied"
        } else {
            "Request body exceeded middleware inspection cap; passed through (fail_open)"
        })
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
            origin: openshell_ocsf::EventOrigin::Supervisor,
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

#[cfg(test)]
mod request_event_tests {
    use openshell_ocsf::SeverityId;
    use openshell_supervisor_middleware::{
        HttpStageDiagnostics, HttpStageInvocation, HttpStageOutcome, StageReport,
    };

    use super::{request_client_timeout_event, request_middleware_events};
    use crate::l7::relay::L7EvalContext;

    fn ctx() -> L7EvalContext {
        L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            binary_path: "DO_NOT_LOG_BINARY".into(),
            ..Default::default()
        }
    }

    fn invocation(
        config_name: &str,
        outcome: HttpStageOutcome,
        transformed: bool,
        failed: bool,
    ) -> HttpStageInvocation {
        HttpStageInvocation {
            config_name: config_name.into(),
            implementation: format!("example/{config_name}"),
            outcome,
            input_bytes: 0,
            output_bytes: None,
            transformed,
            failed,
            reason_code: None,
            failure_reason: failed.then(|| "middleware_timeout".into()),
        }
    }

    #[test]
    fn client_timeout_event_records_the_abort_without_request_data() {
        let event = request_client_timeout_event(&ctx(), "POST", "/v1/upload");
        assert_eq!(event.class_uid(), 4002);
        assert_eq!(event.base().severity, SeverityId::Low);
        let serialized = serde_json::to_string(&event).expect("serialize timeout event");
        assert!(
            serialized.contains("request_client_progress_timeout"),
            "{serialized}"
        );
        assert!(serialized.contains("api-policy"), "{serialized}");
        assert!(!serialized.contains("DO_NOT_LOG_BINARY"), "{serialized}");
    }

    #[test]
    fn stage_invocations_collapse_to_one_event_per_stage() {
        let diagnostics = HttpStageDiagnostics {
            invocations: vec![
                invocation("stream", HttpStageOutcome::Stream, false, false),
                invocation("tagger", HttpStageOutcome::Continue, true, false),
                invocation("stream", HttpStageOutcome::Finish, true, false),
                invocation("missing", HttpStageOutcome::FailOpen, false, true),
                invocation("legacy", HttpStageOutcome::Buffered, false, false),
            ],
            reports: vec![(
                "legacy".into(),
                StageReport::LegacyFailOpen {
                    reason: "request_body_over_capacity".into(),
                },
            )],
            ..Default::default()
        };
        let events =
            request_middleware_events(&ctx(), "POST", "/v1/upload", true, "", None, &diagnostics);
        let activity: Vec<String> = events
            .iter()
            .filter(|event| event.class_uid() == 4002)
            .map(|event| serde_json::to_string(event).expect("serialize event"))
            .collect();
        assert_eq!(activity.len(), 4, "{activity:#?}");
        assert!(activity[0].contains("MIDDLEWARE stream example/stream decision=Allow"));
        assert!(
            activity[0].contains("\"transformed\":true"),
            "{}",
            activity[0]
        );
        assert!(
            activity[1].contains("\"transformed\":true"),
            "{}",
            activity[1]
        );
        assert!(activity[2].contains("\"failed\":true"), "{}", activity[2]);
        assert!(activity[3].contains("\"failed\":true"), "{}", activity[3]);
        // Every stage that passed its input on after a failure is a
        // failed-open finding, as in 0.1.x.
        assert_eq!(
            events
                .iter()
                .filter(|event| event.class_uid() == 2004)
                .count(),
            2
        );
    }

    #[test]
    fn rejected_stage_is_a_denied_invocation() {
        let diagnostics = HttpStageDiagnostics {
            invocations: vec![
                invocation("guard", HttpStageOutcome::Stream, false, false),
                invocation("guard", HttpStageOutcome::Reject, false, false),
            ],
            ..Default::default()
        };
        let events = request_middleware_events(
            &ctx(),
            "POST",
            "/v1/upload",
            false,
            "middleware_denied:guard",
            None,
            &diagnostics,
        );
        let serialized = serde_json::to_string(&events).expect("serialize events");
        assert!(serialized.contains("decision=Deny"), "{serialized}");
        assert!(!serialized.contains("decision=Allow"), "{serialized}");
    }
}
