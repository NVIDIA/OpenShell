// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP session hook stage pipeline, shared by request and response evaluation.
//!
//! Each stage opens when the preceding stage establishes its output headers.
//! Header-only stages continue immediately; inspecting stages emit `Start`
//! after their preflight and body-time header changes. Bounded channels link
//! the stages, and the relay commits headers only on the final `Start`.
//!
//! BUFFERED stages hold one bounded body under a whole-body deadline. STREAM
//! stages run independent input and output pumps with no total deadline and
//! no total byte cap; a stage fails only when it stalls. The supervisor never
//! retains STREAM input for replay.
//!
//! A request whose policy inspects the body runs with a checkpoint after
//! every stage: it holds the stage's output until the stage ends and
//! re-checks a replaced body before the next stage or the output sees it.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::time::Instant;

use openshell_core::proto::{
    Decision, HeaderMutation, HttpBegin, HttpBodyLimits, HttpBodyMode, HttpBodyModeUnavailable,
    HttpBodyUnavailableReason, HttpBufferedBody, HttpBufferedResult, HttpDenial, HttpFinish,
    HttpHeader, HttpInputChunk, HttpInputEnd, HttpOutputChunk, HttpOutputStart,
    HttpPreflightResult, HttpRequestPreflightHead, HttpRequestSessionEvent,
    HttpRequestSessionPreflight, HttpResponsePreflightHead, HttpResponseSessionEvent,
    HttpResponseSessionPreflight, MiddlewareDiagnostics, MiddlewareSessionEnd,
    MiddlewareSessionEndReason, RequestContext, SupervisorMiddlewarePhase, http_buffered_result,
    http_inspect, http_preflight_result, http_request_session_event, http_response_session_event,
};

use crate::headers::{self, HeaderAuthority};
use crate::{
    ChainRunner, DescribedChainEntry, HttpHookVersion, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_PAYLOAD_BYTES, MiddlewareDenial, MiddlewareDiagnosticPolicy,
    MiddlewareInvocation, MiddlewareSessionPermit, NamespacedFinding, OnError,
    TransformedBodyPolicy, middleware_denial_reason, safe_reason,
};

/// Largest normalized body chunk a stage sends or receives.
pub const MAX_HTTP_STREAM_UNIT_BYTES: usize = 64 * 1024;
/// STREAM middleware-stall timeout.
///
/// A STREAM stage fails when it does not accept the next input within this
/// duration while its output is not held back downstream, or when it returns
/// nothing within this duration after it accepted the end of its input.
pub const HTTP_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// BUFFERED whole-body deadline, covering receipt, processing, and delivery
/// of one stage's body.
pub const HTTP_BUFFERED_BODY_TIMEOUT: Duration = Duration::from_mins(2);
/// Messages each link and stage queue holds.
pub const STAGE_QUEUE_MESSAGES: usize = 4;
const SESSION_END_TIMEOUT: Duration = Duration::from_millis(10);
/// Failure reason when a message cannot be shown to an HTTP session hook
/// stage, such as a head over capacity.
pub const MIDDLEWARE_CANNOT_INSPECT: &str = "middleware_cannot_inspect";
/// Failure reason for a chain that selects v1 and HTTP session hook stages for the
/// same HTTP message.
pub const MIDDLEWARE_HOOK_VERSIONS_MIXED: &str = "middleware_hook_versions_mixed";

/// Why an HTTP session hook exchange failed closed, in terms the sandbox can
/// act on: retry when the middleware is unavailable or slow, but not when it
/// cannot inspect the message.
///
/// The set is closed and platform-owned. It never carries service text, so it
/// is safe to return to the sandbox and to record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailureCode {
    /// The message head cannot be shown to middleware.
    CannotInspect,
    /// A stage missed its binding timeout, the chain deadline, or the
    /// BUFFERED whole-body deadline.
    Timeout,
    /// A STREAM stage stalled.
    StreamIdleTimeout,
    /// The middleware was unreachable, failed with an RPC status, or had no
    /// capacity.
    Unavailable,
    /// The stage broke the exchange contract, such as an unexpected result,
    /// an unimplemented RPC, or output that does not match its declared
    /// length.
    LifecycleViolation,
    /// A body exceeded the selected limit.
    BodyOverLimit,
    /// A header or trailer mutation broke a header change rule; carries the
    /// rule's code, such as `header_mutation_protected_header`.
    HeaderMutation(&'static str),
    /// The chain selects v1 HTTP hook and HTTP session hook entries.
    HookVersionsMixed,
}

impl HttpFailureCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CannotInspect => MIDDLEWARE_CANNOT_INSPECT,
            Self::Timeout => "middleware_timeout",
            Self::StreamIdleTimeout => "stream_idle_timeout",
            Self::Unavailable => "middleware_unavailable",
            Self::LifecycleViolation => "middleware_lifecycle_violation",
            Self::BodyOverLimit => "body_over_limit",
            Self::HeaderMutation(code) => code,
            Self::HookVersionsMixed => MIDDLEWARE_HOOK_VERSIONS_MIXED,
        }
    }

    /// Code for a platform-owned failure reason that is not an RPC status or
    /// a header mutation error.
    fn of_reason(reason: &str) -> Self {
        match reason {
            MIDDLEWARE_CANNOT_INSPECT
            | "head_input_over_capacity"
            | "response_input_unrepresentable" => Self::CannotInspect,
            "middleware_timeout" | "middleware_chain_timeout" | "middleware_body_timeout" => {
                Self::Timeout
            }
            "middleware_stall_timeout" => Self::StreamIdleTimeout,
            "binding_not_described" | "session_capacity_exhausted" => Self::Unavailable,
            "buffered_input_over_capacity"
            | "buffered_output_over_capacity"
            | "request_output_over_capacity" => Self::BodyOverLimit,
            MIDDLEWARE_HOOK_VERSIONS_MIXED => Self::HookVersionsMixed,
            _ => Self::LifecycleViolation,
        }
    }
}

/// Why a chain failed closed, as the sandbox sees it. Both fields are
/// platform-owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareFailureDetail {
    /// Policy config name of the stage that failed, when one stage owns the
    /// failure.
    pub config_name: Option<String>,
    pub code: HttpFailureCode,
}

/// Body input to a pipeline: chunks, then exactly one `End`.
#[derive(Debug)]
pub enum HttpBodyInput {
    Chunk(Vec<u8>),
    End { trailers: Vec<HttpHeader> },
}

/// Body output of a pipeline: one `Start`, chunks, then one `End`.
#[derive(Debug, PartialEq, Eq)]
pub enum HttpBodyOutput {
    /// Commit the outgoing head. Apply `header_mutations` after the initial
    /// preflight prefix. These include deferred preflight and body-time
    /// mutations, in stage order. When
    /// `output_body_bytes` is present, the body has exactly that length.
    Start {
        header_mutations: Vec<HeaderMutation>,
        output_body_bytes: Option<u64>,
    },
    Chunk(Vec<u8>),
    End {
        trailers: Vec<HttpHeader>,
    },
}

/// What one stage did in one phase of an exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStageOutcome {
    /// Preflight continued without the body.
    Continue,
    /// The stage denied the exchange.
    Deny,
    /// Preflight selected BUFFERED.
    Buffered,
    /// Preflight selected STREAM.
    Stream,
    /// The BUFFERED result kept the body.
    Unchanged,
    /// The BUFFERED result replaced the body.
    Replacement,
    /// The STREAM stage finished.
    Finish,
    /// The stage failed and the exchange failed closed.
    FailClosed,
    /// The entry did not resolve to a registered binding, and its
    /// `on_error: fail_open` let the message continue without it. Never an
    /// HTTP session hook entry.
    FailOpen,
}

/// Audit record for one stage and phase. Carries no service-provided text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpStageInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: HttpStageOutcome,
    pub input_bytes: usize,
    pub output_bytes: Option<usize>,
    /// True when the stage changed the body or the head.
    pub transformed: bool,
    pub failed: bool,
    pub reason_code: Option<String>,
    /// Platform-owned failure reason.
    pub failure_reason: Option<String>,
}

/// Findings, metadata, and invocations for one exchange.
#[derive(Debug, Default)]
pub struct HttpStageDiagnostics {
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpStageInvocation>,
}

impl HttpStageDiagnostics {
    /// Append `other`, keeping chain order.
    pub fn extend(&mut self, other: Self) {
        self.findings.extend(other.findings);
        self.metadata.extend(other.metadata);
        self.invocations.extend(other.invocations);
    }

    /// One invocation record per stage, in chain order: a stage that denied
    /// or failed closed in any phase denied, and a stage that failed in any
    /// phase is failed. A stage after the last stage that recorded an
    /// outcome, which only selected a body mode, made no decision before the
    /// exchange ended and is left out. When no stage recorded an outcome, as
    /// when the exchange was cancelled, every stage is kept.
    #[must_use]
    pub fn applied(&self) -> Vec<MiddlewareInvocation> {
        let mut applied = Vec::<(MiddlewareInvocation, bool)>::new();
        for invocation in &self.invocations {
            let denied = matches!(
                invocation.outcome,
                HttpStageOutcome::Deny | HttpStageOutcome::FailClosed
            );
            let decided = !matches!(
                invocation.outcome,
                HttpStageOutcome::Buffered | HttpStageOutcome::Stream
            );
            if let Some((existing, existing_decided)) = applied
                .iter_mut()
                .find(|(existing, _)| existing.name == invocation.config_name)
            {
                existing.failed |= invocation.failed;
                existing.transformed |= invocation.transformed;
                if denied {
                    existing.decision = Decision::Deny;
                }
                *existing_decided |= decided;
                continue;
            }
            applied.push((
                MiddlewareInvocation {
                    name: invocation.config_name.clone(),
                    implementation: invocation.implementation.clone(),
                    decision: if denied {
                        Decision::Deny
                    } else {
                        Decision::Allow
                    },
                    transformed: invocation.transformed,
                    failed: invocation.failed,
                },
                decided,
            ));
        }
        let last_decided = applied.iter().rposition(|(_, decided)| *decided);
        applied
            .into_iter()
            .enumerate()
            .filter(|(index, (_, decided))| {
                *decided || last_decided.is_none_or(|last| *index < last)
            })
            .map(|(_, (invocation, _))| invocation)
            .collect()
    }
}

/// The exchange failed closed or was denied.
#[derive(Debug)]
pub struct HttpMiddlewareFailure {
    /// Platform-owned reason: `middleware_denied:<config>[:<code>]` for a
    /// denial, `middleware_failed: <reason>` for a failure, and
    /// `middleware_cancelled: <reason>` when the input producer went away.
    pub reason: String,
    /// Present only when a stage denied the exchange.
    pub denial: Option<MiddlewareDenial>,
    /// Present when the exchange failed closed for a reason the sandbox may
    /// see.
    pub failure: Option<Box<MiddlewareFailureDetail>>,
    /// Session end every stage received.
    pub end_reason: MiddlewareSessionEndReason,
    pub diagnostics: Box<HttpStageDiagnostics>,
}

impl std::fmt::Display for HttpMiddlewareFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for HttpMiddlewareFailure {}

/// A completed body pipeline.
#[derive(Debug)]
pub struct HttpPipelineFinish {
    /// Final trailers after every stage's trailer mutations.
    pub trailers: Vec<HttpHeader>,
    pub diagnostics: HttpStageDiagnostics,
}

/// Deadlines the pipeline applies. Tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineTimeouts {
    pub stream_idle: Duration,
    pub buffered_body: Duration,
}

impl Default for PipelineTimeouts {
    fn default() -> Self {
        Self {
            stream_idle: HTTP_STREAM_IDLE_TIMEOUT,
            buffered_body: HTTP_BUFFERED_BODY_TIMEOUT,
        }
    }
}

/// Direction-specific rules for one exchange.
#[derive(Clone)]
pub struct PipelineSpec {
    pub head_authority: HeaderAuthority,
    pub trailer_authority: HeaderAuthority,
    /// Lowercased names nominated by the original message's `Connection`
    /// fields. Mutations treat them as hop-by-hop.
    pub connection_nominated: Vec<String>,
    /// Lowercased names of request headers omitted from the head because
    /// their values carry a credential placeholder. Mutations cannot
    /// target them.
    pub credential_reference_headers: Vec<String>,
    pub timeouts: PipelineTimeouts,
    /// False when the outgoing message cannot carry trailers. BUFFERED stages
    /// then always declare their output length, and the caller drops the
    /// final trailers.
    pub output_trailers: bool,
}

impl PipelineSpec {
    /// Apply one stage's head mutations to `existing`. Mutations another
    /// result already passed skip the per-result count and size limits.
    fn apply_head(
        &self,
        existing: &[HttpHeader],
        mutations: &[HeaderMutation],
        already_accepted: bool,
    ) -> Result<Vec<HttpHeader>, headers::HeaderMutationError> {
        headers::reject_credential_reference_mutations(
            &self.credential_reference_headers,
            mutations,
        )?;
        let apply = if already_accepted {
            headers::apply_accumulated
        } else {
            headers::apply
        };
        apply(
            self.head_authority,
            existing,
            &self.connection_nominated,
            mutations,
        )
    }
}

/// Body modes offered to one stage.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyModeOffer {
    /// Modes the stage may select.
    pub permitted: Vec<HttpBodyMode>,
    /// Modes the binding supports that are not offered, and why.
    pub unavailable: Vec<HttpBodyModeUnavailable>,
}

impl BodyModeOffer {
    pub fn permit(&mut self, mode: HttpBodyMode) {
        self.permitted.push(mode);
    }

    pub fn withhold(&mut self, mode: HttpBodyMode, reason: HttpBodyUnavailableReason) {
        self.unavailable.push(HttpBodyModeUnavailable {
            mode: mode as i32,
            reason: reason as i32,
        });
    }
}

/// What a pipeline evaluates: the preflight and body eligibility.
pub trait StageHead: Send + Sync {
    /// Sandbox and request identity shown to every stage.
    fn context(&self) -> &RequestContext;

    /// Preflight shown to a stage, given the head after earlier stages'
    /// complete output mutations and the fields every preflight carries.
    fn preflight(&self, headers: &[HttpHeader], fields: PreflightFields) -> StagePreflight;

    /// Refresh platform-owned framing metadata for this representation.
    fn current_headers(
        &self,
        headers: &[HttpHeader],
        _declared_body_bytes: Option<u64>,
    ) -> Vec<HttpHeader> {
        headers.to_vec()
    }

    /// Body modes `entry` may select: those the message is eligible for
    /// within the entry's payload limit. `declared_body_bytes` is the
    /// declared length of the body the stage receives, when known.
    fn body_modes(
        &self,
        entry: &DescribedChainEntry,
        headers: &[HttpHeader],
        declared_body_bytes: Option<u64>,
    ) -> BodyModeOffer;

    /// Largest final output the caller accepts, when it holds the complete
    /// output before delivery. `None` when the output streams uncapped.
    fn max_output_body_bytes(&self) -> Option<u64> {
        None
    }
}

/// Preflight fields both RPCs carry.
pub struct PreflightFields {
    pub context: RequestContext,
    pub middleware_name: String,
    pub config: prost_types::Struct,
    pub permitted_body_modes: Vec<i32>,
    pub unavailable_body_modes: Vec<HttpBodyModeUnavailable>,
    pub limits: HttpBodyLimits,
    pub declared_body_bytes: Option<u64>,
}

impl PreflightFields {
    /// An `HttpSessionMiddleware.EvaluateRequest` preflight at `PRE_CREDENTIALS`.
    pub fn request(self, request: HttpRequestPreflightHead) -> StagePreflight {
        StagePreflight::Request(HttpRequestSessionPreflight {
            request: Some(request),
            phase: SupervisorMiddlewarePhase::PreCredentials as i32,
            context: Some(self.context),
            middleware_name: self.middleware_name,
            config: Some(self.config),
            permitted_body_modes: self.permitted_body_modes,
            unavailable_body_modes: self.unavailable_body_modes,
            limits: Some(self.limits),
            declared_body_bytes: self.declared_body_bytes,
        })
    }

    /// An `HttpSessionMiddleware.EvaluateResponse` preflight at `PRE_RETURN`.
    pub fn response(self, head: HttpResponsePreflightHead) -> StagePreflight {
        StagePreflight::Response(HttpResponseSessionPreflight {
            response: Some(head),
            phase: SupervisorMiddlewarePhase::PreReturn as i32,
            context: Some(self.context),
            middleware_name: self.middleware_name,
            config: Some(self.config),
            permitted_body_modes: self.permitted_body_modes,
            unavailable_body_modes: self.unavailable_body_modes,
            limits: Some(self.limits),
            declared_body_bytes: self.declared_body_bytes,
        })
    }
}

/// The preflight that opens one stage exchange. It selects the RPC.
pub enum StagePreflight {
    Request(HttpRequestSessionPreflight),
    Response(HttpResponseSessionPreflight),
}

/// One event after the preflight. Both RPCs carry the same body events.
#[derive(Debug)]
enum StageEvent {
    Begin(HttpBegin),
    BufferedBody(HttpBufferedBody),
    InputChunk(HttpInputChunk),
    InputEnd(HttpInputEnd),
    SessionEnd(MiddlewareSessionEnd),
}

/// One stage result. Both RPCs carry the same results.
#[derive(Debug)]
pub(super) enum StageResult {
    PreflightResult(HttpPreflightResult),
    BufferedResult(HttpBufferedResult),
    OutputStart(HttpOutputStart),
    OutputChunk(HttpOutputChunk),
    Finish(HttpFinish),
    Deny(HttpDenial),
}

/// Results of one stage exchange. `None` is an unset or unknown result.
type StageResults =
    Pin<Box<dyn futures::Stream<Item = Result<Option<StageResult>, tonic::Status>> + Send>>;

/// Conversions between the stage events and results and one RPC's messages,
/// which differ in their preflight and denial variant.
macro_rules! session_messages {
    ($event:ident, $result:ident, $denial:ident) => {
        impl From<StageEvent> for openshell_core::proto::$event::Event {
            fn from(event: StageEvent) -> Self {
                match event {
                    StageEvent::Begin(begin) => Self::Begin(begin),
                    StageEvent::BufferedBody(body) => Self::BufferedBody(body),
                    StageEvent::InputChunk(chunk) => Self::InputChunk(chunk),
                    StageEvent::InputEnd(end) => Self::InputEnd(end),
                    StageEvent::SessionEnd(end) => Self::SessionEnd(end),
                }
            }
        }

        impl From<openshell_core::proto::$result::Result> for StageResult {
            fn from(result: openshell_core::proto::$result::Result) -> Self {
                use openshell_core::proto::$result::Result as Wire;
                match result {
                    Wire::PreflightResult(result) => Self::PreflightResult(result),
                    Wire::BufferedResult(result) => Self::BufferedResult(result),
                    Wire::OutputStart(start) => Self::OutputStart(start),
                    Wire::OutputChunk(chunk) => Self::OutputChunk(chunk),
                    Wire::Finish(finish) => Self::Finish(finish),
                    Wire::$denial(deny) => Self::Deny(deny),
                }
            }
        }
    };
}

session_messages!(
    http_request_session_event,
    http_request_session_result,
    Deny
);
session_messages!(
    http_response_session_event,
    http_response_session_result,
    BlockDelivery
);

/// Event sender of one open stage exchange, typed by its RPC.
#[derive(Clone)]
enum EventSender {
    Request(mpsc::Sender<HttpRequestSessionEvent>),
    Response(mpsc::Sender<HttpResponseSessionEvent>),
}

impl EventSender {
    /// Send one event. Fails when the stage stopped reading events.
    async fn send(&self, event: StageEvent) -> Result<(), ()> {
        match self {
            Self::Request(sender) => sender
                .send(HttpRequestSessionEvent {
                    event: Some(event.into()),
                })
                .await
                .map_err(drop),
            Self::Response(sender) => sender
                .send(HttpResponseSessionEvent {
                    event: Some(event.into()),
                })
                .await
                .map_err(drop),
        }
    }
}

/// Map one RPC's result stream onto stage results.
fn stage_results<R: 'static>(
    results: Pin<Box<dyn futures::Stream<Item = Result<R, tonic::Status>> + Send>>,
    result: fn(R) -> Option<StageResult>,
) -> StageResults {
    Box::pin(results.map(move |item| item.map(result)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageMode {
    Buffered { max_body_bytes: usize },
    Stream,
}

/// One stage that selected a body mode.
pub struct Stage {
    entry: DescribedChainEntry,
    stream: StageStream,
    mode: StageMode,
}

/// Event sender and result stream of one open stage exchange.
pub(super) struct StageStream {
    sender: Option<EventSender>,
    results: StageResults,
    ended: bool,
}

impl StageStream {
    /// Best-effort `SessionEnd`, then close the exchange.
    pub(super) async fn end(&mut self, reason: MiddlewareSessionEndReason) {
        if self.ended {
            return;
        }
        self.ended = true;
        let Some(sender) = self.sender.take() else {
            return;
        };
        end_exchange(sender, &mut self.results, reason).await;
    }
}

impl Drop for StageStream {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let Some(sender) = self.sender.take() else {
            return;
        };
        let mut results = std::mem::replace(&mut self.results, Box::pin(futures::stream::empty()));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                end_exchange(
                    sender,
                    &mut results,
                    MiddlewareSessionEndReason::Cancellation,
                )
                .await;
            });
        }
    }
}

/// Send `SessionEnd`, half-close the events, and drain the results. Results
/// are read while the `SessionEnd` waits for queue space: a stage blocked on
/// a full result queue stops reading its events.
async fn end_exchange(
    sender: EventSender,
    results: &mut StageResults,
    reason: MiddlewareSessionEndReason,
) {
    let mut drained = false;
    let _ = tokio::time::timeout(SESSION_END_TIMEOUT, async {
        let send = sender.send(session_end(reason));
        tokio::pin!(send);
        loop {
            tokio::select! {
                biased;
                _ = &mut send => return,
                next = results.next() => if next.is_none() {
                    drained = true;
                    return;
                },
            }
        }
    })
    .await;
    drop(sender);
    if drained {
        return;
    }
    let _ = tokio::time::timeout(SESSION_END_TIMEOUT, async {
        while results.next().await.is_some() {}
    })
    .await;
}

fn session_end(reason: MiddlewareSessionEndReason) -> StageEvent {
    StageEvent::SessionEnd(MiddlewareSessionEnd {
        reason: reason as i32,
        protocol_error: None,
    })
}

/// Outcome of preflight across a chain.
pub struct Preflight {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    pub failure: Option<MiddlewareFailureDetail>,
    /// Head after the initial preflight prefix.
    pub headers: Vec<HttpHeader>,
    /// Preflight mutations in chain order.
    pub header_mutations: Vec<HeaderMutation>,
    /// Present when at least one stage selected a body mode.
    pub pipeline: Option<Pipeline>,
    pub diagnostics: HttpStageDiagnostics,
}

/// First result of a stage exchange, as its result stream yields it.
pub(super) type FirstResult = Option<Result<Option<StageResult>, tonic::Status>>;

/// Open one stage exchange on the RPC its preflight selects: send the
/// preflight and read its first result before `deadline`.
pub(super) async fn open_stage(
    entry: &DescribedChainEntry,
    preflight: StagePreflight,
    deadline: Instant,
    timeout_reason: &str,
) -> Result<(StageStream, FirstResult), HttpMiddlewareFailure> {
    let Some(service) = entry.service.as_ref() else {
        return Err(entry_failure(entry, "binding_not_described"));
    };
    let closed = || tonic::Status::unavailable("middleware stage stream closed");
    let opened = tokio::time::timeout_at(deadline, async {
        let (sender, mut results) = match preflight {
            StagePreflight::Request(preflight) => {
                let (sender, receiver) = mpsc::channel(STAGE_QUEUE_MESSAGES);
                sender
                    .send(HttpRequestSessionEvent {
                        event: Some(http_request_session_event::Event::Preflight(preflight)),
                    })
                    .await
                    .map_err(|_| closed())?;
                let results = service.service.open_http_request_session(receiver).await?;
                (
                    EventSender::Request(sender),
                    stage_results(results, |result| result.result.map(StageResult::from)),
                )
            }
            StagePreflight::Response(preflight) => {
                let (sender, receiver) = mpsc::channel(STAGE_QUEUE_MESSAGES);
                sender
                    .send(HttpResponseSessionEvent {
                        event: Some(http_response_session_event::Event::Preflight(preflight)),
                    })
                    .await
                    .map_err(|_| closed())?;
                let results = service.service.open_http_response_session(receiver).await?;
                (
                    EventSender::Response(sender),
                    stage_results(results, |result| result.result.map(StageResult::from)),
                )
            }
        };
        let first = results.next().await;
        Ok::<_, tonic::Status>((sender, results, first))
    })
    .await;
    match opened {
        Ok(Ok((sender, results, first))) => Ok((
            StageStream {
                sender: Some(sender),
                results,
                ended: false,
            },
            first,
        )),
        Ok(Err(status)) => Err(status_failure(entry, &status)),
        Err(_) => Err(entry_failure(entry, timeout_reason)),
    }
}

/// Deadline of one preflight exchange: the binding timeout, bounded by the
/// chain deadline.
pub(super) fn preflight_deadline(
    entry: &DescribedChainEntry,
    chain_deadline: Instant,
) -> (Instant, &'static str) {
    let stage_deadline = Instant::now() + entry.timeout();
    if chain_deadline <= stage_deadline {
        (chain_deadline, "middleware_chain_timeout")
    } else {
        (stage_deadline, "middleware_timeout")
    }
}

/// Build the preflight for `entry`.
pub(super) fn preflight_event(
    entry: &DescribedChainEntry,
    head: &dyn StageHead,
    headers: &[HttpHeader],
    offer: BodyModeOffer,
    timeouts: PipelineTimeouts,
    declared_body_bytes: Option<u64>,
) -> StagePreflight {
    let permitted = offer.permitted;
    head.preflight(
        headers,
        PreflightFields {
            context: head.context().clone(),
            middleware_name: entry.entry.implementation.clone(),
            config: entry.entry.config.clone(),
            permitted_body_modes: permitted.iter().map(|mode| *mode as i32).collect(),
            unavailable_body_modes: offer.unavailable,
            limits: body_limits(entry, &permitted, timeouts, head.max_output_body_bytes()),
            declared_body_bytes,
        },
    )
}

struct PreparedStage {
    headers: Vec<HttpHeader>,
    header_mutations: Vec<HeaderMutation>,
    diagnostics: HttpStageDiagnostics,
    stage: Option<Stage>,
}

async fn prepare_stage(
    entry: &DescribedChainEntry,
    spec: &PipelineSpec,
    input_headers: &[HttpHeader],
    declared_body_bytes: Option<u64>,
    head: &dyn StageHead,
    chain_deadline: Instant,
) -> Result<PreparedStage, HttpMiddlewareFailure> {
    if !entry.is_resolved() {
        if entry.on_error() == OnError::FailOpen {
            let mut diagnostics = HttpStageDiagnostics::default();
            diagnostics
                .invocations
                .push(fail_open_invocation(entry, "binding_not_described"));
            return Ok(PreparedStage {
                headers: input_headers.to_vec(),
                header_mutations: Vec::new(),
                diagnostics,
                stage: None,
            });
        }
        return Err(entry_failure(entry, "binding_not_described"));
    }
    if entry.http_hook_version() != Some(HttpHookVersion::Session) {
        return Err(entry_failure(entry, MIDDLEWARE_HOOK_VERSIONS_MIXED));
    }
    let offer = head.body_modes(entry, input_headers, declared_body_bytes);
    let permitted = offer.permitted.clone();
    let event = preflight_event(
        entry,
        head,
        input_headers,
        offer,
        spec.timeouts,
        declared_body_bytes,
    );
    let (deadline, timeout_reason) = preflight_deadline(entry, chain_deadline);
    let (mut stream, first) = open_stage(entry, event, deadline, timeout_reason).await?;
    let decision = (|| {
        let result = match classify_result(entry, first)? {
            StageResult::PreflightResult(result) => result,
            StageResult::Deny(deny) => return Err(denial(entry, deny.diagnostics.as_ref())),
            _ => return Err(entry_failure(entry, "preflight_result_expected")),
        };
        let diagnostics = validate_diagnostics(entry, result.diagnostics.as_ref())?;
        let headers = spec
            .apply_head(input_headers, &result.header_mutations, false)
            .map_err(|error| mutation_failure(entry, &error))?;
        let mode = match result.decision {
            Some(http_preflight_result::Decision::ContinueWithoutBody(_)) => None,
            Some(http_preflight_result::Decision::Inspect(inspect)) => {
                let mode = inspect
                    .mode
                    .as_ref()
                    .ok_or_else(|| entry_failure(entry, "preflight_result_unknown"))?;
                Some(
                    validate_inspect(mode, &permitted, entry.max_payload_bytes())
                        .map_err(|reason| entry_failure(entry, reason))?,
                )
            }
            None => return Err(entry_failure(entry, "preflight_result_unknown")),
        };
        let mut retained = HttpStageDiagnostics::default();
        let reason_code = nonempty(&diagnostics.reason_code);
        collect_diagnostics(entry, diagnostics, &mut retained);
        retained.invocations.push(HttpStageInvocation {
            transformed: headers != input_headers,
            ..invocation(
                entry,
                match mode {
                    None => HttpStageOutcome::Continue,
                    Some(StageMode::Buffered { .. }) => HttpStageOutcome::Buffered,
                    Some(StageMode::Stream) => HttpStageOutcome::Stream,
                },
                reason_code,
            )
        });
        Ok((headers, result.header_mutations, retained, mode))
    })();
    match decision {
        Ok((headers, header_mutations, diagnostics, mode)) => {
            let stage = if let Some(mode) = mode {
                Some(Stage {
                    entry: entry.clone(),
                    stream,
                    mode,
                })
            } else {
                stream.end(MiddlewareSessionEndReason::StageSkipped).await;
                None
            };
            Ok(PreparedStage {
                headers,
                header_mutations,
                diagnostics,
                stage,
            })
        }
        Err(failure) => {
            stream.end(failure.end_reason).await;
            Err(failure)
        }
    }
}

/// Prepare the header-only prefix and the first inspecting stage. Later
/// stages open only when their predecessor establishes their input headers.
pub async fn preflight(
    entries: &[DescribedChainEntry],
    spec: PipelineSpec,
    headers: Vec<HttpHeader>,
    declared_input_bytes: Option<u64>,
    head: Arc<dyn StageHead>,
    chain_deadline: Instant,
) -> Preflight {
    let mut state = PreflightState {
        headers,
        header_mutations: Vec::new(),
        diagnostics: HttpStageDiagnostics::default(),
    };
    let mut pending = Vec::new();
    let mut first = None;
    for (index, entry) in entries.iter().enumerate() {
        let prepared = match prepare_stage(
            entry,
            &spec,
            &state.headers,
            declared_input_bytes,
            head.as_ref(),
            chain_deadline,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(failure) => return state.fail(failure),
        };
        state.headers = prepared.headers;
        state.header_mutations.extend(prepared.header_mutations);
        state.diagnostics.extend(prepared.diagnostics);
        if let Some(stage) = prepared.stage {
            first = Some(stage);
            pending.extend_from_slice(&entries[index + 1..]);
            break;
        }
    }
    let PreflightState {
        headers,
        header_mutations,
        diagnostics,
    } = state;
    let pipeline = first.map(|stage| Pipeline {
        spec,
        head: headers.clone(),
        head_source: head,
        stage,
        pending,
        declared_input_bytes,
        admission: BodyAdmission::default(),
    });
    Preflight {
        allowed: true,
        reason: String::new(),
        denial: None,
        failure: None,
        headers,
        header_mutations,
        pipeline,
        diagnostics,
    }
}

struct PreflightState {
    headers: Vec<HttpHeader>,
    header_mutations: Vec<HeaderMutation>,
    diagnostics: HttpStageDiagnostics,
}

impl PreflightState {
    fn fail(mut self, failure: HttpMiddlewareFailure) -> Preflight {
        let HttpMiddlewareFailure {
            reason,
            denial,
            failure,
            diagnostics,
            ..
        } = failure;
        self.diagnostics.extend(*diagnostics);
        Preflight {
            allowed: false,
            reason,
            denial,
            failure: failure.map(|failure| *failure),
            headers: self.headers,
            header_mutations: self.header_mutations,
            pipeline: None,
            diagnostics: self.diagnostics,
        }
    }
}

/// The first inspecting stage and the stages whose input is not ready yet.
pub struct Pipeline {
    spec: PipelineSpec,
    /// Head after the initial preflight prefix.
    head: Vec<HttpHeader>,
    stage: Stage,
    pending: Vec<DescribedChainEntry>,
    head_source: Arc<dyn StageHead>,
    declared_input_bytes: Option<u64>,
    admission: BodyAdmission,
}

/// Session budget slots one message holds while its body stages run.
#[derive(Default)]
struct BodyAdmission {
    /// The first stage retains its preflight slot while it buffers.
    buffered: Option<Arc<MiddlewareSessionPermit>>,
    runner: Option<ChainRunner>,
    /// A STREAM slot, kept until the pipeline ends.
    stream: Option<MiddlewareSessionPermit>,
}

impl ChainRunner {
    /// Reserve a stream slot for a STREAM stage or a chain with deferred
    /// stages. Keep the initial preflight slot only if the first stage
    /// buffers. Later stages share or acquire a preflight/buffering slot
    /// when their input headers arrive.
    ///
    /// A message never waits for a stream slot while holding a preflight
    /// slot: messages queued behind open streams would otherwise starve every
    /// preflight. When it has to wait, it releases the preflight slot and,
    /// if a BUFFERED stage runs, takes one again after the stream slot. No
    /// message holds a preflight slot while waiting for a stream slot, so the
    /// two waits cannot deadlock.
    pub(super) async fn admit_body(
        &self,
        mut pipeline: Pipeline,
        slot: MiddlewareSessionPermit,
        deadline: Instant,
    ) -> Option<Pipeline> {
        pipeline.admission.runner = Some(self.clone());
        if !pipeline.may_stream() {
            if pipeline.buffers() {
                pipeline.admission.buffered = Some(Arc::new(slot));
            }
            return Some(pipeline);
        }
        let (stream, slot) = if let Some(stream) = self.try_reserve_http_stream() {
            (stream, Some(slot))
        } else {
            drop(slot);
            let Some(stream) = self.reserve_http_stream(deadline).await else {
                pipeline.end(MiddlewareSessionEndReason::Cancellation).await;
                return None;
            };
            (stream, None)
        };
        pipeline.admission.stream = Some(stream);
        if pipeline.buffers() {
            let slot = if slot.is_some() {
                slot
            } else {
                self.reserve_http_session(deadline).await
            };
            let Some(slot) = slot else {
                pipeline.end(MiddlewareSessionEndReason::Cancellation).await;
                return None;
            };
            pipeline.admission.buffered = Some(Arc::new(slot));
        }
        Some(pipeline)
    }
}

impl Pipeline {
    /// Largest input chunk the first stage accepts.
    pub fn input_unit_limit(&self) -> usize {
        input_unit_limit(&self.stage)
    }

    /// True when the final output is already known to be buffered. Deferred
    /// stages may stream, so their output must use the incremental relay.
    pub fn buffers_final_output(&self) -> bool {
        self.pending.is_empty() && self.buffers()
    }

    fn buffers(&self) -> bool {
        matches!(self.stage.mode, StageMode::Buffered { .. })
    }

    /// True when this pipeline runs or may later select STREAM.
    pub fn may_stream(&self) -> bool {
        self.stage.mode == StageMode::Stream || !self.pending.is_empty()
    }

    #[cfg(test)]
    pub fn set_timeouts(&mut self, timeouts: PipelineTimeouts) {
        self.spec.timeouts = timeouts;
    }

    /// End every stage without running the body.
    pub async fn end(mut self, reason: MiddlewareSessionEndReason) {
        self.stage.stream.end(reason).await;
    }

    /// Run every body stage, re-checking every replaced body with
    /// `body_policy` before the next stage or the output sees it. The caller
    /// must feed `input` and drain `output` concurrently with this future.
    /// Dropping the future cancels the exchange: every open stage receives
    /// `CANCELLATION`. Under
    /// [`TransformedBodyPolicy::Reevaluate`] each stage's output is held until
    /// the stage ends, at most [`MAX_MIDDLEWARE_PAYLOAD_BYTES`].
    pub async fn run_with_body_policy(
        self,
        input: mpsc::Receiver<HttpBodyInput>,
        output: mpsc::Sender<HttpBodyOutput>,
        body_policy: TransformedBodyPolicy<'_>,
    ) -> Result<HttpPipelineFinish, HttpMiddlewareFailure> {
        self.run_inner(input, output, body_policy, std::future::pending())
            .await
    }

    /// Run every body stage without a body policy, ending the exchange when `abort` resolves first,
    /// as when the caller's peer goes away: every open stage receives the
    /// returned reason, and the run fails with `middleware_cancelled`.
    pub async fn run_until(
        self,
        input: mpsc::Receiver<HttpBodyInput>,
        output: mpsc::Sender<HttpBodyOutput>,
        external_abort: impl Future<Output = MiddlewareSessionEndReason>,
    ) -> Result<HttpPipelineFinish, HttpMiddlewareFailure> {
        self.run_inner(
            input,
            output,
            TransformedBodyPolicy::NotPolicyRelevant,
            external_abort,
        )
        .await
    }

    async fn run_inner(
        self,
        input: mpsc::Receiver<HttpBodyInput>,
        output: mpsc::Sender<HttpBodyOutput>,
        body_policy: TransformedBodyPolicy<'_>,
        external_abort: impl Future<Output = MiddlewareSessionEndReason>,
    ) -> Result<HttpPipelineFinish, HttpMiddlewareFailure> {
        let Self {
            spec,
            head,
            stage,
            pending,
            head_source,
            declared_input_bytes,
            mut admission,
        } = self;
        let stages: Vec<_> = std::iter::once(PipelineStage::Ready(stage))
            .chain(pending.into_iter().map(PipelineStage::Pending))
            .collect();
        let count = stages.len();
        let limits: Vec<usize> = stages
            .iter()
            .map(PipelineStage::input_unit_limit)
            .chain(std::iter::once(MAX_HTTP_STREAM_UNIT_BYTES))
            .collect();
        let mut senders = Vec::with_capacity(count + 1);
        let mut receivers = Vec::with_capacity(count + 1);
        for _ in 0..=count {
            let (sender, receiver) = mpsc::channel::<Frame>(STAGE_QUEUE_MESSAGES);
            senders.push(Some(sender));
            receivers.push(Some(receiver));
        }
        let (abort, aborted) = watch::channel(None::<MiddlewareSessionEndReason>);
        let shared = Shared {
            spec,
            head,
            head_source,
            admission: BufferAdmission {
                runner: admission.runner.take().expect("admitted pipeline"),
                active: Mutex::new(
                    admission
                        .buffered
                        .as_ref()
                        .map_or_else(Weak::new, Arc::downgrade),
                ),
            },
        };

        let checks = matches!(body_policy, TransformedBodyPolicy::Reevaluate(_));
        let (source_body, mut checked_body) = if checks {
            let (sender, receiver) = oneshot::channel();
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let mut tasks: FuturesUnordered<Pin<Box<dyn Future<Output = TaskResult> + Send + '_>>> =
            FuturesUnordered::new();
        tasks.push(Box::pin(run_source(
            input,
            senders[0].take().expect("source link"),
            limits[0],
            declared_input_bytes,
            source_body,
            aborted.clone(),
        )));
        for (index, stage) in stages.into_iter().enumerate() {
            let mut stage_output = senders[index + 1].take().expect("stage output link");
            if let Some(previous) = checked_body.take() {
                let (checkpoint_input, checkpoint_link) = mpsc::channel(STAGE_QUEUE_MESSAGES);
                let (checked, next) = oneshot::channel();
                checked_body = Some(next);
                tasks.push(Box::pin(run_checkpoint(
                    Checkpoint {
                        entry: stage.entry().clone(),
                        previous,
                        checked,
                        output_limit: limits[index + 1],
                        body_policy,
                    },
                    checkpoint_link,
                    std::mem::replace(&mut stage_output, checkpoint_input),
                    aborted.clone(),
                )));
            }
            tasks.push(Box::pin(run_stage(
                index,
                stage,
                if index == 0 {
                    admission.buffered.take()
                } else {
                    None
                },
                StageLinks {
                    input: receivers[index].take().expect("stage input link"),
                    output: stage_output,
                    output_limit: limits[index + 1],
                },
                &shared,
                aborted.clone(),
            )));
        }
        drop(checked_body);
        tasks.push(Box::pin(run_sink(
            receivers[count].take().expect("sink link"),
            output,
            aborted.clone(),
        )));
        drop(aborted);

        let mut external_abort = std::pin::pin!(external_abort);
        let mut done: Vec<Option<StageDone>> = (0..count).map(|_| None).collect();
        let mut trailers = None;
        let mut failure: Option<HttpMiddlewareFailure> = None;
        loop {
            // An external abort wins over the failures it causes, such as
            // the input ending early.
            let result = tokio::select! {
                biased;
                reason = &mut external_abort, if failure.is_none() => {
                    abort.send_replace(Some(reason));
                    failure = Some(HttpMiddlewareFailure {
                        end_reason: reason,
                        ..cancelled(&end_reason_name(reason))
                    });
                    continue;
                }
                result = tasks.next() => match result {
                    Some(result) => result,
                    None => break,
                },
            };
            match result {
                Ok(TaskDone::Stage(index, stage)) => {
                    done[index] = Some(stage);
                }
                Ok(TaskDone::Sink(value)) => trailers = Some(value),
                Err(TaskError::Failed(error)) if failure.is_none() => {
                    abort.send_replace(Some(error.end_reason));
                    failure = Some(error);
                }
                Ok(TaskDone::Source | TaskDone::Checkpoint) | Err(_) => {}
            }
        }
        drop(tasks);

        let mut diagnostics = HttpStageDiagnostics::default();
        for stage in done.into_iter().flatten() {
            diagnostics.extend(stage.diagnostics);
        }
        match (failure, trailers) {
            (Some(mut failure), _) => {
                diagnostics.extend(*failure.diagnostics);
                failure.diagnostics = Box::new(diagnostics);
                Err(failure)
            }
            (None, None) => Err(HttpMiddlewareFailure {
                diagnostics: Box::new(diagnostics),
                ..cancelled("pipeline_incomplete")
            }),
            (None, Some(trailers)) => Ok(HttpPipelineFinish {
                trailers,
                diagnostics,
            }),
        }
    }
}

/// Stable lowercase name of a session end reason.
fn end_reason_name(reason: MiddlewareSessionEndReason) -> String {
    reason
        .as_str_name()
        .trim_start_matches("MIDDLEWARE_SESSION_END_REASON_")
        .to_ascii_lowercase()
}

fn input_unit_limit(stage: &Stage) -> usize {
    match stage.mode {
        StageMode::Stream => stage_chunk_limit(&stage.entry),
        StageMode::Buffered { .. } => MAX_HTTP_STREAM_UNIT_BYTES,
    }
}

fn stage_chunk_limit(entry: &DescribedChainEntry) -> usize {
    entry
        .max_payload_bytes()
        .clamp(1, MAX_HTTP_STREAM_UNIT_BYTES)
}

/// Message on a link between pipeline tasks.
#[derive(Debug)]
enum Frame {
    /// Mutations since the initial preflight prefix, in stage order.
    Start {
        header_mutations: Vec<HeaderMutation>,
        output_body_bytes: Option<u64>,
    },
    Chunk(Vec<u8>),
    End(Vec<HttpHeader>),
}

struct Shared {
    spec: PipelineSpec,
    /// Head after the initial preflight prefix. Each stage begins on it plus the
    /// late mutations of earlier stages.
    head: Vec<HttpHeader>,
    head_source: Arc<dyn StageHead>,
    admission: BufferAdmission,
}

/// Buffered stages of one message share a slot, including while passing
/// output to the next stage. A stream releases the slot until it is needed.
struct BufferAdmission {
    runner: ChainRunner,
    active: Mutex<Weak<MiddlewareSessionPermit>>,
}

impl BufferAdmission {
    async fn acquire(&self, deadline: Instant) -> Option<Arc<MiddlewareSessionPermit>> {
        let mut active = self.active.lock().await;
        if let Some(permit) = active.upgrade() {
            return Some(permit);
        }
        let permit = Arc::new(self.runner.reserve_http_session(deadline).await?);
        *active = Arc::downgrade(&permit);
        Some(permit)
    }
}

enum PipelineStage {
    Ready(Stage),
    Pending(DescribedChainEntry),
}

impl PipelineStage {
    fn input_unit_limit(&self) -> usize {
        match self {
            Self::Ready(stage) => input_unit_limit(stage),
            Self::Pending(entry) if entry.max_payload_bytes() == 0 => MAX_HTTP_STREAM_UNIT_BYTES,
            Self::Pending(entry) => stage_chunk_limit(entry),
        }
    }

    fn entry(&self) -> &DescribedChainEntry {
        match self {
            Self::Ready(stage) => &stage.entry,
            Self::Pending(entry) => entry,
        }
    }
}

#[derive(Default)]
struct StageDone {
    diagnostics: HttpStageDiagnostics,
}

enum TaskDone {
    Source,
    Checkpoint,
    Stage(usize, StageDone),
    Sink(Vec<HttpHeader>),
}

enum TaskError {
    /// The task caused the exchange to fail.
    Failed(HttpMiddlewareFailure),
    /// The task stopped because the exchange already failed.
    Aborted,
}

type TaskResult = Result<TaskDone, TaskError>;

/// Error inside one stage.
enum StageError {
    Failed(HttpMiddlewareFailure),
    /// A neighbouring task closed its link because the exchange failed.
    LinkClosed,
}

impl From<HttpMiddlewareFailure> for StageError {
    fn from(failure: HttpMiddlewareFailure) -> Self {
        Self::Failed(failure)
    }
}

async fn abort_reason(
    aborted: &mut watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> MiddlewareSessionEndReason {
    aborted
        .wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|reason| *reason)
        .unwrap_or(MiddlewareSessionEndReason::Cancellation)
}

/// Feeds the first stage. With `original`, it also records the input body
/// for the first checkpoint, or `None` past [`MAX_MIDDLEWARE_PAYLOAD_BYTES`].
async fn run_source(
    mut input: mpsc::Receiver<HttpBodyInput>,
    link: mpsc::Sender<Frame>,
    limit: usize,
    declared_input_bytes: Option<u64>,
    original: Option<oneshot::Sender<Option<Vec<u8>>>>,
    mut aborted: watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> TaskResult {
    let work = async {
        let mut recorded = original.is_some().then(Vec::new);
        link.send(Frame::Start {
            header_mutations: Vec::new(),
            output_body_bytes: declared_input_bytes,
        })
        .await
        .map_err(|_| TaskError::Aborted)?;
        loop {
            match input.recv().await {
                Some(HttpBodyInput::Chunk(data)) => {
                    if let Some(body) = recorded.as_mut() {
                        if body.len().saturating_add(data.len()) > MAX_MIDDLEWARE_PAYLOAD_BYTES {
                            recorded = None;
                        } else {
                            body.extend_from_slice(&data);
                        }
                    }
                    for unit in data.chunks(limit) {
                        link.send(Frame::Chunk(unit.to_vec()))
                            .await
                            .map_err(|_| TaskError::Aborted)?;
                    }
                }
                Some(HttpBodyInput::End { trailers }) => {
                    link.send(Frame::End(trailers))
                        .await
                        .map_err(|_| TaskError::Aborted)?;
                    if let Some(original) = original {
                        let _ = original.send(recorded);
                    }
                    return Ok(TaskDone::Source);
                }
                None => {
                    return Err(TaskError::Failed(cancelled("input_ended_early")));
                }
            }
        }
    };
    tokio::select! {
        biased;
        _ = abort_reason(&mut aborted) => Err(TaskError::Aborted),
        result = work => result,
    }
}

/// What one checkpoint compares and where it sends what it checked.
struct Checkpoint<'p> {
    /// The stage whose output the checkpoint holds.
    entry: DescribedChainEntry,
    /// The body that stage received, or `None` when it was not recorded.
    previous: oneshot::Receiver<Option<Vec<u8>>>,
    /// Receives the body this checkpoint released, for the next checkpoint.
    checked: oneshot::Sender<Option<Vec<u8>>>,
    output_limit: usize,
    body_policy: TransformedBodyPolicy<'p>,
}

/// Holds one stage's output until the stage ends, re-checks it with the body
/// policy when it differs from the stage's input, and then releases it. A
/// policy denial fails the exchange before the next stage or the output sees
/// the body, as v1 HTTP hooks re-checks every replacement before the next stage.
async fn run_checkpoint(
    checkpoint: Checkpoint<'_>,
    mut link: mpsc::Receiver<Frame>,
    output: mpsc::Sender<Frame>,
    mut aborted: watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> TaskResult {
    let Checkpoint {
        entry,
        previous,
        checked,
        output_limit,
        body_policy,
    } = checkpoint;
    let work = async {
        let mut start = None;
        let mut body = Vec::new();
        let trailers = loop {
            match link.recv().await {
                Some(Frame::Start {
                    header_mutations,
                    output_body_bytes,
                }) if start.is_none() => {
                    start = Some((header_mutations, output_body_bytes));
                }
                Some(Frame::Chunk(data)) if start.is_some() => {
                    if body.len().saturating_add(data.len()) > MAX_MIDDLEWARE_PAYLOAD_BYTES {
                        return Err(TaskError::Failed(entry_failure(
                            &entry,
                            "request_output_over_capacity",
                        )));
                    }
                    body.extend_from_slice(&data);
                }
                Some(Frame::End(trailers)) if start.is_some() => break trailers,
                Some(_) => {
                    return Err(TaskError::Failed(platform_failure(
                        "pipeline_event_order_invalid",
                    )));
                }
                None => return Err(TaskError::Aborted),
            }
        };
        let replaced = previous
            .await
            .ok()
            .flatten()
            .is_none_or(|previous| previous != body);
        if replaced && let Some(reason) = transformed_body_denial(body_policy, &body) {
            return Err(TaskError::Failed(HttpMiddlewareFailure {
                reason,
                denial: None,
                failure: None,
                end_reason: MiddlewareSessionEndReason::PolicyDenial,
                diagnostics: Box::default(),
            }));
        }
        let (header_mutations, output_body_bytes) = start.expect("a started stage output");
        let release = async {
            send_frame(
                &output,
                Frame::Start {
                    header_mutations,
                    output_body_bytes,
                },
            )
            .await?;
            send_body(&output, &body, output_limit).await?;
            send_frame(&output, Frame::End(trailers)).await
        };
        release.await.map_err(|_| TaskError::Aborted)?;
        let _ = checked.send(Some(body));
        Ok(TaskDone::Checkpoint)
    };
    tokio::select! {
        biased;
        _ = abort_reason(&mut aborted) => Err(TaskError::Aborted),
        result = work => result,
    }
}

async fn run_sink(
    mut link: mpsc::Receiver<Frame>,
    output: mpsc::Sender<HttpBodyOutput>,
    mut aborted: watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> TaskResult {
    let work = async {
        let mut started = false;
        loop {
            let event = match link.recv().await {
                Some(Frame::Start {
                    header_mutations,
                    output_body_bytes,
                }) if !started => {
                    started = true;
                    HttpBodyOutput::Start {
                        header_mutations,
                        output_body_bytes,
                    }
                }
                Some(Frame::Chunk(data)) if started => HttpBodyOutput::Chunk(data),
                Some(Frame::End(trailers)) if started => {
                    output
                        .send(HttpBodyOutput::End {
                            trailers: trailers.clone(),
                        })
                        .await
                        .map_err(|_| TaskError::Failed(cancelled("output_closed")))?;
                    return Ok(TaskDone::Sink(trailers));
                }
                Some(_) => {
                    return Err(TaskError::Failed(platform_failure(
                        "pipeline_event_order_invalid",
                    )));
                }
                None => return Err(TaskError::Aborted),
            };
            output
                .send(event)
                .await
                .map_err(|_| TaskError::Failed(cancelled("output_closed")))?;
        }
    };
    tokio::select! {
        biased;
        _ = abort_reason(&mut aborted) => Err(TaskError::Aborted),
        result = work => result,
    }
}

enum StageExit {
    Done(Result<StageDone, StageError>),
    Aborted(MiddlewareSessionEndReason),
}

/// Links of one stage task.
struct StageLinks {
    input: mpsc::Receiver<Frame>,
    output: mpsc::Sender<Frame>,
    output_limit: usize,
}

async fn run_stage(
    index: usize,
    stage: PipelineStage,
    mut permit: Option<Arc<MiddlewareSessionPermit>>,
    mut links: StageLinks,
    shared: &Shared,
    mut aborted: watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> TaskResult {
    let entry = stage.entry().clone();
    let mut active = match stage {
        PipelineStage::Ready(stage) => Some(stage),
        PipelineStage::Pending(_) => None,
    };
    let mut diagnostics = HttpStageDiagnostics::default();
    let exit = tokio::select! {
        biased;
        reason = abort_reason(&mut aborted) => StageExit::Aborted(reason),
        result = drive_stage(&entry, &mut active, &mut permit, &mut diagnostics, &mut links, shared) => StageExit::Done(result),
    };
    match exit {
        StageExit::Done(Ok(mut done)) => {
            if let Some(stage) = active.as_mut() {
                stage.stream.end(MiddlewareSessionEndReason::Normal).await;
            }
            diagnostics.extend(done.diagnostics);
            done.diagnostics = diagnostics;
            Ok(TaskDone::Stage(index, done))
        }
        StageExit::Done(Err(StageError::Failed(mut failure))) => {
            if let Some(stage) = active.as_mut() {
                stage.stream.end(failure.end_reason).await;
            }
            diagnostics.extend(*failure.diagnostics);
            failure.diagnostics = Box::new(diagnostics);
            Err(TaskError::Failed(failure))
        }
        StageExit::Done(Err(StageError::LinkClosed)) => {
            let reason = abort_reason(&mut aborted).await;
            if let Some(stage) = active.as_mut() {
                stage.stream.end(reason).await;
            }
            Ok(TaskDone::Stage(index, StageDone { diagnostics }))
        }
        StageExit::Aborted(reason) => {
            if let Some(stage) = active.as_mut() {
                stage.stream.end(reason).await;
            }
            Ok(TaskDone::Stage(index, StageDone { diagnostics }))
        }
    }
}

/// `Start` received from the previous link.
struct UpstreamStart {
    header_mutations: Vec<HeaderMutation>,
    output_body_bytes: Option<u64>,
}

async fn drive_stage(
    entry: &DescribedChainEntry,
    active: &mut Option<Stage>,
    permit: &mut Option<Arc<MiddlewareSessionPermit>>,
    diagnostics: &mut HttpStageDiagnostics,
    links: &mut StageLinks,
    shared: &Shared,
) -> Result<StageDone, StageError> {
    let StageLinks {
        input,
        output,
        output_limit,
    } = links;
    let output_limit = *output_limit;
    let mut upstream = match input.recv().await {
        Some(Frame::Start {
            header_mutations,
            output_body_bytes,
        }) => UpstreamStart {
            header_mutations,
            output_body_bytes,
        },
        Some(_) => return Err(entry_failure(entry, "stage_input_order_invalid").into()),
        None => return Err(StageError::LinkClosed),
    };
    let mut begin_head = shared
        .spec
        .apply_head(&shared.head, &upstream.header_mutations, true)
        .map_err(|error| mutation_failure(entry, &error))?;
    if active.is_none() {
        begin_head = shared
            .head_source
            .current_headers(&begin_head, upstream.output_body_bytes);
        let deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        *permit = Some(
            shared
                .admission
                .acquire(deadline)
                .await
                .ok_or_else(|| entry_failure(entry, "session_capacity_exhausted"))?,
        );
        let prepared = prepare_stage(
            entry,
            &shared.spec,
            &begin_head,
            upstream.output_body_bytes,
            shared.head_source.as_ref(),
            deadline,
        )
        .await?;
        begin_head = prepared.headers;
        upstream.header_mutations.extend(prepared.header_mutations);
        diagnostics.extend(prepared.diagnostics);
        *active = prepared.stage;
    }
    let Some(stage) = active else {
        *permit = None;
        send_frame(
            output,
            Frame::Start {
                header_mutations: upstream.header_mutations,
                output_body_bytes: upstream.output_body_bytes,
            },
        )
        .await?;
        loop {
            match input.recv().await {
                Some(Frame::Chunk(data)) => send_body(output, &data, output_limit).await?,
                Some(Frame::End(trailers)) => {
                    send_frame(output, Frame::End(trailers)).await?;
                    return Ok(StageDone::default());
                }
                Some(Frame::Start { .. }) => {
                    return Err(entry_failure(entry, "stage_input_order_invalid").into());
                }
                None => return Err(StageError::LinkClosed),
            }
        }
    };
    match stage.mode {
        StageMode::Buffered { max_body_bytes } => {
            drive_buffered(
                stage,
                input,
                output,
                output_limit,
                shared,
                upstream,
                begin_head,
                max_body_bytes,
            )
            .await
        }
        StageMode::Stream => {
            *permit = None;
            drive_stream(
                stage,
                input,
                output,
                output_limit,
                shared,
                upstream,
                begin_head,
            )
            .await
        }
    }
}

/// Send `event` before `deadline`.
async fn send_until(
    entry: &DescribedChainEntry,
    stream: &mut StageStream,
    event: StageEvent,
    deadline: Option<Instant>,
    timeout_reason: &str,
) -> Result<(), HttpMiddlewareFailure> {
    let Some(sender) = stream.sender.as_ref() else {
        return Err(entry_failure(entry, "middleware_stream_closed"));
    };
    let sent = match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, sender.send(event))
            .await
            .map_err(|_| entry_failure(entry, timeout_reason))?,
        None => sender.send(event).await,
    };
    if sent.is_ok() {
        return Ok(());
    }
    let deadline = deadline.unwrap_or_else(|| Instant::now() + entry.timeout());
    let next = tokio::time::timeout_at(deadline, stream.results.next())
        .await
        .ok()
        .flatten();
    Err(closed_stream_failure(entry, next))
}

/// The stage stopped reading events. A denial or RPC status it ended with
/// explains why better than the closed stream does.
fn closed_stream_failure(entry: &DescribedChainEntry, next: FirstResult) -> HttpMiddlewareFailure {
    match next {
        Some(Ok(Some(StageResult::Deny(deny)))) => denial(entry, deny.diagnostics.as_ref()),
        Some(Err(status)) => status_failure(entry, &status),
        _ => entry_failure(entry, "middleware_stream_closed"),
    }
}

async fn send_frame(output: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), StageError> {
    output.send(frame).await.map_err(|_| StageError::LinkClosed)
}

async fn send_body(
    output: &mpsc::Sender<Frame>,
    body: &[u8],
    output_limit: usize,
) -> Result<(), StageError> {
    for unit in body.chunks(output_limit) {
        send_frame(output, Frame::Chunk(unit.to_vec())).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_buffered(
    stage: &mut Stage,
    input: &mut mpsc::Receiver<Frame>,
    output: &mpsc::Sender<Frame>,
    output_limit: usize,
    shared: &Shared,
    upstream: UpstreamStart,
    begin_head: Vec<HttpHeader>,
    max_body_bytes: usize,
) -> Result<StageDone, StageError> {
    let Stage { entry, stream, .. } = stage;
    // One deadline for receipt, processing, and delivery of the body.
    let body_deadline = Instant::now() + shared.spec.timeouts.buffered_body;
    send_until(
        entry,
        stream,
        StageEvent::Begin(HttpBegin {
            headers: begin_head.clone(),
        }),
        Some(body_deadline),
        "middleware_body_timeout",
    )
    .await?;

    let mut body = Vec::new();
    let trailers = loop {
        let frame = tokio::select! {
            biased;
            frame = input.recv() => frame,
            () = tokio::time::sleep_until(body_deadline) => {
                return Err(entry_failure(entry, "middleware_body_timeout").into());
            }
        };
        match frame {
            Some(Frame::Chunk(data)) => {
                if body.len().saturating_add(data.len()) > max_body_bytes {
                    return Err(entry_failure(entry, "buffered_input_over_capacity").into());
                }
                body.extend_from_slice(&data);
            }
            Some(Frame::End(trailers)) => break trailers,
            Some(Frame::Start { .. }) => {
                return Err(entry_failure(entry, "stage_input_order_invalid").into());
            }
            None => return Err(StageError::LinkClosed),
        }
    };

    let stage_deadline = Instant::now() + entry.timeout();
    let (exchange_deadline, timeout_reason) = if stage_deadline < body_deadline {
        (stage_deadline, "middleware_timeout")
    } else {
        (body_deadline, "middleware_body_timeout")
    };
    let input_bytes = body.len();
    let event = StageEvent::BufferedBody(HttpBufferedBody {
        data: body.clone(),
        trailers: trailers.clone(),
    });
    let exchange = async {
        send_until(
            entry,
            stream,
            event,
            Some(exchange_deadline),
            timeout_reason,
        )
        .await?;
        Ok::<_, HttpMiddlewareFailure>(stream.results.next().await)
    };
    let next = tokio::time::timeout_at(exchange_deadline, exchange)
        .await
        .map_err(|_| entry_failure(entry, timeout_reason))??;
    let result = match classify_result(entry, next)? {
        StageResult::BufferedResult(result) => result,
        StageResult::Deny(deny) => {
            return Err(denial(entry, deny.diagnostics.as_ref()).into());
        }
        _ => return Err(entry_failure(entry, "buffered_result_expected").into()),
    };
    let diagnostics = validate_diagnostics(entry, result.diagnostics.as_ref())?;
    let late_head = shared
        .spec
        .apply_head(&begin_head, &result.header_mutations, false)
        .map_err(|error| mutation_failure(entry, &error))?;
    let trailers = headers::apply(
        shared.spec.trailer_authority,
        &trailers,
        &shared.spec.connection_nominated,
        &result.trailer_mutations,
    )
    .map_err(|error| mutation_failure(entry, &error))?;
    let (body, outcome) = match result.body {
        Some(http_buffered_result::Body::Unchanged(_)) => (body, HttpStageOutcome::Unchanged),
        Some(http_buffered_result::Body::Replacement(replacement)) => {
            if replacement.len() > max_body_bytes {
                return Err(entry_failure(entry, "buffered_output_over_capacity").into());
            }
            (replacement, HttpStageOutcome::Replacement)
        }
        None => return Err(entry_failure(entry, "buffered_result_unknown").into()),
    };
    let head_changed = late_head != begin_head;
    let transformed = outcome == HttpStageOutcome::Replacement;
    let mut header_mutations = upstream.header_mutations;
    header_mutations.extend(result.header_mutations);
    let delivery = async {
        send_frame(
            output,
            Frame::Start {
                header_mutations,
                // Content-Length framing cannot carry trailers.
                output_body_bytes: (trailers.is_empty() || !shared.spec.output_trailers)
                    .then_some(body.len() as u64),
            },
        )
        .await?;
        send_body(output, &body, output_limit).await?;
        send_frame(output, Frame::End(trailers)).await
    };
    tokio::time::timeout_at(body_deadline, delivery)
        .await
        .map_err(|_| entry_failure(entry, "middleware_body_timeout"))??;
    let mut done = StageDone::default();
    let reason_code = nonempty(&diagnostics.reason_code);
    collect_diagnostics(entry, diagnostics, &mut done.diagnostics);
    done.diagnostics.invocations.push(HttpStageInvocation {
        input_bytes,
        output_bytes: Some(body.len()),
        transformed: transformed || head_changed,
        ..invocation(entry, outcome, reason_code)
    });
    Ok(done)
}

/// The body policy's verdict on a replaced body, or `None` when it passes.
fn transformed_body_denial(policy: TransformedBodyPolicy<'_>, body: &[u8]) -> Option<String> {
    let TransformedBodyPolicy::Reevaluate(validate) = policy else {
        return None;
    };
    match validate(body) {
        Ok(reason) => reason,
        Err(error) => Some(format!(
            "transformed_body_policy_evaluation_failed: {}",
            safe_reason(&error.to_string())
        )),
    }
}

/// Why a STREAM stage's input pump stopped early.
enum InputStop {
    /// The stage stopped reading input.
    Closed,
    Failed(StageError),
}

/// Why sending STREAM input to a stage stopped.
enum StallError {
    Closed,
    Stalled,
}

/// Send STREAM input, failing when the stage does not accept it within
/// `idle`. Time the stage's output spends held back downstream does not
/// count, and the timer restarts when that backpressure ends.
async fn send_stalled(
    sender: &EventSender,
    event: StageEvent,
    idle: Duration,
    output_held: &mut watch::Receiver<bool>,
) -> Result<(), StallError> {
    let pending = sender.send(event);
    tokio::pin!(pending);
    let mut deadline = Instant::now() + idle;
    let mut watching = true;
    loop {
        let held = watching && *output_held.borrow_and_update();
        tokio::select! {
            biased;
            sent = &mut pending => return sent.map_err(|()| StallError::Closed),
            changed = output_held.changed(), if watching => {
                if changed.is_err() {
                    watching = false;
                } else if !*output_held.borrow() {
                    deadline = Instant::now() + idle;
                }
            }
            () = tokio::time::sleep_until(deadline), if !held => return Err(StallError::Stalled),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_stream(
    stage: &mut Stage,
    input: &mut mpsc::Receiver<Frame>,
    output: &mpsc::Sender<Frame>,
    output_limit: usize,
    shared: &Shared,
    upstream: UpstreamStart,
    begin_head: Vec<HttpHeader>,
) -> Result<StageDone, StageError> {
    let Stage { entry, stream, .. } = stage;
    let entry = &*entry;
    let idle = shared.spec.timeouts.stream_idle;
    send_until(
        entry,
        stream,
        StageEvent::Begin(HttpBegin {
            headers: begin_head.clone(),
        }),
        Some(Instant::now() + idle),
        "middleware_stall_timeout",
    )
    .await?;
    let Some(sender) = stream.sender.clone() else {
        return Err(entry_failure(entry, "middleware_stream_closed").into());
    };
    let chunk_limit = stage_chunk_limit(entry);
    // Trailers are published before InputEnd is sent: a Finish can race the
    // send as soon as the stage consumes InputEnd.
    let (input_end, input_ended) = watch::channel(None::<Vec<HttpHeader>>);
    let (delivered, mut input_delivered) = watch::channel(false);
    let (held, mut output_held) = watch::channel(false);

    let input_pump = async {
        let mut input_bytes = 0usize;
        loop {
            let event = match input.recv().await {
                Some(Frame::Chunk(data)) => {
                    input_bytes = input_bytes.saturating_add(data.len());
                    StageEvent::InputChunk(HttpInputChunk { data })
                }
                Some(Frame::End(trailers)) => {
                    input_end.send_replace(Some(trailers.clone()));
                    StageEvent::InputEnd(HttpInputEnd { trailers })
                }
                Some(Frame::Start { .. }) => {
                    return Err(InputStop::Failed(
                        entry_failure(entry, "stage_input_order_invalid").into(),
                    ));
                }
                None => return Err(InputStop::Failed(StageError::LinkClosed)),
            };
            let end = matches!(event, StageEvent::InputEnd(_));
            match send_stalled(&sender, event, idle, &mut output_held).await {
                Ok(()) => {}
                Err(StallError::Closed) => {
                    // The output pump now reads the stage's terminal result
                    // under the idle timeout.
                    delivered.send_replace(true);
                    return Err(InputStop::Closed);
                }
                Err(StallError::Stalled) => {
                    return Err(InputStop::Failed(
                        entry_failure(entry, "middleware_stall_timeout").into(),
                    ));
                }
            }
            if end {
                delivered.send_replace(true);
                return Ok::<usize, InputStop>(input_bytes);
            }
        }
    };

    let results = &mut stream.results;
    let output_pump = async {
        let mut header_mutations = upstream.header_mutations;
        let mut started = false;
        let mut declared = None;
        let mut output_bytes = 0usize;
        loop {
            let next = if *input_delivered.borrow_and_update() {
                tokio::time::timeout(idle, results.next())
                    .await
                    .map_err(|_| entry_failure(entry, "middleware_stall_timeout"))?
            } else {
                // A stage may withhold output until all input arrives, so
                // there is no result timeout while input is still flowing.
                tokio::select! {
                    next = results.next() => next,
                    _ = input_delivered.changed() => continue,
                }
            };
            match classify_result(entry, next)? {
                StageResult::OutputStart(start) if !started => {
                    shared
                        .spec
                        .apply_head(&begin_head, &start.header_mutations, false)
                        .map_err(|error| mutation_failure(entry, &error))?;
                    header_mutations.extend(start.header_mutations);
                    declared = start.output_body_bytes;
                    started = true;
                    held.send_replace(true);
                    send_frame(
                        output,
                        Frame::Start {
                            header_mutations: header_mutations.clone(),
                            output_body_bytes: declared,
                        },
                    )
                    .await?;
                    held.send_replace(false);
                }
                StageResult::OutputChunk(chunk) if started => {
                    if chunk.data.is_empty() || chunk.data.len() > chunk_limit {
                        return Err(entry_failure(entry, "stream_output_chunk_invalid").into());
                    }
                    output_bytes = output_bytes.saturating_add(chunk.data.len());
                    if declared.is_some_and(|declared| output_bytes as u64 > declared) {
                        return Err(entry_failure(entry, "stream_output_length_mismatch").into());
                    }
                    held.send_replace(true);
                    send_body(output, &chunk.data, output_limit).await?;
                    held.send_replace(false);
                }
                StageResult::Finish(finish) if started => {
                    let Some(trailers) = input_ended.borrow().clone() else {
                        return Err(entry_failure(entry, "stream_finish_before_input_end").into());
                    };
                    if declared.is_some_and(|declared| declared != output_bytes as u64) {
                        return Err(entry_failure(entry, "stream_output_length_mismatch").into());
                    }
                    let diagnostics = validate_diagnostics(entry, finish.diagnostics.as_ref())?;
                    let trailers = headers::apply(
                        shared.spec.trailer_authority,
                        &trailers,
                        &shared.spec.connection_nominated,
                        &finish.trailer_mutations,
                    )
                    .map_err(|error| mutation_failure(entry, &error))?;
                    send_frame(output, Frame::End(trailers)).await?;
                    return Ok::<_, StageError>((diagnostics, output_bytes));
                }
                StageResult::Deny(deny) => {
                    return Err(denial(entry, deny.diagnostics.as_ref()).into());
                }
                _ => return Err(entry_failure(entry, "stream_result_order_invalid").into()),
            }
        }
    };

    let closed = || StageError::from(entry_failure(entry, "middleware_stream_closed"));
    let mut input_pump = std::pin::pin!(input_pump);
    let mut output_pump = std::pin::pin!(output_pump);
    let (input_bytes, (diagnostics, output_bytes)) = tokio::select! {
        input = &mut input_pump => match input {
            Ok(input_bytes) => (input_bytes, output_pump.await?),
            // A stage that denies or fails stops reading input; its result
            // stream carries the reason.
            Err(InputStop::Closed) => {
                return Err(output_pump.await.err().unwrap_or_else(closed));
            }
            Err(InputStop::Failed(error)) => return Err(error),
        },
        output = &mut output_pump => {
            let output = output?;
            match input_pump.await {
                Ok(input_bytes) => (input_bytes, output),
                Err(InputStop::Closed) => return Err(closed()),
                Err(InputStop::Failed(error)) => return Err(error),
            }
        }
    };
    let mut done = StageDone::default();
    let reason_code = nonempty(&diagnostics.reason_code);
    collect_diagnostics(entry, diagnostics, &mut done.diagnostics);
    done.diagnostics.invocations.push(HttpStageInvocation {
        input_bytes,
        output_bytes: Some(output_bytes),
        transformed: true,
        ..invocation(entry, HttpStageOutcome::Finish, reason_code)
    });
    Ok(done)
}

/// Unwrap one stage result. An unset or unknown result fails the exchange.
pub(super) fn classify_result(
    entry: &DescribedChainEntry,
    next: FirstResult,
) -> Result<StageResult, HttpMiddlewareFailure> {
    match next {
        Some(Ok(Some(result))) => Ok(result),
        Some(Ok(None)) => Err(entry_failure(entry, "result_unknown")),
        Some(Err(status)) => Err(status_failure(entry, &status)),
        None => Err(entry_failure(entry, "middleware_result_stream_closed")),
    }
}

/// Classify an RPC status. Every status fails the exchange closed; the reason
/// is platform-owned for external services.
fn status_failure(entry: &DescribedChainEntry, status: &tonic::Status) -> HttpMiddlewareFailure {
    match status.code() {
        tonic::Code::DeadlineExceeded => entry_failure(entry, "middleware_timeout"),
        // The service does not implement the HTTP session hook RPC its binding
        // selected.
        tonic::Code::Unimplemented => entry_failure(entry, "middleware_unimplemented"),
        // The reason may carry an in-process service's status text, so the
        // sandbox sees only that the middleware failed.
        _ => entry_failure_with_code(
            entry,
            &diagnostic_policy(entry).error_reason(status),
            HttpFailureCode::Unavailable,
        ),
    }
}

fn diagnostic_policy(entry: &DescribedChainEntry) -> MiddlewareDiagnosticPolicy {
    entry
        .service
        .as_ref()
        .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
            service.diagnostic_policy
        })
}

fn mutation_failure(
    entry: &DescribedChainEntry,
    error: &headers::HeaderMutationError,
) -> HttpMiddlewareFailure {
    entry_failure_with_code(
        entry,
        &diagnostic_policy(entry).header_mutation_error_reason(error),
        HttpFailureCode::HeaderMutation(error.code()),
    )
}

fn validate_inspect(
    mode: &http_inspect::Mode,
    permitted: &[HttpBodyMode],
    buffered_limit: usize,
) -> Result<StageMode, &'static str> {
    match mode {
        http_inspect::Mode::Buffered(mode)
            if permitted.contains(&HttpBodyMode::Buffered)
                && mode.max_body_bytes > 0
                && mode.max_body_bytes <= buffered_limit as u64 =>
        {
            Ok(StageMode::Buffered {
                max_body_bytes: usize::try_from(mode.max_body_bytes)
                    .map_err(|_| "body_mode_not_permitted")?,
            })
        }
        http_inspect::Mode::Stream(_) if permitted.contains(&HttpBodyMode::Stream) => {
            Ok(StageMode::Stream)
        }
        _ => Err("body_mode_not_permitted"),
    }
}

fn body_limits(
    entry: &DescribedChainEntry,
    permitted: &[HttpBodyMode],
    timeouts: PipelineTimeouts,
    max_output_body_bytes: Option<u64>,
) -> HttpBodyLimits {
    let buffered_limit = entry.max_payload_bytes();
    let chunk = if permitted.is_empty() {
        0
    } else {
        stage_chunk_limit(entry) as u64
    };
    let streams = permitted.contains(&HttpBodyMode::Stream);
    HttpBodyLimits {
        max_chunk_bytes: chunk,
        max_buffered_body_bytes: if permitted.contains(&HttpBodyMode::Buffered) {
            buffered_limit as u64
        } else {
            0
        },
        idle_timeout: streams.then(|| duration_to_proto(timeouts.stream_idle)),
        max_output_body_bytes: max_output_body_bytes.filter(|_| streams),
    }
}

fn duration_to_proto(duration: Duration) -> prost_types::Duration {
    prost_types::Duration {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
    }
}

fn validate_diagnostics(
    entry: &DescribedChainEntry,
    diagnostics: Option<&MiddlewareDiagnostics>,
) -> Result<MiddlewareDiagnostics, HttpMiddlewareFailure> {
    crate::diagnostics::validate_diagnostics(diagnostics)
        .map_err(|reason| entry_failure(entry, reason))
}

/// Namespace one stage's findings and metadata. External services get the
/// same normalization as v1 HTTP hook results: no metadata and no service-chosen
/// finding text.
fn collect_diagnostics(
    entry: &DescribedChainEntry,
    mut diagnostics: MiddlewareDiagnostics,
    collected: &mut HttpStageDiagnostics,
) {
    crate::diagnostics::normalize_diagnostics(
        &entry.entry.implementation,
        diagnostic_policy(entry),
        &mut diagnostics,
    );
    collected.findings.extend(
        diagnostics
            .findings
            .into_iter()
            .map(|finding| NamespacedFinding {
                middleware: entry.entry.name.clone(),
                finding,
            }),
    );
    if !diagnostics.metadata.is_empty() {
        collected.metadata.insert(
            entry.entry.name.clone(),
            diagnostics.metadata.into_iter().collect(),
        );
    }
}

pub(super) fn denial(
    entry: &DescribedChainEntry,
    diagnostics: Option<&MiddlewareDiagnostics>,
) -> HttpMiddlewareFailure {
    let diagnostics = match validate_diagnostics(entry, diagnostics) {
        Ok(diagnostics) => diagnostics,
        Err(failure) => return failure,
    };
    let reason_code = nonempty(&diagnostics.reason_code);
    let denial = MiddlewareDenial {
        config_name: entry.entry.name.clone(),
        reason_code: reason_code.clone(),
    };
    let mut retained = HttpStageDiagnostics::default();
    collect_diagnostics(entry, diagnostics, &mut retained);
    retained
        .invocations
        .push(invocation(entry, HttpStageOutcome::Deny, reason_code));
    HttpMiddlewareFailure {
        reason: middleware_denial_reason(&denial.config_name, denial.reason_code.as_deref()),
        denial: Some(denial),
        failure: None,
        end_reason: MiddlewareSessionEndReason::MiddlewareDenial,
        diagnostics: Box::new(retained),
    }
}

/// The stage failed and the exchange fails closed.
pub fn entry_failure(entry: &DescribedChainEntry, reason: &str) -> HttpMiddlewareFailure {
    entry_failure_with_code(entry, reason, HttpFailureCode::of_reason(reason))
}

/// The stage failed with `reason`, which the sandbox sees as `code`.
fn entry_failure_with_code(
    entry: &DescribedChainEntry,
    reason: &str,
    code: HttpFailureCode,
) -> HttpMiddlewareFailure {
    let mut diagnostics = HttpStageDiagnostics::default();
    diagnostics.invocations.push(HttpStageInvocation {
        failed: true,
        failure_reason: Some(reason.to_string()),
        ..invocation(entry, HttpStageOutcome::FailClosed, None)
    });
    HttpMiddlewareFailure {
        reason: format!("middleware_failed: {reason}"),
        denial: None,
        failure: Some(Box::new(MiddlewareFailureDetail {
            config_name: Some(entry.entry.name.clone()),
            code,
        })),
        end_reason: MiddlewareSessionEndReason::MiddlewareFailure,
        diagnostics: Box::new(diagnostics),
    }
}

/// The exchange failed for a reason no single stage owns.
pub fn platform_failure(reason: &str) -> HttpMiddlewareFailure {
    HttpMiddlewareFailure {
        reason: format!("middleware_failed: {reason}"),
        denial: None,
        failure: None,
        end_reason: MiddlewareSessionEndReason::MiddlewareFailure,
        diagnostics: Box::default(),
    }
}

fn cancelled(reason: &str) -> HttpMiddlewareFailure {
    HttpMiddlewareFailure {
        reason: format!("middleware_cancelled: {reason}"),
        denial: None,
        failure: None,
        end_reason: MiddlewareSessionEndReason::Cancellation,
        diagnostics: Box::default(),
    }
}

pub fn invocation(
    entry: &DescribedChainEntry,
    outcome: HttpStageOutcome,
    reason_code: Option<String>,
) -> HttpStageInvocation {
    HttpStageInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome,
        input_bytes: 0,
        output_bytes: None,
        transformed: false,
        failed: false,
        reason_code,
        failure_reason: None,
    }
}

pub fn fail_open_invocation(entry: &DescribedChainEntry, reason: &str) -> HttpStageInvocation {
    HttpStageInvocation {
        failed: true,
        failure_reason: Some(reason.to_string()),
        ..invocation(entry, HttpStageOutcome::FailOpen, None)
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}
