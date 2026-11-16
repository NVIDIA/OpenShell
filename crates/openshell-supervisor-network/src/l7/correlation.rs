// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request receipts and emission-time correlation without changing audit records.

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use openshell_ocsf::OcsfEvent;
use tracing::Instrument as _;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;
pub use crate::l7::request_trace::RequestStage;
use crate::l7::request_trace::RequestTrace;

tokio::task_local! {
    static CURRENT_REQUEST: Arc<Mutex<Option<Arc<RequestScope>>>>;
}

/// Give each connection its own request slot, including across task migration.
pub fn scope_connection<F: Future>(future: F) -> impl Future<Output = F::Output> {
    #[cfg(test)]
    init_request_correlation().expect("request correlation enricher registration");
    let slot = CURRENT_REQUEST
        .try_with(Arc::clone)
        .unwrap_or_else(|_| Arc::new(Mutex::new(None)));
    CURRENT_REQUEST.scope(slot, future)
}

/// Install the network supervisor's process-wide audit enrichment at startup.
///
/// A different enricher is a configuration conflict, not a reason to silently
/// emit inspected records without their request receipt.
pub fn init_request_correlation() -> miette::Result<()> {
    static REGISTRATION: OnceLock<Result<(), &'static str>> = OnceLock::new();
    match REGISTRATION.get_or_init(|| {
        openshell_ocsf::register_event_enricher(enrich_request)
            .then_some(())
            .ok_or("cannot initialize HTTP request correlation: an OCSF event enricher is already registered")
    }) {
        Ok(()) => Ok(()),
        Err(message) => Err(miette::miette!("{message}")),
    }
}

pub fn is_inspected_request() -> bool {
    current_request().is_some_and(|scope| scope.inspected)
}

pub fn current_request_span() -> Option<tracing::Span> {
    current_request()
        .filter(|scope| scope.inspected)
        .map(|scope| scope.span())
}

fn current_request() -> Option<Arc<RequestScope>> {
    CURRENT_REQUEST
        .try_with(|current| {
            current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
        .ok()
        .flatten()
}

fn in_request_scope<T>(scope: &Arc<RequestScope>, operation: impl FnOnce() -> T) -> T {
    if current_request().is_some_and(|current| Arc::ptr_eq(&current, scope)) {
        operation()
    } else {
        let slot = Arc::new(Mutex::new(Some(Arc::clone(scope))));
        CURRENT_REQUEST.sync_scope(slot, operation)
    }
}

pub fn record_current_failure(outcome: HttpOutcome, reason: &'static str) {
    if let Some(scope) = current_request().filter(|scope| scope.inspected) {
        scope.record_failure(outcome, reason);
    }
}

fn enrich_request(event: &mut openshell_ocsf::BaseEventData) {
    let Some(scope) = current_request().filter(|scope| scope.inspected) else {
        return;
    };
    event.metadata.correlation_uid = Some(scope.request_id.clone());
    let sequence = scope.sequence.fetch_add(1, Ordering::Relaxed);
    let event_kind = default_event_kind(event.class_uid);
    let fields = event.unmapped.get_or_insert_with(|| serde_json::json!({}));
    if let Some(fields) = fields.as_object_mut() {
        fields
            .entry("http_event_kind")
            .or_insert_with(|| event_kind.into());
        fields.insert("request_sequence".into(), sequence.into());
    }
}

fn default_event_kind(class_uid: u32) -> &'static str {
    match class_uid {
        4002 => "decision",
        2004 => "finding",
        4001 | 4007 => "connection",
        1007 | 6002 => "lifecycle",
        5019 => "configuration",
        3002 => "authentication",
        _ => "event",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpOutcome {
    Allowed,
    Denied,
    PlatformError,
    UpstreamError,
    Upgraded,
}

#[derive(Debug)]
struct RequestScope {
    request_id: String,
    inspected: bool,
    sequence: AtomicU64,
    trace: Mutex<Option<RequestTrace>>,
}

impl RequestScope {
    fn span(&self) -> tracing::Span {
        self.trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or_else(tracing::Span::none, RequestTrace::span)
    }

    fn record_failure(&self, outcome: HttpOutcome, reason: &'static str) {
        if let Some(trace) = self
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            trace.record_outcome(outcome);
            trace.record_failure_reason(reason);
        }
    }
}

/// Carry request attribution only with an actual terminal error, never as a
/// connection-wide "last request" that could misattribute unrelated events.
#[derive(Debug)]
struct CapturedRequestError {
    scope: Arc<RequestScope>,
    span: tracing::Span,
    detail: String,
}

impl fmt::Display for CapturedRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

/// Emit the existing terminal record in the request that returned the error,
/// even after its request guard has restored the connection's ambient scope.
pub fn emit_error_event(event: OcsfEvent, error: &miette::Report) {
    if let Some(captured) = error.downcast_ref::<CapturedRequestError>() {
        in_request_scope(&captured.scope, || {
            crate::telemetry::emit_inspected_decision([event], Some(&captured.span));
        });
    } else {
        crate::telemetry::emit_decision([event], None);
    }
}

#[derive(Debug)]
pub struct RequestCorrelation {
    scope: Arc<RequestScope>,
    // Request loops are sequential; nested scopes restore in LIFO order.
    previous: Option<Arc<RequestScope>>,
}

/// An interrupted stage is an error even if its future never returns a result.
struct StageResult {
    span: tracing::Span,
    completed: bool,
}

impl StageResult {
    fn record(&mut self, failure_reason: Option<&'static str>) {
        self.completed = true;
        if let Some(reason) = failure_reason {
            self.span.record("otel.status_code", "ERROR");
            self.span.record("openshell.request.failure_reason", reason);
        } else {
            self.span.record("otel.status_code", "OK");
        }
    }
}

impl Drop for StageResult {
    fn drop(&mut self) {
        if !self.completed {
            self.span.record("otel.status_code", "ERROR");
            self.span
                .record("openshell.request.failure_reason", "cancelled");
        }
    }
}

impl RequestCorrelation {
    pub(crate) fn new(request: &L7Request, ctx: &L7EvalContext) -> Self {
        Self::new_http(&request.action, &request.raw_header, ctx)
    }

    pub(crate) fn new_http(method: &str, raw_header: &[u8], ctx: &L7EvalContext) -> Self {
        Self::build(method, raw_header, ctx, uuid::Uuid::new_v4().to_string())
    }

    pub(crate) fn uninspected() -> Self {
        Self::install(RequestScope {
            request_id: uuid::Uuid::new_v4().to_string(),
            inspected: false,
            sequence: AtomicU64::new(1),
            trace: Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_request_id(
        request: &L7Request,
        ctx: &L7EvalContext,
        request_id: String,
    ) -> Self {
        init_request_correlation().expect("request correlation enricher registration");
        Self::build(&request.action, &request.raw_header, ctx, request_id)
    }

    fn build(method: &str, raw_header: &[u8], ctx: &L7EvalContext, request_id: String) -> Self {
        let trace = RequestTrace::new(&request_id, method, &ctx.host, ctx.port, raw_header);
        Self::install(RequestScope {
            request_id,
            inspected: true,
            sequence: AtomicU64::new(1),
            trace: Mutex::new(Some(trace)),
        })
    }

    fn install(scope: RequestScope) -> Self {
        let scope = Arc::new(scope);
        let previous = CURRENT_REQUEST
            .try_with(|current| {
                current
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .replace(Arc::clone(&scope))
            })
            .ok()
            .flatten();
        Self { scope, previous }
    }

    pub(crate) fn request_id(&self) -> &str {
        &self.scope.request_id
    }

    pub(crate) fn capture_error(&self, error: miette::Report) -> miette::Report {
        if !self.scope.inspected || error.downcast_ref::<CapturedRequestError>().is_some() {
            return error;
        }
        if let Some(trace) = self
            .scope
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            trace.record_unclassified_failure();
        }
        let captured = CapturedRequestError {
            scope: Arc::clone(&self.scope),
            span: self.scope.span(),
            detail: error.to_string(),
        };
        error.wrap_err(captured)
    }

    pub(crate) fn stage(&self, stage: RequestStage) -> tracing::Span {
        self.scope
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or_else(tracing::Span::none, |trace| trace.stage(stage))
    }

    /// Record a stage's actual result without exporting its potentially
    /// sensitive error value or changing cancellation behavior.
    pub(crate) fn run_stage<T, E>(
        &self,
        stage: RequestStage,
        failure_outcome: HttpOutcome,
        reason: &'static str,
        future: impl Future<Output = Result<T, E>>,
    ) -> impl Future<Output = Result<T, E>> {
        self.run_stage_classified(stage, failure_outcome, reason, future, |_| None)
    }

    /// Include handled failures returned as successful transport results.
    pub(crate) fn run_stage_classified<T, E>(
        &self,
        stage: RequestStage,
        failure_outcome: HttpOutcome,
        reason: &'static str,
        future: impl Future<Output = Result<T, E>>,
        classify_failure: impl FnOnce(&T) -> Option<&'static str>,
    ) -> impl Future<Output = Result<T, E>> {
        let mut stage = StageResult {
            span: self.stage(stage),
            completed: false,
        };
        let future = future.instrument(stage.span.clone());
        async move {
            let result = future.await;
            let failure_reason = result.as_ref().map_or(Some(reason), classify_failure);
            stage.record(failure_reason);
            if let Some(reason) = failure_reason {
                self.record_failure(failure_outcome, reason);
            }
            result
        }
    }

    pub(crate) fn run_stage_sync<T, E>(
        &self,
        stage: RequestStage,
        failure_outcome: HttpOutcome,
        reason: &'static str,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let mut stage = StageResult {
            span: self.stage(stage),
            completed: false,
        };
        let result = stage.span.in_scope(operation);
        stage.record(result.is_err().then_some(reason));
        if result.is_err() {
            self.record_failure(failure_outcome, reason);
        }
        result
    }

    /// End HTTP tracing and restore the previous ambient scope before handing
    /// an upgraded connection to its longer-lived protocol relay.
    pub(crate) fn finish_http_request(self) {
        drop(self);
    }

    fn finish_http_trace(&self) {
        let trace = self
            .scope
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(trace);
    }

    pub(crate) fn record_outcome(&self, outcome: HttpOutcome) {
        if let Some(trace) = self
            .scope
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            trace.record_outcome(outcome);
        }
    }

    pub(crate) fn record_response_status(&self, status: u16) {
        if let Some(trace) = self
            .scope
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            trace.record_status(status);
            if status == 101 {
                trace.record_outcome(HttpOutcome::Upgraded);
            }
        }
    }

    pub(crate) fn record_rejection(
        &self,
        status: u16,
        outcome: HttpOutcome,
        reason: Option<&'static str>,
    ) {
        self.record_outcome(outcome);
        self.record_response_status(status);
        if let Some(reason) = reason {
            self.record_failure(outcome, reason);
        }
    }

    pub(crate) fn record_failure(&self, outcome: HttpOutcome, reason: &'static str) {
        self.scope.record_failure(outcome, reason);
    }

    pub(crate) fn emit(&self, event: OcsfEvent) {
        if !self.scope.inspected {
            crate::telemetry::emit_decision([event], None);
            return;
        }
        in_request_scope(&self.scope, || {
            crate::telemetry::emit_inspected_decision([event], Some(&self.scope.span()));
        });
    }
}

pub fn emit_request_events(
    correlation: Option<&RequestCorrelation>,
    events: impl IntoIterator<Item = OcsfEvent>,
) {
    if let Some(correlation) = correlation {
        for event in events {
            correlation.emit(event);
        }
    } else {
        crate::telemetry::emit_decision(events, None);
    }
}

impl Drop for RequestCorrelation {
    fn drop(&mut self) {
        self.finish_http_trace();
        let _ = CURRENT_REQUEST.try_with(|current| {
            let mut current = current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if current
                .as_ref()
                .is_some_and(|scope| Arc::ptr_eq(scope, &self.scope))
            {
                *current = self.previous.take();
            }
        });
    }
}

#[cfg(test)]
mod tests;
