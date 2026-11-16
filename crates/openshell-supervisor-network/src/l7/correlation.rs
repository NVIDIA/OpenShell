// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request receipts and emission-time correlation without changing audit records.

use std::cell::RefCell;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use openshell_ocsf::OcsfEvent;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;
pub use crate::l7::request_trace::RequestStage;
use crate::l7::request_trace::RequestTrace;

tokio::task_local! {
    static CURRENT_REQUEST: RefCell<Option<Arc<RequestScope>>>;
}

/// Give each connection its own request slot, including across task migration.
pub fn scope_connection<F: Future>(future: F) -> impl Future<Output = F::Output> {
    CURRENT_REQUEST.scope(RefCell::new(None), future)
}

pub fn is_inspected_request() -> bool {
    CURRENT_REQUEST
        .try_with(|current| {
            current
                .borrow()
                .as_ref()
                .is_some_and(|scope| scope.inspected)
        })
        .unwrap_or(false)
}

pub fn current_request_span() -> Option<tracing::Span> {
    CURRENT_REQUEST
        .try_with(|current| current.borrow().clone())
        .ok()
        .flatten()
        .filter(|scope| scope.inspected)
        .map(|scope| scope.span())
}

fn enrich_request(event: &mut openshell_ocsf::BaseEventData) {
    let _ = CURRENT_REQUEST.try_with(|current| {
        let current = current.borrow();
        let Some(scope) = current.as_ref().filter(|scope| scope.inspected) else {
            return;
        };
        event.metadata.correlation_uid = Some(scope.request_id.clone());
        let sequence = scope.sequence.fetch_add(1, Ordering::Relaxed);
        let fields = event.unmapped.get_or_insert_with(|| serde_json::json!({}));
        if let Some(fields) = fields.as_object_mut() {
            fields
                .entry("http_event_kind")
                .or_insert_with(|| "decision".into());
            fields.insert("request_sequence".into(), sequence.into());
        }
    });
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
}

#[derive(Debug)]
pub struct RequestCorrelation {
    scope: Arc<RequestScope>,
    // Request loops are sequential; nested scopes restore in LIFO order.
    previous: Option<Arc<RequestScope>>,
}

impl RequestCorrelation {
    pub(crate) fn new(request: &L7Request, ctx: &L7EvalContext) -> Self {
        Self::build(request, ctx, uuid::Uuid::new_v4().to_string())
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
        Self::build(request, ctx, request_id)
    }

    fn build(request: &L7Request, ctx: &L7EvalContext, request_id: String) -> Self {
        let trace = RequestTrace::new(
            &request_id,
            &request.action,
            &ctx.host,
            ctx.port,
            &request.raw_header,
        );
        Self::install(RequestScope {
            request_id,
            inspected: true,
            sequence: AtomicU64::new(1),
            trace: Mutex::new(Some(trace)),
        })
    }

    fn install(scope: RequestScope) -> Self {
        openshell_ocsf::register_event_enricher(enrich_request);
        let scope = Arc::new(scope);
        let previous = CURRENT_REQUEST
            .try_with(|current| current.replace(Some(Arc::clone(&scope))))
            .ok()
            .flatten();
        Self { scope, previous }
    }

    pub(crate) fn request_id(&self) -> &str {
        &self.scope.request_id
    }

    pub(crate) fn stage(&self, stage: RequestStage) -> tracing::Span {
        self.scope
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or_else(tracing::Span::none, |trace| trace.stage(stage))
    }

    pub(crate) fn finish_http_trace(&self) {
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
        if let Some(trace) = self
            .scope
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            trace.record_outcome(outcome);
            trace.record_failure_reason(reason);
        }
    }

    pub(crate) fn emit(&self, event: OcsfEvent) {
        if !self.scope.inspected {
            crate::telemetry::emit_decision([event], None);
            return;
        }
        if let OcsfEvent::HttpActivity(http) = &event
            && let Some(trace) = self
                .scope
                .trace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
        {
            trace.observe_http(http);
        }
        CURRENT_REQUEST.sync_scope(RefCell::new(Some(Arc::clone(&self.scope))), || {
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
            let mut current = current.borrow_mut();
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
