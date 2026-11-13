// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request receipts and consolidated HTTP audit records.

use std::sync::Mutex;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use openshell_ocsf::{
    ActionId, DispositionId, Endpoint, HttpActivityBuilder, HttpActivityEvent, HttpRequest,
    HttpResponse, OcsfEvent, SeverityId, StatusId,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;
pub use crate::l7::request_trace::RequestStage;
use crate::l7::request_trace::RequestTrace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpOutcome {
    Allowed,
    Denied,
    PlatformError,
    UpstreamError,
    Upgraded,
}

impl HttpOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::PlatformError => "platform_error",
            Self::UpstreamError => "upstream_error",
            Self::Upgraded => "upgraded",
        }
    }
}

#[derive(Debug)]
pub struct RequestCorrelation {
    request_id: String,
    inspected: bool,
    // Keep the audit payload off the async state machine.
    state: Box<Mutex<RequestState>>,
}

#[derive(Debug, Default)]
struct RequestState {
    trace: Option<RequestTrace>,
    primary: Option<OcsfEvent>,
    seeded: bool,
    status: Option<u16>,
    upstream_status: Option<u16>,
    outcome: Option<HttpOutcome>,
    blocked: bool,
    failure_reason: Option<&'static str>,
    late_failure_emitted: bool,
}

impl RequestState {
    fn record_outcome(&mut self, outcome: HttpOutcome) {
        self.outcome = Some(outcome);
        if let Some(trace) = &mut self.trace {
            trace.record_outcome(outcome);
        }
    }

    fn record_status(&mut self, status: u16) {
        self.status = Some(status);
        if let Some(trace) = &self.trace {
            trace.record_status(status);
        }
    }

    fn record_failure_reason(&mut self, reason: &'static str) {
        self.failure_reason = Some(reason);
        if let Some(trace) = &self.trace {
            trace.record_failure_reason(reason);
        }
    }
}

impl RequestCorrelation {
    #[must_use]
    pub(crate) fn new(request: &L7Request, ctx: &L7EvalContext) -> Self {
        Self::build(request, ctx, uuid::Uuid::new_v4().to_string())
    }

    pub(crate) fn uninspected() -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            inspected: false,
            state: Box::default(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_request_id(
        request: &L7Request,
        ctx: &L7EvalContext,
        request_id: String,
    ) -> Self {
        Self::build(request, ctx, request_id)
    }

    fn build(request: &L7Request, ctx: &L7EvalContext, request_id: String) -> Self {
        let target = request.target.split(['?', '#']).next().unwrap_or("/");
        let target = if target.starts_with('/') { target } else { "/" };
        let path = openshell_core::secrets::redact_target_for_policy(target)
            .unwrap_or_else(|_| "/".to_string());
        let fallback = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .http_request(HttpRequest::new(&request.action, ctx.ocsf_url(&path)))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .message("HTTP request ended before a response was selected")
            .build();
        let trace = RequestTrace::new(
            &request_id,
            &request.action,
            &ctx.host,
            ctx.port,
            &request.raw_header,
        );
        Self {
            request_id,
            inspected: true,
            state: Box::new(Mutex::new(RequestState {
                trace: Some(trace),
                primary: Some(fallback),
                ..RequestState::default()
            })),
        }
    }

    #[must_use]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) fn stage(&self, stage: RequestStage) -> tracing::Span {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trace
            .as_ref()
            .map_or_else(tracing::Span::none, |trace| trace.stage(stage))
    }

    #[cfg(test)]
    pub(crate) fn trace_span(&self) -> tracing::Span {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trace
            .as_ref()
            .map_or_else(tracing::Span::none, RequestTrace::span)
    }

    pub(crate) fn finish_http_trace(&self) {
        let (mut trace, status) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (state.trace.take(), state.status)
        };
        if status == Some(101)
            && let Some(trace) = &mut trace
        {
            trace.record_outcome(HttpOutcome::Upgraded);
        }
        drop(trace);
    }

    pub(crate) fn observe_response<'a, C>(&'a self, client: &'a mut C) -> AuditedClient<'a, C> {
        AuditedClient {
            inner: client,
            correlation: self,
            head: ResponseHead::default(),
        }
    }

    pub(crate) fn record_enforcement_block(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .blocked = true;
    }

    pub(crate) fn record_outcome(&self, outcome: HttpOutcome) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_outcome(outcome);
    }

    pub(crate) fn record_response_status(&self, status: u16) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_status(status);
    }

    pub(crate) fn record_upstream_status(&self, status: u16) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upstream_status = Some(status);
    }

    pub(crate) fn record_rejection(
        &self,
        status: u16,
        outcome: HttpOutcome,
        reason: Option<&'static str>,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.blocked = true;
        state.record_outcome(outcome);
        state.record_status(status);
        if let Some(reason) = reason {
            state.record_failure_reason(reason);
        }
    }

    pub(crate) fn record_failure(&self, outcome: HttpOutcome, reason: &'static str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.record_outcome(outcome);
        state.record_failure_reason(reason);
    }

    pub(crate) fn emit(&self, event: OcsfEvent) {
        if !self.inspected {
            crate::telemetry::emit_decision([event], None);
            return;
        }
        if let OcsfEvent::HttpActivity(mut incoming) = event {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if is_middleware_invocation(&incoming) {
                if incoming.action == Some(ActionId::Denied)
                    && let Some(OcsfEvent::HttpActivity(primary)) = &mut state.primary
                {
                    merge_middleware_denial(primary, &incoming);
                }
                drop(state);
                self.emit_correlated(OcsfEvent::HttpActivity(incoming));
                return;
            }
            if !state.seeded && state.primary.is_some() {
                state.primary = Some(OcsfEvent::HttpActivity(incoming));
                state.seeded = true;
                return;
            }
            if let Some(OcsfEvent::HttpActivity(primary)) = &mut state.primary {
                merge_http_outcome(primary, incoming);
                return;
            }
            let fail_open = incoming.action == Some(ActionId::Other)
                && (incoming.disposition == Some(DispositionId::Allowed)
                    || incoming
                        .base
                        .unmapped
                        .as_ref()
                        .and_then(|fields| fields.get("response_middleware_outcome"))
                        .and_then(serde_json::Value::as_str)
                        == Some("failopen"));
            if !is_failure(&incoming) || fail_open || state.late_failure_emitted {
                return;
            }
            state.late_failure_emitted = true;
            if let Some(code) = state.status {
                incoming.http_response = Some(HttpResponse { code });
            }
            drop(state);
            self.emit_correlated(OcsfEvent::HttpActivity(incoming));
        } else {
            if let OcsfEvent::NetworkActivity(network) = &event {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !state.seeded
                    && (network.action == Some(ActionId::Denied)
                        || network.base.status == Some(StatusId::Failure))
                    && let Some(OcsfEvent::HttpActivity(primary)) = &mut state.primary
                {
                    primary.action = network.action;
                    primary.disposition = network.disposition;
                    primary.base.status = Some(StatusId::Failure);
                    primary
                        .base
                        .status_detail
                        .clone_from(&network.base.status_detail);
                    primary.base.severity = network.base.severity;
                    primary.base.message =
                        Some("HTTP request rejected before policy evaluation".into());
                    primary.src_endpoint.clone_from(&network.src_endpoint);
                    primary.actor.clone_from(&network.actor);
                }
            }
            self.emit_correlated(event);
        }
    }

    pub(crate) fn response_selected(&self, status: u16) {
        self.record_response_status(status);
        self.emit_primary(false);
    }

    fn emit_primary(&self, incomplete: bool) {
        if !self.inspected {
            return;
        }
        let (mut event, status, upstream_status, outcome, blocked, failure_reason) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(primary) = state.primary.take() else {
                return;
            };
            (
                primary,
                state.status,
                state.upstream_status,
                state.outcome,
                state.blocked,
                state.failure_reason,
            )
        };
        if let OcsfEvent::HttpActivity(http) = &mut event {
            let has_failure_reason = is_failure(http) && http.base.status_detail.is_some();
            if let Some(code) = status {
                http.http_response = Some(HttpResponse { code });
            }
            if let serde_json::Value::Object(unmapped) = http
                .base
                .unmapped
                .get_or_insert_with(|| serde_json::json!({}))
            {
                unmapped.insert("http_event_kind".into(), "request".into());
                if let Some(upstream) = upstream_status.filter(|upstream| Some(*upstream) != status)
                {
                    unmapped.insert("upstream_response_code".into(), serde_json::json!(upstream));
                }
            }
            if blocked || outcome == Some(HttpOutcome::Denied) {
                if http.action != Some(ActionId::Denied) {
                    http.base.message = Some("HTTP request blocked by supervisor".into());
                }
                http.action = Some(ActionId::Denied);
                http.disposition = Some(DispositionId::Blocked);
                http.base.status = Some(StatusId::Failure);
                raise_severity(http, SeverityId::Medium);
                if !has_failure_reason {
                    http.base.status_detail = Some(
                        failure_reason
                            .or_else(|| outcome.map(HttpOutcome::as_str))
                            .unwrap_or("supervisor_blocked")
                            .into(),
                    );
                }
            } else if matches!(
                outcome,
                Some(HttpOutcome::PlatformError | HttpOutcome::UpstreamError)
            ) {
                http.base.status = Some(StatusId::Failure);
                raise_severity(http, SeverityId::Low);
                if !has_failure_reason {
                    http.base.status_detail = failure_reason
                        .or_else(|| outcome.map(HttpOutcome::as_str))
                        .map(str::to_string);
                }
            }
            if incomplete && outcome.is_none() {
                http.base.status = Some(StatusId::Failure);
                if !has_failure_reason {
                    http.base.status_detail = Some("request_incomplete".into());
                }
                raise_severity(http, SeverityId::Low);
            }
        }
        self.emit_correlated(event);
    }

    fn emit_correlated(&self, mut event: OcsfEvent) {
        event.set_correlation_uid(self.request_id.clone());
        let parent = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.trace.as_mut().map(|trace| {
                if let OcsfEvent::HttpActivity(http) = &event
                    && !is_middleware_invocation(http)
                {
                    trace.observe_http(http);
                }
                trace.span()
            })
        };
        crate::telemetry::emit_inspected_decision([event], parent.as_ref());
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

fn is_failure(event: &HttpActivityEvent) -> bool {
    event.action == Some(ActionId::Denied) || event.base.status == Some(StatusId::Failure)
}

fn is_middleware_invocation(event: &HttpActivityEvent) -> bool {
    event
        .base
        .unmapped
        .as_ref()
        .and_then(|fields| fields.get("http_event_kind"))
        .and_then(serde_json::Value::as_str)
        == Some("middleware_invocation")
}

fn merge_middleware_denial(primary: &mut HttpActivityEvent, invocation: &HttpActivityEvent) {
    primary.action = invocation.action;
    primary.disposition = invocation.disposition;
    primary.base.status = Some(StatusId::Failure);
    raise_severity(primary, invocation.base.severity);
    if invocation.base.message.is_some() {
        primary.base.message.clone_from(&invocation.base.message);
    }
    if invocation.base.status_detail.is_some() {
        primary
            .base
            .status_detail
            .clone_from(&invocation.base.status_detail);
    }
}

fn raise_severity(event: &mut HttpActivityEvent, severity: SeverityId) {
    if event.base.severity.as_u8() < severity.as_u8() {
        event.base.severity = severity;
    }
}

fn merge_http_outcome(primary: &mut HttpActivityEvent, incoming: HttpActivityEvent) {
    let failed = is_failure(&incoming);
    if primary.actor.is_none() {
        primary.actor = incoming.actor;
    }
    if primary.src_endpoint.is_none() {
        primary.src_endpoint = incoming.src_endpoint;
    }
    if primary.dst_endpoint.is_none() {
        primary.dst_endpoint = incoming.dst_endpoint;
    }
    if primary.firewall_rule.is_none() {
        primary.firewall_rule = incoming.firewall_rule;
    }
    if primary
        .http_request
        .as_ref()
        .and_then(|request| request.url.as_ref())
        .is_none()
        && incoming
            .http_request
            .as_ref()
            .and_then(|request| request.url.as_ref())
            .is_some()
    {
        primary.http_request = incoming.http_request;
    }
    if !failed {
        if incoming
            .base
            .unmapped
            .as_ref()
            .and_then(|fields| fields.get("transformed_body_policy"))
            .and_then(serde_json::Value::as_str)
            == Some("audit")
        {
            if let serde_json::Value::Object(fields) = primary
                .base
                .unmapped
                .get_or_insert_with(|| serde_json::json!({}))
            {
                fields.insert("transformed_body_policy".into(), "audit".into());
            }
            if !is_failure(primary) && incoming.base.status_detail.is_some() {
                primary
                    .base
                    .status_detail
                    .clone_from(&incoming.base.status_detail);
            }
        }
        if primary.action.is_none() {
            primary.action = incoming.action;
            primary.disposition = incoming.disposition;
            primary.base.status = incoming.base.status;
            primary.base.message = incoming.base.message;
            primary.base.status_detail = incoming.base.status_detail;
        }
        return;
    }
    if incoming.action == Some(ActionId::Denied) {
        primary.action = incoming.action;
        primary.disposition = incoming.disposition;
    }
    primary.base.status = Some(StatusId::Failure);
    raise_severity(primary, incoming.base.severity);
    if incoming.base.message.is_some() {
        primary.base.message = incoming.base.message;
    }
    if incoming.base.status_detail.is_some() {
        primary.base.status_detail = incoming.base.status_detail;
    }
    if incoming.http_response.is_some() {
        primary.http_response = incoming.http_response;
    }
    if let Some(serde_json::Value::Object(fields)) = incoming.base.unmapped
        && let serde_json::Value::Object(existing) = primary
            .base
            .unmapped
            .get_or_insert_with(|| serde_json::json!({}))
    {
        existing.extend(fields);
    }
}

/// Observe accepted response bytes without buffering or changing delivery.
pub struct AuditedClient<'a, C> {
    inner: &'a mut C,
    correlation: &'a RequestCorrelation,
    head: ResponseHead,
}

#[derive(Default)]
struct ResponseHead {
    prefix: [u8; 12],
    prefix_len: usize,
    delimiter: u32,
    complete: bool,
}

impl ResponseHead {
    fn accept(&mut self, bytes: &[u8], correlation: &RequestCorrelation) {
        for &byte in bytes {
            if self.complete {
                break;
            }
            if self.prefix_len < self.prefix.len() {
                self.prefix[self.prefix_len] = byte;
                self.prefix_len += 1;
            }
            self.delimiter = (self.delimiter << 8) | u32::from(byte);
            if self.delimiter != u32::from_be_bytes(*b"\r\n\r\n") {
                continue;
            }
            let status = std::str::from_utf8(&self.prefix[9..12])
                .ok()
                .and_then(|code| code.parse::<u16>().ok());
            if status.is_some_and(|code| (100..200).contains(&code) && code != 101) {
                *self = Self::default();
            } else {
                self.complete = true;
                if let Some(status) = status {
                    correlation.response_selected(status);
                }
            }
        }
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for AuditedClient<'_, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for AuditedClient<'_, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(accepted)) = result
            && this.correlation.inspected
        {
            this.head.accept(&bytes[..accepted], this.correlation);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Drop for RequestCorrelation {
    fn drop(&mut self) {
        self.emit_primary(true);
        self.finish_http_trace();
    }
}

#[cfg(test)]
mod tests;
