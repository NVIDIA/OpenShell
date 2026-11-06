// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request correlation for HTTP enforcement events.

use std::sync::Mutex;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderMap, HeaderValue};
use openshell_ocsf::{
    ActionId, Endpoint, HttpActivityBuilder, HttpRequest, HttpResponse, OcsfEvent, SeverityId,
    StatusId,
};

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct RequestCorrelation {
    request_id: String,
    span: tracing::Span,
    // Keep the audit payload off the async state machine.
    state: Box<Mutex<RequestState>>,
}

#[derive(Debug)]
struct RequestState {
    primary: Option<OcsfEvent>,
    status: Option<u16>,
    upstream_status: Option<u16>,
    outcome: Option<&'static str>,
    policy_span: Option<tracing::Span>,
}

impl RequestCorrelation {
    #[must_use]
    pub(crate) fn new(request: &L7Request, ctx: &L7EvalContext) -> Self {
        Self::build(request, ctx, uuid::Uuid::new_v4().to_string())
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
        let method = bounded_http_method(&request.action);
        let span = tracing::info_span!(
            "openshell.http.request",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            "openshell.request.id" = %request_id,
            "http.request.method" = method,
            "server.address" = %ctx.host,
            "server.port" = ctx.port,
            "openshell.policy.name" = %ctx.policy_name,
            "openshell.target.reached" = false,
            "openshell.policy.decision" = tracing::field::Empty,
            "openshell.enforcement.action" = tracing::field::Empty,
            "openshell.http.outcome" = tracing::field::Empty,
            "http.response.status_code" = tracing::field::Empty,
        );
        let headers = trace_headers(&request.raw_header);
        let _ = openshell_otel::set_parent_from_headers(&span, &headers);
        let fallback = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .http_request(HttpRequest::new(method, ctx.ocsf_url("/")))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "l7")
            .message("HTTP request ended before a response was selected")
            .build();
        Self {
            request_id,
            span,
            state: Box::new(Mutex::new(RequestState {
                primary: Some(fallback),
                status: None,
                upstream_status: None,
                outcome: None,
                policy_span: None,
            })),
        }
    }

    #[must_use]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) fn observe_response<'a, C>(&'a self, client: &'a mut C) -> AuditedClient<'a, C> {
        AuditedClient {
            inner: client,
            correlation: self,
            head: ResponseHead::default(),
        }
    }

    pub(crate) fn record_policy_decision(&self, decision: &str) {
        self.span.record("openshell.policy.decision", decision);
        let policy_span = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .policy_span
            .take();
        if let Some(span) = policy_span {
            span.record("openshell.policy.decision", decision);
        }
    }

    pub(crate) fn evaluate_policy<T>(&self, operation: impl FnOnce() -> T) -> T {
        let span = tracing::info_span!(
            parent: &self.span,
            "openshell.policy.evaluate",
            "openshell.policy.decision" = tracing::field::Empty,
        );
        let result = span.in_scope(operation);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .policy_span = Some(span);
        result
    }

    pub(crate) fn record_enforcement_action(&self, action: &str) {
        self.span.record("openshell.enforcement.action", action);
    }

    pub(crate) fn record_final_http_outcome(&self, outcome: &'static str) {
        self.span.record("openshell.http.outcome", outcome);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcome = Some(outcome);
    }

    pub(crate) fn record_response_status(&self, status: u16) {
        self.span.record("http.response.status_code", status);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .status = Some(status);
    }

    pub(crate) fn record_upstream_status(&self, status: u16) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upstream_status = Some(status);
    }

    pub(crate) fn record_target_reached(&self) {
        self.span.record("openshell.target.reached", true);
    }

    pub(crate) fn record_error_stage(&self, _stage: &str) {
        openshell_otel::mark_error(&self.span);
    }

    pub(crate) fn emit(&self, event: OcsfEvent) {
        if matches!(event, OcsfEvent::HttpActivity(_)) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(primary) = &mut state.primary {
                *primary = event;
            }
        } else {
            self.emit_correlated(event);
        }
    }

    pub(crate) fn response_selected(&self, status: u16) {
        self.record_response_status(status);
        self.emit_primary(false);
    }

    fn emit_primary(&self, incomplete: bool) {
        let (mut event, status, upstream_status, outcome) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(primary) = state.primary.take() else {
                return;
            };
            (primary, state.status, state.upstream_status, state.outcome)
        };
        if let OcsfEvent::HttpActivity(http) = &mut event {
            http.http_response = status.map(|code| HttpResponse { code });
            if let Some(upstream) = upstream_status.filter(|upstream| Some(*upstream) != status) {
                let unmapped = http
                    .base
                    .unmapped
                    .get_or_insert_with(|| serde_json::json!({}));
                unmapped["upstream_response_code"] = serde_json::json!(upstream);
            }
            if incomplete && outcome.is_none() {
                http.base.status = Some(StatusId::Failure);
                http.base.status_detail = Some("request_incomplete".into());
                http.base.severity = SeverityId::Low;
            }
            if outcome == Some("denied") {
                if http.action != Some(ActionId::Denied) {
                    http.base.message = Some("HTTP request blocked after policy admission".into());
                }
                http.action = Some(ActionId::Denied);
                http.disposition = Some(openshell_ocsf::DispositionId::Blocked);
                http.base.status = Some(StatusId::Failure);
                http.base.severity = SeverityId::Medium;
            }
        }
        self.emit_correlated(event);
    }

    fn emit_correlated(&self, mut event: OcsfEvent) {
        event.set_correlation_uid(self.request_id.clone());
        self.span
            .in_scope(|| crate::telemetry::emit_correlated(event));
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
        if let Poll::Ready(Ok(accepted)) = result {
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

fn bounded_http_method(method: &str) -> &'static str {
    [
        "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
    ]
    .into_iter()
    .find(|known| method.eq_ignore_ascii_case(known))
    .unwrap_or("OTHER")
}

impl Drop for RequestCorrelation {
    fn drop(&mut self) {
        if self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcome
            .is_none()
        {
            self.span.record("openshell.http.outcome", "incomplete");
            openshell_otel::mark_error(&self.span);
        }
        self.emit_primary(true);
    }
}

fn trace_headers(raw_header: &[u8]) -> HeaderMap {
    let Some(header_end) = raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 2)
    else {
        return HeaderMap::new();
    };

    let mut headers = HeaderMap::new();
    for line in raw_header[..header_end]
        .split(|byte| *byte == b'\n')
        .skip(1)
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_optional_whitespace(&line[..separator]);
        if !name.eq_ignore_ascii_case(b"traceparent") {
            continue;
        }
        let Ok(name) = http::HeaderName::from_bytes(name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(trim_optional_whitespace(&line[separator + 1..]))
        else {
            continue;
        };
        if value.to_str().is_err() {
            continue;
        }
        headers.append(name, value);
    }
    headers
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> L7Request {
        L7Request {
            action: "GET".into(),
            target: "/data".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
            body_length: crate::l7::provider::BodyLength::None,
        }
    }

    #[test]
    fn request_ids_are_unique_canonical_uuids() {
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };
        let first = RequestCorrelation::new(&request(), &ctx);
        let second = RequestCorrelation::new(&request(), &ctx);

        assert_ne!(first.request_id(), second.request_id());
        assert!(uuid::Uuid::parse_str(first.request_id()).is_ok());
        assert!(uuid::Uuid::parse_str(second.request_id()).is_ok());
    }

    #[test]
    fn extracts_only_traceparent_and_preserves_duplicates() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-OpenShell-Request-ID: forged\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTraceParent: 00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01\r\ntracestate: vendor=value\r\n\r\n",
        );
        assert_eq!(headers.get_all("traceparent").iter().count(), 2);
        assert!(headers.get("tracestate").is_none());
        assert!(headers.get("x-openshell-request-id").is_none());
    }

    #[test]
    fn unrelated_obs_text_does_not_discard_valid_trace_context() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nx-observation-note: contains traceparent: but is not a field\r\n\r\n",
        );

        assert_eq!(headers.get_all("traceparent").iter().count(), 1);
    }

    #[test]
    fn non_ascii_traceparent_is_rejected_and_tracestate_is_ignored() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\ntraceparent: \xff\r\ntracestate: vendor=value\r\n\r\n",
        );

        assert!(headers.get("traceparent").is_none());
        assert!(headers.get("tracestate").is_none());
    }

    #[test]
    fn records_only_bounded_enforcement_outcome_fields() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &ctx,
                "00000000-0000-4000-8000-000000000001".into(),
            );
            assert!(!correlation.evaluate_policy(|| false));
            correlation.record_policy_decision("deny");
            correlation.record_enforcement_action("block");
            correlation.record_final_http_outcome("denied");
            correlation.record_response_status(403);
            correlation.record_error_stage("policy");
            correlation.record_target_reached();
        });

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let policy = spans
            .iter()
            .find(|span| span.name == "openshell.policy.evaluate")
            .unwrap();
        assert_eq!(policy.parent_span_id, span.span_context.span_id());
        assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Server);
        let attributes = span
            .attributes
            .iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.policy.decision"], "deny");
        assert_eq!(attributes["openshell.enforcement.action"], "block");
        assert_eq!(attributes["openshell.http.outcome"], "denied");
        assert_eq!(attributes["http.response.status_code"], "403");
        assert!(!attributes.contains_key("openshell.error.stage"));
        assert_eq!(attributes["openshell.target.reached"], "true");
    }

    #[test]
    fn custom_method_is_bounded_in_telemetry() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };
        let mut custom = request();
        custom.action = "SENTINEL-UNTRUSTED-METHOD".into();

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &custom,
                &ctx,
                "00000000-0000-4000-8000-000000000002".into(),
            );
            correlation.record_final_http_outcome("denied");
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let method = span
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "http.request.method")
            .expect("method attribute");
        assert_eq!(method.value.to_string(), "OTHER");
    }

    #[test]
    fn unfinished_request_is_recorded_as_incomplete() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            let _correlation = RequestCorrelation::with_request_id(
                &request(),
                &ctx,
                "00000000-0000-4000-8000-000000000002".into(),
            );
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let attributes = span
            .attributes
            .into_iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.http.outcome"], "incomplete");
        assert!(!attributes.contains_key("openshell.error.stage"));
    }

    #[test]
    fn malformed_or_incomplete_header_block_has_no_trace_context() {
        assert!(trace_headers(b"GET / HTTP/1.1\r\ntraceparent: value").is_empty());
        assert!(trace_headers(&[0xff, b'\r', b'\n', b'\r', b'\n']).is_empty());
    }

    #[tokio::test]
    async fn primary_record_waits_for_the_final_response_head_and_is_emitted_once() {
        use tokio::io::AsyncWriteExt as _;
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let ctx = L7EvalContext::default();
        let correlation = RequestCorrelation::new(&request(), &ctx);
        let id = correlation.request_id().to_string();
        correlation.emit(
            HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .http_request(HttpRequest::new("GET", ctx.ocsf_url("/data")))
                .action(ActionId::Allowed)
                .build(),
        );
        let mut output = Vec::new();
        {
            let mut client = correlation.observe_response(&mut output);
            client
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n")
                .await
                .unwrap();
            assert!(capture.events().is_empty());
            client.write_all(b"\r\nbody").await.unwrap();
            let events = capture.json_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["http_response"]["code"], 200);
            assert_eq!(events[0]["metadata"]["correlation_uid"], id);
        }
        drop(correlation);
        assert_eq!(capture.events().len(), 1);
        assert!(output.ends_with(b"\r\n\r\nbody"));
    }

    #[test]
    fn request_ending_before_response_headers_still_has_one_primary_record() {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let correlation = RequestCorrelation::new(&request(), &L7EvalContext::default());
        let id = correlation.request_id().to_string();
        let mut head = ResponseHead::default();
        head.accept(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n", &correlation);
        assert!(capture.events().is_empty());
        drop(correlation);
        let events = capture.json_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["metadata"]["correlation_uid"], id);
        assert_eq!(events[0]["status_detail"], "request_incomplete");
        assert!(events[0].get("http_response").is_none());
    }
}
