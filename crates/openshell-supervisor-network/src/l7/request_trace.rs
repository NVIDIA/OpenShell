// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned request traces with untrusted workload links.

use opentelemetry::propagation::{Extractor, TextMapPropagator as _};
use opentelemetry::trace::{SpanContext, TraceContextExt as _};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use super::correlation::HttpOutcome;
use crate::metrics::{self, InspectionType, Outcome, Policy, ResultLabel, Scope, Stage, Timer};

const MAX_TRACEPARENT_BYTES: usize = 256;

#[derive(Debug)]
pub(super) struct RequestTrace {
    span: Span,
    outcome: &'static str,
    failure_reason: Option<&'static str>,
    inspection: Option<Timer>,
    inspection_result: Option<(ResultLabel, Option<Outcome>)>,
    inspection_type: InspectionType,
    policy: String,
    admission: Outcome,
}

#[derive(Debug, Clone, Copy)]
pub enum RequestStage {
    PolicyEvaluate,
    RequestMiddleware,
    WebsocketPreflight,
    CredentialPrepare,
    UpstreamResolve,
    UpstreamDial,
    UpstreamSend,
    Response,
    ResponseMiddleware,
}

impl RequestStage {
    fn name(self) -> &'static str {
        match self {
            Self::PolicyEvaluate => "openshell.policy.evaluate",
            Self::RequestMiddleware => "openshell.middleware.request",
            Self::WebsocketPreflight => "openshell.middleware.websocket.preflight",
            Self::CredentialPrepare => "openshell.credential.prepare",
            Self::UpstreamResolve => "openshell.upstream.resolve",
            Self::UpstreamDial => "openshell.upstream.connect",
            Self::UpstreamSend => "openshell.upstream.send",
            Self::Response => "openshell.http.response",
            Self::ResponseMiddleware => "openshell.middleware.response",
        }
    }
}

impl RequestTrace {
    pub(super) fn new(
        request_id: &str,
        method: &str,
        host: &str,
        port: u16,
        raw_request: &[u8],
    ) -> Self {
        let span = tracing::info_span!(
            parent: None,
            "openshell.http.request",
            openshell.request.id = request_id,
            http.request.method = normalized_method(method),
            server.address = host,
            server.port = i64::from(port),
            openshell.request.outcome = tracing::field::Empty,
            openshell.request.failure_reason = tracing::field::Empty,
            openshell.egress.outcome = tracing::field::Empty,
            openshell.egress.inspection_type = tracing::field::Empty,
            openshell.egress.result = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
        );
        if let Some(context) = workload_link(raw_request) {
            span.add_link_with_attributes(
                context,
                vec![
                    KeyValue::new("openshell.correlation.source", "http.traceparent"),
                    KeyValue::new("openshell.correlation.trust", "workload"),
                ],
            );
        }
        Self {
            span,
            outcome: "incomplete",
            failure_reason: None,
            inspection: None,
            inspection_result: None,
            inspection_type: InspectionType::Http,
            policy: String::new(),
            admission: Outcome::Allow,
        }
    }

    pub(super) fn start_inspection(&mut self, policy: &str) {
        self.policy.push_str(policy);
        self.inspection = Some(
            self.span
                .in_scope(|| Timer::new(Stage::Inspection(Scope::Request, self.inspection_type))),
        );
    }

    pub(super) fn select_inspector(&mut self, inspection_type: InspectionType, policy: &str) {
        self.inspection_type = inspection_type;
        self.policy.clear();
        self.policy.push_str(policy);
        if let Some(timer) = self.inspection.as_mut() {
            timer.set_stage(Stage::Inspection(Scope::Request, inspection_type));
        }
    }

    pub(super) fn note_admission(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Audit if !matches!(self.admission, Outcome::FailOpen) => {
                self.admission = outcome;
            }
            Outcome::FailOpen => self.admission = outcome,
            _ => {}
        }
    }

    pub(super) fn inspection_timer(&mut self) -> Option<&mut Timer> {
        self.inspection.as_mut()
    }

    pub(super) fn finished_inspection(
        &self,
    ) -> Option<(InspectionType, ResultLabel, Option<Outcome>)> {
        let (result, outcome) = self.inspection_result?;
        Some((self.inspection_type, result, outcome))
    }

    pub(super) fn finish_inspection(&mut self, result: ResultLabel) {
        let Some(timer) = self.inspection.take() else {
            return;
        };
        let outcome = match result {
            ResultLabel::Success => Some(self.admission),
            ResultLabel::Deny => Some(Outcome::Deny),
            _ => None,
        };
        self.inspection_result = Some((result, outcome));
        self.span.record("openshell.egress.result", result.label());
        self.span.record(
            "openshell.egress.inspection_type",
            self.inspection_type.label(),
        );
        if let Some(outcome) = outcome {
            self.span
                .record("openshell.egress.outcome", outcome.label());
            metrics::decision(
                Scope::Request,
                outcome,
                self.inspection_type,
                Policy::from(Some(self.policy.as_str())),
            );
        }
        timer.finish(result);
    }

    pub(super) fn span(&self) -> Span {
        self.span.clone()
    }

    pub(super) fn stage(&self, stage: RequestStage) -> Span {
        if self.span.is_disabled() || !self.span.context().span().span_context().is_valid() {
            return Span::none();
        }
        tracing::info_span!(
            parent: &self.span,
            "openshell.http.stage",
            otel.name = stage.name(),
            otel.status_code = tracing::field::Empty,
            openshell.request.failure_reason = tracing::field::Empty,
            openshell.egress.result = tracing::field::Empty,
        )
    }

    pub(super) fn record_status(&self, status: u16) {
        self.span
            .record("http.response.status_code", i64::from(status));
    }

    pub(super) fn record_outcome(&mut self, outcome: HttpOutcome) {
        if matches!(outcome, HttpOutcome::Denied) {
            self.finish_inspection(ResultLabel::Deny);
        }
        let outcome = match outcome {
            _ if self.outcome == "failed" => "failed",
            HttpOutcome::Allowed if self.outcome == "denied" => "denied",
            HttpOutcome::Allowed => "allowed",
            HttpOutcome::Denied => "denied",
            HttpOutcome::PlatformError | HttpOutcome::UpstreamError => "failed",
            HttpOutcome::Upgraded => "upgraded",
        };
        self.outcome = outcome;
        self.span.record("openshell.request.outcome", outcome);
    }

    pub(super) fn record_failure_reason(&mut self, reason: &'static str) {
        if self.failure_reason.is_none() {
            self.failure_reason = Some(reason);
            self.span.record("openshell.request.failure_reason", reason);
        }
    }

    pub(super) fn record_unclassified_failure(&mut self) {
        self.record_outcome(HttpOutcome::PlatformError);
        self.record_failure_reason("request_failed");
    }
}

impl Drop for RequestTrace {
    fn drop(&mut self) {
        self.finish_inspection(ResultLabel::Cancelled);
        // Finalize exported timing after the request's child stages.
        self.span.in_scope(|| {
            self.span.record("openshell.request.outcome", self.outcome);
            if matches!(self.outcome, "failed" | "incomplete") {
                self.span.record("otel.status_code", "ERROR");
            }
        });
    }
}

fn normalized_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => "_OTHER",
    }
}

fn workload_link(raw_request: &[u8]) -> Option<SpanContext> {
    let end = raw_request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")?;
    let mut value = None;
    for line in raw_request[..end].split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if !line[..colon].eq_ignore_ascii_case(b"traceparent") {
            continue;
        }
        if value.is_some() {
            return None;
        }
        let candidate = std::str::from_utf8(&line[colon + 1..]).ok()?.trim();
        if candidate.len() > MAX_TRACEPARENT_BYTES {
            return None;
        }
        value = Some(candidate);
    }
    let context = TraceContextPropagator::new()
        .extract_with_context(&Context::new(), &OnlyTraceparent(value?));
    let span_context = context.span().span_context().clone();
    span_context.is_valid().then_some(span_context)
}

struct OnlyTraceparent<'a>(&'a str);

impl Extractor for OnlyTraceparent<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        (key == "traceparent").then_some(self.0)
    }

    fn keys(&self) -> Vec<&str> {
        vec!["traceparent"]
    }
}

#[cfg(test)]
mod tests;
