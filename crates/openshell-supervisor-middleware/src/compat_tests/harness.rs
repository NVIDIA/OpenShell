// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral drivers and observations for the compatibility suites.
//!
//! Suites build chains with [`connect`] and [`entry`], run them with
//! [`run_request`], [`run_response`], or [`preflight_response`], and assert
//! only on the returned observations. A cutover adds an [`Engine`] variant and
//! one match arm per driver.

use prost::Message;

use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpHeader, HttpRequestTarget, MiddlewareSessionEndReason,
    RequestContext, SupervisorMiddlewareService,
};
use openshell_supervisor_middleware_wire_fixture::RunningFixture;

use crate::{
    ChainEntry, ChainRunner, HttpRequestInput, HttpResponseInvocationOutcome,
    HttpResponseMiddlewareFailure, HttpResponsePreflightInput, HttpResponseSession,
    MiddlewareDenial, MiddlewareRegistry, OnError,
};

/// Engine that executes a legacy chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Engine {
    /// The 0.1.x engines on `main`: `ChainRunner::evaluate_described` for
    /// requests and the lockstep `HttpResponseSession` for responses.
    Legacy,
}

impl Engine {
    /// Engines every compatibility test must pass on.
    pub(super) const ALL: [Self; 1] = [Self::Legacy];
}

/// Operator registration for a fixture. The timeout is the 500 ms platform
/// default because 0.1.x registrations commonly omit it.
pub(super) fn registration(
    name: &str,
    fixture: &RunningFixture,
    max_payload_bytes: u64,
) -> SupervisorMiddlewareService {
    SupervisorMiddlewareService {
        name: name.into(),
        grpc_endpoint: fixture.endpoint(),
        max_payload_bytes,
        request_timeout: None,
        tls_ca_cert_pem: Vec::new(),
        audience: String::new(),
        allow_insecure_transport: true,
    }
}

/// Describe and register every service, as the supervisor does at startup.
pub(super) async fn connect(registrations: Vec<SupervisorMiddlewareService>) -> ChainRunner {
    let registry = MiddlewareRegistry::connect_services(Vec::new(), registrations)
        .await
        .expect("register legacy middleware");
    ChainRunner::from_registry(registry)
}

/// One policy attachment with a config the fixture can echo back.
pub(super) fn entry(name: &str, implementation: &str, order: i32, on_error: OnError) -> ChainEntry {
    ChainEntry {
        name: name.into(),
        implementation: implementation.into(),
        order,
        config: prost_types::Struct {
            fields: std::iter::once((
                "attachment".to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(name.into())),
                },
            ))
            .collect(),
        },
        on_error,
    }
}

/// Decode a v0.1.2 message with the in-tree schema.
pub(super) fn transcode<T: Message, U: Message + Default>(message: &T) -> U {
    U::decode(message.encode_to_vec().as_slice())
        .expect("a v0.1.2 message decodes with the in-tree schema")
}

/// Request input with a fixed identity and target.
pub(super) fn request(body: &[u8], headers: &[(&str, &str)]) -> HttpRequestInput {
    HttpRequestInput {
        request_id: "compat-request".into(),
        sandbox_id: "compat-sandbox-id".into(),
        sandbox_name: "compat-sandbox".into(),
        workspace: "compat-workspace".into(),
        scheme: "https".into(),
        host: "api.example.test".into(),
        port: 443,
        method: "POST".into(),
        path: "/v1/messages".into(),
        query: "trace=1".into(),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect(),
        connection_nominated_headers: Vec::new(),
        body: body.to_vec(),
    }
}

/// Outcome of one stage in a request chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StageOutcome {
    pub(super) name: String,
    pub(super) decision: Decision,
    pub(super) transformed: bool,
    pub(super) failed: bool,
}

/// Everything a request chain makes observable to the relay.
#[derive(Debug, Clone)]
pub(super) struct RequestObservation {
    pub(super) allowed: bool,
    pub(super) reason: String,
    pub(super) body: Vec<u8>,
    /// Validated mutations, in the order the relay replays them.
    pub(super) header_mutations: Vec<HeaderMutation>,
    pub(super) stages: Vec<StageOutcome>,
    pub(super) denial: Option<MiddlewareDenial>,
    pub(super) findings: Vec<(String, Finding)>,
}

/// Run one request chain on `engine`.
pub(super) async fn run_request(
    engine: Engine,
    runner: &ChainRunner,
    entries: &[ChainEntry],
    input: HttpRequestInput,
) -> RequestObservation {
    match engine {
        Engine::Legacy => {
            let described = runner
                .describe_chain(entries)
                .await
                .expect("describe request chain");
            let outcome = runner
                .evaluate_described(&described, input)
                .await
                .expect("evaluate request chain");
            RequestObservation {
                allowed: outcome.allowed,
                reason: outcome.reason,
                body: outcome.body,
                header_mutations: outcome.header_mutations,
                stages: outcome
                    .applied
                    .into_iter()
                    .map(|invocation| StageOutcome {
                        name: invocation.name,
                        decision: invocation.decision,
                        transformed: invocation.transformed,
                        failed: invocation.failed,
                    })
                    .collect(),
                denial: outcome.denial,
                findings: outcome
                    .findings
                    .into_iter()
                    .map(|finding| (finding.middleware, finding.finding))
                    .collect(),
            }
        }
    }
}

/// One upstream response, as the relay hands it to the response chain.
#[derive(Debug, Clone)]
pub(super) struct ResponseCase {
    pub(super) method: String,
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) declared_body_length: Option<u64>,
    /// Normalized body bytes in arrival order. Each chunk is one upstream read.
    pub(super) chunks: Vec<Vec<u8>>,
    pub(super) trailers: Vec<(String, String)>,
}

impl ResponseCase {
    /// A `200` response of `content_type` with an unknown length.
    pub(super) fn ok(content_type: &str, chunks: &[&[u8]]) -> Self {
        Self {
            method: "GET".into(),
            status: 200,
            headers: vec![("content-type".into(), content_type.into())],
            declared_body_length: None,
            chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
            trailers: Vec::new(),
        }
    }

    pub(super) fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub(super) fn with_trailer(mut self, name: &str, value: &str) -> Self {
        self.trailers.push((name.into(), value.into()));
        self
    }

    pub(super) fn with_declared_length(mut self) -> Self {
        let length = self.chunks.iter().map(Vec::len).sum::<usize>();
        self.declared_body_length = Some(length as u64);
        self.headers
            .push(("content-length".into(), length.to_string()));
        self
    }

    fn preflight_input(&self) -> HttpResponsePreflightInput {
        HttpResponsePreflightInput {
            context: RequestContext {
                request_id: "compat-request".into(),
                sandbox_id: "compat-sandbox-id".into(),
                sandbox: "compat-sandbox".into(),
                workspace: "compat-workspace".into(),
                originating_process: None,
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "api.example.test".into(),
                port: 443,
                method: self.method.clone(),
                path: "/v1/stream".into(),
                query: String::new(),
            },
            status_code: self.status,
            declared_body_length: self.declared_body_length,
            headers: http_headers(&self.headers),
            connection_nominated_headers: Vec::new(),
        }
    }
}

/// Where a response chain stopped delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseStep {
    Preflight,
    /// While processing the chunk at this index.
    Chunk(usize),
    Finish,
}

#[derive(Debug, Clone)]
pub(super) struct ResponseFailure {
    pub(super) step: ResponseStep,
    pub(super) reason: String,
    pub(super) denial: Option<MiddlewareDenial>,
}

/// Everything a response chain makes observable to the relay.
#[derive(Debug, Clone)]
pub(super) struct ResponseObservation {
    pub(super) session_capacity_exhausted: bool,
    /// Response head after every preflight mutation.
    pub(super) headers: Vec<(String, String)>,
    /// Whether any stage selected body inspection.
    pub(super) inspected: bool,
    /// Bytes released for delivery while each chunk was processed.
    pub(super) released: Vec<Vec<u8>>,
    /// Bytes released when the body ended.
    pub(super) finished: Vec<u8>,
    pub(super) trailers: Vec<(String, String)>,
    pub(super) strip_stale_integrity_headers: bool,
    pub(super) failure: Option<ResponseFailure>,
    pub(super) invocations: Vec<(String, HttpResponseInvocationOutcome, bool)>,
}

impl ResponseObservation {
    /// Whether preflight let the response continue toward the client.
    pub(super) fn preflight_allowed(&self) -> bool {
        !matches!(
            self.failure,
            Some(ResponseFailure {
                step: ResponseStep::Preflight,
                ..
            })
        )
    }

    /// Every byte released for delivery, in order.
    pub(super) fn body(&self) -> Vec<u8> {
        let mut body = self.released.concat();
        body.extend_from_slice(&self.finished);
        body
    }

    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A response session kept open after preflight, as a long-lived stream holds it.
pub(super) struct HeldResponse {
    session: Option<HttpResponseSession>,
}

impl HeldResponse {
    pub(super) async fn end(self) {
        if let Some(session) = self.session {
            session.end(MiddlewareSessionEndReason::Normal).await;
        }
    }
}

/// Run response preflight only and keep any opened session alive.
pub(super) async fn preflight_response(
    engine: Engine,
    runner: &ChainRunner,
    entries: &[ChainEntry],
    case: &ResponseCase,
) -> (ResponseObservation, HeldResponse) {
    match engine {
        Engine::Legacy => {
            let described = runner
                .describe_http_response_chain(entries)
                .await
                .expect("describe response chain");
            let preflight = runner
                .preflight_described_http_response(described, case.preflight_input())
                .await
                .expect("response preflight");
            let observation = ResponseObservation {
                session_capacity_exhausted: preflight.session_capacity_exhausted,
                headers: header_pairs(&preflight.headers),
                inspected: preflight.session.is_some(),
                released: Vec::new(),
                finished: Vec::new(),
                trailers: case.trailers.clone(),
                strip_stale_integrity_headers: false,
                failure: (!preflight.allowed).then(|| ResponseFailure {
                    step: ResponseStep::Preflight,
                    reason: preflight.reason.clone(),
                    denial: preflight.denial.clone(),
                }),
                invocations: invocation_summary(&preflight.invocations),
            };
            (
                observation,
                HeldResponse {
                    session: preflight.session,
                },
            )
        }
    }
}

/// Run one response through preflight, every chunk, and the end of the body.
pub(super) async fn run_response(
    engine: Engine,
    runner: &ChainRunner,
    entries: &[ChainEntry],
    case: ResponseCase,
) -> ResponseObservation {
    let (mut observation, held) = preflight_response(engine, runner, entries, &case).await;
    match engine {
        Engine::Legacy => {
            let Some(mut session) = held.session else {
                if observation.preflight_allowed() {
                    observation.released.clone_from(&case.chunks);
                }
                return observation;
            };
            for (index, chunk) in case.chunks.iter().enumerate() {
                let limit = session.stream_unit_limit().max(1);
                let mut released = Vec::new();
                for unit in chunk.chunks(limit) {
                    match session.push_body(unit.to_vec()).await {
                        Ok(units) => released.extend(units.concat()),
                        Err(failure) => {
                            let diagnostics = session.take_diagnostics();
                            observation
                                .invocations
                                .extend(invocation_summary(&diagnostics.invocations));
                            end_failed_session(session, &failure).await;
                            observation.released.push(released);
                            observation.failure = Some(ResponseFailure {
                                step: ResponseStep::Chunk(index),
                                reason: failure.reason,
                                denial: failure.denial,
                            });
                            return observation;
                        }
                    }
                }
                observation.released.push(released);
            }
            match session.finish(http_headers(&case.trailers)).await {
                Ok(finish) => {
                    observation.finished = finish.body_units.concat();
                    observation.trailers = header_pairs(&finish.trailers);
                    observation.strip_stale_integrity_headers =
                        finish.strip_stale_integrity_headers;
                    observation
                        .invocations
                        .extend(invocation_summary(&finish.invocations));
                }
                Err(failure) => {
                    observation
                        .invocations
                        .extend(invocation_summary(&failure.diagnostics.invocations));
                    observation.failure = Some(ResponseFailure {
                        step: ResponseStep::Finish,
                        reason: failure.reason,
                        denial: failure.denial,
                    });
                }
            }
            observation
        }
    }
}

async fn end_failed_session(session: HttpResponseSession, failure: &HttpResponseMiddlewareFailure) {
    session
        .end(if failure.denial.is_some() {
            MiddlewareSessionEndReason::MiddlewareDenial
        } else {
            MiddlewareSessionEndReason::MiddlewareFailure
        })
        .await;
}

fn invocation_summary(
    invocations: &[crate::HttpResponseInvocation],
) -> Vec<(String, HttpResponseInvocationOutcome, bool)> {
    invocations
        .iter()
        .map(|invocation| {
            (
                invocation.config_name.clone(),
                invocation.outcome,
                invocation.failed,
            )
        })
        .collect()
}

fn http_headers(pairs: &[(String, String)]) -> Vec<HttpHeader> {
    pairs
        .iter()
        .map(|(name, value)| HttpHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect()
}

fn header_pairs(headers: &[HttpHeader]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|header| (header.name.clone(), header.value.clone()))
        .collect()
}
