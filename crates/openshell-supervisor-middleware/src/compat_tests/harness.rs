// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Drivers and observations for the compatibility suites.
//!
//! Suites build chains with [`connect`] and [`entry`], run them with
//! [`run_request`], [`run_response`], or [`preflight_response`], and assert
//! only on the returned observations. Request and response chains run on
//! their stage pipelines, where legacy entries are adapter stages.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miette::Result;
use prost::Message;
use tokio::sync::mpsc;

use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpHeader, HttpRequestTarget, MiddlewareSessionEndReason,
    RequestContext, SupervisorMiddlewareService,
};
use openshell_supervisor_middleware_wire_fixture::RunningFixture;

use crate::pipeline::STAGE_QUEUE_MESSAGES;
use crate::{
    ChainEntry, ChainOutcome, ChainRunner, DescribedChainEntry, HttpBodyInput, HttpBodyOutput,
    HttpMiddlewareFailure, HttpPipelineFinish, HttpProtocol, HttpRequestPreflightInput,
    HttpResponseDelivery, HttpResponseInvocation, HttpResponseInvocationOutcome,
    HttpResponsePipelineSession, HttpResponsePreflightInput, HttpStageDiagnostics,
    HttpStageOutcome, MiddlewareDenial, MiddlewareRegistry, OnError, StageReport, StageReportSink,
    TransformedBodyPolicy, headers, is_stale_http_response_integrity_header,
};

/// Longest a response run waits for output after feeding one upstream read
/// before it feeds the next. A stage that streams answers within its entry
/// timeout, so its output is attributed to the read that produced it.
const RELEASE_WAIT: Duration = Duration::from_secs(2);
/// The same wait when a BUFFERED stage withholds every byte until the body
/// ends. Only a stage that gives up on its input, which needs no exchange,
/// can then produce output or a failure before the end.
const WITHHELD_RELEASE_WAIT: Duration = Duration::from_millis(500);
/// Quiet period that ends one read's output once some has arrived.
const RELEASE_QUIET: Duration = Duration::from_millis(250);

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
        ..Default::default()
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

/// One request as the relay hands it to request middleware once it has
/// received the whole body.
#[derive(Debug, Clone)]
pub struct RequestInput {
    pub request_id: String,
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub workspace: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub query: String,
    /// Lowercased middleware-visible headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Lowercased names nominated by the request's `Connection` headers.
    pub connection_nominated_headers: Vec<String>,
    pub body: Vec<u8>,
}

/// Request chains run on the request pipeline, as the relay runs a request
/// with a `Content-Length` body, and reported as 0.1.x reported a chain.
pub trait RequestChains {
    async fn run_chain(&self, entries: &[ChainEntry], input: RequestInput) -> Result<ChainOutcome>;

    async fn run_described(
        &self,
        entries: &[DescribedChainEntry],
        input: RequestInput,
    ) -> Result<ChainOutcome> {
        self.run_described_with_policy(entries, input, TransformedBodyPolicy::NotPolicyRelevant)
            .await
    }

    async fn run_described_with_policy(
        &self,
        entries: &[DescribedChainEntry],
        input: RequestInput,
        body_policy: TransformedBodyPolicy<'_>,
    ) -> Result<ChainOutcome>;
}

impl RequestChains for ChainRunner {
    async fn run_chain(&self, entries: &[ChainEntry], input: RequestInput) -> Result<ChainOutcome> {
        let described = self.describe_chain(entries).await?;
        self.run_described(&described, input).await
    }

    async fn run_described_with_policy(
        &self,
        entries: &[DescribedChainEntry],
        input: RequestInput,
        body_policy: TransformedBodyPolicy<'_>,
    ) -> Result<ChainOutcome> {
        let RequestInput {
            request_id,
            sandbox_id,
            sandbox_name,
            workspace,
            scheme,
            host,
            port,
            method,
            path,
            query,
            headers,
            connection_nominated_headers,
            body,
        } = input;
        let preflight = self
            .preflight_described_http_request(
                entries.to_vec(),
                HttpRequestPreflightInput {
                    context: RequestContext {
                        request_id,
                        sandbox_id,
                        sandbox: sandbox_name,
                        workspace,
                        originating_process: None,
                    },
                    target: HttpRequestTarget {
                        scheme,
                        host,
                        port: u32::from(port),
                        method,
                        path,
                        query,
                    },
                    declared_body_length: Some(body.len() as u64),
                    headers: headers
                        .into_iter()
                        .map(|(name, value)| HttpHeader { name, value })
                        .collect(),
                    connection_nominated_headers,
                },
            )
            .await?;
        let mut diagnostics = preflight.diagnostics;
        if !preflight.allowed {
            return Ok(chain_outcome(
                Err((preflight.reason, preflight.denial)),
                body,
                Vec::new(),
                diagnostics,
            ));
        }
        let Some(session) = preflight.session else {
            return Ok(chain_outcome(
                Ok(()),
                body,
                preflight.header_mutations,
                diagnostics,
            ));
        };
        let limit = session.input_unit_limit();
        let (input, inputs) = mpsc::channel(STAGE_QUEUE_MESSAGES);
        let (output, mut outputs) = mpsc::channel(STAGE_QUEUE_MESSAGES);
        let feed = async move {
            for unit in body.chunks(limit) {
                if input
                    .send(HttpBodyInput::Chunk(unit.to_vec()))
                    .await
                    .is_err()
                {
                    return body;
                }
            }
            let _ = input
                .send(HttpBodyInput::End {
                    trailers: Vec::new(),
                })
                .await;
            body
        };
        let collect = async move {
            let mut late = Vec::new();
            let mut released = Vec::new();
            while let Some(event) = outputs.recv().await {
                match event {
                    HttpBodyOutput::Start {
                        header_mutations, ..
                    } => late = header_mutations,
                    HttpBodyOutput::Chunk(data) => released.extend_from_slice(&data),
                    HttpBodyOutput::End { .. } => {}
                }
            }
            (late, released)
        };
        let (finish, body, (late, released)) = tokio::join!(
            session.run_with_body_policy(inputs, output, body_policy),
            feed,
            collect
        );
        Ok(match finish {
            Ok(finish) => {
                diagnostics.extend(finish.diagnostics);
                let mut header_mutations = preflight.header_mutations;
                header_mutations.extend(late);
                chain_outcome(Ok(()), released, header_mutations, diagnostics)
            }
            Err(failure) => {
                diagnostics.extend(*failure.diagnostics);
                chain_outcome(
                    Err((failure.reason, failure.denial)),
                    body,
                    Vec::new(),
                    diagnostics,
                )
            }
        })
    }
}

/// A finished request chain. A denied chain keeps the request body it was
/// given and replays no header mutation.
fn chain_outcome(
    result: std::result::Result<(), (String, Option<MiddlewareDenial>)>,
    body: Vec<u8>,
    header_mutations: Vec<HeaderMutation>,
    diagnostics: HttpStageDiagnostics,
) -> ChainOutcome {
    let applied = diagnostics.applied();
    let (allowed, reason, denial) = match result {
        Ok(()) => (true, String::new(), None),
        Err((reason, denial)) => (false, reason, denial),
    };
    ChainOutcome {
        allowed,
        reason,
        body,
        header_mutations,
        findings: diagnostics.findings,
        metadata: diagnostics.metadata.into_iter().collect::<BTreeMap<_, _>>(),
        applied,
        denial,
    }
}

/// Request input with a fixed identity and target.
pub(super) fn request(body: &[u8], headers: &[(&str, &str)]) -> RequestInput {
    RequestInput {
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

/// Run one request chain on the request pipeline.
pub(super) async fn run_request(
    runner: &ChainRunner,
    entries: &[ChainEntry],
    input: RequestInput,
) -> RequestObservation {
    let outcome = runner
        .run_chain(entries, input)
        .await
        .expect("run request chain");
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

/// One upstream response, as the relay hands it to the response chain.
#[derive(Debug, Clone)]
pub struct ResponseCase {
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub declared_body_length: Option<u64>,
    /// Normalized body bytes in arrival order. Each chunk is one upstream read.
    pub chunks: Vec<Vec<u8>>,
    pub trailers: Vec<(String, String)>,
}

impl ResponseCase {
    /// A `200` response of `content_type` with an unknown length.
    pub fn ok(content_type: &str, chunks: &[&[u8]]) -> Self {
        Self {
            request_id: "compat-request".into(),
            method: "GET".into(),
            path: "/v1/stream".into(),
            status: 200,
            headers: vec![("content-type".into(), content_type.into())],
            declared_body_length: None,
            chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
            trailers: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_trailer(mut self, name: &str, value: &str) -> Self {
        self.trailers.push((name.into(), value.into()));
        self
    }

    pub fn with_declared_length(mut self) -> Self {
        let length = self.chunks.iter().map(Vec::len).sum::<usize>();
        self.declared_body_length = Some(length as u64);
        self.headers
            .push(("content-length".into(), length.to_string()));
        self
    }

    fn preflight_input(&self) -> HttpResponsePreflightInput {
        HttpResponsePreflightInput {
            context: RequestContext {
                request_id: self.request_id.clone(),
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
                path: self.path.clone(),
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
pub enum ResponseStep {
    Preflight,
    /// While processing the chunk at this index.
    Chunk(usize),
    Finish,
}

#[derive(Debug, Clone)]
pub struct ResponseFailure {
    pub step: ResponseStep,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
}

/// Everything a response chain makes observable to the relay.
#[derive(Debug, Clone)]
pub struct ResponseObservation {
    pub session_capacity_exhausted: bool,
    /// Response head after every preflight mutation.
    pub headers: Vec<(String, String)>,
    /// Whether any stage selected body inspection.
    pub inspected: bool,
    /// Bytes released for delivery after each chunk was fed and before the
    /// next one, which for a streaming stage is that chunk's output.
    pub released: Vec<Vec<u8>>,
    /// Bytes released when the body ended.
    pub finished: Vec<u8>,
    pub trailers: Vec<(String, String)>,
    /// A stage streamed or replaced the body, so the relay strips stale
    /// representation validators from the head it commits.
    pub strip_stale_integrity_headers: bool,
    pub failure: Option<ResponseFailure>,
    /// The config name, outcome, and failure of each 0.1.x invocation
    /// record, in the order stages reported them.
    pub invocations: Vec<(String, HttpResponseInvocationOutcome, bool)>,
    /// The same records in full.
    pub records: Vec<HttpResponseInvocation>,
}

impl ResponseObservation {
    /// Whether preflight let the response continue toward the client.
    pub fn preflight_allowed(&self) -> bool {
        !matches!(
            self.failure,
            Some(ResponseFailure {
                step: ResponseStep::Preflight,
                ..
            })
        )
    }

    /// Every byte released for delivery, in order.
    pub fn body(&self) -> Vec<u8> {
        let mut body = self.released.concat();
        body.extend_from_slice(&self.finished);
        body
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A response session kept open after preflight, as a long-lived stream holds it.
pub struct HeldResponse {
    session: Option<HttpResponsePipelineSession>,
    records: Arc<ResponseRecords>,
}

impl HeldResponse {
    pub async fn end(self) {
        if let Some(session) = self.session {
            session.end(MiddlewareSessionEndReason::Normal).await;
        }
    }
}

/// The 0.1.x invocation records of one response, as the relay emits them:
/// the records legacy adapters report as each step completes, and failures
/// the pipeline recorded for a legacy or unbound entry without its adapter.
#[derive(Default)]
struct ResponseRecords {
    records: Mutex<Vec<HttpResponseInvocation>>,
    /// Stages whose adapter recorded a failure.
    failed: Mutex<HashSet<String>>,
}

impl StageReportSink for ResponseRecords {
    fn report(&self, config_name: &str, report: StageReport) {
        let StageReport::LegacyResponseInvocation { invocation, .. } = report else {
            return;
        };
        if invocation.failed {
            self.failed
                .lock()
                .expect("records")
                .insert(config_name.to_string());
        }
        self.records.lock().expect("records").push(invocation);
    }
}

impl ResponseRecords {
    /// Record the failures the pipeline recorded for a stage without its
    /// adapter, as the relay emits them.
    fn record_pipeline_failures(&self, diagnostics: &HttpStageDiagnostics) {
        let failed = self.failed.lock().expect("records").clone();
        let mut records = self.records.lock().expect("records");
        for invocation in &diagnostics.invocations {
            if invocation.protocol == Some(HttpProtocol::V2)
                || failed.contains(&invocation.config_name)
            {
                continue;
            }
            let outcome = match invocation.outcome {
                HttpStageOutcome::FailOpen => HttpResponseInvocationOutcome::FailOpen,
                HttpStageOutcome::FailClosed => HttpResponseInvocationOutcome::FailClosed,
                _ => continue,
            };
            records.push(HttpResponseInvocation {
                config_name: invocation.config_name.clone(),
                implementation: invocation.implementation.clone(),
                outcome,
                sequence: None,
                input_size: invocation.input_bytes,
                output_size: None,
                failed: true,
                stage_disabled: true,
                reason_code: None,
                failure_category: invocation
                    .failure_reason
                    .as_deref()
                    .map(|reason| crate::legacy::response::failure_category(reason).into()),
            });
        }
    }

    /// Records so far, in full and summarized.
    fn take(
        &self,
    ) -> (
        Vec<HttpResponseInvocation>,
        Vec<(String, HttpResponseInvocationOutcome, bool)>,
    ) {
        let records = std::mem::take(&mut *self.records.lock().expect("records"));
        let summary = records
            .iter()
            .map(|record| (record.config_name.clone(), record.outcome, record.failed))
            .collect();
        (records, summary)
    }
}

/// Run response preflight only and keep any opened session alive.
pub async fn preflight_response(
    runner: &ChainRunner,
    entries: &[ChainEntry],
    case: &ResponseCase,
) -> (ResponseObservation, HeldResponse) {
    let described = runner
        .describe_http_response_chain(entries)
        .await
        .expect("describe response chain");
    let records = Arc::new(ResponseRecords::default());
    let preflight = runner
        .preflight_http_response_pipeline(
            described,
            case.preflight_input(),
            HttpResponseDelivery {
                reports: Some(records.clone()),
                ..HttpResponseDelivery::new(true)
            },
        )
        .await
        .expect("response preflight");
    records.record_pipeline_failures(&preflight.diagnostics);
    let (records_so_far, invocations) = records.take();
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
        invocations,
        records: records_so_far,
    };
    (
        observation,
        HeldResponse {
            session: preflight.session,
            records,
        },
    )
}

/// Run one response through preflight, every chunk, and the end of the body,
/// as the relay feeds upstream reads to the pipeline and writes its output.
pub async fn run_response(
    runner: &ChainRunner,
    entries: &[ChainEntry],
    case: ResponseCase,
) -> ResponseObservation {
    let (mut observation, HeldResponse { session, records }) =
        preflight_response(runner, entries, &case).await;
    let Some(session) = session else {
        if observation.preflight_allowed() {
            observation.released.clone_from(&case.chunks);
        }
        return observation;
    };
    let wait = if session.withholds_output() {
        WITHHELD_RELEASE_WAIT
    } else {
        RELEASE_WAIT
    };
    let limit = session.input_unit_limit();
    let (input, inputs) = mpsc::channel(STAGE_QUEUE_MESSAGES);
    let (output, outputs) = mpsc::channel(STAGE_QUEUE_MESSAGES);
    let mut relay = ResponseRelay {
        run: tokio::spawn(session.run_until(inputs, output, std::future::pending())),
        outputs,
        output: ResponseOutput::default(),
        result: None,
    };
    let mut step = ResponseStep::Finish;
    for (index, chunk) in case.chunks.iter().enumerate() {
        for unit in chunk.chunks(limit) {
            relay
                .feed(&input, HttpBodyInput::Chunk(unit.to_vec()))
                .await;
        }
        relay.settle(wait).await;
        observation
            .released
            .push(std::mem::take(&mut relay.output.body));
        if relay.result.is_some() {
            step = ResponseStep::Chunk(index);
            break;
        }
    }
    if relay.result.is_none() {
        relay
            .feed(
                &input,
                HttpBodyInput::End {
                    trailers: http_headers(&case.trailers),
                },
            )
            .await;
    }
    drop(input);
    let (result, output) = relay.finish().await;
    observation.finished = output.body;
    if let Some((late, body_transformed)) = output.start {
        let mut committed = headers::apply_accumulated(
            headers::HeaderAuthority::Response,
            &http_headers(&observation.headers),
            &[],
            &late,
        )
        .expect("the relay commits valid late mutations");
        if body_transformed {
            committed.retain(|header| !is_stale_http_response_integrity_header(&header.name));
        }
        observation.headers = header_pairs(&committed);
        observation.strip_stale_integrity_headers = body_transformed;
    }
    match result {
        Ok(finish) => {
            records.record_pipeline_failures(&finish.diagnostics);
            observation.trailers = header_pairs(&output.trailers.unwrap_or(finish.trailers));
        }
        Err(failure) => {
            records.record_pipeline_failures(&failure.diagnostics);
            observation.failure = Some(ResponseFailure {
                step,
                reason: failure.reason,
                denial: failure.denial,
            });
        }
    }
    let (full, summary) = records.take();
    observation.records.extend(full);
    observation.invocations.extend(summary);
    observation
}

/// What the relay received from the pipeline so far.
#[derive(Default)]
struct ResponseOutput {
    /// Late mutations and whether the body changed, from the output `Start`.
    start: Option<(Vec<HeaderMutation>, bool)>,
    body: Vec<u8>,
    trailers: Option<Vec<HttpHeader>>,
}

/// The relay's side of one running response pipeline.
struct ResponseRelay {
    run: tokio::task::JoinHandle<std::result::Result<HttpPipelineFinish, HttpMiddlewareFailure>>,
    outputs: mpsc::Receiver<HttpBodyOutput>,
    output: ResponseOutput,
    result: Option<std::result::Result<HttpPipelineFinish, HttpMiddlewareFailure>>,
}

impl ResponseRelay {
    fn record(&mut self, event: HttpBodyOutput) -> bool {
        match event {
            HttpBodyOutput::Start {
                header_mutations,
                body_transformed,
                ..
            } => {
                self.output.start = Some((header_mutations, body_transformed));
                false
            }
            HttpBodyOutput::Chunk(data) => {
                self.output.body.extend_from_slice(&data);
                true
            }
            HttpBodyOutput::End { trailers } => {
                self.output.trailers = Some(trailers);
                false
            }
        }
    }

    /// Feed one input event while reading output, unless the run ends first.
    async fn feed(&mut self, input: &mpsc::Sender<HttpBodyInput>, event: HttpBodyInput) {
        let sending = input.send(event);
        tokio::pin!(sending);
        while self.result.is_none() {
            tokio::select! {
                _ = &mut sending => return,
                Some(event) = self.outputs.recv() => {
                    self.record(event);
                }
                result = &mut self.run => self.result = Some(result.expect("join pipeline")),
            }
        }
    }

    /// Read output until some arrives and then stops for a moment, the run
    /// ends, or `wait` passes without output.
    async fn settle(&mut self, wait: Duration) {
        let mut deadline = tokio::time::Instant::now() + wait;
        while self.result.is_none() {
            tokio::select! {
                event = self.outputs.recv() => match event {
                    Some(event) => {
                        if self.record(event) {
                            deadline = tokio::time::Instant::now() + RELEASE_QUIET;
                        }
                    }
                    None => {
                        self.result = Some((&mut self.run).await.expect("join pipeline"));
                    }
                },
                result = &mut self.run => self.result = Some(result.expect("join pipeline")),
                () = tokio::time::sleep_until(deadline) => return,
            }
        }
    }

    /// Read the rest of the output and the run's result.
    async fn finish(
        mut self,
    ) -> (
        std::result::Result<HttpPipelineFinish, HttpMiddlewareFailure>,
        ResponseOutput,
    ) {
        while let Some(event) = self.outputs.recv().await {
            self.record(event);
        }
        let result = match self.result.take() {
            Some(result) => result,
            None => self.run.await.expect("join pipeline"),
        };
        (result, self.output)
    }
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
