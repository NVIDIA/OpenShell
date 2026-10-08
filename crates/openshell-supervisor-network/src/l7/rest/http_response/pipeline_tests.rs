// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 response middleware through the duplex response relay.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_core::extension_protocol::{ExtensionFamily, extension_metadata};
use openshell_core::middleware::{HttpRequestView, HttpResultStream, InProcessMiddleware};
use openshell_core::proto::{
    ExistingHeaderAction, Finding, HeaderMutation, HttpBodyMode, HttpBodyModeUnavailable,
    HttpBodyUnavailableReason, HttpBufferedMode, HttpBufferedResult, HttpContinue, HttpEvent,
    HttpFinish, HttpInspect, HttpOutputChunk, HttpOutputStart, HttpPreflight, HttpPreflightResult,
    HttpReject, HttpRequestResult, HttpResult, HttpStreamMode, HttpUnchanged, MiddlewareBinding,
    MiddlewareDiagnostics, MiddlewareManifest, MiddlewareSessionEndReason,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, WriteHeader, header_mutation,
    http_buffered_result, http_event, http_inspect, http_preflight_result, http_result,
};
use openshell_supervisor_middleware::{
    HttpStageDiagnostics, HttpStageOutcome, StageReport, StageReportSink as _,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::*;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// What a test version 2 response stage does with the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behavior {
    /// Select STREAM when offered, BUFFERED otherwise, and pass the body on.
    Inspect,
    /// STREAM: uppercase every chunk.
    Uppercase,
    /// STREAM: reject the chunk that contains `needle`.
    RejectOn(&'static str),
    /// STREAM: rewrite the `x-checksum` trailer.
    RewriteTrailer,
    /// BUFFERED: redact `sk-live` tokens and write `x-redacted: 1` late.
    Redact,
    /// STREAM: fail on the first chunk before starting output.
    FailBeforeOutput,
    /// BUFFERED: reject the body.
    RejectBody,
    /// Reject at preflight.
    RejectAtPreflight,
}

#[derive(Default)]
struct StageLog {
    preflights: Vec<HttpPreflight>,
    session_ends: Vec<MiddlewareSessionEndReason>,
}

/// In-process version 2 response middleware for relay tests.
#[derive(Clone)]
struct ResponseStage {
    behavior: Behavior,
    modes: Vec<HttpBodyMode>,
    log: Arc<Mutex<StageLog>>,
}

impl ResponseStage {
    fn new(behavior: Behavior) -> Self {
        let modes = match behavior {
            Behavior::Inspect | Behavior::RejectAtPreflight => {
                vec![HttpBodyMode::Buffered, HttpBodyMode::Stream]
            }
            Behavior::Uppercase
            | Behavior::RejectOn(_)
            | Behavior::RewriteTrailer
            | Behavior::FailBeforeOutput => vec![HttpBodyMode::Stream],
            Behavior::Redact | Behavior::RejectBody => vec![HttpBodyMode::Buffered],
        };
        Self {
            behavior,
            modes,
            log: Arc::default(),
        }
    }

    fn offered(&self) -> HttpPreflight {
        self.log.lock().expect("stage log").preflights[0].clone()
    }

    async fn session_end(&self) -> MiddlewareSessionEndReason {
        within(async {
            loop {
                let reason = self
                    .log
                    .lock()
                    .expect("stage log")
                    .session_ends
                    .first()
                    .copied();
                if let Some(reason) = reason {
                    return reason;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
    }

    fn decide(&self, preflight: &HttpPreflight) -> http_result::Result {
        let permitted =
            |mode: HttpBodyMode| preflight.permitted_body_modes.contains(&(mode as i32));
        let buffered = || {
            http_preflight_result::Decision::Inspect(HttpInspect {
                mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                    max_body_bytes: preflight
                        .limits
                        .map_or(1, |limits| limits.max_buffered_body_bytes),
                })),
            })
        };
        let stream = http_preflight_result::Decision::Inspect(HttpInspect {
            mode: Some(http_inspect::Mode::Stream(HttpStreamMode {})),
        });
        let decision = match self.behavior {
            Behavior::RejectAtPreflight => return reject("blocked_status"),
            _ if permitted(HttpBodyMode::Stream) => stream,
            _ if permitted(HttpBodyMode::Buffered) => buffered(),
            _ => http_preflight_result::Decision::ContinueWithoutBody(HttpContinue {}),
        };
        http_result::Result::PreflightResult(HttpPreflightResult {
            decision: Some(decision),
            header_mutations: Vec::new(),
            diagnostics: None,
        })
    }

    fn chunk(&self, data: Vec<u8>) -> http_result::Result {
        match self.behavior {
            Behavior::Uppercase => output_chunk(data.to_ascii_uppercase()),
            Behavior::RejectOn(needle) if contains(&data, needle.as_bytes()) => {
                reject("blocked_content")
            }
            _ => output_chunk(data),
        }
    }

    fn buffered(&self, data: Vec<u8>) -> http_result::Result {
        let (body, header_mutations) = match self.behavior {
            Behavior::RejectBody => return reject("blocked_content"),
            Behavior::Redact => (
                http_buffered_result::Body::Replacement(
                    String::from_utf8(data)
                        .expect("UTF-8 body")
                        .replace("sk-live-123", "[redacted]")
                        .into_bytes(),
                ),
                vec![write("x-redacted", "1")],
            ),
            _ => (
                http_buffered_result::Body::Unchanged(HttpUnchanged {}),
                Vec::new(),
            ),
        };
        http_result::Result::BufferedResult(HttpBufferedResult {
            body: Some(body),
            header_mutations,
            ..Default::default()
        })
    }
}

fn output_chunk(data: Vec<u8>) -> http_result::Result {
    http_result::Result::OutputChunk(HttpOutputChunk { data })
}

fn reject(reason_code: &str) -> http_result::Result {
    http_result::Result::Reject(HttpReject {
        diagnostics: Some(MiddlewareDiagnostics {
            reason_code: reason_code.into(),
            ..Default::default()
        }),
    })
}

fn write(name: &str, value: &str) -> HeaderMutation {
    HeaderMutation {
        operation: Some(header_mutation::Operation::Write(WriteHeader {
            name: name.into(),
            value: value.into(),
            on_existing: ExistingHeaderAction::Overwrite as i32,
        })),
    }
}

#[tonic::async_trait]
impl InProcessMiddleware for ResponseStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/response-stage".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: 64 * 1024,
                http_protocol_version: 2,
                supported_http_body_modes: self.modes.iter().map(|mode| *mode as i32).collect(),
                ..Default::default()
            }],
            expected_audience: String::new(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "test/response-stage",
                "test",
                [],
            )),
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        Err(miette!("version 2 response test middleware"))
    }

    async fn open_http_response_stage(
        &self,
        mut events: mpsc::Receiver<HttpEvent>,
    ) -> std::result::Result<HttpResultStream, tonic::Status> {
        let stage = self.clone();
        let (results, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut streams = false;
            while let Some(event) = events.recv().await {
                let reply = match event.event {
                    Some(http_event::Event::Preflight(preflight)) => {
                        let reply = stage.decide(&preflight);
                        streams = matches!(
                            &reply,
                            http_result::Result::PreflightResult(HttpPreflightResult {
                                decision: Some(http_preflight_result::Decision::Inspect(
                                    HttpInspect {
                                        mode: Some(http_inspect::Mode::Stream(_)),
                                    }
                                )),
                                ..
                            })
                        );
                        stage
                            .log
                            .lock()
                            .expect("stage log")
                            .preflights
                            .push(preflight);
                        Some(reply)
                    }
                    Some(http_event::Event::Begin(_)) => (streams
                        && stage.behavior != Behavior::FailBeforeOutput)
                        .then(|| http_result::Result::OutputStart(HttpOutputStart::default())),
                    Some(http_event::Event::InputChunk(_))
                        if stage.behavior == Behavior::FailBeforeOutput =>
                    {
                        let _ = results
                            .send(Err(tonic::Status::internal("guard crashed")))
                            .await;
                        None
                    }
                    Some(http_event::Event::InputChunk(chunk)) => Some(stage.chunk(chunk.data)),
                    Some(http_event::Event::InputEnd(_)) => {
                        Some(http_result::Result::Finish(HttpFinish {
                            trailer_mutations: if stage.behavior == Behavior::RewriteTrailer {
                                vec![write("x-checksum", "rewritten")]
                            } else {
                                Vec::new()
                            },
                            diagnostics: None,
                        }))
                    }
                    Some(http_event::Event::BufferedBody(body)) => Some(stage.buffered(body.data)),
                    Some(http_event::Event::SessionEnd(end)) => {
                        if let Ok(reason) = MiddlewareSessionEndReason::try_from(end.reason) {
                            stage
                                .log
                                .lock()
                                .expect("stage log")
                                .session_ends
                                .push(reason);
                        }
                        break;
                    }
                    None => None,
                };
                if let Some(reply) = reply
                    && results
                        .send(Ok(HttpResult {
                            result: Some(reply),
                        }))
                        .await
                        .is_err()
                {
                    return;
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .expect("operation finished in time")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// One response relay with a version 2 stage. The test writes the upstream
/// response to `upstream` and reads what the client receives from `client`.
struct Relay {
    upstream: DuplexStream,
    client: DuplexStream,
    task: tokio::task::JoinHandle<Result<RelayOutcome>>,
}

fn start(stage: &ResponseStage, method: &'static str, client_accepts_chunked: bool) -> Relay {
    start_guarded(stage, method, client_accepts_chunked, None)
}

fn start_guarded(
    stage: &ResponseStage,
    method: &'static str,
    client_accepts_chunked: bool,
    generation_guard: Option<PolicyGenerationGuard>,
) -> Relay {
    let (mut relay_upstream, upstream) = tokio::io::duplex(1024 * 1024);
    let (mut relay_client, client) = tokio::io::duplex(1024 * 1024);
    let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(stage.clone()));
    let task = tokio::spawn(async move {
        let chain = [openshell_supervisor_middleware::ChainEntry {
            name: "guard".into(),
            implementation: "test/response-stage".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "request-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "api.example.test".into(),
                port: 443,
                method: method.into(),
                path: "/v1/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: generation_guard.as_ref(),
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
            client_accepts_chunked,
        };
        relay_response(
            method,
            &mut relay_upstream,
            &mut relay_client,
            RelayResponseOptions::default(),
            Some(middleware),
        )
        .await
    });
    Relay {
        upstream,
        client,
        task,
    }
}

/// Relay one complete upstream response and return the outcome and what the
/// client received.
async fn exchange(
    stage: &ResponseStage,
    method: &'static str,
    client_accepts_chunked: bool,
    response: &[u8],
) -> (Result<RelayOutcome>, Vec<u8>) {
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start(stage, method, client_accepts_chunked);
    upstream.write_all(response).await.expect("upstream write");
    upstream.shutdown().await.expect("upstream close");
    let mut delivered = Vec::new();
    within(client.read_to_end(&mut delivered))
        .await
        .expect("client read");
    let outcome = within(task).await.expect("join relay");
    (outcome, delivered)
}

/// Read until `marker` arrives.
async fn read_until(client: &mut DuplexStream, delivered: &mut Vec<u8>, marker: &[u8]) {
    within(async {
        let mut buffer = [0u8; 4096];
        while !contains(delivered, marker) {
            let read = client.read(&mut buffer).await.expect("client read");
            assert!(
                read > 0,
                "client closed before {:?}: {:?}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(delivered)
            );
            delivered.extend_from_slice(&buffer[..read]);
        }
    })
    .await;
}

fn head_and_body(message: &[u8]) -> (String, &[u8]) {
    let end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("complete head")
        + 4;
    (
        String::from_utf8_lossy(&message[..end]).to_ascii_lowercase(),
        &message[end..],
    )
}

fn dechunk(mut body: &[u8]) -> (Vec<u8>, String) {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line");
        let size = usize::from_str_radix(String::from_utf8_lossy(&body[..line_end]).trim(), 16)
            .expect("hex chunk size");
        body = &body[line_end + 2..];
        if size == 0 {
            return (decoded, String::from_utf8_lossy(body).into_owned());
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

const CHUNKED_JSON: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"v1\"\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n";

#[tokio::test]
async fn stream_stage_reframes_the_response_and_strips_stale_validators() {
    let stage = ResponseStage::new(Behavior::Uppercase);
    let (outcome, delivered) = exchange(&stage, "GET", true, CHUNKED_JSON).await;
    assert!(matches!(outcome, Ok(RelayOutcome::Reusable)), "{outcome:?}");
    let (head, body) = head_and_body(&delivered);
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert!(head.contains("transfer-encoding: chunked\r\n"), "{head}");
    assert!(
        !head.contains("etag"),
        "STREAM output makes validators stale: {head}"
    );
    assert_eq!(dechunk(body), (b"HELLO WORLD".to_vec(), "\r\n".into()));
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::Normal
    );
}

#[tokio::test]
async fn stream_output_of_a_fixed_length_response_is_chunked() {
    let stage = ResponseStage::new(Behavior::Uppercase);
    let (outcome, delivered) = exchange(
        &stage,
        "GET",
        true,
        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
    )
    .await;
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
    let (head, body) = head_and_body(&delivered);
    assert!(head.contains("transfer-encoding: chunked\r\n"), "{head}");
    assert!(head.contains("connection: close\r\n"), "{head}");
    assert!(!head.contains("content-length"), "{head}");
    assert_eq!(dechunk(body).0, b"HELLO WORLD");
}

#[tokio::test]
async fn buffered_redaction_commits_with_the_new_length_and_late_headers() {
    let stage = ResponseStage::new(Behavior::Redact);
    let body = br#"{"id":7,"token":"sk-live-123"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"v1\"\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    let (outcome, delivered) = exchange(&stage, "GET", true, response.as_bytes()).await;
    assert!(matches!(outcome, Ok(RelayOutcome::Reusable)), "{outcome:?}");
    let (head, body) = head_and_body(&delivered);
    let redacted = br#"{"id":7,"token":"[redacted]"}"#;
    assert!(
        head.contains(&format!("content-length: {}\r\n", redacted.len())),
        "{head}"
    );
    assert!(head.contains("x-redacted: 1\r\n"), "{head}");
    assert!(!head.contains("etag"), "{head}");
    assert_eq!(body, redacted);
}

#[tokio::test]
async fn http_1_0_delivery_is_offered_buffered_only_and_framed_by_length() {
    for (client_http11, response) in [
        // HTTP/1.0 client, HTTP/1.1 chunked upstream.
        (false, CHUNKED_JSON.to_vec()),
        // HTTP/1.1 client, HTTP/1.0 close-delimited upstream.
        (
            true,
            b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\nhello world".to_vec(),
        ),
    ] {
        let stage = ResponseStage::new(Behavior::Inspect);
        let (outcome, delivered) = exchange(&stage, "GET", client_http11, &response).await;
        assert!(outcome.is_ok(), "{outcome:?}");
        let offered = stage.offered();
        assert_eq!(
            offered.permitted_body_modes,
            [HttpBodyMode::Buffered as i32]
        );
        assert_eq!(
            offered.unavailable_body_modes,
            [HttpBodyModeUnavailable {
                mode: HttpBodyMode::Stream as i32,
                reason: HttpBodyUnavailableReason::TruncationUndetectable as i32,
            }]
        );
        let (head, body) = head_and_body(&delivered);
        assert!(head.contains("content-length: 11\r\n"), "{head}");
        assert!(!head.contains("transfer-encoding"), "{head}");
        assert_eq!(body, b"hello world");
    }
}

#[tokio::test]
async fn server_sent_events_over_http_1_0_get_preflight_only() {
    let stage = ResponseStage::new(Behavior::Inspect);
    let (outcome, delivered) = exchange(
        &stage,
        "GET",
        false,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: one\n\n",
    )
    .await;
    assert!(outcome.is_ok(), "{outcome:?}");
    let offered = stage.offered();
    assert!(offered.permitted_body_modes.is_empty());
    assert_eq!(offered.unavailable_body_modes.len(), 2);
    let (_head, body) = head_and_body(&delivered);
    assert_eq!(body, b"data: one\n\n");
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::StageSkipped
    );
}

#[tokio::test]
async fn reject_at_preflight_returns_the_canonical_denial() {
    let stage = ResponseStage::new(Behavior::RejectAtPreflight);
    let (outcome, delivered) = exchange(&stage, "GET", true, CHUNKED_JSON).await;
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
    let (head, body) = head_and_body(&delivered);
    assert!(head.starts_with("http/1.1 403 forbidden\r\n"), "{head}");
    let body: serde_json::Value = serde_json::from_slice(body).expect("JSON denial");
    assert_eq!(body["error"], "middleware_denied");
    assert_eq!(body["reason_code"], "blocked_status");
    assert!(!contains(&delivered, b"hello"));
}

#[tokio::test]
async fn buffered_reject_before_commit_returns_the_canonical_denial() {
    let stage = ResponseStage::new(Behavior::RejectBody);
    let (outcome, delivered) = exchange(&stage, "GET", true, CHUNKED_JSON).await;
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
    assert!(delivered.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::MiddlewareDenial
    );
}

#[tokio::test]
async fn reject_after_commit_aborts_without_a_terminator() {
    let stage = ResponseStage::new(Behavior::RejectOn("two"));
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start(&stage, "GET", true);
    upstream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\n",
        )
        .await
        .expect("first event");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"data: one\n\n").await;
    upstream
        .write_all(b"b\r\ndata: two\n\n\r\n")
        .await
        .expect("second event");

    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("a reject after commit aborts the response");
    assert!(
        error.to_string().contains("failed after commitment"),
        "{error}"
    );
    let mut rest = Vec::new();
    within(client.read_to_end(&mut rest))
        .await
        .expect("client read");
    delivered.extend(rest);
    let (_head, body) = head_and_body(&delivered);
    assert!(!contains(body, b"data: two"), "{body:?}");
    assert!(
        !contains(body, b"0\r\n\r\n"),
        "no terminating chunk: {body:?}"
    );
    assert!(!contains(body, b"middleware_denied"));
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::MiddlewareDenial
    );
}

#[tokio::test]
async fn late_trailer_mutations_reach_the_client() {
    let stage = ResponseStage::new(Behavior::RewriteTrailer);
    let (outcome, delivered) = exchange(
        &stage,
        "GET",
        true,
        b"HTTP/1.1 200 OK\r\nTrailer: x-checksum, digest\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\nx-checksum: original\r\ndigest: sha-256=stale\r\n\r\n",
    )
    .await;
    assert!(outcome.is_ok(), "{outcome:?}");
    let (head, body) = head_and_body(&delivered);
    // The STREAM stage made the digest trailer stale.
    assert!(head.contains("trailer: x-checksum\r\n"), "{head}");
    assert_eq!(
        dechunk(body),
        (b"data".to_vec(), "x-checksum: rewritten\r\n\r\n".into())
    );
}

#[tokio::test]
async fn upstream_failure_before_commit_returns_502() {
    let stage = ResponseStage::new(Behavior::Redact);
    let (outcome, delivered) = exchange(
        &stage,
        "GET",
        true,
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\ntruncated",
    )
    .await;
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
    assert!(delivered.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    assert!(contains(&delivered, b"response_delivery_failed"));
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::UpstreamDisconnect
    );
}

#[tokio::test]
async fn upstream_failure_after_commit_aborts() {
    let stage = ResponseStage::new(Behavior::Uppercase);
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start(&stage, "GET", true);
    upstream
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        .await
        .expect("first chunk");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"HELLO").await;
    // The upstream closes in the middle of the next chunk.
    upstream
        .write_all(b"20\r\ncut")
        .await
        .expect("partial chunk");
    upstream.shutdown().await.expect("upstream close");

    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("a truncated upstream aborts a committed response");
    assert!(error.to_string().contains("ended unexpectedly"), "{error}");
    let mut rest = Vec::new();
    within(client.read_to_end(&mut rest))
        .await
        .expect("client read");
    delivered.extend(rest);
    let (head, body) = head_and_body(&delivered);
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert!(!contains(body, b"0\r\n\r\n"), "{body:?}");
    assert!(!contains(body, b"response_delivery_failed"));
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::UpstreamDisconnect
    );
}

#[tokio::test]
async fn client_disconnect_ends_the_stages_with_downstream_disconnect() {
    let stage = ResponseStage::new(Behavior::Uppercase);
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start(&stage, "GET", true);
    upstream
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        .await
        .expect("first chunk");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"HELLO").await;
    drop(client);
    upstream
        .write_all(b"5\r\nworld\r\n")
        .await
        .expect("second chunk");
    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("the client went away");
    assert!(error.to_string().contains("client write failed"), "{error}");
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::DownstreamDisconnect
    );
}

#[tokio::test(start_paused = true)]
async fn server_sent_events_survive_a_five_minute_quiet_gap() {
    let stage = ResponseStage::new(Behavior::Uppercase);
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start(&stage, "GET", true);
    upstream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\n",
        )
        .await
        .expect("first event");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"DATA: ONE\n\n").await;
    // Neither the stall timeout nor anything else times upstream silence.
    tokio::time::sleep(Duration::from_mins(5)).await;
    assert!(!task.is_finished());
    upstream
        .write_all(b"b\r\ndata: two\n\n\r\n0\r\n\r\n")
        .await
        .expect("second event");
    read_until(&mut client, &mut delivered, b"\r\n0\r\n\r\n").await;
    let (_head, body) = head_and_body(&delivered);
    assert_eq!(dechunk(body).0, b"DATA: ONE\n\nDATA: TWO\n\n");
    drop(client);
    within(task)
        .await
        .expect("join relay")
        .expect("relay completes");
}

#[tokio::test]
async fn a_policy_reload_mid_stream_ends_the_stages_and_the_connection() {
    const TEST_POLICY: &str = include_str!("../../../../data/sandbox-policy.rego");
    let engine =
        crate::opa::OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("policy");
    let guard = engine
        .generation_guard(engine.current_generation())
        .expect("generation guard");
    let stage = ResponseStage::new(Behavior::Uppercase);
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start_guarded(&stage, "GET", true, Some(guard));
    upstream
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        .await
        .expect("first chunk");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"HELLO").await;
    engine
        .reload(TEST_POLICY, "network_policies: {}\n")
        .expect("policy reload");
    upstream
        .write_all(b"5\r\nworld\r\n")
        .await
        .expect("second chunk");

    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("stale output must not be delivered");
    assert!(
        error.to_string().contains("policy generation is stale"),
        "{error}"
    );
    let mut rest = Vec::new();
    within(client.read_to_end(&mut rest))
        .await
        .expect("client read");
    assert!(!contains(&rest, b"WORLD"));
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::PolicyReload
    );
}

/// A policy reload while the upstream is silent ends the stages with
/// `POLICY_RELOAD` at once and aborts the response, without waiting for the
/// upstream's next byte.
#[tokio::test]
async fn a_policy_reload_during_upstream_silence_ends_the_stages_at_once() {
    const TEST_POLICY: &str = include_str!("../../../../data/sandbox-policy.rego");
    let engine =
        crate::opa::OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("policy");
    let guard = engine
        .generation_guard(engine.current_generation())
        .expect("generation guard");
    let stage = ResponseStage::new(Behavior::Uppercase);
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start_guarded(&stage, "GET", true, Some(guard));
    upstream
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        .await
        .expect("first chunk");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"HELLO").await;
    engine
        .reload(TEST_POLICY, "network_policies: {}\n")
        .expect("policy reload");

    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::PolicyReload
    );
    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("a stale policy ends the response");
    assert!(
        error.to_string().contains("policy generation is stale"),
        "{error}"
    );
    let mut rest = Vec::new();
    within(client.read_to_end(&mut rest))
        .await
        .expect("client read");
    assert!(!contains(&rest, b"0\r\n\r\n"), "{rest:?}");
}

/// A policy reload before the head commits ends the connection without a
/// response, as a stale policy does before preflight: not even a canonical
/// failure response is produced under it.
#[tokio::test]
async fn a_policy_reload_before_commit_ends_the_connection_without_a_response() {
    const TEST_POLICY: &str = include_str!("../../../../data/sandbox-policy.rego");
    let engine =
        crate::opa::OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("policy");
    let guard = engine
        .generation_guard(engine.current_generation())
        .expect("generation guard");
    let stage = ResponseStage::new(Behavior::Redact);
    let Relay {
        mut upstream,
        mut client,
        task,
    } = start_guarded(&stage, "GET", true, Some(guard));
    upstream
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        .await
        .expect("first chunk");
    within(async {
        while stage.log.lock().expect("stage log").preflights.is_empty() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    engine
        .reload(TEST_POLICY, "network_policies: {}\n")
        .expect("policy reload");
    upstream
        .write_all(b"5\r\nworld\r\n0\r\n\r\n")
        .await
        .expect("rest of the body");

    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("a stale policy ends the connection");
    assert!(
        error.to_string().contains("policy generation is stale"),
        "{error}"
    );
    let mut delivered = Vec::new();
    within(client.read_to_end(&mut delivered))
        .await
        .expect("client read");
    assert!(
        delivered.is_empty(),
        "{}",
        String::from_utf8_lossy(&delivered)
    );
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::PolicyReload
    );
}

const TEST_POLICY: &str = include_str!("../../../../data/sandbox-policy.rego");
const HOST: &str = "api.example.test";
const PORT: u16 = 8080;

/// Policy that inspects every response from [`HOST`] with the test stage.
fn response_policy() -> String {
    format!(
        r#"network_middlewares:
  guard:
    middleware: test/response-stage
    order: 0
    on_error: fail_closed
    endpoints:
      include: ["{HOST}"]
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: {HOST}
        port: {PORT}
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/v1/**"
    binaries:
      - {{ path: /usr/bin/curl }}
"#
    )
}

/// An inspected tunnel to [`HOST`]. The test is the sandbox client on `app`
/// and the destination server on `server`.
struct Tunnel {
    app: DuplexStream,
    server: DuplexStream,
    relay: tokio::task::JoinHandle<Result<()>>,
}

async fn tunnel(stage: &ResponseStage) -> Tunnel {
    let engine =
        crate::opa::OpaEngine::from_strings(TEST_POLICY, &response_policy()).expect("load policy");
    let registry = openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
        vec![Arc::new(stage.clone())],
        Vec::new(),
    )
    .await
    .expect("this build registers version 2 response bindings");
    engine
        .replace_middleware_registry(registry)
        .expect("install middleware registry");
    let (endpoint, generation) = engine
        .query_endpoint_config_with_generation(&crate::opa::NetworkInput {
            host: HOST.into(),
            port: PORT,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        })
        .expect("endpoint config");
    let config =
        crate::l7::parse_l7_config(&endpoint.expect("configured endpoint")).expect("REST config");
    let tunnel_engine = engine
        .clone_engine_for_tunnel(generation)
        .expect("tunnel engine");
    let ctx = crate::l7::relay::L7EvalContext {
        host: HOST.into(),
        port: PORT,
        request_default_port: Some(PORT),
        policy_name: "rest_api".into(),
        binary_path: "/usr/bin/curl".into(),
        ..Default::default()
    };
    let (app, mut relay_client) = tokio::io::duplex(1024 * 1024);
    let (mut relay_upstream, server) = tokio::io::duplex(1024 * 1024);
    let relay = tokio::spawn(async move {
        let _engine = engine;
        crate::l7::relay::relay_with_inspection(
            &config,
            tunnel_engine,
            &mut relay_client,
            &mut relay_upstream,
            &ctx,
        )
        .await
    });
    Tunnel { app, server, relay }
}

/// Read one request head from the upstream side.
async fn read_request(server: &mut DuplexStream) -> Vec<u8> {
    let mut request = Vec::new();
    read_until(server, &mut request, b"\r\n\r\n").await;
    request
}

#[tokio::test(start_paused = true)]
async fn tunnel_streams_server_sent_events_through_an_inspector_across_a_quiet_gap() {
    let stage = ResponseStage::new(Behavior::Inspect);
    let Tunnel {
        mut app,
        mut server,
        relay,
    } = tunnel(&stage).await;
    app.write_all(
        b"GET /v1/events HTTP/1.1\r\nHost: api.example.test\r\nAccept: text/event-stream\r\n\r\n",
    )
    .await
    .expect("request");
    read_request(&mut server).await;
    server
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\n",
        )
        .await
        .expect("first event");
    let mut delivered = Vec::new();
    read_until(&mut app, &mut delivered, b"data: one\n\n").await;
    let offered = stage.offered();
    assert_eq!(
        offered.permitted_body_modes,
        [HttpBodyMode::Stream as i32],
        "server-sent events are never offered BUFFERED"
    );

    tokio::time::sleep(Duration::from_mins(5)).await;
    assert!(!relay.is_finished());
    server
        .write_all(b"b\r\ndata: two\n\n\r\n0\r\n\r\n")
        .await
        .expect("second event");
    read_until(&mut app, &mut delivered, b"\r\n0\r\n\r\n").await;
    let (head, body) = head_and_body(&delivered);
    assert!(head.contains("transfer-encoding: chunked\r\n"), "{head}");
    assert_eq!(dechunk(body).0, b"data: one\n\ndata: two\n\n");
    drop(app);
    within(relay)
        .await
        .expect("join relay")
        .expect("relay result");
}

#[tokio::test]
async fn tunnel_streams_a_large_download_through_a_transforming_stage() {
    let stage = ResponseStage::new(Behavior::Uppercase);
    let Tunnel {
        mut app,
        mut server,
        relay,
    } = tunnel(&stage).await;
    app.write_all(
        b"GET /v1/download HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("request");
    read_request(&mut server).await;
    // Twice the platform payload maximum: STREAM has no total byte cap.
    let total = 2 * openshell_supervisor_middleware::MAX_MIDDLEWARE_PAYLOAD_BYTES + 1;
    let upstream = tokio::spawn(async move {
        server
            .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n").as_bytes())
            .await
            .expect("head");
        for piece in vec![b'a'; total].chunks(48 * 1024) {
            server.write_all(piece).await.expect("body");
        }
        server
    });
    let mut delivered = Vec::new();
    within(async {
        let mut buffer = vec![0u8; 64 * 1024];
        while !delivered.ends_with(b"\r\n0\r\n\r\n") {
            let read = app.read(&mut buffer).await.expect("download");
            assert!(read > 0, "the download ended early");
            delivered.extend_from_slice(&buffer[..read]);
        }
    })
    .await;
    let (head, body) = head_and_body(&delivered);
    assert!(head.contains("transfer-encoding: chunked\r\n"), "{head}");
    let (body, _trailers) = dechunk(body);
    assert_eq!(body.len(), total);
    assert!(body.iter().all(|byte| *byte == b'A'));
    drop(within(upstream).await.expect("upstream"));
    drop(app);
    within(relay)
        .await
        .expect("join relay")
        .expect("relay result");
}

#[tokio::test]
async fn tunnel_http_1_0_client_is_never_offered_stream() {
    let stage = ResponseStage::new(Behavior::Inspect);
    let Tunnel {
        mut app,
        mut server,
        relay,
    } = tunnel(&stage).await;
    app.write_all(b"GET /v1/data HTTP/1.0\r\nHost: api.example.test\r\n\r\n")
        .await
        .expect("request");
    read_request(&mut server).await;
    server
        .write_all(CHUNKED_JSON)
        .await
        .expect("chunked response");
    server.shutdown().await.expect("upstream close");
    let mut delivered = Vec::new();
    read_until(&mut app, &mut delivered, b"hello world").await;
    assert_eq!(
        stage.offered().permitted_body_modes,
        [HttpBodyMode::Buffered as i32]
    );
    let (head, body) = head_and_body(&delivered);
    assert!(head.contains("content-length: 11\r\n"), "{head}");
    assert!(!head.contains("transfer-encoding"), "{head}");
    assert_eq!(body, b"hello world");
    drop(app);
    within(relay)
        .await
        .expect("join relay")
        .expect("relay result");
}

#[tokio::test]
async fn stream_failure_before_output_starts_returns_502() {
    let stage = ResponseStage::new(Behavior::FailBeforeOutput);
    let (outcome, delivered) = exchange(&stage, "GET", true, CHUNKED_JSON).await;
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
    assert!(delivered.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    assert!(contains(&delivered, b"response_delivery_failed"));
    assert!(!contains(&delivered, b"hello"));
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::MiddlewareFailure
    );
}

fn event_target() -> HttpRequestTarget {
    HttpRequestTarget {
        scheme: "https".into(),
        host: "api.example.test".into(),
        port: 443,
        method: "GET".into(),
        path: "/v1/data".into(),
        query: String::new(),
    }
}

fn legacy_reports() -> pipeline::LegacyResponseReports {
    pipeline::LegacyResponseReports {
        policy_name: "policy".into(),
        target: event_target(),
        status_code: 200,
        failed: Mutex::default(),
    }
}

fn legacy_record(
    outcome: openshell_supervisor_middleware::HttpResponseInvocationOutcome,
    failure_category: Option<&str>,
) -> openshell_supervisor_middleware::HttpResponseInvocation {
    openshell_supervisor_middleware::HttpResponseInvocation {
        config_name: "guard".into(),
        implementation: "legacy/guard".into(),
        outcome,
        sequence: Some(2),
        input_size: 5,
        output_size: None,
        failed: failure_category.is_some(),
        stage_disabled: failure_category.is_some(),
        reason_code: None,
        failure_category: failure_category.map(Into::into),
    }
}

fn stage_invocation(
    config_name: &str,
    protocol: Option<openshell_supervisor_middleware::HttpProtocol>,
    outcome: HttpStageOutcome,
    failure_reason: Option<&str>,
) -> openshell_supervisor_middleware::HttpStageInvocation {
    openshell_supervisor_middleware::HttpStageInvocation {
        config_name: config_name.into(),
        implementation: format!("example/{config_name}"),
        protocol,
        outcome,
        input_bytes: 0,
        output_bytes: None,
        transformed: false,
        failed: failure_reason.is_some(),
        reason_code: None,
        failure_reason: failure_reason.map(Into::into),
    }
}

fn event_values(events: &[openshell_ocsf::OcsfEvent]) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|event| serde_json::to_value(event).expect("serialize event"))
        .collect()
}

/// HTTP protocol 1 (0.1): one adapter record becomes the 0.1.x events:
/// the invocation, its `fail_open` or block finding, and the step's findings
/// under the stage's config name.
#[test]
fn legacy_records_become_their_0_1_x_events() {
    use openshell_supervisor_middleware::HttpResponseInvocationOutcome as Outcome;

    let fail_open = event_values(&pipeline::legacy_response_invocation_events(
        "policy",
        &event_target(),
        200,
        "guard",
        &legacy_record(Outcome::FailOpen, Some("timeout")),
        Vec::new(),
    ));
    assert_eq!(fail_open.len(), 2, "{fail_open:#?}");
    assert_eq!(fail_open[0]["unmapped"]["sequence"], 2);
    assert_eq!(
        fail_open[1]["finding_info"]["uid"],
        "openshell.middleware.http_response_fail_open"
    );
    assert_eq!(fail_open[1]["unmapped"]["failure_category"], "timeout");

    let blocked = event_values(&pipeline::legacy_response_invocation_events(
        "policy",
        &event_target(),
        200,
        "guard",
        &legacy_record(Outcome::BlockDelivery, None),
        vec![Finding {
            r#type: "legacy/guard.finding".into(),
            label: "match".into(),
            severity: "high".into(),
            ..Default::default()
        }],
    ));
    assert_eq!(blocked.len(), 3, "{blocked:#?}");
    assert_eq!(
        blocked[1]["finding_info"]["uid"],
        "openshell.middleware.http_response_blocked"
    );
    assert_eq!(blocked[2]["finding_info"]["uid"], "legacy/guard.finding");
    assert!(blocked[2].to_string().contains("guard"), "{}", blocked[2]);
}

/// HTTP protocol 1 (0.1): the stage events of a response leave out the
/// legacy stages whose adapter reported its own records, so nothing is
/// emitted twice. A legacy failure recorded only by the pipeline, such as an
/// exhausted session budget, is still emitted, and every `fail_open` finding
/// keeps the 0.1.x failure category.
#[test]
fn stage_events_leave_legacy_records_to_the_adapter() {
    use openshell_supervisor_middleware::HttpProtocol;
    use openshell_supervisor_middleware::HttpResponseInvocationOutcome as Outcome;

    let reports = legacy_reports();
    reports.report(
        "guard",
        StageReport::LegacyResponseInvocation {
            invocation: legacy_record(Outcome::FailClosed, Some("timeout")),
            findings: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        },
    );
    let diagnostics = HttpStageDiagnostics {
        invocations: vec![
            stage_invocation(
                "guard",
                Some(HttpProtocol::Legacy),
                HttpStageOutcome::Stream,
                None,
            ),
            stage_invocation(
                "guard",
                Some(HttpProtocol::Legacy),
                HttpStageOutcome::FailClosed,
                Some("middleware_timeout"),
            ),
            stage_invocation(
                "saturated",
                Some(HttpProtocol::Legacy),
                HttpStageOutcome::FailOpen,
                Some("middleware_session_capacity_exhausted"),
            ),
            stage_invocation(
                "unbound",
                None,
                HttpStageOutcome::FailOpen,
                Some("binding_not_described"),
            ),
            stage_invocation("v2", Some(HttpProtocol::V2), HttpStageOutcome::Reject, None),
        ],
        ..Default::default()
    };
    let events = event_values(&pipeline::http_response_stage_events(
        "policy",
        &event_target(),
        200,
        &diagnostics,
        &reports,
    ));
    let invocations: Vec<_> = events
        .iter()
        .filter_map(|event| event["unmapped"]["middleware_config"].as_str())
        .collect();
    assert_eq!(
        invocations,
        ["saturated", "saturated", "unbound", "unbound", "v2", "v2"],
        "{events:#?}"
    );
    let categories: Vec<_> = events
        .iter()
        .filter(|event| {
            event["finding_info"]["uid"] == "openshell.middleware.http_response_fail_open"
        })
        .map(|event| event["unmapped"]["failure_category"].clone())
        .collect();
    assert_eq!(categories, ["session_capacity", "invalid_result"]);
}

/// A response refused for platform capacity reports it as a request does.
#[test]
fn exhausted_capacity_is_reported_for_responses() {
    let preflight = |session_capacity_exhausted, admission_exhausted| {
        openshell_supervisor_middleware::HttpResponsePipelinePreflight {
            allowed: false,
            reason: String::new(),
            denial: None,
            headers: Vec::new(),
            session: None,
            diagnostics: HttpStageDiagnostics::default(),
            admission_exhausted,
            session_capacity_exhausted,
        }
    };
    assert!(
        pipeline::http_response_capacity_events(
            "policy",
            &event_target(),
            &preflight(false, false)
        )
        .is_empty()
    );
    for (session, admission, uid) in [
        (
            true,
            false,
            "openshell.middleware.session_capacity_exhausted",
        ),
        (false, true, "openshell.middleware.admission_exhausted"),
    ] {
        let events = event_values(&pipeline::http_response_capacity_events(
            "policy",
            &event_target(),
            &preflight(session, admission),
        ));
        assert_eq!(events.len(), 1, "{events:#?}");
        assert_eq!(events[0]["finding_info"]["uid"], uid);
        let serialized = events[0].to_string();
        assert!(serialized.contains("http_response"), "{serialized}");
        assert!(serialized.contains("policy"), "{serialized}");
    }
}
