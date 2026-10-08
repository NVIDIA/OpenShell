// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 request middleware through the L7 relay.
//!
//! Each test installs in-process version 2 request stages in a policy engine
//! and drives raw HTTP/1.1 bytes through `relay_with_inspection`. Assertions
//! are on what the sandbox client and the upstream server observe.

use std::fmt::Write as _;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_core::extension_protocol::{ExtensionFamily, extension_metadata};
use openshell_core::middleware::{HttpRequestView, HttpResultStream, InProcessMiddleware};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpBodyMode, HttpBufferedMode,
    HttpBufferedResult, HttpContinue, HttpEvent, HttpFinish, HttpInspect, HttpOutputChunk,
    HttpOutputStart, HttpPreflightResult, HttpReject, HttpRequestResult, HttpResult,
    HttpStreamMode, MiddlewareBinding, MiddlewareDiagnostics, MiddlewareManifest,
    MiddlewareSessionEndReason, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    WriteHeader, header_mutation, http_buffered_result, http_event, http_inspect,
    http_preflight_result, http_result,
};
use openshell_supervisor_middleware::{MAX_HTTP_STREAM_UNIT_BYTES, MiddlewareRegistry};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::l7::relay::{L7EvalContext, relay_with_inspection, relay_with_route_selection};
use crate::l7::{L7EndpointConfig, parse_l7_config};
use crate::opa::{NetworkInput, OpaEngine, TunnelPolicyEngine};

const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");
const HOST: &str = "api.example.test";
const PORT: u16 = 8080;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const NO_CONTENT: &[u8] =
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// How a test request stage treats the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Preflight-only: continue with the preflight mutations.
    HeadersOnly,
    /// STREAM: append `!` to every input chunk.
    AppendPerChunk,
    /// STREAM: uppercase every input chunk.
    Uppercase,
    /// STREAM: hold all input, then emit it with a declared length.
    DelayedWholeBody,
    /// STREAM: emit a credential placeholder for every input chunk.
    CredentialMarker,
    /// STREAM: start output, then stop reading input.
    StallAfterBegin,
    /// STREAM: reject on the first input chunk.
    RejectOnInput,
    /// BUFFERED: append `!` to the body.
    WholeBodyAppend,
    /// Reject at preflight with a reason code.
    RejectAtPreflight,
}

impl Mode {
    fn body_modes(self) -> Vec<HttpBodyMode> {
        match self {
            Self::HeadersOnly => Vec::new(),
            Self::WholeBodyAppend => vec![HttpBodyMode::Buffered],
            _ => vec![HttpBodyMode::Stream],
        }
    }
}

/// In-process version 2 request middleware for relay tests.
#[derive(Clone)]
struct RequestStage {
    name: &'static str,
    mode: Mode,
    preflight_mutations: Vec<HeaderMutation>,
    late_mutations: Vec<HeaderMutation>,
    rewrite_trailer: bool,
    session_ends: Arc<Mutex<Vec<MiddlewareSessionEndReason>>>,
}

impl RequestStage {
    fn new(name: &'static str, mode: Mode) -> Self {
        Self {
            name,
            mode,
            preflight_mutations: Vec::new(),
            late_mutations: Vec::new(),
            rewrite_trailer: false,
            session_ends: Arc::default(),
        }
    }

    fn preflight(mut self, mutations: Vec<HeaderMutation>) -> Self {
        self.preflight_mutations = mutations;
        self
    }

    fn late(mut self, mutations: Vec<HeaderMutation>) -> Self {
        self.late_mutations = mutations;
        self
    }

    async fn session_end(&self) -> MiddlewareSessionEndReason {
        within(async {
            loop {
                if let Some(reason) = self.session_ends.lock().expect("session ends").first() {
                    return *reason;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
    }
}

fn result(result: http_result::Result) -> HttpResult {
    HttpResult {
        result: Some(result),
    }
}

#[tonic::async_trait]
impl InProcessMiddleware for RequestStage {
    async fn describe(&self) -> MiddlewareManifest {
        let modes = self.mode.body_modes();
        MiddlewareManifest {
            name: self.name.into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: if modes.is_empty() {
                    0
                } else {
                    MAX_HTTP_STREAM_UNIT_BYTES as u64
                },
                request_timeout: None,
                http_protocol_version: 2,
                supported_http_body_modes: modes.iter().map(|mode| *mode as i32).collect(),
            }],
            expected_audience: String::new(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                self.name,
                "test",
                [],
            )),
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Err(miette::miette!("version 2 test middleware"))
    }

    async fn open_http_request_stage(
        &self,
        mut events: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, tonic::Status> {
        let stage = self.clone();
        let (results, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(event) = events.recv().await {
                let reply = match event.event {
                    Some(http_event::Event::Preflight(preflight)) => {
                        let decision = match stage.mode {
                            Mode::HeadersOnly => {
                                http_preflight_result::Decision::ContinueWithoutBody(
                                    HttpContinue {},
                                )
                            }
                            Mode::RejectAtPreflight => {
                                let _ = results
                                    .send(Ok(result(http_result::Result::Reject(HttpReject {
                                        diagnostics: Some(MiddlewareDiagnostics {
                                            reason_code: "blocked_upload".into(),
                                            ..Default::default()
                                        }),
                                    }))))
                                    .await;
                                continue;
                            }
                            Mode::WholeBodyAppend => {
                                http_preflight_result::Decision::Inspect(HttpInspect {
                                    mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                                        max_body_bytes: preflight
                                            .limits
                                            .map_or(1, |limits| limits.max_buffered_body_bytes),
                                    })),
                                })
                            }
                            _ => http_preflight_result::Decision::Inspect(HttpInspect {
                                mode: Some(http_inspect::Mode::Stream(HttpStreamMode {})),
                            }),
                        };
                        vec![http_result::Result::PreflightResult(HttpPreflightResult {
                            decision: Some(decision),
                            header_mutations: stage.preflight_mutations.clone(),
                            diagnostics: None,
                        })]
                    }
                    Some(http_event::Event::Begin(_)) => match stage.mode {
                        Mode::AppendPerChunk
                        | Mode::Uppercase
                        | Mode::CredentialMarker
                        | Mode::StallAfterBegin => {
                            vec![http_result::Result::OutputStart(HttpOutputStart {
                                header_mutations: stage.late_mutations.clone(),
                                output_body_bytes: None,
                            })]
                        }
                        _ => Vec::new(),
                    },
                    Some(http_event::Event::InputChunk(chunk)) => match stage.mode {
                        Mode::AppendPerChunk => {
                            let mut data = chunk.data;
                            if data.len() == MAX_HTTP_STREAM_UNIT_BYTES {
                                vec![
                                    http_result::Result::OutputChunk(HttpOutputChunk { data }),
                                    http_result::Result::OutputChunk(HttpOutputChunk {
                                        data: b"!".to_vec(),
                                    }),
                                ]
                            } else {
                                data.push(b'!');
                                vec![http_result::Result::OutputChunk(HttpOutputChunk { data })]
                            }
                        }
                        Mode::Uppercase => {
                            vec![http_result::Result::OutputChunk(HttpOutputChunk {
                                data: chunk.data.to_ascii_uppercase(),
                            })]
                        }
                        Mode::CredentialMarker => {
                            vec![http_result::Result::OutputChunk(HttpOutputChunk {
                                data: b"openshell:resolve:env:v1_API_TOKEN".to_vec(),
                            })]
                        }
                        Mode::DelayedWholeBody => {
                            held.extend_from_slice(&chunk.data);
                            Vec::new()
                        }
                        Mode::StallAfterBegin => {
                            std::future::pending::<()>().await;
                            Vec::new()
                        }
                        Mode::RejectOnInput => {
                            vec![http_result::Result::Reject(HttpReject {
                                diagnostics: Some(MiddlewareDiagnostics {
                                    reason_code: "content_match".into(),
                                    ..Default::default()
                                }),
                            })]
                        }
                        _ => Vec::new(),
                    },
                    Some(http_event::Event::InputEnd(_)) => {
                        let mut replies = Vec::new();
                        if stage.mode == Mode::DelayedWholeBody {
                            replies.push(http_result::Result::OutputStart(HttpOutputStart {
                                header_mutations: stage.late_mutations.clone(),
                                output_body_bytes: Some(held.len() as u64),
                            }));
                            if !held.is_empty() {
                                replies.push(http_result::Result::OutputChunk(HttpOutputChunk {
                                    data: std::mem::take(&mut held),
                                }));
                            }
                        }
                        replies.push(http_result::Result::Finish(HttpFinish {
                            trailer_mutations: trailer_rewrite(stage.rewrite_trailer),
                            diagnostics: None,
                        }));
                        replies
                    }
                    Some(http_event::Event::BufferedBody(body)) => {
                        let mut data = body.data;
                        data.push(b'!');
                        vec![http_result::Result::BufferedResult(HttpBufferedResult {
                            body: Some(http_buffered_result::Body::Replacement(data)),
                            header_mutations: stage.late_mutations.clone(),
                            trailer_mutations: trailer_rewrite(stage.rewrite_trailer),
                            diagnostics: None,
                        })]
                    }
                    Some(http_event::Event::SessionEnd(end)) => {
                        if let Ok(reason) = MiddlewareSessionEndReason::try_from(end.reason) {
                            stage
                                .session_ends
                                .lock()
                                .expect("session ends")
                                .push(reason);
                        }
                        break;
                    }
                    None => break,
                };
                for reply in reply {
                    if results.send(Ok(result(reply))).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

fn trailer_rewrite(rewrite: bool) -> Vec<HeaderMutation> {
    if rewrite {
        vec![write("x-trace", "rewritten")]
    } else {
        Vec::new()
    }
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

/// Legacy in-process request middleware that appends `+legacy`.
struct LegacyStage;

#[tonic::async_trait]
impl InProcessMiddleware for LegacyStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/legacy".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: 4096,
                ..Default::default()
            }],
            expected_audience: String::new(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "test/legacy",
                "test",
                [],
            )),
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        let mut body = request.body().to_vec();
        body.extend_from_slice(b"+legacy");
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            body,
            has_body: true,
            header_mutations: vec![write("x-legacy", "1")],
            ..Default::default()
        })
    }
}

const REST_ENDPOINT: &str = r#"        protocol: rest
        token_grant_owner: test-owner
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: "/v1/**"
"#;

fn policy_yaml(names: &[&str]) -> String {
    let mut middlewares = String::from("network_middlewares:\n");
    for (order, name) in names.iter().enumerate() {
        let _ = write!(
            middlewares,
            "  {config}:\n    middleware: {name}\n    order: {order}\n    on_error: fail_closed\n    endpoints:\n      include: [\"{HOST}\"]\n",
            config = name.replace('/', "-"),
        );
    }
    format!(
        r"{middlewares}network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: {HOST}
        port: {PORT}
{REST_ENDPOINT}    binaries:
      - {{ path: /usr/bin/curl }}
"
    )
}

/// A policy engine with registered request middleware.
struct Supervisor {
    engine: OpaEngine,
}

impl Supervisor {
    async fn start(services: Vec<Arc<dyn InProcessMiddleware>>, names: &[&str]) -> Self {
        let engine =
            OpaEngine::from_strings(TEST_POLICY, &policy_yaml(names)).expect("load policy");
        let registry = MiddlewareRegistry::connect_services(services, Vec::new())
            .await
            .expect("register request middleware");
        engine
            .replace_middleware_registry(registry)
            .expect("install middleware registry");
        Self { engine }
    }

    async fn with_stages(stages: &[RequestStage]) -> Self {
        let names: Vec<&str> = stages.iter().map(|stage| stage.name).collect();
        let services = stages
            .iter()
            .map(|stage| -> Arc<dyn InProcessMiddleware> { Arc::new(stage.clone()) })
            .collect();
        Self::start(services, &names).await
    }

    fn tunnel(&self) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let input = NetworkInput {
            host: HOST.into(),
            port: PORT,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint, generation) = self
            .engine
            .query_endpoint_config_with_generation(&input)
            .expect("endpoint config");
        let config = parse_l7_config(&endpoint.expect("configured endpoint")).expect("REST config");
        let tunnel = self
            .engine
            .clone_engine_for_tunnel(generation)
            .expect("tunnel engine");
        let ctx = L7EvalContext {
            host: HOST.into(),
            port: PORT,
            request_default_port: Some(PORT),
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ..Default::default()
        };
        (config, tunnel, ctx)
    }

    /// Open one inspected tunnel, optionally adjusting the endpoint and
    /// request context first.
    fn connect_with(
        &self,
        adjust: impl FnOnce(&mut L7EndpointConfig, &mut L7EvalContext),
    ) -> Tunnel {
        let (mut config, tunnel, mut ctx) = self.tunnel();
        adjust(&mut config, &mut ctx);
        let (app, mut relay_client) = tokio::io::duplex(256 * 1024);
        let (mut relay_upstream, upstream) = tokio::io::duplex(256 * 1024);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });
        Tunnel {
            app,
            upstream,
            relay,
        }
    }

    fn connect(&self) -> Tunnel {
        self.connect_with(|_, _| {})
    }
}

struct Tunnel {
    app: DuplexStream,
    upstream: DuplexStream,
    relay: tokio::task::JoinHandle<miette::Result<()>>,
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .expect("operation finished in time")
}

async fn read_head(stream: &mut DuplexStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.expect("read head byte");
        head.push(byte);
    }
    String::from_utf8(head).expect("UTF-8 head")
}

async fn read_line(stream: &mut DuplexStream) -> Vec<u8> {
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n") {
        line.push(stream.read_u8().await.expect("read line byte"));
    }
    line.truncate(line.len() - 2);
    line
}

/// Read one chunk, or `None` at the last chunk.
async fn read_chunk(stream: &mut DuplexStream) -> Option<Vec<u8>> {
    let size = String::from_utf8(read_line(stream).await).expect("chunk size");
    let size = usize::from_str_radix(size.split(';').next().expect("size"), 16).expect("hex size");
    if size == 0 {
        return None;
    }
    let mut payload = vec![0; size];
    stream
        .read_exact(&mut payload)
        .await
        .expect("chunk payload");
    assert_eq!(read_line(stream).await, b"", "chunk terminator");
    Some(payload)
}

async fn read_chunk_trailers(stream: &mut DuplexStream) -> Vec<String> {
    let mut trailers = Vec::new();
    loop {
        let line = read_line(stream).await;
        if line.is_empty() {
            return trailers;
        }
        trailers.push(String::from_utf8(line).expect("trailer"));
    }
}

async fn read_chunked_body(stream: &mut DuplexStream) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(chunk) = read_chunk(stream).await {
        body.extend_from_slice(&chunk);
    }
    assert!(read_chunk_trailers(stream).await.is_empty());
    body
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

async fn read_response(app: &mut DuplexStream) -> String {
    let mut response = Vec::new();
    let _ = app.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}

fn json_body(response: &str) -> serde_json::Value {
    let (_, body) = response.split_once("\r\n\r\n").expect("HTTP response");
    serde_json::from_str(body).expect("JSON body")
}

/// Write `body` as chunks of at most `chunk` bytes.
async fn write_chunked(app: &mut DuplexStream, body: &[u8], chunk: usize) {
    for piece in body.chunks(chunk) {
        app.write_all(format!("{:x}\r\n", piece.len()).as_bytes())
            .await
            .expect("chunk size");
        app.write_all(piece).await.expect("chunk payload");
        app.write_all(b"\r\n").await.expect("chunk terminator");
    }
    app.write_all(b"0\r\n\r\n").await.expect("last chunk");
}

#[tokio::test]
async fn stream_middleware_transforms_a_large_chunked_upload_end_to_end() {
    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/upper", Mode::Uppercase)]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    // Twice the platform payload maximum: STREAM has no total byte cap.
    let body_len = 2 * openshell_supervisor_middleware::MAX_MIDDLEWARE_PAYLOAD_BYTES + 1;
    let client = tokio::spawn(async move {
        app.write_all(
            b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("head");
        write_chunked(&mut app, &vec![b'a'; body_len], 48 * 1024).await;
        read_response(&mut app).await
    });
    let server = tokio::spawn(async move {
        let head = read_head(&mut upstream).await;
        assert_eq!(header_value(&head, "transfer-encoding"), Some("chunked"));
        assert_eq!(header_value(&head, "content-length"), None);
        let body = read_chunked_body(&mut upstream).await;
        upstream.write_all(NO_CONTENT).await.expect("response");
        body
    });

    let body = within(server).await.expect("server");
    assert_eq!(body.len(), body_len);
    assert!(body.iter().all(|byte| *byte == b'A'));
    assert!(
        within(client)
            .await
            .expect("client")
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

#[tokio::test(start_paused = true)]
async fn stream_upload_with_steady_progress_succeeds_past_two_minutes() {
    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/upper", Mode::Uppercase)]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    let started = tokio::time::Instant::now();
    let client = tokio::spawn(async move {
        app.write_all(
            b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("head");
        // One chunk every 10 s for 3 minutes. Each pause stays under the
        // 30 s client-progress timeout.
        for _ in 0..18 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            app.write_all(b"4\r\ntick\r\n").await.expect("chunk");
        }
        app.write_all(b"0\r\n\r\n").await.expect("last chunk");
        read_response(&mut app).await
    });
    let server = tokio::spawn(async move {
        read_head(&mut upstream).await;
        let body = read_chunked_body(&mut upstream).await;
        upstream.write_all(NO_CONTENT).await.expect("response");
        body
    });

    assert_eq!(server.await.expect("server"), b"TICK".repeat(18));
    assert!(client.await.expect("client").starts_with("HTTP/1.1 204"));
    relay.await.expect("relay task").expect("relay");
    assert!(started.elapsed() >= Duration::from_mins(3));
}

#[tokio::test(start_paused = true)]
async fn silent_client_mid_upload_gets_408_and_cancels_the_stages() {
    let stage = RequestStage::new("test/append", Mode::AppendPerChunk);
    let supervisor = Supervisor::with_stages(std::slice::from_ref(&stage)).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    let started = tokio::time::Instant::now();
    app.write_all(
        b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 10\r\n\r\nhello",
    )
    .await
    .expect("partial request");

    // The stage started output, so the upstream head and the first unit went
    // out. The upstream connection then closes without a complete body.
    let head = read_head(&mut upstream).await;
    assert_eq!(header_value(&head, "transfer-encoding"), Some("chunked"));
    assert_eq!(
        read_chunk(&mut upstream).await.as_deref(),
        Some(&b"hello!"[..])
    );
    let mut rest = Vec::new();
    upstream.read_to_end(&mut rest).await.expect("upstream EOF");
    assert!(
        rest.is_empty(),
        "upstream received {rest:?} after the timeout"
    );

    let response = read_response(&mut app).await;
    assert!(
        response.starts_with("HTTP/1.1 408 Request Timeout\r\n"),
        "{response}"
    );
    assert!(response.contains("Connection: close\r\n"), "{response}");
    assert_eq!(json_body(&response)["error"], "request_timeout");
    assert!(started.elapsed() >= crate::l7::middleware::REQUEST_CLIENT_PROGRESS_TIMEOUT);
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::Cancellation
    );
    relay.await.expect("relay task").expect("relay");
}

#[tokio::test(start_paused = true)]
async fn silent_client_on_a_withheld_stream_body_gets_408() {
    let stage = RequestStage::new("test/append", Mode::AppendPerChunk);
    let supervisor = Supervisor::with_stages(std::slice::from_ref(&stage)).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    // HTTP/1.0 cannot carry chunked output, so the output is withheld.
    app.write_all(
        b"POST /v1/upload HTTP/1.0\r\nHost: api.example.test\r\nContent-Length: 10\r\n\r\nhello",
    )
    .await
    .expect("partial request");

    let response = read_response(&mut app).await;
    assert!(
        response.starts_with("HTTP/1.1 408 Request Timeout\r\n"),
        "{response}"
    );
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::Cancellation
    );
    relay.await.expect("relay task").expect("relay");
    let mut forwarded = Vec::new();
    upstream
        .read_to_end(&mut forwarded)
        .await
        .expect("upstream EOF");
    assert!(
        forwarded.is_empty(),
        "withheld output must not reach upstream"
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_stream_middleware_fails_closed_after_30_seconds() {
    let stage = RequestStage::new("test/stalled", Mode::StallAfterBegin);
    let supervisor = Supervisor::with_stages(std::slice::from_ref(&stage)).await;
    let Tunnel {
        mut app,
        upstream: _upstream,
        relay,
    } = supervisor.connect();
    let started = tokio::time::Instant::now();
    let body = vec![b'x'; 8 * MAX_HTTP_STREAM_UNIT_BYTES];
    let client = tokio::spawn(async move {
        app.write_all(
            format!(
                "POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("head");
        let _ = app.write_all(&body).await;
        read_response(&mut app).await
    });

    let response = client.await.expect("client");
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert_eq!(json_body(&response)["error"], "middleware_failed");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= openshell_supervisor_middleware::HTTP_STREAM_IDLE_TIMEOUT,
        "{elapsed:?}"
    );
    relay.await.expect("relay task").expect("relay");
}

#[tokio::test]
async fn late_header_mutations_reach_upstream_after_every_preflight_mutation() {
    let first = RequestStage::new("test/first", Mode::AppendPerChunk)
        .preflight(vec![
            write("x-first-pre", "1"),
            write("x-shared", "first-pre"),
        ])
        .late(vec![
            write("x-first-late", "1"),
            write("x-shared", "first-late"),
        ]);
    let second = RequestStage::new("test/second", Mode::AppendPerChunk)
        .preflight(vec![write("x-second-pre", "1")])
        .late(vec![write("x-second-late", "1")]);
    let third = RequestStage::new("test/third", Mode::HeadersOnly)
        .preflight(vec![write("x-shared", "third-pre")]);
    let supervisor = Supervisor::with_stages(&[first, second, third]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    app.write_all(
        b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await
    .expect("request");

    let head = within(read_head(&mut upstream)).await;
    let mutated: Vec<&str> = head.lines().filter(|line| line.starts_with("x-")).collect();
    // Every preflight mutation, then every late mutation, each in chain
    // order: an earlier stage's late write wins over a later stage's
    // preflight write to the same header.
    assert_eq!(
        mutated,
        [
            "x-first-pre: 1",
            "x-second-pre: 1",
            "x-first-late: 1",
            "x-shared: first-late",
            "x-second-late: 1",
        ],
        "{head}"
    );
    assert_eq!(within(read_chunked_body(&mut upstream)).await, b"hello!!");
    upstream.write_all(NO_CONTENT).await.expect("response");
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

#[tokio::test]
async fn preflight_only_middleware_forwards_the_body_without_collecting_it() {
    let stage = RequestStage::new("test/tagger", Mode::HeadersOnly)
        .preflight(vec![write("x-middleware-mode", "headers-only")]);
    let supervisor = Supervisor::with_stages(&[stage]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    let body_len = 4 * 1024 * 1024 + 17;
    app.write_all(
        format!(
            "POST /v1/large HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("head");

    // The upstream head arrives before the client sends any body byte.
    let head = within(read_head(&mut upstream)).await;
    assert_eq!(
        header_value(&head, "content-length"),
        Some(&*body_len.to_string())
    );
    assert_eq!(
        header_value(&head, "x-middleware-mode"),
        Some("headers-only")
    );

    let server = tokio::spawn(async move {
        let mut body = vec![0; body_len];
        upstream.read_exact(&mut body).await.expect("body");
        upstream.write_all(NO_CONTENT).await.expect("response");
        body
    });
    app.write_all(&vec![b'x'; body_len]).await.expect("body");
    let body = within(server).await.expect("server");
    assert!(body.iter().all(|byte| *byte == b'x'));
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

#[tokio::test]
async fn request_middleware_rejects_at_preflight_before_reading_the_body() {
    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/guard", Mode::RejectAtPreflight)]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    // Only the head is sent: the denial needs no body.
    app.write_all(
        b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 10\r\n\r\n",
    )
    .await
    .expect("head");
    let mut response = Vec::new();
    let mut byte = [0; 1];
    while !response.ends_with(b"}") {
        within(app.read_exact(&mut byte))
            .await
            .expect("response byte");
        response.push(byte[0]);
    }
    let response = String::from_utf8(response).expect("response");
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    let body = json_body(&response);
    assert_eq!(body["error"], "middleware_denied");
    assert_eq!(body["reason_code"], "blocked_upload");
    drop(app);
    within(relay).await.expect("relay task").expect("relay");
    let mut forwarded = Vec::new();
    upstream
        .read_to_end(&mut forwarded)
        .await
        .expect("upstream EOF");
    assert!(forwarded.is_empty());
}

#[tokio::test]
async fn stream_rejection_before_any_response_returns_the_denial() {
    let stage = RequestStage::new("test/guard", Mode::RejectOnInput);
    let supervisor = Supervisor::with_stages(std::slice::from_ref(&stage)).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    app.write_all(
        b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
    )
    .await
    .expect("request");
    let response = within(read_response(&mut app)).await;
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert_eq!(json_body(&response)["reason_code"], "content_match");
    within(relay).await.expect("relay task").expect("relay");
    let mut forwarded = Vec::new();
    upstream
        .read_to_end(&mut forwarded)
        .await
        .expect("upstream EOF");
    assert!(forwarded.is_empty(), "nothing commits before OutputStart");
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::MiddlewareDenial
    );
}

#[tokio::test]
async fn buffered_middleware_output_is_inlined_with_late_mutations() {
    for (trailers, expected_framing) in [(false, "content-length"), (true, "transfer-encoding")] {
        let mut stage =
            RequestStage::new("test/whole", Mode::WholeBodyAppend).late(vec![write("x-late", "1")]);
        stage.rewrite_trailer = trailers;
        let supervisor = Supervisor::with_stages(&[stage]).await;
        let Tunnel {
            mut app,
            mut upstream,
            relay,
        } = supervisor.connect();
        let request = if trailers {
            "POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trace\r\nConnection: close\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trace: original\r\n\r\n"
        } else {
            "POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        };
        app.write_all(request.as_bytes()).await.expect("request");

        let head = within(read_head(&mut upstream)).await;
        assert_eq!(header_value(&head, "x-late"), Some("1"), "{head}");
        assert!(header_value(&head, expected_framing).is_some(), "{head}");
        if trailers {
            assert_eq!(header_value(&head, "trailer"), Some("x-trace"));
            assert_eq!(
                within(read_chunk(&mut upstream)).await.as_deref(),
                Some(&b"Wikipedia!"[..])
            );
            assert!(within(read_chunk(&mut upstream)).await.is_none());
            assert_eq!(
                within(read_chunk_trailers(&mut upstream)).await,
                ["x-trace: rewritten"]
            );
        } else {
            assert_eq!(header_value(&head, "content-length"), Some("10"));
            assert_eq!(header_value(&head, "transfer-encoding"), None);
            let mut body = [0; 10];
            within(upstream.read_exact(&mut body)).await.expect("body");
            assert_eq!(&body, b"Wikipedia!");
        }
        upstream.write_all(NO_CONTENT).await.expect("response");
        assert!(
            within(read_response(&mut app))
                .await
                .starts_with("HTTP/1.1 204")
        );
        within(relay).await.expect("relay task").expect("relay");
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_middleware_keeps_the_whole_body_deadline() {
    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/whole", Mode::WholeBodyAppend)]).await;
    let Tunnel {
        mut app,
        upstream: _upstream,
        relay,
    } = supervisor.connect();
    let started = tokio::time::Instant::now();
    let client = tokio::spawn(async move {
        app.write_all(
            b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 64\r\n\r\n",
        )
        .await
        .expect("head");
        // Steady progress that STREAM would accept still exceeds the
        // BUFFERED whole-body deadline.
        for _ in 0..64 {
            if app.write_all(b"x").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
            if started.elapsed() > Duration::from_mins(3) {
                break;
            }
        }
        read_response(&mut app).await
    });
    let response = client.await.expect("client");
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert_eq!(json_body(&response)["error"], "middleware_failed");
    relay.await.expect("relay task").expect("relay");
}

/// Advertises a version 2 binding but keeps the default stage RPC, or
/// answers with an undecodable result.
struct BrokenStage {
    decode_failure: bool,
}

#[tonic::async_trait]
impl InProcessMiddleware for BrokenStage {
    async fn describe(&self) -> MiddlewareManifest {
        RequestStage::new("test/broken", Mode::AppendPerChunk)
            .describe()
            .await
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Err(miette::miette!("version 2 test middleware"))
    }

    async fn open_http_request_stage(
        &self,
        _events: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, tonic::Status> {
        if !self.decode_failure {
            return Err(tonic::Status::unimplemented("no version 2 request stage"));
        }
        Ok(Box::pin(futures::stream::iter([Err(
            tonic::Status::internal(
                "failed to decode Protobuf message: HttpResult.result: invalid wire type",
            ),
        )])))
    }
}

#[tokio::test]
async fn contract_failures_fail_closed_and_request_reconciliation() {
    for decode_failure in [false, true] {
        let supervisor = Supervisor::start(
            vec![Arc::new(BrokenStage { decode_failure })],
            &["test/broken"],
        )
        .await;
        let Tunnel {
            mut app,
            mut upstream,
            relay,
        } = supervisor.connect();
        app.write_all(
            b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .expect("request");
        let response = within(read_response(&mut app)).await;
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "decode_failure={decode_failure}: {response}"
        );
        assert_eq!(json_body(&response)["error"], "middleware_failed");
        within(relay).await.expect("relay task").expect("relay");
        let mut forwarded = Vec::new();
        upstream
            .read_to_end(&mut forwarded)
            .await
            .expect("upstream EOF");
        assert!(forwarded.is_empty());
        assert!(
            supervisor
                .engine
                .middleware_runner()
                .expect("runner")
                .take_reconciliation_request(),
            "decode_failure={decode_failure}"
        );
    }
}

#[tokio::test]
async fn early_upstream_response_closes_the_client_connection() {
    let stage = RequestStage::new("test/append", Mode::AppendPerChunk);
    let supervisor = Supervisor::with_stages(std::slice::from_ref(&stage)).await;
    let (config, tunnel, ctx) = supervisor.tunnel();
    let (mut app, mut relay_client) = tokio::io::duplex(8192);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
    let early_response = b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n";
    // The upload is still incomplete, so the relay cannot reuse the
    // connection. Keep the relay-side stream alive: the client must receive
    // EOF from an explicit shutdown, not from a dropped socket.
    let relay = relay_with_inspection(
        &config,
        tunnel,
        &mut relay_client,
        &mut relay_upstream,
        &ctx,
    );
    let server = async {
        let head = read_head(&mut upstream).await;
        assert!(head.starts_with("POST /v1/early HTTP/1.1\r\n"), "{head}");
        upstream
            .write_all(early_response)
            .await
            .expect("early response");
        upstream.flush().await.expect("flush");
    };
    let client = async {
        app.write_all(
            b"POST /v1/early HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 10\r\n\r\nhello",
        )
        .await
        .expect("partial request");
        let mut response = Vec::new();
        app.read_to_end(&mut response).await.expect("client EOF");
        response
    };
    let (result, (), response) =
        Box::pin(within(async { tokio::join!(relay, server, client) })).await;
    result.expect("relay");
    assert_eq!(response, early_response);
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::Cancellation
    );
    drop(relay_client);
}

#[tokio::test]
async fn pipelined_requests_stay_in_read_ahead_through_request_middleware() {
    for route_selected in [false, true] {
        for chunked in [false, true] {
            for second_allowed in [false, true] {
                let supervisor = Supervisor::with_stages(&[RequestStage::new(
                    "test/append",
                    Mode::AppendPerChunk,
                )])
                .await;
                let (config, tunnel, ctx) = supervisor.tunnel();
                let mut wire = String::new();
                for (index, body) in ["first", "second"].into_iter().enumerate() {
                    let target = if index == 0 || second_allowed {
                        "/v1/allowed"
                    } else {
                        "/v2/blocked"
                    };
                    let framing = if chunked {
                        format!(
                            "Transfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                            body.len()
                        )
                    } else {
                        format!("Content-Length: {}\r\n\r\n{body}", body.len())
                    };
                    let _ = write!(
                        wire,
                        "POST {target} HTTP/1.1\r\nHost: api.example.test\r\n{framing}"
                    );
                }
                let (mut app, mut relay_client) = tokio::io::duplex(8192);
                let (mut relay_upstream, upstream) = tokio::io::duplex(8192);
                // Both requests are queued before the relay reads, so the
                // second sits in connection read-ahead while middleware
                // consumes the first body.
                app.write_all(wire.as_bytes()).await.expect("requests");
                app.shutdown().await.expect("client half-close");
                let relay = async move {
                    if route_selected {
                        relay_with_route_selection(
                            &[config],
                            tunnel,
                            &mut relay_client,
                            &mut relay_upstream,
                            &ctx,
                        )
                        .await
                    } else {
                        relay_with_inspection(
                            &config,
                            tunnel,
                            &mut relay_client,
                            &mut relay_upstream,
                            &ctx,
                        )
                        .await
                    }
                };
                let server = async move {
                    let mut upstream = tokio::io::BufReader::new(upstream);
                    let provider = crate::l7::rest::RestProvider::with_options(
                        crate::l7::path::CanonicalizeOptions::default(),
                    );
                    let mut forwarded = Vec::new();
                    while let Some(mut request) =
                        crate::l7::provider::L7Provider::parse_request(&provider, &mut upstream)
                            .await
                            .expect("forwarded request")
                    {
                        let body = crate::l7::http::read_body_for_inspection(
                            &mut upstream,
                            &mut request,
                            1024,
                        )
                        .await
                        .expect("forwarded body");
                        forwarded.push((request.target, String::from_utf8(body).expect("body")));
                        upstream
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .expect("response");
                    }
                    forwarded
                };
                let client = async move {
                    let mut response = String::new();
                    let _ = app.read_to_string(&mut response).await;
                    response
                };
                let (result, forwarded, response) =
                    Box::pin(within(async { tokio::join!(relay, server, client) })).await;
                result.expect("relay");
                let case = format!(
                    "route_selected={route_selected}, chunked={chunked}, second_allowed={second_allowed}"
                );
                let mut expected = vec![("/v1/allowed".to_string(), "first!".to_string())];
                if second_allowed {
                    expected.push(("/v1/allowed".to_string(), "second!".to_string()));
                }
                assert_eq!(forwarded, expected, "{case}");
                assert_eq!(
                    response.matches("HTTP/1.1 204 No Content").count(),
                    expected.len(),
                    "{case}: {response}"
                );
                assert_eq!(
                    response.contains("403 Forbidden"),
                    !second_allowed,
                    "{case}: {response}"
                );
            }
        }
    }
}

#[tokio::test]
async fn sigv4_route_signs_the_withheld_middleware_body() {
    use sha2::Digest as _;

    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/append", Mode::AppendPerChunk)]).await;
    let (_, resolver) = openshell_core::secrets::SecretResolver::from_provider_env(
        [
            ("AWS_ACCESS_KEY_ID".to_string(), "AKIATESTKEY".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "test-secret-key".to_string(),
            ),
        ]
        .into_iter()
        .collect(),
    );
    let resolver = Arc::new(resolver.expect("resolver"));
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect_with(|config, ctx| {
        config.credential_signing = crate::l7::CredentialSigning::SigV4Body;
        config.signing_service = "execute-api".into();
        config.signing_region = "us-west-2".into();
        ctx.secret_resolver = Some(resolver);
    });
    app.write_all(
        b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await
    .expect("request");

    let head = within(read_head(&mut upstream)).await;
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("authorization: aws4-hmac-sha256"), "{head}");
    assert_eq!(header_value(&head, "content-length"), Some("6"));
    let expected_hash = hex::encode(sha2::Sha256::digest(b"hello!"));
    assert_eq!(
        header_value(&head, "x-amz-content-sha256"),
        Some(expected_hash.as_str()),
        "{head}"
    );
    let mut body = [0; 6];
    within(upstream.read_exact(&mut body))
        .await
        .expect("signed body");
    assert_eq!(&body, b"hello!");
    upstream.write_all(NO_CONTENT).await.expect("response");
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

#[tokio::test]
async fn provider_guard_rejects_a_marker_created_by_stream_middleware() {
    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/marker", Mode::CredentialMarker)]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect_with(|config, _| config.provider_credentialed = true);
    app.write_all(
        b"POST /v1/marker HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsafe",
    )
    .await
    .expect("request");
    let response = within(read_response(&mut app)).await;
    assert!(response.contains("403 Forbidden"), "{response}");
    within(relay).await.expect("relay task").expect("relay");
    let mut forwarded = Vec::new();
    upstream
        .read_to_end(&mut forwarded)
        .await
        .expect("upstream EOF");
    assert!(
        !forwarded
            .windows(b"openshell:resolve:".len())
            .any(|window| window == b"openshell:resolve:"),
        "middleware-created credential marker reached upstream"
    );
}

#[tokio::test]
async fn delayed_whole_body_stream_holds_the_head_until_output_starts() {
    let stage = RequestStage::new("test/delayed", Mode::DelayedWholeBody);
    let supervisor = Supervisor::with_stages(std::slice::from_ref(&stage)).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect_with(|config, _| config.provider_credentialed = true);
    app.write_all(
        b"POST /v1/delayed HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 2\r\nConnection: close\r\n\r\na",
    )
    .await
    .expect("partial request");
    // Longer than the 500 ms binding timeout: a STREAM stage may withhold
    // output while its input is still arriving.
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_head(&mut upstream))
            .await
            .is_err(),
        "STREAM must hold the upstream head until OutputStart"
    );
    app.write_all(b"b").await.expect("rest of body");

    let head = within(read_head(&mut upstream)).await;
    assert_eq!(header_value(&head, "content-length"), Some("2"));
    assert_eq!(header_value(&head, "transfer-encoding"), None);
    let mut body = [0; 2];
    within(upstream.read_exact(&mut body)).await.expect("body");
    assert_eq!(&body, b"ab");
    upstream.write_all(NO_CONTENT).await.expect("response");
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
    assert_eq!(
        stage.session_end().await,
        MiddlewareSessionEndReason::Normal
    );
}

#[tokio::test]
async fn stream_middleware_keeps_trailers_and_answers_expect_continue() {
    let mut stage = RequestStage::new("test/append", Mode::AppendPerChunk);
    stage.rewrite_trailer = true;
    let supervisor = Supervisor::with_stages(&[stage]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    app.write_all(
        b"POST /v1/chunked HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trace\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("head");
    let mut interim = [0; 25];
    within(app.read_exact(&mut interim))
        .await
        .expect("100 Continue");
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    // Chunks that arrive together coalesce into one unit.
    app.write_all(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trace: original\r\n\r\n")
        .await
        .expect("body");

    let head = within(read_head(&mut upstream)).await;
    let lower = head.to_ascii_lowercase();
    assert_eq!(header_value(&head, "transfer-encoding"), Some("chunked"));
    assert!(lower.contains("trailer: x-trace\r\n"), "{head}");
    assert!(!lower.contains("expect:"), "{head}");
    assert!(!lower.contains("content-length:"), "{head}");
    assert_eq!(
        within(read_chunk(&mut upstream)).await.as_deref(),
        Some(&b"Wikipedia!"[..])
    );
    assert!(within(read_chunk(&mut upstream)).await.is_none());
    assert_eq!(
        within(read_chunk_trailers(&mut upstream)).await,
        ["x-trace: rewritten"]
    );
    upstream.write_all(NO_CONTENT).await.expect("response");
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

#[tokio::test]
async fn mixed_legacy_and_version_2_chain_runs_in_chain_order() {
    let v2 = RequestStage::new("test/v2", Mode::AppendPerChunk)
        .preflight(vec![write("x-v2-pre", "1")])
        .late(vec![write("x-v2-late", "1")]);
    let supervisor = Supervisor::start(
        vec![Arc::new(LegacyStage), Arc::new(v2)],
        &["test/legacy", "test/v2"],
    )
    .await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    app.write_all(
        b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await
    .expect("request");

    let head = within(read_head(&mut upstream)).await;
    let mutated: Vec<&str> = head.lines().filter(|line| line.starts_with("x-")).collect();
    assert_eq!(
        mutated,
        ["x-legacy: 1", "x-v2-pre: 1", "x-v2-late: 1"],
        "{head}"
    );
    assert_eq!(header_value(&head, "content-length"), Some("13"));
    let mut body = [0; 13];
    within(upstream.read_exact(&mut body)).await.expect("body");
    assert_eq!(&body, b"hello+legacy!");
    upstream.write_all(NO_CONTENT).await.expect("response");
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

#[tokio::test]
async fn late_header_mutations_cannot_replace_an_injected_token_grant() {
    use crate::l7::token_grant_injection::test_support::TokenGrantTestFixture;

    let key = "api.example.test\t8080\t/v1/**\tprovider:access_token";
    let fixture = TokenGrantTestFixture::success(key, "platform-token");
    let mut credential = fixture.dynamic_credentials().read().expect("credentials")[key].clone();
    credential.auth_style = "header".into();
    credential.header_name = "X-Api-Key".into();
    fixture.add_credential(key, credential, Ok("platform-token"));
    let stage = RequestStage::new("test/append", Mode::AppendPerChunk)
        .late(vec![write("x-api-key", "middleware-value")]);
    let supervisor = Supervisor::with_stages(&[stage]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect_with(|_, ctx| {
        ctx.dynamic_credentials = Some(fixture.dynamic_credentials());
        ctx.provider_credentials = Some(fixture.provider_credentials());
        ctx.token_grant_resolver = Some(fixture.resolver());
    });
    app.write_all(
        b"POST /v1/upload HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
    )
    .await
    .expect("request");

    let head = within(read_head(&mut upstream)).await;
    let api_keys: Vec<&str> = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-api-key"))
        .map(|(_, value)| value.trim())
        .collect();
    assert_eq!(api_keys, ["platform-token"], "{head}");
    assert_eq!(within(read_chunked_body(&mut upstream)).await, b"data!");
    upstream.write_all(NO_CONTENT).await.expect("response");
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

#[tokio::test]
async fn declared_output_length_keeps_chunked_framing_for_client_trailers() {
    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/delayed", Mode::DelayedWholeBody)]).await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();
    app.write_all(
        b"POST /v1/chunked HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trace\r\nConnection: close\r\n\r\n4\r\nWiki\r\n0\r\nX-Trace: original\r\n\r\n",
    )
    .await
    .expect("request");

    let head = within(read_head(&mut upstream)).await;
    assert_eq!(header_value(&head, "transfer-encoding"), Some("chunked"));
    assert_eq!(header_value(&head, "content-length"), None);
    assert_eq!(
        within(read_chunk(&mut upstream)).await.as_deref(),
        Some(&b"Wiki"[..])
    );
    assert!(within(read_chunk(&mut upstream)).await.is_none());
    assert_eq!(
        within(read_chunk_trailers(&mut upstream)).await,
        ["x-trace: original"]
    );
    upstream.write_all(NO_CONTENT).await.expect("response");
    assert!(
        within(read_response(&mut app))
            .await
            .starts_with("HTTP/1.1 204")
    );
    within(relay).await.expect("relay task").expect("relay");
}

struct OcsfCapture(Arc<Mutex<Vec<serde_json::Value>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for OcsfCapture {
    fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(event) = openshell_ocsf::tracing_layers::clone_current_event() {
            self.0
                .lock()
                .expect("events")
                .push(serde_json::to_value(&event).expect("serialize event"));
        }
    }
}

#[tokio::test]
async fn streamed_credential_marker_denial_emits_the_uninspectable_finding() {
    use tracing_subscriber::layer::SubscriberExt as _;

    const CHILD: &str = "OPENSHELL_TEST_STREAMED_MARKER_EVENTS_CHILD";
    // Tracing callsite interest is process-wide, so concurrent tests with
    // other subscribers can disable this thread's capture. Run in an isolated
    // test process.
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "l7::request_middleware_tests::streamed_credential_marker_denial_emits_the_uninspectable_finding",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run child test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(OcsfCapture(Arc::clone(&events))),
    );
    let supervisor =
        Supervisor::with_stages(&[RequestStage::new("test/marker", Mode::CredentialMarker)]).await;
    let Tunnel {
        mut app,
        upstream: _upstream,
        relay,
    } = supervisor.connect_with(|config, _| config.provider_credentialed = true);
    app.write_all(
        b"POST /v1/marker HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsafe",
    )
    .await
    .expect("request");
    let response = within(read_response(&mut app)).await;
    assert!(response.contains("403 Forbidden"), "{response}");
    within(relay).await.expect("relay task").expect("relay");

    let events = events.lock().expect("events");
    assert!(
        events.iter().any(|event| {
            event["finding_info"]["uid"] == "openshell.credentials.traffic_uninspectable"
        }),
        "{events:#?}"
    );
}
