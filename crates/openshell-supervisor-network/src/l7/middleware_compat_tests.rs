// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! 0.1.x characterization of legacy HTTP middleware through the L7 relay.
//!
//! Each test registers a service generated from the released v0.1.2 schema
//! (`openshell-supervisor-middleware-wire-fixture`) with
//! `MiddlewareRegistry::connect_services`, installs it with
//! `OpaEngine::replace_middleware_registry` as the supervisor does, and drives
//! raw HTTP/1.x bytes through `relay_with_inspection`. Assertions are mostly
//! on what the sandbox client and the upstream server observe on the wire.
//! Some also read what the fixture received, the shared admission budget
//! (`OpaEngine::middleware_runner`), or policy loading, which a cutover may
//! need to reach differently. Expectations that the legacy adapters
//! deliberately change say so where they are asserted.

use std::fmt::Write as _;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use openshell_core::proto::SupervisorMiddlewareService;
use openshell_supervisor_middleware::{
    MAX_CONCURRENT_MIDDLEWARE_SESSIONS, MAX_CONCURRENT_MIDDLEWARE_WORK, MAX_QUEUED_MIDDLEWARE_WORK,
    MiddlewareRegistry,
};
use openshell_supervisor_middleware_wire_fixture::proto::middleware::{
    ExistingHeaderAction, HttpResponseBodyMode, HttpResponseBodyResult, HttpResponseBodyUnit,
    http_response_body_unit,
};
use openshell_supervisor_middleware_wire_fixture::{
    LegacyMiddlewareFixture, LegacyRpc, Reply, RunningFixture, http_request_binding,
    http_response_binding, results,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tonic::Status;

use crate::l7::relay::{L7EvalContext, relay_with_inspection};
use crate::l7::{L7EndpointConfig, parse_l7_config};
use crate::opa::{NetworkInput, OpaEngine, TunnelPolicyEngine};

const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");
const HOST: &str = "api.example.test";
const PORT: u16 = 8080;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const LIMIT: u64 = 4096;

/// One `network_middlewares` entry selecting [`HOST`].
struct Attachment<'a> {
    name: &'a str,
    registration: &'a str,
    order: i32,
    on_error: &'a str,
}

fn policy_yaml(attachments: &[Attachment<'_>], endpoint_options: &str) -> String {
    let mut middlewares = String::from("network_middlewares:\n");
    for attachment in attachments {
        let _ = write!(
            middlewares,
            "  {name}:\n    middleware: {registration}\n    order: {order}\n    on_error: {on_error}\n    endpoints:\n      include: [\"{HOST}\"]\n",
            name = attachment.name,
            registration = attachment.registration,
            order = attachment.order,
            on_error = attachment.on_error,
        );
    }
    format!(
        r"{middlewares}network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: {HOST}
        port: {PORT}
{endpoint_options}    binaries:
      - {{ path: /usr/bin/curl }}
"
    )
}

const REST_ENDPOINT: &str = r#"        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/v1/**"
          - allow:
              method: POST
              path: "/v1/**"
"#;

fn registration(name: &str, fixture: &RunningFixture) -> SupervisorMiddlewareService {
    SupervisorMiddlewareService {
        name: name.into(),
        grpc_endpoint: fixture.endpoint(),
        max_payload_bytes: LIMIT,
        request_timeout: None,
        tls_ca_cert_pem: Vec::new(),
        audience: String::new(),
        allow_insecure_transport: true,
        ..Default::default()
    }
}

fn network_input() -> NetworkInput {
    NetworkInput {
        host: HOST.into(),
        port: PORT,
        binary_path: PathBuf::from("/usr/bin/curl"),
        binary_sha256: "unused".into(),
        ancestors: vec![],
        cmdline_paths: vec![],
    }
}

/// A policy engine with registered legacy services, ready to open tunnels.
struct Supervisor {
    engine: OpaEngine,
}

impl Supervisor {
    async fn start(
        attachments: &[Attachment<'_>],
        registrations: Vec<SupervisorMiddlewareService>,
    ) -> Self {
        let engine = OpaEngine::from_strings(TEST_POLICY, &policy_yaml(attachments, REST_ENDPOINT))
            .expect("load policy");
        let registry = MiddlewareRegistry::connect_services(Vec::new(), registrations)
            .await
            .expect("register legacy middleware");
        engine
            .replace_middleware_registry(registry)
            .expect("install middleware registry");
        Self { engine }
    }

    fn tunnel(&self) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let (endpoint, generation) = self
            .engine
            .query_endpoint_config_with_generation(&network_input())
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

    /// Open one inspected tunnel. `app` is the sandbox client and `upstream`
    /// the destination server.
    fn connect(&self) -> Tunnel {
        let (config, tunnel, ctx) = self.tunnel();
        let (app, mut relay_client) = tokio::io::duplex(64 * 1024);
        let (mut relay_upstream, upstream) = tokio::io::duplex(64 * 1024);
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

    /// Send one `Connection: close` request and answer it with `response` if
    /// it reaches the upstream.
    async fn exchange(&self, request: &[u8], response: &[u8]) -> Exchange {
        let Tunnel {
            mut app,
            mut upstream,
            relay,
        } = self.connect();
        let response = response.to_vec();
        let upstream_task = tokio::spawn(async move {
            let received = read_http_request(&mut upstream).await;
            if received.is_some() {
                upstream.write_all(&response).await.expect("write response");
                upstream.shutdown().await.expect("close upstream");
            }
            received
        });
        app.write_all(request).await.expect("send request");
        let client = within(read_to_end(&mut app)).await;
        drop(app);
        let relay = within(relay).await.expect("join relay");
        let upstream = within(upstream_task).await.expect("join upstream");
        Exchange {
            client,
            upstream,
            relay,
        }
    }
}

struct Tunnel {
    app: DuplexStream,
    upstream: DuplexStream,
    relay: tokio::task::JoinHandle<miette::Result<()>>,
}

struct Exchange {
    client: Vec<u8>,
    /// The request the upstream received, if one arrived.
    upstream: Option<Vec<u8>>,
    relay: miette::Result<()>,
}

impl Exchange {
    fn client_text(&self) -> String {
        String::from_utf8_lossy(&self.client).into_owned()
    }
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .expect("operation finished in time")
}

async fn read_to_end(stream: &mut DuplexStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes).await;
    bytes
}

/// Read until `marker` has arrived and return everything read so far.
async fn read_until(stream: &mut DuplexStream, buffer: &mut Vec<u8>, marker: &[u8]) {
    within(async {
        let mut chunk = [0u8; 4096];
        while !contains(buffer, marker) {
            let read = stream.read(&mut chunk).await.expect("read stream");
            assert!(
                read > 0,
                "stream closed before {:?}; got {:?}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(buffer)
            );
            buffer.extend_from_slice(&chunk[..read]);
        }
    })
    .await;
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|end| end + 4)
}

/// Read one complete request, or `None` if the connection closed first.
async fn read_http_request(stream: &mut DuplexStream) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = head_end(&bytes) {
            let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let complete = if head.contains("transfer-encoding: chunked") {
                contains(&bytes[end..], b"0\r\n\r\n")
            } else {
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .map_or(0, |value| value.trim().parse::<usize>().expect("length"));
                bytes.len() >= end + length
            };
            if complete {
                return Some(bytes);
            }
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn header_lines(message: &[u8]) -> Vec<String> {
    let end = head_end(message).expect("complete head");
    String::from_utf8_lossy(&message[..end])
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn body_of(message: &[u8]) -> &[u8] {
    &message[head_end(message).expect("complete head")..]
}

fn json_body(message: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body_of(message)).expect("JSON body")
}

/// Decode a complete chunked body, ignoring extensions and trailers.
fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line");
        let size_text = String::from_utf8_lossy(&body[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16)
            .expect("hex chunk size");
        body = &body[line_end + 2..];
        if size == 0 {
            return decoded;
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

fn uppercase_units(unit: &HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult> {
    let Some(http_response_body_unit::Payload::Data(data)) = unit.payload.as_ref() else {
        return Reply::Fail(Status::invalid_argument("body data required"));
    };
    if data.is_empty() {
        results::body_pass_through(unit.sequence).into()
    } else {
        results::body_transform(unit.sequence, data.to_ascii_uppercase()).into()
    }
}

async fn stream_guard(
    body: impl Fn(&HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult> + Send + Sync + 'static,
    on_error: &str,
) -> (RunningFixture, Supervisor) {
    let fixture = LegacyMiddlewareFixture::new("compat/stream-guard")
        .with_binding(http_response_binding(LIMIT))
        .on_response_preflight(|_| {
            results::preflight_inspect(HttpResponseBodyMode::StreamBytes, Vec::new()).into()
        })
        .on_response_body(body)
        .spawn()
        .await
        .expect("spawn response fixture");
    let supervisor = Supervisor::start(
        &[Attachment {
            name: "stream-guard",
            registration: "legacy-stream-guard",
            order: 10,
            on_error,
        }],
        vec![registration("legacy-stream-guard", &fixture)],
    )
    .await;
    (fixture, supervisor)
}

const SSE_REQUEST: &[u8] =
    b"GET /v1/events HTTP/1.1\r\nHost: api.example.test\r\nAccept: text/event-stream\r\n\r\n";

/// Server-sent events through legacy `STREAM_BYTES` reach the client one event
/// at a time: the transformed first event arrives while the upstream still
/// withholds the second.
#[tokio::test]
async fn sse_through_stream_bytes_is_delivered_incrementally() {
    let (_fixture, supervisor) = stream_guard(uppercase_units, "fail_closed").await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();

    app.write_all(SSE_REQUEST).await.expect("send request");
    let request = within(read_http_request(&mut upstream))
        .await
        .expect("request reaches upstream");
    assert!(request.starts_with(b"GET /v1/events HTTP/1.1\r\n"));
    upstream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nETag: \"v1\"\r\n\r\nb\r\ndata: one\n\n\r\n",
        )
        .await
        .expect("send first event");

    let mut delivered = Vec::new();
    read_until(&mut app, &mut delivered, b"DATA: ONE\n\n").await;
    let head = header_lines(&delivered);
    assert!(delivered.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        head.iter()
            .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    );
    assert!(
        !head
            .iter()
            .any(|line| line.to_ascii_lowercase().starts_with("etag:")),
        "STREAM_BYTES strips stale validators: {head:?}"
    );

    upstream
        .write_all(b"b\r\ndata: two\n\n\r\n0\r\n\r\n")
        .await
        .expect("send second event");
    read_until(&mut app, &mut delivered, b"\r\n0\r\n\r\n").await;
    assert_eq!(dechunk(body_of(&delivered)), b"DATA: ONE\n\nDATA: TWO\n\n");

    drop(app);
    within(relay)
        .await
        .expect("join relay")
        .expect("relay result");
}

struct OcsfCapture(std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>);

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

/// Every 0.1.x invocation record of a legacy stream stage reaches OCSF once,
/// with its body unit sequence, as 0.1.x emitted it: the selected mode, each
/// unit, the empty final unit, and the trailers. The stage pipeline's own
/// records of the stage are left out.
#[tokio::test]
async fn legacy_stream_invocations_are_emitted_once_per_record() {
    use tracing_subscriber::layer::SubscriberExt as _;

    const CHILD: &str = "OPENSHELL_TEST_LEGACY_RESPONSE_EVENTS_CHILD";
    // Tracing callsite interest is process-wide, so concurrent tests with
    // other subscribers can disable this thread's capture. Run in an isolated
    // test process.
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "l7::middleware_compat_tests::legacy_stream_invocations_are_emitted_once_per_record",
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

    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(OcsfCapture(std::sync::Arc::clone(&events))),
    );
    let (_fixture, supervisor) = stream_guard(uppercase_units, "fail_closed").await;
    let exchange = supervisor
        .exchange(
            b"GET /v1/events HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n",
        )
        .await;
    assert!(exchange.relay.is_ok(), "{:?}", exchange.relay);
    assert_eq!(dechunk(body_of(&exchange.client)), b"ONETWO");

    let events = events.lock().expect("events");
    let records: Vec<_> = events
        .iter()
        .filter(|event| {
            event["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("HTTP_RESPONSE_MIDDLEWARE"))
        })
        .map(|event| {
            (
                event["unmapped"]["response_middleware_outcome"]
                    .as_str()
                    .expect("outcome")
                    .to_string(),
                event["unmapped"]["sequence"].as_u64(),
            )
        })
        .collect();
    assert_eq!(
        records,
        [
            ("stream", Some(0)),
            ("transform", Some(1)),
            ("transform", Some(2)),
            ("passthrough", Some(3)),
            ("trailers", Some(0)),
        ]
        .map(|(outcome, sequence)| (outcome.to_string(), sequence)),
        "{events:#?}"
    );
}

/// An HTTP/1.0 upstream has no chunked framing, so 0.1.x streams the
/// transformed body close-delimited with `Connection: close`. A failure after
/// commit is indistinguishable from the end of the body for this client.
/// Legacy stages keep this close-delimited parity after the cutover.
#[tokio::test]
async fn sse_from_an_http_1_0_upstream_is_streamed_close_delimited() {
    let (_fixture, supervisor) = stream_guard(uppercase_units, "fail_closed").await;
    let Tunnel {
        mut app,
        mut upstream,
        relay,
    } = supervisor.connect();

    app.write_all(SSE_REQUEST).await.expect("send request");
    within(read_http_request(&mut upstream))
        .await
        .expect("request reaches upstream");
    upstream
        .write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: one\n\n")
        .await
        .expect("send first event");

    let mut delivered = Vec::new();
    read_until(&mut app, &mut delivered, b"DATA: ONE\n\n").await;
    assert!(delivered.starts_with(b"HTTP/1.0 200 OK\r\n"));
    let head = header_lines(&delivered);
    assert!(
        head.iter().any(|line| line == "Connection: close"),
        "{head:?}"
    );
    assert!(
        !head
            .iter()
            .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding")),
        "{head:?}"
    );

    upstream
        .write_all(b"data: two\n\n")
        .await
        .expect("send second event");
    upstream.shutdown().await.expect("close upstream");
    delivered.extend(within(read_to_end(&mut app)).await);
    assert_eq!(body_of(&delivered), b"DATA: ONE\n\nDATA: TWO\n\n");
    within(relay)
        .await
        .expect("join relay")
        .expect("relay result");
}

/// Downstream framing depends on both the client request and the upstream
/// status line. An HTTP/1.0 client whose HTTP/1.1 upstream answers
/// close-delimited receives the stream close-delimited too, since it cannot
/// decode chunked framing. 0.1.x looked at the status line alone and sent
/// this client chunked output.
#[tokio::test]
async fn http_1_0_client_receives_close_delimited_stream_bytes_output() {
    let (_fixture, supervisor) = stream_guard(uppercase_units, "fail_closed").await;
    let exchange = supervisor
        .exchange(
            b"GET /v1/events HTTP/1.0\r\nHost: api.example.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: one\n\n",
        )
        .await;
    assert!(exchange.relay.is_ok(), "{:?}", exchange.relay);
    let head = header_lines(&exchange.client);
    assert!(
        !head
            .iter()
            .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding")),
        "{head:?}"
    );
    assert!(
        head.iter().any(|line| line == "Connection: close"),
        "{head:?}"
    );
    assert_eq!(body_of(&exchange.client), b"DATA: ONE\n\n");
}

fn fail_second_unit(unit: &HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult> {
    if unit.sequence == 2 {
        Reply::Fail(Status::internal("guard crashed"))
    } else {
        uppercase_units(unit)
    }
}

/// A legacy stream stage that fails mid-body under `fail_open` delivers the
/// unit it was given and the rest of the response uninspected. Under
/// `fail_closed` the committed response is aborted without a terminating
/// chunk.
#[tokio::test]
async fn stream_failure_mid_body_follows_on_error_at_the_relay() {
    for on_error in ["fail_open", "fail_closed"] {
        let (_fixture, supervisor) = stream_guard(fail_second_unit, on_error).await;
        let Tunnel {
            mut app,
            mut upstream,
            relay,
        } = supervisor.connect();
        app.write_all(SSE_REQUEST).await.expect("send request");
        within(read_http_request(&mut upstream))
            .await
            .expect("request reaches upstream");
        upstream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n",
            )
            .await
            .expect("send first unit");
        let mut delivered = Vec::new();
        read_until(&mut app, &mut delivered, b"3\r\nONE\r\n").await;
        upstream
            .write_all(b"3\r\ntwo\r\n")
            .await
            .expect("send second unit");

        if on_error == "fail_open" {
            read_until(&mut app, &mut delivered, b"3\r\ntwo\r\n").await;
            upstream
                .write_all(b"5\r\nthree\r\n0\r\n\r\n")
                .await
                .expect("send last unit");
            read_until(&mut app, &mut delivered, b"\r\n0\r\n\r\n").await;
            assert_eq!(dechunk(body_of(&delivered)), b"ONEtwothree");
            drop(app);
            within(relay)
                .await
                .expect("join relay")
                .expect("relay result");
        } else {
            delivered.extend(within(read_to_end(&mut app)).await);
            let delivered = String::from_utf8_lossy(&delivered);
            assert!(delivered.starts_with("HTTP/1.1 200 OK\r\n"), "{delivered}");
            assert!(
                delivered.ends_with("3\r\nONE\r\n"),
                "aborted without a terminator: {delivered}"
            );
            assert!(
                within(relay).await.expect("join relay").is_err(),
                "a post-commit failure aborts the relay"
            );
        }
    }
}

/// 0.1.x delivered the original response when the stream answered
/// `UNIMPLEMENTED` under `fail_open`. That contract failure now gets the
/// canonical 502 before commit regardless of `on_error`, and asks the
/// supervisor to describe its services again.
#[tokio::test]
async fn unimplemented_response_stream_fails_closed_at_the_relay() {
    let request: &[u8] =
        b"GET /v1/data HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n";
    let response: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

    for on_error in ["fail_open", "fail_closed"] {
        let (fixture, supervisor) = stream_guard(uppercase_units, on_error).await;
        fixture.set_unimplemented(LegacyRpc::HttpResponsePreReturn, true);
        let exchange = supervisor.exchange(request, response).await;
        assert!(
            exchange.client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
            "{on_error}"
        );
        assert_eq!(
            json_body(&exchange.client)["error"],
            "response_delivery_failed"
        );
        assert!(
            supervisor.engine.take_middleware_reconciliation_request(),
            "{on_error}"
        );
    }
}

async fn request_guard(on_error: &str) -> (RunningFixture, Supervisor) {
    let fixture = LegacyMiddlewareFixture::new("compat/request-guard")
        .with_binding(http_request_binding(16))
        .on_http_request(|_| results::replace_body("inspected").into())
        .spawn()
        .await
        .expect("spawn request fixture");
    let mut registration = registration("legacy-request-guard", &fixture);
    registration.max_payload_bytes = 16;
    // Evaluations held by the admission test must outlive its setup.
    registration.request_timeout = Some(prost_types::Duration {
        seconds: 30,
        nanos: 0,
    });
    let supervisor = Supervisor::start(
        &[Attachment {
            name: "request-guard",
            registration: "legacy-request-guard",
            order: 10,
            on_error,
        }],
        vec![registration],
    )
    .await;
    (fixture, supervisor)
}

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn post(body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

fn post_chunked(body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request.extend_from_slice(b"\r\n0\r\n\r\n");
    request
}

fn assert_middleware_failed(exchange: &Exchange) {
    let client = exchange.client_text();
    assert!(client.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{client}");
    let body = json_body(&exchange.client);
    assert_eq!(body["error"], "middleware_failed");
    assert_eq!(body["policy"], "rest_api");
    assert!(
        exchange.upstream.is_none(),
        "denied before upstream contact"
    );
}

/// A request body over the chain's largest legacy limit is never sent to the
/// service. A declared `Content-Length` has not been read yet, so an all
/// `fail_open` chain forwards it untouched. A chunked body has already been
/// consumed while measuring it, so it is denied even under `fail_open`.
#[tokio::test]
async fn over_capacity_request_bodies_depend_on_framing_and_on_error() {
    let oversized = [b'x'; 32];

    let (open_fixture, open) = request_guard("fail_open").await;
    let within_limit = open.exchange(&post(b"small"), OK_RESPONSE).await;
    let forwarded = within_limit.upstream.expect("request reaches upstream");
    assert_eq!(body_of(&forwarded), b"inspected");
    assert_eq!(open_fixture.http_requests().len(), 1);

    let recoverable = open.exchange(&post(&oversized), OK_RESPONSE).await;
    let forwarded = recoverable.upstream.expect("recoverable body is forwarded");
    assert_eq!(body_of(&forwarded), oversized);
    assert!(recoverable.client.starts_with(b"HTTP/1.1 200 OK\r\n"));

    let unrecoverable = open.exchange(&post_chunked(&oversized), OK_RESPONSE).await;
    assert_middleware_failed(&unrecoverable);
    assert_eq!(
        open_fixture.http_requests().len(),
        1,
        "over-capacity bodies never reach the service"
    );

    let (_closed_fixture, closed) = request_guard("fail_closed").await;
    assert_middleware_failed(&closed.exchange(&post(&oversized), OK_RESPONSE).await);
    assert_middleware_failed(
        &closed
            .exchange(&post_chunked(&oversized), OK_RESPONSE)
            .await,
    );
}

/// 0.1.x skipped a legacy stage that answered `UNIMPLEMENTED` under
/// `fail_open`. That contract failure now denies before upstream contact
/// regardless of `on_error`, and asks the supervisor to describe its services
/// again.
#[tokio::test]
async fn unimplemented_request_evaluation_fails_closed_at_the_relay() {
    for on_error in ["fail_open", "fail_closed"] {
        let (fixture, supervisor) = request_guard(on_error).await;
        fixture.set_unimplemented(LegacyRpc::EvaluateHttpRequest, true);
        assert_middleware_failed(&supervisor.exchange(&post(b"original"), OK_RESPONSE).await);
        assert!(
            supervisor.engine.take_middleware_reconciliation_request(),
            "{on_error}"
        );
    }
}

/// Each stage sees the head as earlier stages left it, credential headers are
/// never shown to services, and the upstream receives every stage's mutations
/// replayed in chain order against the original head.
#[tokio::test]
async fn header_mutations_are_visible_in_chain_order_and_reach_upstream() {
    let first = LegacyMiddlewareFixture::new("compat/first")
        .with_binding(http_request_binding(LIMIT))
        .on_http_request(|_| {
            results::mutate_headers(vec![
                results::write_header("x-shared", "first", ExistingHeaderAction::Overwrite),
                results::write_header("x-trace", "first", ExistingHeaderAction::Append),
                results::remove_header("x-drop"),
            ])
            .into()
        })
        .spawn()
        .await
        .expect("spawn first fixture");
    let second = LegacyMiddlewareFixture::new("compat/second")
        .with_binding(http_request_binding(LIMIT))
        .on_http_request(|_| {
            results::mutate_headers(vec![
                results::write_header("x-shared", "second", ExistingHeaderAction::Skip),
                results::write_header("x-trace", "second", ExistingHeaderAction::Append),
            ])
            .into()
        })
        .spawn()
        .await
        .expect("spawn second fixture");
    let supervisor = Supervisor::start(
        &[
            Attachment {
                name: "second",
                registration: "legacy-second",
                order: 20,
                on_error: "fail_closed",
            },
            Attachment {
                name: "first",
                registration: "legacy-first",
                order: 10,
                on_error: "fail_closed",
            },
        ],
        vec![
            registration("legacy-first", &first),
            registration("legacy-second", &second),
        ],
    )
    .await;

    let exchange = supervisor
        .exchange(
            b"POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer sk-not-for-middleware\r\nX-Shared: original\r\nX-Drop: gone\r\nX-Keep: kept\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            OK_RESPONSE,
        )
        .await;
    assert!(exchange.relay.is_ok(), "{:?}", exchange.relay);

    let seen = |fixture: &RunningFixture| -> Vec<(String, String)> {
        fixture.http_requests()[0]
            .headers
            .iter()
            .map(|header| (header.name.clone(), header.value.clone()))
            .collect()
    };
    let first_saw = seen(&first);
    assert!(
        !first_saw.iter().any(|(name, _)| name == "authorization"),
        "credential headers are omitted: {first_saw:?}"
    );
    assert_eq!(
        first_saw,
        [
            ("x-shared", "original"),
            ("x-drop", "gone"),
            ("x-keep", "kept"),
            ("content-type", "application/json"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()))
    );
    assert_eq!(
        seen(&second),
        [
            ("x-keep", "kept"),
            ("content-type", "application/json"),
            ("x-shared", "first"),
            ("x-trace", "first"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()))
    );

    let forwarded = exchange.upstream.expect("request reaches upstream");
    let lines = header_lines(&forwarded);
    assert!(lines.contains(&"Authorization: Bearer sk-not-for-middleware".to_string()));
    let middleware_visible: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|line| line.to_ascii_lowercase().starts_with("x-"))
        .collect();
    assert_eq!(
        middleware_visible,
        [
            "X-Keep: kept",
            "x-shared: first",
            "x-trace: first",
            "x-trace: second",
        ]
    );
}

/// When every middleware work slot is held and the bounded wait queue is
/// full, the next inspected request is shed with a 503 before its body is
/// read or the upstream is contacted. Held legacy evaluations complete once
/// the service answers.
#[tokio::test]
async fn exhausted_work_admission_sheds_requests_with_503() {
    let (fixture, supervisor) = request_guard("fail_closed").await;
    fixture.hold_http_requests();

    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_MIDDLEWARE_WORK {
        let Tunnel {
            mut app,
            mut upstream,
            relay,
        } = supervisor.connect();
        app.write_all(&post(b"held"))
            .await
            .expect("send held request");
        let upstream_task = tokio::spawn(async move {
            let received = read_http_request(&mut upstream).await;
            if received.is_some() {
                upstream.write_all(OK_RESPONSE).await.expect("respond");
                upstream.shutdown().await.expect("close upstream");
            }
            received
        });
        held.push((app, relay, upstream_task));
    }
    within(async {
        while fixture.held_http_requests() < MAX_CONCURRENT_MIDDLEWARE_WORK {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;

    let runner = supervisor
        .engine
        .middleware_runner()
        .expect("installed middleware runner");
    let mut waiters = Vec::new();
    for _ in 0..MAX_QUEUED_MIDDLEWARE_WORK {
        let runner = runner.clone();
        let mut waiter = Box::pin(async move { runner.reserve_middleware_work().await });
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        waiters.push(waiter);
    }

    let shed = supervisor
        .exchange(
            b"POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
            OK_RESPONSE,
        )
        .await;
    let client = shed.client_text();
    assert!(
        client.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "{client}"
    );
    assert!(!client.contains("100 Continue"), "{client}");
    assert_eq!(json_body(&shed.client)["error"], "middleware_failed");
    assert!(shed.upstream.is_none());
    assert_eq!(
        fixture.http_requests().len(),
        MAX_CONCURRENT_MIDDLEWARE_WORK
    );

    drop(waiters);
    fixture.release_http_requests();
    for (mut app, relay, upstream_task) in held {
        let response = within(read_to_end(&mut app)).await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        drop(app);
        within(relay)
            .await
            .expect("join relay")
            .expect("relay result");
        let forwarded = within(upstream_task)
            .await
            .expect("join upstream")
            .expect("held request reaches upstream");
        assert_eq!(body_of(&forwarded), b"inspected");
    }
}

/// Every inspected response holds one of the supervisor's session permits
/// until it ends. With every permit held by an open event stream, the next
/// inspected response is not a 503: it gets the canonical 502 under
/// `fail_closed` and is delivered uninspected under `fail_open`, without
/// contacting the service.
#[tokio::test]
async fn exhausted_response_sessions_follow_on_error_at_the_relay() {
    for on_error in ["fail_closed", "fail_open"] {
        let (fixture, supervisor) = stream_guard(uppercase_units, on_error).await;

        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_SESSIONS {
            let Tunnel {
                mut app,
                mut upstream,
                relay,
            } = supervisor.connect();
            app.write_all(SSE_REQUEST).await.expect("send request");
            within(read_http_request(&mut upstream))
                .await
                .expect("request reaches upstream");
            upstream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nc\r\ndata: open\n\n\r\n",
                )
                .await
                .expect("open event stream");
            let mut delivered = Vec::new();
            read_until(&mut app, &mut delivered, b"DATA: OPEN\n\n").await;
            held.push((app, upstream, relay));
        }

        let exchange = supervisor
            .exchange(
                b"GET /v1/data HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            )
            .await;
        if on_error == "fail_closed" {
            assert!(
                exchange.client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
                "{}",
                exchange.client_text()
            );
            assert_eq!(
                json_body(&exchange.client)["error"],
                "response_delivery_failed"
            );
        } else {
            assert!(exchange.client.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert_eq!(body_of(&exchange.client), b"hello", "delivered uninspected");
        }
        assert_eq!(
            fixture.response_sessions().len(),
            MAX_CONCURRENT_MIDDLEWARE_SESSIONS,
            "an exhausted budget never opens a stream"
        );

        for (app, mut upstream, relay) in held {
            upstream.write_all(b"0\r\n\r\n").await.expect("end stream");
            drop(upstream);
            drop(app);
            let _ = within(relay).await;
        }
    }
}

/// A `fail_open` attachment may select a `tls: skip` endpoint, which the
/// supervisor then relays raw without inspection. A `fail_closed` attachment
/// on the same endpoint is rejected when the supervisor loads the policy.
#[test]
fn tls_skip_endpoints_require_a_fail_open_selector() {
    let load = |on_error: &str| {
        let yaml = format!(
            "version: 1\n{}",
            policy_yaml(
                &[Attachment {
                    name: "guard",
                    registration: "legacy-guard",
                    order: 10,
                    on_error,
                }],
                "        tls: skip\n",
            )
        );
        let policy = openshell_policy::parse_sandbox_policy(&yaml).expect("parse policy");
        OpaEngine::from_proto(&policy)
    };

    let open = load("fail_open").expect("fail_open may select a tls: skip endpoint");
    let (chain, _) = open
        .query_middleware_chain_with_generation(&network_input())
        .expect("query middleware chain");
    assert_eq!(chain.len(), 1);
    assert_eq!(
        chain[0].on_error,
        openshell_supervisor_middleware::OnError::FailOpen
    );

    let error = load("fail_closed")
        .err()
        .expect("fail_closed conflicts with tls: skip");
    assert!(
        error
            .to_string()
            .contains("middleware conflicts with TLS inspection"),
        "{error}"
    );
}
