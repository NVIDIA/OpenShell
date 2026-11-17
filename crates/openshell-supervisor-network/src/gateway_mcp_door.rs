// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local door to the gateway's MCP endpoint.
//!
//! The workload reaches `http://openshell.local/mcp`. The supervisor forwards
//! the request body to the gateway's `/mcp` over one gateway connection the
//! door opens on first use and then reuses, with the sandbox's own
//! credentials attached to each request. The workload never holds a gateway
//! credential.

use crate::policy_local::PolicyLocalContext;
use bytes::Bytes;
use http_body_util::BodyExt;
use miette::{IntoDiagnostic, Result};
use openshell_ocsf::{ActivityId, HttpActivityBuilder, HttpRequest, SeverityId, StatusId};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tower::ServiceExt;

pub const DOOR_HOST: &str = "openshell.local";
const DOOR_PATH: &str = "/mcp";
/// Largest request body the door forwards.
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Largest gateway reply the door holds in memory.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Covers the gateway's 45 second tool limit with margin.
const GATEWAY_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);
/// Door requests one sandbox may have open at once, so a workload cannot
/// flood the gateway through its supervisor.
const MAX_CONCURRENT_REQUESTS: usize = 8;
/// Request headers copied from the workload. Identity headers are never copied.
const FORWARDED_HEADERS: [&str; 3] = ["content-type", "accept", "mcp-protocol-version"];

/// Whether `host` (a Host header or proxy target, with optional `:80`) names the door.
pub fn is_door_host(host: &str) -> bool {
    host.eq_ignore_ascii_case(DOOR_HOST) || host.eq_ignore_ascii_case("openshell.local:80")
}

/// The single Host header of a raw HTTP request, when there is exactly one.
pub fn request_host(initial_request: &[u8]) -> Option<String> {
    let mut hosts = header_values(initial_request, "host");
    let host = hosts.next()?;
    hosts.next().is_none().then_some(host)
}

/// Serve one door request. The caller has already matched the door host.
pub async fn handle<S>(
    ctx: &PolicyLocalContext,
    method: &str,
    target: &str,
    initial_request: &[u8],
    client: &mut S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // A browser in the sandbox attaches Origin; only the door's own origin is
    // accepted. Agents send none.
    if let Some(origin) = header_values(initial_request, "origin").next()
        && !is_door_host(
            origin
                .trim_end_matches('/')
                .strip_prefix("http://")
                .unwrap_or(""),
        )
    {
        return refuse(client, method, 403, "origin not allowed").await;
    }
    let path = target.split('?').next().unwrap_or(target);
    if path != DOOR_PATH {
        return refuse(
            client,
            method,
            404,
            "only /mcp is served at openshell.local",
        )
        .await;
    }
    if method != "POST" {
        return refuse(client, method, 405, "openshell.local/mcp accepts POST only").await;
    }
    if crate::policy_local::declared_body_len(initial_request).unwrap_or(0) > MAX_REQUEST_BYTES {
        return refuse(
            client,
            method,
            413,
            "request body is larger than the 2 MiB openshell.local/mcp accepts",
        )
        .await;
    }
    let door = ctx.mcp_door();
    let Ok(_slot) = door.slots.try_acquire() else {
        return refuse(
            client,
            method,
            503,
            "too many gateway requests at once; try again",
        )
        .await;
    };
    let body =
        crate::policy_local::read_request_body(initial_request, client, MAX_REQUEST_BYTES).await?;
    let Some(gateway) = ctx.gateway() else {
        return refuse(
            client,
            method,
            503,
            "this sandbox has no gateway connection",
        )
        .await;
    };

    let mut request = http::Request::builder().method("POST").uri(DOOR_PATH);
    for name in FORWARDED_HEADERS {
        if let Some(value) = header_values(initial_request, name).next() {
            request = request.header(name, value);
        }
    }
    let request = request
        .body(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::from(body),
        )))
        .into_diagnostic()?;

    match tokio::time::timeout(GATEWAY_TIMEOUT, forward(door, gateway, request)).await {
        Ok(Ok((status, content_type, reply))) => {
            emit_door_event(
                method,
                status,
                SeverityId::Informational,
                StatusId::Success,
                "forwarded to the gateway",
            );
            respond(client, status, &content_type, &reply).await
        }
        Ok(Err(Forward::TooLarge)) => {
            refuse(
                client,
                method,
                502,
                "the gateway reply is larger than the door accepts",
            )
            .await
        }
        Ok(Err(Forward::Refused(error))) => {
            tracing::warn!(%error, "openshell.local: gateway request refused locally");
            refuse(
                client,
                method,
                502,
                "this sandbox's gateway credentials are not available",
            )
            .await
        }
        Ok(Err(Forward::Unreachable(error))) => {
            tracing::warn!(%error, "openshell.local: gateway request failed");
            refuse(client, method, 502, "gateway unreachable").await
        }
        Err(_) => refuse(client, method, 504, "the gateway did not answer in time").await,
    }
}

enum Forward {
    Unreachable(String),
    TooLarge,
    /// The request was refused before it reached `/mcp`, such as by the
    /// credential interceptor once the sandbox's token is revoked.
    Refused(String),
}

/// The door's gateway connection and request slots, shared by every door
/// request of one sandbox.
pub struct DoorConnection {
    /// Opened on first use and reused: one HTTP/2 connection carries every
    /// request. The interceptor reads the sandbox's token slot on each
    /// request, so a renewed token is used without reconnecting.
    channel: tokio::sync::Mutex<Option<openshell_core::grpc_client::AuthedChannel>>,
    slots: tokio::sync::Semaphore,
}

impl Default for DoorConnection {
    fn default() -> Self {
        Self {
            channel: tokio::sync::Mutex::new(None),
            slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_REQUESTS),
        }
    }
}

impl DoorConnection {
    async fn channel(
        &self,
        gateway: &openshell_core::grpc_client::GatewayEndpoint,
    ) -> std::result::Result<openshell_core::grpc_client::AuthedChannel, Forward> {
        let mut cached = self.channel.lock().await;
        if let Some(channel) = cached.as_ref() {
            return Ok(channel.clone());
        }
        let channel = openshell_core::grpc_client::connect_channel_pub(gateway)
            .await
            .map_err(|e| Forward::Unreachable(e.to_string()))?;
        *cached = Some(channel.clone());
        Ok(channel)
    }

    /// Drop the cached connection after a transport failure, so the next
    /// request connects again.
    async fn discard(&self) {
        *self.channel.lock().await = None;
    }
}

/// POST to the gateway's `/mcp` over the door's gateway connection, which
/// shares TLS settings, the gateway address and the token slot with gRPC.
async fn forward(
    door: &DoorConnection,
    gateway: &openshell_core::grpc_client::GatewayEndpoint,
    request: http::Request<tonic::body::Body>,
) -> std::result::Result<(u16, String, Vec<u8>), Forward> {
    let channel = door.channel(gateway).await?;
    let response = match channel.oneshot(request).await {
        Ok(response) => response,
        Err(error) => {
            door.discard().await;
            return Err(Forward::Unreachable(error.to_string()));
        }
    };
    // `/mcp` never answers with gRPC status. One here comes from the channel
    // itself, which reports a refusal as an empty gRPC reply, not as an error.
    if let Some(code) = response
        .headers()
        .get("grpc-status")
        .filter(|code| code.as_bytes() != b"0")
    {
        let message = response
            .headers()
            .get("grpc-message")
            .and_then(|message| message.to_str().ok())
            .unwrap_or_default();
        return Err(Forward::Refused(format!(
            "grpc-status {}: {message}",
            String::from_utf8_lossy(code.as_bytes())
        )));
    }
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let mut body = response.into_body();
    let mut reply = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                door.discard().await;
                return Err(Forward::Unreachable(error.to_string()));
            }
        };
        if let Some(data) = frame.data_ref() {
            if reply.len() + data.len() > MAX_RESPONSE_BYTES {
                return Err(Forward::TooLarge);
            }
            reply.extend_from_slice(data);
        }
    }
    Ok((status, content_type, reply))
}

/// Refuse a CONNECT to the door, which only speaks plain HTTP.
pub async fn refuse_connect<S: AsyncWrite + Unpin>(client: &mut S) -> Result<()> {
    refuse(
        client,
        "CONNECT",
        400,
        "openshell.local is plain HTTP on port 80",
    )
    .await
}

/// Answer with `status` and a plain-text `message`, logged as a refusal.
pub(crate) async fn refuse<S: AsyncWrite + Unpin>(
    client: &mut S,
    method: &str,
    status: u16,
    message: &str,
) -> Result<()> {
    emit_door_event(method, status, SeverityId::Low, StatusId::Failure, message);
    respond(client, status, "text/plain", message.as_bytes()).await
}

async fn respond<S: AsyncWrite + Unpin>(
    client: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client.write_all(head.as_bytes()).await.into_diagnostic()?;
    client.write_all(body).await.into_diagnostic()?;
    client.flush().await.into_diagnostic()
}

fn header_values<'a>(
    initial_request: &'a [u8],
    wanted: &'a str,
) -> impl Iterator<Item = String> + 'a {
    let head_end = initial_request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(initial_request.len());
    std::str::from_utf8(&initial_request[..head_end])
        .unwrap_or("")
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(move |(name, _)| name.trim().eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.trim().to_string())
}

fn emit_door_event(
    method: &str,
    response_code: u16,
    severity: SeverityId,
    status: StatusId,
    message: &str,
) {
    crate::telemetry::egress_emit!(build_door_event(
        method,
        response_code,
        severity,
        status,
        message
    ));
}

fn build_door_event(
    method: &str,
    response_code: u16,
    severity: SeverityId,
    status: StatusId,
    message: &str,
) -> openshell_ocsf::OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::for_http_method(method))
        .http_request(HttpRequest {
            http_method: method.parse().expect("HTTP method parsing is infallible"),
            url: None,
        })
        .http_response(openshell_ocsf::HttpResponse {
            code: response_code,
        })
        .severity(severity)
        .status(status)
        .message(format!("openshell.local: {message}"))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::grpc_client::{GatewayCredentials, GatewayEndpoint};
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncReadExt;

    fn context(gateway: Option<GatewayEndpoint>) -> PolicyLocalContext {
        PolicyLocalContext::new(
            None,
            gateway,
            None,
            openshell_core::proposals::AgentProposals::new(false),
            tokio::sync::watch::channel(String::new()).1,
        )
    }

    /// Run one request through the door and return the raw response.
    async fn door(ctx: &PolicyLocalContext, request: &[u8]) -> String {
        let head = std::str::from_utf8(request).unwrap();
        let mut line = head.split_whitespace();
        let (method, target) = (line.next().unwrap(), line.next().unwrap());
        let (mut client, mut workload) = tokio::io::duplex(8 * 1024 * 1024);
        handle(ctx, method, target, request, &mut client)
            .await
            .unwrap();
        drop(client);
        let mut response = Vec::new();
        workload.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    #[test]
    fn only_openshell_local_on_port_80_is_the_door() {
        assert!(is_door_host("openshell.local"));
        assert!(is_door_host("OpenShell.Local:80"));
        assert!(!is_door_host("policy.local"));
        assert!(!is_door_host("openshell.local:8080"));
        assert!(!is_door_host("attacker.example"));
    }

    #[test]
    fn door_events_are_valid_ocsf_and_carry_no_body_or_token() {
        for (method, code, severity, status) in [
            ("POST", 200, SeverityId::Informational, StatusId::Success),
            ("GET", 405, SeverityId::Low, StatusId::Failure),
            ("CONNECT", 400, SeverityId::Low, StatusId::Failure),
        ] {
            let json = serde_json::to_value(build_door_event(method, code, severity, status, "x"))
                .unwrap();
            assert_eq!(json["http_response"]["code"], code);
            assert!(json["http_request"].get("url").is_none());
            openshell_ocsf_validate::validate_event(&json).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn a_request_needs_exactly_one_host() {
        let one = b"POST /mcp HTTP/1.1\r\nHost: openshell.local\r\n\r\n";
        let none = b"POST /mcp HTTP/1.1\r\n\r\n";
        let two = b"POST /mcp HTTP/1.1\r\nHost: openshell.local\r\nHost: evil\r\n\r\n";
        assert_eq!(request_host(one).as_deref(), Some("openshell.local"));
        assert_eq!(request_host(none), None);
        assert_eq!(request_host(two), None);
    }

    #[tokio::test]
    async fn the_door_refuses_what_it_does_not_serve() {
        let ctx = context(None);
        let cases: [(&[u8], &str); 5] = [
            (b"POST /other HTTP/1.1\r\nHost: openshell.local\r\n\r\n", "404"),
            (b"GET /mcp HTTP/1.1\r\nHost: openshell.local\r\n\r\n", "405"),
            (
                b"POST /mcp HTTP/1.1\r\nHost: openshell.local\r\nOrigin: http://evil.example\r\n\r\n",
                "403",
            ),
            (
                b"POST /mcp HTTP/1.1\r\nHost: openshell.local\r\nContent-Length: 3000000\r\n\r\n",
                "413",
            ),
            (b"POST /mcp HTTP/1.1\r\nHost: openshell.local\r\nContent-Length: 2\r\n\r\n{}", "503"),
        ];
        for (request, status) in cases {
            let response = door(&ctx, request).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{response}"
            );
        }
    }

    type Seen = Arc<Mutex<Option<(http::HeaderMap, Bytes)>>>;

    /// A plaintext HTTP/2 server that records one request and answers with `reply`.
    async fn fake_gateway(reply: Vec<u8>) -> (GatewayEndpoint, Seen) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let recorder = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (recorder, reply) = (recorder.clone(), reply.clone());
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: http::Request<hyper::body::Incoming>| {
                            let (recorder, reply) = (recorder.clone(), reply.clone());
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = body.collect().await.unwrap().to_bytes();
                                *recorder.lock().unwrap() = Some((parts.headers, body));
                                Ok::<_, std::convert::Infallible>(
                                    http::Response::builder()
                                        .header("content-type", "application/json")
                                        .body(http_body_util::Full::new(Bytes::from(reply)))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
                });
            }
        });
        let credentials = GatewayCredentials::from_gateway_token("sandbox-token").unwrap();
        (
            GatewayEndpoint::new(format!("http://{address}"), credentials),
            seen,
        )
    }

    #[tokio::test]
    async fn the_door_forwards_with_the_sandbox_token_and_only_mcp_headers() {
        let (gateway, seen) =
            fake_gateway(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec()).await;
        let ctx = context(Some(gateway));
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"q":"a b $HOME"}}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: openshell.local\r\nAuthorization: Bearer agent-token\r\nCookie: a=b\r\nContent-Type: application/json\r\nMcp-Protocol-Version: 2025-11-25\r\nMcp-Session-Id: s1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = door(&ctx, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#));

        let (headers, forwarded) = seen
            .lock()
            .unwrap()
            .take()
            .expect("gateway saw the request");
        assert_eq!(forwarded, body.as_bytes());
        assert_eq!(headers["authorization"], "Bearer sandbox-token");
        assert_eq!(headers["mcp-protocol-version"], "2025-11-25");
        assert_eq!(headers["content-type"], "application/json");
        assert!(headers.get("cookie").is_none());
        assert!(headers.get("mcp-session-id").is_none());
    }

    #[tokio::test]
    async fn the_door_refuses_an_oversized_gateway_reply() {
        let (gateway, _) = fake_gateway(vec![b'x'; MAX_RESPONSE_BYTES + 1]).await;
        let ctx = context(Some(gateway));
        let response = door(
            &ctx,
            b"POST /mcp HTTP/1.1\r\nHost: openshell.local\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    }

    const PING: &[u8] =
        b"POST /mcp HTTP/1.1\r\nHost: openshell.local\r\nContent-Length: 2\r\n\r\n{}";

    /// A plaintext HTTP/2 gateway that counts the connections it accepts,
    /// can drop them all, and answers each request only once `replies`
    /// grants a permit.
    struct CountingGateway {
        endpoint: GatewayEndpoint,
        connections: Arc<std::sync::atomic::AtomicUsize>,
        requests: Arc<std::sync::atomic::AtomicUsize>,
        replies: Arc<tokio::sync::Semaphore>,
        open: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    }

    impl CountingGateway {
        async fn start(replies: usize) -> Self {
            use std::sync::atomic::Ordering;

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let replies = Arc::new(tokio::sync::Semaphore::new(replies));
            let open: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
            let (counted, seen, gate, tasks) = (
                connections.clone(),
                requests.clone(),
                replies.clone(),
                open.clone(),
            );
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    counted.fetch_add(1, Ordering::SeqCst);
                    let (seen, gate) = (seen.clone(), gate.clone());
                    let task = tokio::spawn(async move {
                        let service = hyper::service::service_fn(
                            move |_: http::Request<hyper::body::Incoming>| {
                                let (seen, gate) = (seen.clone(), gate.clone());
                                async move {
                                    seen.fetch_add(1, Ordering::SeqCst);
                                    gate.acquire().await.unwrap().forget();
                                    Ok::<_, std::convert::Infallible>(
                                        http::Response::builder()
                                            .header("content-type", "application/json")
                                            .body(http_body_util::Full::new(Bytes::from_static(
                                                b"{}",
                                            )))
                                            .unwrap(),
                                    )
                                }
                            },
                        );
                        let _ = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                    });
                    tasks.lock().unwrap().push(task.abort_handle());
                }
            });
            let credentials = GatewayCredentials::from_gateway_token("sandbox-token").unwrap();
            Self {
                endpoint: GatewayEndpoint::new(format!("http://{address}"), credentials),
                connections,
                requests,
                replies,
                open,
            }
        }

        fn connections(&self) -> usize {
            self.connections.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Close every connection the gateway holds, as a restart would.
        fn drop_connections(&self) {
            for task in self.open.lock().unwrap().drain(..) {
                task.abort();
            }
        }
    }

    #[tokio::test]
    async fn door_requests_share_one_gateway_connection() {
        let gateway = CountingGateway::start(usize::MAX >> 4).await;
        let ctx = context(Some(gateway.endpoint.clone()));

        for _ in 0..5 {
            let response = door(&ctx, PING).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }

        assert_eq!(gateway.connections(), 1);
    }

    #[tokio::test]
    async fn the_door_reconnects_after_the_gateway_drops_its_connection() {
        let gateway = CountingGateway::start(usize::MAX >> 4).await;
        let ctx = context(Some(gateway.endpoint.clone()));
        assert!(door(&ctx, PING).await.starts_with("HTTP/1.1 200"));

        gateway.drop_connections();

        // The request on the dropped connection may fail once; the next one
        // must reach the gateway on a new connection.
        let mut response = door(&ctx, PING).await;
        if !response.starts_with("HTTP/1.1 200") {
            response = door(&ctx, PING).await;
        }
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(gateway.connections(), 2);
    }

    #[tokio::test]
    async fn the_door_refuses_at_once_when_every_slot_is_busy() {
        let gateway = CountingGateway::start(0).await;
        let ctx = Arc::new(context(Some(gateway.endpoint.clone())));
        let busy: Vec<_> = (0..MAX_CONCURRENT_REQUESTS)
            .map(|_| {
                let ctx = ctx.clone();
                tokio::spawn(async move { door(&ctx, PING).await })
            })
            .collect();
        while gateway.requests.load(std::sync::atomic::Ordering::SeqCst) < MAX_CONCURRENT_REQUESTS {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let response = tokio::time::timeout(std::time::Duration::from_secs(1), door(&ctx, PING))
            .await
            .expect("refused at once, not queued");
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.ends_with("too many gateway requests at once; try again"));

        // Finished requests free their slots.
        gateway.replies.add_permits(MAX_CONCURRENT_REQUESTS + 1);
        for request in busy {
            assert!(request.await.unwrap().starts_with("HTTP/1.1 200"));
        }
        assert!(door(&ctx, PING).await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn a_reused_connection_reads_the_token_slot_on_every_request() {
        let gateway = CountingGateway::start(usize::MAX >> 4).await;
        let ctx = context(Some(gateway.endpoint.clone()));
        assert!(door(&ctx, PING).await.starts_with("HTTP/1.1 200"));

        // Renewal and revocation write the same slot. Revoking shows the
        // cached connection does not keep the token it was opened with.
        gateway.endpoint.credentials().revoke();
        let before = gateway.requests.load(std::sync::atomic::Ordering::SeqCst);
        let response = door(&ctx, PING).await;

        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(response.ends_with("this sandbox's gateway credentials are not available"));
        assert_eq!(
            gateway.requests.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "the request never reached the gateway"
        );
    }
}
