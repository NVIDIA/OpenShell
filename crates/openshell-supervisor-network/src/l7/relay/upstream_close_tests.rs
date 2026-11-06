// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::opa::{NetworkInput, OpaEngine};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const REQUEST: &[u8] =
    b"POST /mcp HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 2\r\n\r\n{}";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";

fn context() -> L7EvalContext {
    L7EvalContext {
        host: "api.example.test".into(),
        port: 80,
        request_default_port: Some(80),
        policy_name: "rest_api".into(),
        binary_path: "/usr/bin/curl".into(),
        ..Default::default()
    }
}

async fn read_exact_message<S: AsyncRead + Unpin>(stream: &mut S, expected: &[u8]) {
    let mut bytes = vec![0; expected.len()];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, expected);
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    openshell_core::net::set_tcp_nodelay_best_effort(&client);
    openshell_core::net::set_tcp_nodelay_best_effort(&server);
    (client, server)
}

async fn relay_fixture<C, U>(protocol: &str, mut client: C, mut upstream: U) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ctx = context();
    let policy_protocol = if protocol == "passthrough" {
        "rest"
    } else {
        protocol
    };
    let rule = if policy_protocol == "rest" {
        serde_json::json!({"method":"POST", "path":"/mcp"})
    } else {
        serde_json::json!({"method":"initialize"})
    };
    let data = serde_json::json!({"network_policies": {"rest_api": {
        "name":"rest_api", "endpoints":[{"host":ctx.host, "port":ctx.port,
            "path":"/mcp", "protocol":policy_protocol, "enforcement":"enforce", "rules":[{"allow":rule}]}],
        "binaries":[{"path":ctx.binary_path}]
    }}});
    let engine = OpaEngine::from_strings(
        include_str!("../../../data/sandbox-policy.rego"),
        &data.to_string(),
    )
    .unwrap();
    if protocol == "passthrough" {
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        relay_passthrough_with_credentials(&mut client, &mut upstream, &ctx, &guard, Some(&engine))
            .await
    } else {
        let input = NetworkInput {
            host: ctx.host.clone(),
            port: ctx.port,
            binary_path: PathBuf::from(&ctx.binary_path),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&config.unwrap()).unwrap();
        relay_with_inspection(
            &config,
            engine.clone_engine_for_tunnel(generation).unwrap(),
            &mut client,
            &mut upstream,
            &ctx,
        )
        .await
    }
}

fn assert_bad_gateway(bytes: &[u8]) {
    let response = std::str::from_utf8(bytes).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "{response:?}"
    );
    assert!(response.contains("Content-Length: 0\r\n"));
    assert!(response.ends_with("Connection: close\r\n\r\n"));
    let prefix = format!(
        "{}: ",
        openshell_core::token_grant_failure::REQUEST_ID_HEADER
    );
    let id = response
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("correlation header");
    uuid::Uuid::parse_str(id).unwrap();
}

#[tokio::test]
async fn keep_alive_propagates_upstream_idle_close_over_tcp() {
    timeout(Duration::from_secs(5), async {
        for protocol in ["passthrough", "rest", "json-rpc", "mcp"] {
            let body = if matches!(protocol, "json-rpc" | "mcp") {
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
            } else { "{}" };
            let request = format!("POST /mcp HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            let (mut app, client) = tcp_pair().await;
            let (relay_upstream, mut upstream) = tcp_pair().await;
            let relay = tokio::spawn(relay_fixture(protocol, client, relay_upstream));
            for _ in 0..2 {
                app.write_all(request.as_bytes()).await.unwrap();
                read_exact_message(&mut upstream, request.as_bytes()).await;
                upstream.write_all(RESPONSE).await.unwrap();
                read_exact_message(&mut app, RESPONSE).await;
            }
            upstream.shutdown().await.unwrap();
            let mut rest = Vec::new();
            app.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "idle close must not invent an HTTP response");
            relay.await.unwrap().unwrap();
        }
    }).await.expect("idle upstream close must reach the client promptly");
}

#[tokio::test]
async fn queued_request_handles_upstream_close_without_replay() {
    timeout(Duration::from_secs(5), async {
        // None closes before request two is forwarded (BrokenPipe). The other
        // cases accept it, then close before or during the response headers.
        for protocol in ["passthrough", "rest"] {
            for (response, expect_gateway) in [
                (None, true),
                (Some(&b""[..]), true),
                (Some(&b"HTTP/1.1 100 Continue\r\n\r\n"[..]), false),
                (Some(&b"HTTP/1.1 200"[..]), true),
                (
                    Some(&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nOK"[..]),
                    false,
                ),
                (
                    Some(&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n"[..]),
                    false,
                ),
            ] {
                let (mut app, client) = tokio::io::duplex(8192);
                let (relay_upstream, mut upstream) = tokio::io::duplex(8192);
                // Buffer both requests so request two and the upstream close can
                // become ready together after the first successful exchange.
                app.write_all(&[REQUEST, REQUEST].concat()).await.unwrap();
                let relay = tokio::spawn(relay_fixture(protocol, client, relay_upstream));
                read_exact_message(&mut upstream, REQUEST).await;
                upstream.write_all(RESPONSE).await.unwrap();
                let server = response.map(|response| {
                    tokio::spawn(async move {
                        read_exact_message(&mut upstream, REQUEST).await;
                        upstream.write_all(response).await.unwrap();
                        upstream.shutdown().await.unwrap();
                        let mut extra = Vec::new();
                        upstream.read_to_end(&mut extra).await.unwrap();
                        assert!(extra.is_empty(), "POST must not be replayed");
                    })
                });
                let mut received = Vec::new();
                app.read_to_end(&mut received).await.unwrap();
                assert!(received.starts_with(RESPONSE));
                if expect_gateway {
                    assert_bad_gateway(&received[RESPONSE.len()..]);
                } else {
                    assert_eq!(&received[RESPONSE.len()..], response.unwrap());
                }
                relay.await.unwrap().unwrap();
                if let Some(server) = server {
                    server.await.unwrap();
                }
            }
        }
    })
    .await
    .expect("queued request must finish with a response or a clean close");
}

#[tokio::test]
async fn client_body_eof_is_not_an_upstream_failure() {
    timeout(Duration::from_secs(5), async {
        let engine = OpaEngine::from_strings(
            include_str!("../../../data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let (mut app, mut client) = tokio::io::duplex(8192);
        let (mut relay_upstream, _upstream) = tokio::io::duplex(8192);
        app.write_all(&REQUEST[..REQUEST.len() - 2]).await.unwrap();
        app.shutdown().await.unwrap();
        relay_passthrough_with_credentials(
            &mut client,
            &mut relay_upstream,
            &context(),
            &guard,
            Some(&engine),
        )
        .await
        .expect_err("client did not provide its declared body");
        drop(client);
        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert!(
            response.is_empty(),
            "client error must not be reported as a 502"
        );
    })
    .await
    .expect("client EOF must terminate the exchange");
}

#[test]
fn upstream_failure_event_reports_502_without_request_secrets() {
    for response_started in [false, true] {
        let event = build_upstream_http_failure_event(
            &context(),
            "POST",
            (!response_started).then_some(502),
        );
        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 4002);
        assert_eq!(json["status_detail"], "upstream_http_transport_failure");
        assert_eq!(json["http_request"]["http_method"], "POST");
        assert!(json["http_request"].get("url").is_none());
        if response_started {
            assert!(json.get("http_response").is_none());
        } else {
            assert_eq!(json["http_response"]["code"], 502);
        }
        openshell_ocsf_validate::validate_event(&json).unwrap();
    }
}

// A reset after a scripted prefix covers the error path separately from FIN.
struct ResetAfterPrefix(&'static [u8], bool);
impl AsyncRead for ResetAfterPrefix {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.0.is_empty() {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        } else {
            let n = this.0.len().min(buf.remaining());
            buf.put_slice(&this.0[..n]);
            this.0 = &this.0[n..];
            std::task::Poll::Ready(Ok(()))
        }
    }
}
impl AsyncWrite for ResetAfterPrefix {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.get_mut().1 = true;
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn upstream_reset_uses_client_commitment_and_preserves_cause() {
    timeout(Duration::from_secs(5), async {
        for (prefix, committed) in [
            (&b""[..], false),
            (&b"HTTP/1.1 200"[..], false),
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nOK"[..], true),
        ] {
            let (mut app, mut client) = tokio::io::duplex(8192);
            let mut upstream = ResetAfterPrefix(prefix, false);
            let request = crate::l7::rest::request_from_buffered_http(
                "POST",
                "/mcp",
                "/mcp",
                REQUEST.to_vec(),
            )
            .unwrap();
            let report =
                crate::l7::rest::relay_http_request_with_response_middleware_guarded_observed(
                    &request,
                    &mut client,
                    &mut upstream,
                    crate::l7::rest::RelayRequestOptions::default(),
                    None,
                    None,
                )
                .await
                .expect_err("scripted upstream reset");
            assert!(
                report
                    .chain()
                    .any(|cause| cause.to_string().to_lowercase().contains("reset")),
                "original I/O cause must remain available: {report:?}"
            );
            let error = report
                .downcast_ref::<crate::l7::rest::UpstreamHttpError>()
                .unwrap();
            assert_eq!(error.response_started, committed);
            let request_id = "9b8a7f6e-5d4c-4b3a-9f8e-7d6c5b4a3f2e";
            handle_upstream_http_error(
                &mut client,
                &mut upstream,
                &context(),
                "POST",
                Some(request_id),
                error,
            )
            .await
            .unwrap();
            assert!(upstream.1, "failed upstream must be shut down");
            drop(client);
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            if committed {
                assert_eq!(response, prefix);
            } else {
                assert_bad_gateway(&response);
                assert!(std::str::from_utf8(&response).unwrap().contains(request_id));
            }
        }
    })
    .await
    .expect("reset must terminate the exchange");
}

#[tokio::test]
async fn ready_request_does_not_consume_unsolicited_upstream_response() {
    for unsolicited in [false, true] {
        let (mut upstream, mut server) = tokio::io::duplex(1024);
        if unsolicited {
            server.write_all(RESPONSE).await.unwrap();
        } else {
            server.shutdown().await.unwrap();
        }
        let result =
            parse_next_http_request(std::future::ready(Ok(Some(()))), &mut upstream, &context())
                .await
                .unwrap();
        assert_eq!(
            result.is_none(),
            unsolicited,
            "EOF must retain the request for the 502 path; unsolicited data must close"
        );
    }
}
