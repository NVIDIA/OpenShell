// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::provider::{BodyLength, L7Request};
use crate::opa::{NetworkInput, OpaEngine};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const REQUEST: &[u8] =
    b"POST /mcp HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 2\r\n\r\n{}";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

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

#[tokio::test]
async fn keep_alive_propagates_upstream_idle_close_over_tcp() {
    timeout(Duration::from_secs(5), async {
        for inspected in [false, true] {
            let engine = OpaEngine::from_strings(
                include_str!("../../../data/sandbox-policy.rego"),
                r"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 80
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: POST, path: /mcp }
    binaries:
      - { path: /usr/bin/curl }
",
            )
            .unwrap();
            let (mut app, mut client) = tcp_pair().await;
            let (mut relay_upstream, mut upstream) = tcp_pair().await;
            let relay = tokio::spawn(async move {
                let ctx = context();
                if inspected {
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
                    let evaluator = engine.clone_engine_for_tunnel(generation).unwrap();
                    relay_with_inspection(
                        &config,
                        evaluator,
                        &mut client,
                        &mut relay_upstream,
                        &ctx,
                    )
                    .await
                } else {
                    let guard = engine
                        .generation_guard(engine.current_generation())
                        .unwrap();
                    relay_passthrough_with_credentials(
                        &mut client,
                        &mut relay_upstream,
                        &ctx,
                        &guard,
                        Some(&engine),
                    )
                    .await
                }
            });
            // Healthy keep-alive must still carry more than one complete exchange.
            for _ in 0..2 {
                app.write_all(REQUEST).await.unwrap();
                read_exact_message(&mut upstream, REQUEST).await;
                upstream.write_all(RESPONSE).await.unwrap();
                read_exact_message(&mut app, RESPONSE).await;
            }
            upstream.shutdown().await.unwrap();
            // Do not send another request: FIN must propagate while the client is idle.
            let mut rest = Vec::new();
            app.read_to_end(&mut rest).await.unwrap();
            assert!(
                rest.is_empty(),
                "idle close must not invent an HTTP response"
            );
            relay.await.unwrap().unwrap();
        }
    })
    .await
    .expect("idle upstream close must reach the client promptly");
}

#[tokio::test]
async fn queued_request_after_upstream_close_returns_502() {
    timeout(Duration::from_secs(5), async {
        let engine = OpaEngine::from_strings(
            include_str!("../../../data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let (mut app, mut client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        // Both requests are buffered before the relay starts. When the first
        // response arrives, request two and the upstream close are ready together.
        app.write_all(&[REQUEST, REQUEST].concat()).await.unwrap();
        let relay = tokio::spawn(async move {
            let guard = engine
                .generation_guard(engine.current_generation())
                .unwrap();
            relay_passthrough_with_credentials(
                &mut client,
                &mut relay_upstream,
                &context(),
                &guard,
                Some(&engine),
            )
            .await
        });
        read_exact_message(&mut upstream, REQUEST).await;
        upstream.write_all(RESPONSE).await.unwrap();
        drop(upstream);
        let mut received = Vec::new();
        app.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [RESPONSE, BAD_GATEWAY].concat());
        relay.await.unwrap().unwrap();
    })
    .await
    .expect("queued request must receive an explicit gateway error");
}

#[tokio::test]
async fn upstream_failure_returns_502_only_before_response_starts() {
    timeout(Duration::from_secs(5), async {
        for response in [
            None,           // Upstream disappeared before the first write.
            Some(&b""[..]), // Request was accepted, then upstream closed without responding.
            Some(&b"HTTP/1.1 100 Continue\r\n\r\n"[..]),
            Some(&b"HTTP/1.1 200"[..]),
            Some(&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nOK"[..]),
            Some(&b"HTTP/1.0 200 OK\r\n\r\nOK"[..]), // Valid close-delimited response.
        ] {
            let (mut app, mut client) = tokio::io::duplex(8192);
            let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
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
            let relay = tokio::spawn(async move {
                let req = L7Request {
                    action: "POST".into(),
                    target: "/mcp".into(),
                    query_params: HashMap::new(),
                    raw_header: REQUEST.to_vec(),
                    body_length: BodyLength::ContentLength(2),
                };
                relay_http_request_with_credential_rejection(
                    &req,
                    &mut client,
                    &mut relay_upstream,
                    crate::l7::rest::RelayRequestOptions::default(),
                    &context(),
                    None,
                )
                .await
            });
            let mut received = Vec::new();
            app.read_to_end(&mut received).await.unwrap();
            let result = relay.await.unwrap();
            if response.is_none_or(<[u8]>::is_empty) {
                assert_eq!(received, BAD_GATEWAY);
                assert!(result.unwrap().is_none());
            } else {
                let expected = if response == Some(&b"HTTP/1.0 200 OK\r\n\r\nOK"[..]) {
                    &b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nOK"[..]
                } else {
                    response.unwrap()
                };
                assert_eq!(received, expected);
                assert!(
                    !received
                        .windows(15)
                        .any(|bytes| bytes == b"502 Bad Gateway")
                );
            }
            if let Some(server) = server {
                server.await.unwrap();
            }
        }
    })
    .await
    .expect("failed upstream exchange must close promptly");
}

#[tokio::test]
async fn client_body_eof_is_not_an_upstream_failure() {
    timeout(Duration::from_secs(5), async {
        let (mut app, mut client) = tokio::io::duplex(8192);
        let (mut relay_upstream, _upstream) = tokio::io::duplex(8192);
        app.shutdown().await.unwrap();
        let req = L7Request {
            action: "POST".into(),
            target: "/mcp".into(),
            query_params: HashMap::new(),
            raw_header: REQUEST[..REQUEST.len() - 2].to_vec(),
            body_length: BodyLength::ContentLength(2),
        };
        let error = relay_http_request_with_credential_rejection(
            &req,
            &mut client,
            &mut relay_upstream,
            crate::l7::rest::RelayRequestOptions::default(),
            &context(),
            None,
        )
        .await
        .expect_err("client did not provide its declared body");
        assert!(
            error
                .downcast_ref::<crate::l7::rest::UpstreamHttpError>()
                .is_none()
        );
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
        let event = build_upstream_http_failure_event(&context(), "POST", response_started);
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
