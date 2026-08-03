// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compatibility and regression contracts for the shared proxy egress pipeline.

use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn allowed_decision(intent: EgressIntent) -> EgressDecision {
    EgressDecision {
        intent,
        action: NetworkAction::Allow {
            matched_policy: Some("proxy_compatibility".to_string()),
        },
        l4_policy_generation: 0,
        identity: ProcessIdentityEvidence::Available,
        endpoint: EndpointDecision::default(),
        binary: Some(PathBuf::from("/usr/bin/curl")),
        binary_pid: Some(42),
        ancestors: vec![PathBuf::from("/usr/bin/sh")],
        cmdline_paths: vec![],
    }
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

fn assert_json_response(
    response: &[u8],
    expected_status: &str,
    expected_error: &str,
    expected_detail: &str,
) {
    let (headers, body) = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|end| (&response[..end + 4], &response[end + 4..]))
        .expect("complete HTTP response");
    let headers = String::from_utf8(headers.to_vec()).unwrap();
    assert!(headers.starts_with(expected_status));
    assert!(headers.contains("Content-Type: application/json\r\n"));
    assert!(headers.contains(&format!("Content-Length: {}\r\n", body.len())));
    assert!(headers.contains("Connection: close\r\n"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(body).unwrap(),
        serde_json::json!({
            "error": expected_error,
            "detail": expected_detail,
        })
    );
}

#[tokio::test]
async fn destination_denials_preserve_adapter_specific_wire_contracts() {
    let cases = [
        (
            DestinationDenialKind::TrustedGateway,
            "trusted-gateway check failed",
        ),
        (
            DestinationDenialKind::InvalidAllowedIps,
            "invalid allowed_ips in policy",
        ),
        (
            DestinationDenialKind::AllowedIps,
            "allowed_ips check failed",
        ),
        (
            DestinationDenialKind::DeclaredEndpoint,
            "declared endpoint check failed",
        ),
        (DestinationDenialKind::InternalAddress, "internal address"),
    ];

    for (kind, detail) in cases {
        let denial = DestinationDenial {
            kind,
            reason: "proxy compatibility destination failure".to_string(),
        };
        let peer: SocketAddr = "127.0.0.1:41000".parse().unwrap();

        let (mut app, mut proxy) = tcp_pair().await;
        deny_connect_destination(
            &mut proxy,
            &denial,
            peer,
            "target.example",
            8443,
            "/usr/bin/curl",
            "42",
            "/usr/bin/sh",
            "curl",
            &allowed_decision(EgressIntent::connect("target.example".to_string(), 8443)),
            &None,
            &None,
        )
        .await
        .unwrap();
        proxy.shutdown().await.unwrap();
        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert_json_response(
            &response,
            "HTTP/1.1 403 Forbidden\r\n",
            "ssrf_denied",
            &format!("CONNECT target.example:8443 blocked: {detail}"),
        );

        let (mut app, mut proxy) = tcp_pair().await;
        deny_forward_destination(
            &mut proxy,
            &denial,
            peer,
            "POST",
            "target.example",
            8080,
            "/v1/items",
            "/usr/bin/curl",
            "42",
            "/usr/bin/sh",
            "curl",
            "proxy_compatibility",
            &allowed_decision(EgressIntent::forward_http(
                "target.example".to_string(),
                8080,
            )),
            None,
            None,
        )
        .await
        .unwrap();
        proxy.shutdown().await.unwrap();
        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert_json_response(
            &response,
            "HTTP/1.1 403 Forbidden\r\n",
            "ssrf_denied",
            &format!("POST target.example:8080 blocked: {detail}"),
        );
    }
}

#[test]
fn representative_adapter_denials_preserve_ocsf_fields() {
    let denial_reason = "target.example resolves to internal address 10.0.0.5";
    let denial = DestinationDenial {
        kind: DestinationDenialKind::InternalAddress,
        reason: denial_reason.to_string(),
    };
    let peer: SocketAddr = "127.0.0.1:41000".parse().unwrap();

    // Build the production events directly rather than routing through the
    // global tracing pipeline. Its callsite-interest cache is process-global,
    // so parallel tests can otherwise make captured-event assertions flaky.
    let connect = serde_json::to_value(build_connect_destination_deny_ocsf_event(
        &denial,
        peer,
        "target.example",
        8443,
        "/usr/bin/curl",
        "42",
        "/usr/bin/sh",
        "curl --proxy",
    ))
    .unwrap();
    assert_eq!(connect["class_name"], "Network Activity");
    assert_eq!(connect["activity_name"], "Open");
    assert_eq!(connect["action"], "Denied");
    assert_eq!(connect["disposition"], "Blocked");
    assert_eq!(connect["severity"], "Medium");
    assert_eq!(connect["status"], "Failure");
    assert_eq!(connect["dst_endpoint"]["domain"], "target.example");
    assert_eq!(connect["dst_endpoint"]["port"], 8443);
    assert_eq!(connect["actor"]["process"]["name"], "/usr/bin/curl");
    assert_eq!(connect["actor"]["process"]["pid"], 42);
    assert_eq!(connect["firewall_rule"]["name"], "-");
    assert_eq!(connect["firewall_rule"]["type"], "ssrf");
    assert_eq!(
        connect["message"],
        "CONNECT blocked: internal address target.example:8443"
    );
    assert_eq!(connect["status_detail"], denial_reason);

    let forward = serde_json::to_value(build_forward_destination_deny_ocsf_event(
        &denial,
        peer,
        "POST",
        "target.example",
        8080,
        "/v1/items",
        "/usr/bin/curl",
        "42",
        "/usr/bin/sh",
        "curl --proxy",
        "proxy_compatibility",
    ))
    .unwrap();
    assert_eq!(forward["class_name"], "HTTP Activity");
    assert_eq!(forward["activity_name"], "Other");
    assert_eq!(forward["action"], "Denied");
    assert_eq!(forward["disposition"], "Blocked");
    assert_eq!(forward["severity"], "Medium");
    assert_eq!(forward["status"], "Failure");
    assert_eq!(forward["dst_endpoint"]["domain"], "target.example");
    assert_eq!(forward["dst_endpoint"]["port"], 8080);
    assert_eq!(forward["http_request"]["http_method"], "POST");
    assert_eq!(forward["firewall_rule"]["name"], "proxy_compatibility");
    assert_eq!(forward["firewall_rule"]["type"], "ssrf");
    assert_eq!(
        forward["message"],
        "FORWARD blocked: internal IP without allowed_ips for target.example:8080"
    );
    assert_eq!(forward["status_detail"], denial_reason);
}

#[test]
fn representative_adapter_allows_preserve_ocsf_fields() {
    let peer: SocketAddr = "127.0.0.1:41000".parse().unwrap();
    let connect = serde_json::to_value(build_connect_allow_ocsf_event(
        peer,
        "target.example",
        8443,
        "/usr/bin/curl",
        "42",
        "/usr/bin/sh",
        "curl --proxy",
        "proxy_compatibility",
        true,
    ))
    .unwrap();
    assert_eq!(connect["class_name"], "Network Activity");
    assert_eq!(connect["activity_name"], "Open");
    assert_eq!(connect["action"], "Allowed");
    assert_eq!(connect["disposition"], "Allowed");
    assert_eq!(connect["severity"], "Informational");
    assert_eq!(connect["status"], "Success");
    assert_eq!(connect["dst_endpoint"]["domain"], "target.example");
    assert_eq!(connect["dst_endpoint"]["port"], 8443);
    assert_eq!(connect["actor"]["process"]["name"], "/usr/bin/curl");
    assert_eq!(connect["firewall_rule"]["name"], "proxy_compatibility");
    assert_eq!(connect["firewall_rule"]["type"], "opa");
    assert_eq!(connect["message"], "CONNECT_L7 allowed target.example:8443");

    let forward = serde_json::to_value(build_forward_allow_ocsf_event(
        peer,
        "GET",
        "target.example",
        8080,
        "/v1/items",
        "/usr/bin/curl",
        "42",
        "/usr/bin/sh",
        "curl --proxy",
        "proxy_compatibility",
    ))
    .unwrap();
    assert_eq!(forward["class_name"], "HTTP Activity");
    assert_eq!(forward["activity_name"], "Other");
    assert_eq!(forward["action"], "Allowed");
    assert_eq!(forward["disposition"], "Allowed");
    assert_eq!(forward["severity"], "Informational");
    assert_eq!(forward["status"], "Success");
    assert_eq!(forward["dst_endpoint"]["domain"], "target.example");
    assert_eq!(forward["dst_endpoint"]["port"], 8080);
    assert_eq!(forward["http_request"]["http_method"], "GET");
    assert_eq!(forward["firewall_rule"]["name"], "proxy_compatibility");
    assert_eq!(forward["firewall_rule"]["type"], "opa");
    assert_eq!(
        forward["message"],
        "FORWARD allowed GET target.example:8080/v1/items"
    );
}

fn poisoned_engine() -> OpaEngine {
    let engine = OpaEngine::from_strings(
        include_str!("../../../data/sandbox-policy.rego"),
        r#"
network_policies:
  proxy_compatibility:
    name: proxy_compatibility
    endpoints:
      - host: target.example
        port: 443
        protocol: rest
        enforcement: enforce
        tls: skip
        allowed_ips: ["10.0.0.0/8"]
        rules:
          - allow: { method: GET, path: "/**" }
    binaries:
      - path: /usr/bin/curl
"#,
    )
    .unwrap();
    engine.poison_lock_for_test();
    engine
}

#[test]
fn l7_query_failure_preserves_l4_only_fallback() {
    let engine = poisoned_engine();
    let decision = allowed_decision(EgressIntent::connect("target.example".to_string(), 443));
    assert!(query_l7_route_snapshot(&engine, &decision, "target.example", 443).is_none());
}

#[test]
fn tls_query_failure_preserves_auto_fallback() {
    let engine = poisoned_engine();
    let decision = allowed_decision(EgressIntent::connect("target.example".to_string(), 443));
    assert_eq!(
        query_tls_mode(&engine, &decision, "target.example", 443),
        crate::l7::TlsMode::Auto
    );
}

#[test]
fn allowed_ips_query_failure_preserves_empty_fallback() {
    let engine = poisoned_engine();
    let decision = allowed_decision(EgressIntent::connect("target.example".to_string(), 443));
    assert!(query_allowed_ips(&engine, &decision, "target.example", 443).is_empty());
}

#[test]
fn exact_host_query_failure_preserves_false_fallback() {
    let engine = poisoned_engine();
    let decision = allowed_decision(EgressIntent::connect("target.example".to_string(), 443));
    assert!(!query_exact_declared_endpoint_host(
        &engine,
        &decision,
        "target.example",
        443
    ));
}

#[test]
fn identity_required_policy_accepts_real_binary_and_rejects_empty_exec_path() {
    let engine = OpaEngine::from_strings(
        include_str!("../../../data/sandbox-policy.rego"),
        r#"
network_policies:
  proxy_compatibility:
    name: proxy_compatibility
    endpoints:
      - host: target.example
        port: 443
    binaries:
      - path: /usr/bin/curl
"#,
    )
    .unwrap();
    let input = |binary_path: PathBuf| crate::opa::NetworkInput {
        host: "target.example".to_string(),
        port: 443,
        binary_path,
        binary_sha256: String::new(),
        ancestors: vec![],
        cmdline_paths: vec![],
    };

    assert!(matches!(
        engine
            .evaluate_network_action(&input(PathBuf::from("/usr/bin/curl")))
            .unwrap(),
        NetworkAction::Allow { .. }
    ));
    assert!(matches!(
        engine
            .evaluate_network_action(&input(PathBuf::new()))
            .unwrap(),
        NetworkAction::Deny { .. }
    ));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn identity_required_mode_is_explicitly_unsupported_off_linux() {
    let engine = OpaEngine::from_strings(
        include_str!("../../../data/sandbox-policy.rego"),
        "network_policies: {}\n",
    )
    .unwrap();
    let decision = authorize_egress_intent(
        crate::procfs::WorkloadProxyTcpConnection::new(
            "127.0.0.1:41000".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        ),
        &engine,
        &BinaryIdentityCache::new(),
        &AtomicU32::new(1),
        EgressIntent::connect("target.example".to_string(), 443),
    );

    assert!(matches!(decision.action, NetworkAction::Deny { .. }));
    assert_eq!(
        decision.identity,
        ProcessIdentityEvidence::Unavailable(IdentityUnavailableReason::UnsupportedPlatform)
    );
}

#[test]
fn forward_rewrite_does_not_treat_a_pipelined_request_as_body_overflow() {
    let raw = b"GET http://target.example/allowed HTTP/1.1\r\n\
                Host: target.example\r\n\
                Connection: keep-alive\r\n\r\n\
                POST http://target.example/blocked HTTP/1.1\r\n\
                Host: target.example\r\n\
                Content-Length: 0\r\n\r\n";
    let rewritten =
        rewrite_forward_request(raw, raw.len(), "/allowed", "target.example", None, false).unwrap();
    let rewritten = String::from_utf8(rewritten).unwrap();

    assert!(rewritten.starts_with("GET /allowed HTTP/1.1\r\n"));
    assert!(rewritten.contains("Connection: close\r\n"));
    assert!(!rewritten.contains("POST http://target.example/blocked"));
}

#[test]
fn forward_rewrite_trims_pipeline_after_content_length_body() {
    let raw = b"POST http://target.example/allowed HTTP/1.1\r\n\
                Host: target.example\r\n\
                Content-Length: 4\r\n\r\n\
                body\
                GET http://target.example/blocked HTTP/1.1\r\n\
                Host: target.example\r\n\r\n";
    let rewritten =
        rewrite_forward_request(raw, raw.len(), "/allowed", "target.example", None, false).unwrap();
    let rewritten = String::from_utf8(rewritten).unwrap();

    assert!(rewritten.ends_with("\r\n\r\nbody"));
    assert!(!rewritten.contains("GET http://target.example/blocked"));
}

#[test]
fn forward_rewrite_trims_pipeline_after_complete_chunked_body() {
    let raw = b"POST http://target.example/allowed HTTP/1.1\r\n\
                Host: target.example\r\n\
                Transfer-Encoding: chunked\r\n\r\n\
                4\r\nbody\r\n0\r\n\r\n\
                GET http://target.example/blocked HTTP/1.1\r\n\
                Host: target.example\r\n\r\n";
    let rewritten =
        rewrite_forward_request(raw, raw.len(), "/allowed", "target.example", None, false).unwrap();
    let rewritten = String::from_utf8(rewritten).unwrap();

    assert!(rewritten.ends_with("4\r\nbody\r\n0\r\n\r\n"));
    assert!(!rewritten.contains("GET http://target.example/blocked"));
}

#[tokio::test]
async fn forward_https_absolute_form_rejection_is_snapshotted() {
    let (response, denial_stages) = drive_forward_through_handler(
        "      - { host: \"target.example\", port: 443 }\n",
        "https://target.example/private",
    )
    .await;

    assert_eq!(
        response,
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\nUse CONNECT for HTTPS URLs"
    );
    assert!(denial_stages.is_empty());
}

async fn exercise_benchmark_request(proxy_addr: SocketAddr, target: SocketAddr, connect: bool) {
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let authority = target.to_string();
    let request = if connect {
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
    } else {
        format!(
            "GET http://{authority}/proxy-baseline HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        )
    };
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403 Forbidden"));
}

/// Run with:
/// `cargo test -p openshell-supervisor-network proxy_performance_baseline -- --ignored --nocapture --test-threads=1`
#[test]
#[ignore = "manual proxy allocation/query/latency baseline"]
fn proxy_performance_baseline() {
    temp_env::with_vars(
        [(
            openshell_core::sandbox_env::NETWORK_BINARY_IDENTITY,
            Some("endpoint-only"),
        )],
        || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    // Benchmark the full fail-closed path using a declared loopback
                    // destination. This is deterministic and never opens a listener
                    // outside the local process, so it does not trigger host firewall
                    // prompts during manual baseline collection.
                    let target: SocketAddr = "127.0.0.1:18080".parse().unwrap();

                    let policy = format!(
                        r#"
network_policies:
  proxy_compatibility:
    name: proxy_compatibility
    endpoints:
      - host: {host}
        port: {port}
        tls: skip
    binaries:
      - path: "/**"
"#,
                        host = target.ip(),
                        port = target.port(),
                    );
                    let engine = Arc::new(
                        OpaEngine::from_strings_with_binary_identity_required(
                            include_str!("../../../data/sandbox-policy.rego"),
                            &policy,
                            false,
                        )
                        .unwrap(),
                    );
                    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let proxy_addr = proxy_listener.local_addr().unwrap();
                    let proxy_engine = engine.clone();
                    let proxy_task = tokio::spawn(async move {
                        while let Ok((stream, _)) = proxy_listener.accept().await {
                            let engine = proxy_engine.clone();
                            tokio::spawn(async move {
                                Box::pin(handle_tcp_connection(
                                    stream,
                                    engine,
                                    Arc::new(BinaryIdentityCache::new()),
                                    Arc::new(AtomicU32::new(0)),
                                    None,
                                    None,
                                    None,
                                    AgentProposals::default(),
                                    Arc::new(None),
                                    Arc::new(None),
                                    None,
                                    None,
                                    None,
                                    None,
                                ))
                                .await
                                .unwrap();
                            });
                        }
                    });

                    for connect in [true, false] {
                        exercise_benchmark_request(proxy_addr, target, connect).await;
                    }

                    let iterations = std::env::var("OPENSHELL_PROXY_BASELINE_ITERATIONS")
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|value| *value > 0)
                        .unwrap_or(25);
                    let mut results = serde_json::Map::new();
                    for (name, connect) in [("connect", true), ("forward", false)] {
                        crate::test_alloc::reset();
                        crate::opa::reset_test_opa_query_count();
                        let started = std::time::Instant::now();
                        for _ in 0..iterations {
                            exercise_benchmark_request(proxy_addr, target, connect).await;
                        }
                        let elapsed = started.elapsed();
                        let queries = crate::opa::test_opa_query_count();
                        let (allocations, allocated_bytes) = crate::test_alloc::snapshot();
                        let expected_queries = 4;
                        assert_eq!(queries, expected_queries * iterations);
                        results.insert(
                            name.to_string(),
                            serde_json::json!({
                                "allocated_bytes_per_request": allocated_bytes / iterations,
                                "allocations_per_request": allocations / iterations,
                                "latency_ns_per_request": elapsed.as_nanos() / u128::from(iterations),
                                "opa_queries_per_request": queries / iterations,
                            }),
                        );
                    }
                    println!(
                        "{}",
                        serde_json::json!({
                            "iterations": iterations,
                            "proxy_performance_baseline": results,
                            "scenario": "declared_loopback_destination_denied",
                            "schema_version": 1,
                        })
                    );

                    proxy_task.abort();
                });
        },
    );
}
