// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::request_tracing::{RequestTracing, span_attribute};
use crate::test_support::response_request_id;
use opentelemetry_sdk::trace::Sampler;
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::SubscriberExt as _;

const WORKLOAD_TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const WORKLOAD_SPAN_ID: &str = "00f067aa0ba902b7";

#[derive(Clone, Copy)]
enum Outcome {
    Allowed,
    PolicyDenied,
    MalformedQueryPolicyDenied,
    AuditDenied,
    UnresolvedCredential,
    UpstreamClosed,
}

fn assert_request_record_sequence(records: &[serde_json::Value], receipt: &str) {
    for (index, record) in records.iter().enumerate() {
        assert_eq!(
            record["metadata"]["correlation_uid"], receipt,
            "{records:?}"
        );
        assert_eq!(
            record["unmapped"]["request_sequence"],
            index + 1,
            "{records:?}"
        );
        assert_eq!(
            record["unmapped"]["http_event_kind"], "decision",
            "{records:?}"
        );
    }
}

#[tokio::test]
async fn shared_proxy_startup_registers_correlation_and_terminal_errors() {
    use crate::l7::tls::{CertCache, SandboxCa, tls_terminate_client};
    use openshell_isolation_interface::contract::DuplexStream;
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};

    const CHILD: &str = "OPENSHELL_REQUEST_CORRELATION_STARTUP_CHILD";
    const COMPLETED: &str = "shared proxy startup and terminal regressions completed";
    if std::env::var_os(CHILD).is_none() {
        // A fresh process prevents scope_connection's cfg(test) auto-init (or
        // another fixture) from hiding a missing production startup hook.
        let module = module_path!().split_once("::").unwrap().1;
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!(
                        "{module}::shared_proxy_startup_registers_correlation_and_terminal_errors"
                    ),
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("isolated startup regression must finish")
        .expect("start isolated startup regression");
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains(COMPLETED),
            "isolated startup regression failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let ip = non_loopback_test_ipv4()
        .expect("shared proxy regression requires a non-loopback IPv4 address");
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let engine = Arc::new(
        native_identity_engine(
            include_str!("../../../data/sandbox-policy.rego"),
            &format!(
                r#"
network_policies:
  traced_api:
    name: traced_api
    endpoints:
      - host: "{ip}"
        port: {port}
        allowed_ips: ["{ip}/32"]
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {{ method: GET, path: /allowed }}
    binaries:
      - path: /usr/bin/python3
"#
            ),
        )
        .unwrap(),
    );
    let ca = SandboxCa::generate().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(&mut ca.cert_pem().as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let client_config = Arc::new(
        openshell_crypto::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tls = Arc::new(ProxyTlsState::new(
        CertCache::new(ca),
        client_config.clone(),
    ));
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    // Production accept/connection tasks are spawned independently; the
    // isolated process gives them the same subscriber without test wrappers.
    tracing::subscriber::set_global_default(
        capture
            .subscriber()
            .with(openshell_otel::supervisor_span_filter("info")),
    )
    .unwrap();
    let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
    let proxy = ProxyHandle::start_with_bind_addr(
        &ProxyPolicy { http_addr: None },
        Some(([127, 0, 0, 1], 0).into()),
        engine,
        Arc::new(BinaryIdentityCache::new()),
        Arc::new(AtomicU32::new(0)),
        Some(tls.clone()),
        None,
        None,
        None,
        None,
        None,
        ready_rx,
        &upstream_proxy::UpstreamProxyArgs::default(),
        None,
        None,
        None,
        Some(ContractBinaryIdentity {
            executable: ContractExecutableIdentity {
                path: executable_path("/usr/bin/python3"),
                digest: Some("00".repeat(32).parse().unwrap()),
            },
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        }),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(
        !openshell_ocsf::register_event_enricher(|_| {}),
        "shared proxy startup must register correlation before the first request"
    );
    ready_tx.send(true).unwrap();

    let scenario = async {
        // One exchange per real terminal emission boundary, not a sampler or
        // transport matrix. Each fails only after the client receives its ID.
        for (connect, encrypted, terminal_prefix) in [
            (false, false, "Proxy connection error: "),
            (true, false, "L7 relay error: "),
            (true, true, "TLS relay error: "),
        ] {
            let (release, released) = tokio::sync::oneshot::channel();
            let serve = async {
                let (upstream, _) = listener.accept().await.unwrap();
                let hostname = ip.to_string();
                let mut upstream: Box<dyn DuplexStream + '_> = if encrypted {
                    Box::new(
                        tls_terminate_client(upstream, &tls, &hostname)
                            .await
                            .unwrap(),
                    )
                } else {
                    Box::new(upstream)
                };
                let request = read_http_headers(&mut upstream).await;
                assert!(String::from_utf8_lossy(&request).starts_with("GET /allowed HTTP/1.1\r\n"));
                upstream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                upstream.flush().await.unwrap();
                released.await.unwrap();
                upstream.write_all(b"ok").await.unwrap();
                // Clean TLS EOF too: the HTTP declared-length failure must
                // reach the non-benign outer relay-error callsite.
                upstream.shutdown().await.unwrap();
            };
            let exchange = async {
                let mut client = connect_tcp_nodelay_best_effort(proxy.http_addr().unwrap())
                    .await
                    .unwrap();
                if connect {
                    client
                        .write_all(
                            format!("CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                    let established = read_http_headers(&mut client).await;
                    assert!(established.starts_with(b"HTTP/1.1 200 Connection Established\r\n"));
                }
                let mut client: BoundaryDuplexStream = if encrypted {
                    Box::new(
                        tokio_rustls::TlsConnector::from(client_config.clone())
                            .connect(ServerName::try_from(ip.to_string()).unwrap(), client)
                            .await
                            .unwrap(),
                    )
                } else {
                    Box::new(client)
                };
                let target = if connect {
                    "/allowed".to_string()
                } else {
                    format!("http://{ip}:{port}/allowed")
                };
                client
                    .write_all(
                        format!("GET {target} HTTP/1.1\r\nHost: {ip}:{port}\r\ntraceparent: 00-{WORKLOAD_TRACE_ID}-{WORKLOAD_SPAN_ID}-01\r\nx-openshell-request-id: forged-receipt\r\nConnection: close\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                client.flush().await.unwrap();
                let response = read_http_headers(&mut client).await;
                assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
                let receipt = response_request_id(&response).to_string();
                assert!(uuid::Uuid::parse_str(&receipt).is_ok());
                release.send(()).unwrap();
                let mut body = Vec::new();
                // The downstream TLS stream may omit close_notify when its
                // failed HTTP relay drops it. The captured event is the oracle.
                let _ = client.read_to_end(&mut body).await;
                assert_eq!(body, b"ok");
                receipt
            };
            let ((), receipt) = tokio::join!(serve, exchange);
            let (records, root) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                loop {
                    let records = capture.events.json_events();
                    let root = capture.spans().into_iter().find(|span| {
                        span.name == "openshell.http.request"
                            && span_attribute(span, "openshell.request.id")
                                .is_some_and(|value| value.as_str() == receipt)
                    });
                    if let Some(root) = root
                        && records.iter().any(|record| {
                            record["message"]
                                .as_str()
                                .is_some_and(|message| message.starts_with(terminal_prefix))
                                && record["metadata"]["correlation_uid"] == receipt
                        })
                    {
                        break (records, root);
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("actual outer terminal record must retain the failed request receipt");
            let correlated = records
                .iter()
                .filter(|record| record["metadata"]["correlation_uid"] == receipt)
                .collect::<Vec<_>>();
            assert_eq!(correlated.len(), 2, "{records:?}");
            for (index, record) in correlated.iter().enumerate() {
                assert_eq!(
                    record["unmapped"]["request_sequence"],
                    index + 1,
                    "{records:?}"
                );
            }
            let terminal = correlated.last().unwrap();
            assert!(
                terminal["message"]
                    .as_str()
                    .unwrap()
                    .starts_with(terminal_prefix)
            );
            assert!(
                terminal["message"]
                    .as_str()
                    .unwrap()
                    .contains("2 bytes remaining")
            );
            assert_eq!(terminal["class_uid"], 4001);
            assert_eq!(terminal["unmapped"]["http_event_kind"], "connection");
            assert_ne!(receipt, "forged-receipt");
            assert_ne!(root.span_context.trace_id().to_string(), WORKLOAD_TRACE_ID);
            assert_eq!(root.parent_span_id, opentelemetry::trace::SpanId::INVALID);
            assert_eq!(root.links.links.len(), 1);
            assert!(matches!(
                root.status,
                opentelemetry::trace::Status::Error { .. }
            ));
            for decision in &correlated[..correlated.len() - 1] {
                assert_eq!(
                    decision["trace"]["uid"],
                    root.span_context.trace_id().to_string()
                );
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), scenario)
        .await
        .expect("real proxy terminal-error exchanges must finish");
    assert!(
        !capture
            .created_span_names()
            .contains(&"supervisor.egress.deny")
    );
    drop(proxy);
    capture.shutdown();
    println!("{COMPLETED}");
}

async fn forward_case(ip: Ipv4Addr, outcome: Outcome, sampler: Option<Sampler>) {
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let policy_denied = matches!(
        outcome,
        Outcome::PolicyDenied | Outcome::MalformedQueryPolicyDenied
    );
    let credential_failure = matches!(outcome, Outcome::UnresolvedCredential);
    let secret_resolver = credential_failure.then(|| {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("OTHER_KEY".into(), "inert-test-value".into())]
                .into_iter()
                .collect(),
        );
        Arc::new(resolver.expect("test credential resolver"))
    });
    let mode = if matches!(outcome, Outcome::AuditDenied) {
        "audit"
    } else {
        "enforce"
    };
    let path = if policy_denied || matches!(outcome, Outcome::AuditDenied) {
        "/blocked"
    } else {
        "/allowed"
    };
    let engine = Arc::new(
        native_identity_engine(
            include_str!("../../../data/sandbox-policy.rego"),
            &format!(
                r#"
network_policies:
  traced_api:
    name: traced_api
    endpoints:
      - host: "{ip}"
        port: {port}
        allowed_ips: ["{ip}/32"]
        protocol: rest
        enforcement: {mode}
        rules:
          - allow: {{ method: GET, path: /allowed }}
    binaries:
      - path: /usr/bin/python3
"#
            ),
        )
        .unwrap(),
    );
    let identity = Ok(ContractBinaryIdentity {
        executable: ContractExecutableIdentity {
            path: executable_path("/usr/bin/python3"),
            digest: Some("00".repeat(32).parse().unwrap()),
        },
        ancestors: Vec::new(),
        cmdline_paths: vec![executable_path("/workspace/investigate.py")],
    });
    let expect_export = matches!(sampler, Some(Sampler::AlwaysOn));
    let capture = RequestTracing::new(sampler);
    let subscriber = capture
        .subscriber()
        .with(openshell_otel::supervisor_span_filter("info"));
    let (mut app, proxy) = tokio::io::duplex(8192);
    let mut proxy: ProxyClient = tokio::io::BufReader::new(Box::new(proxy));
    let query = if matches!(outcome, Outcome::MalformedQueryPolicyDenied) {
        "token=%ff"
    } else {
        "token=SENTINEL-QUERY"
    };
    let target = format!("http://{ip}:{port}{path}?{query}");
    let credential_header = if credential_failure {
        "Authorization: Bearer openshell:resolve:env:MISSING\r\n"
    } else {
        ""
    };
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {ip}:{port}\r\ntraceparent: 00-{WORKLOAD_TRACE_ID}-{WORKLOAD_SPAN_ID}-01\r\ntracestate: vendor=SENTINEL-VENDOR\r\nx-openshell-request-id: forged-receipt\r\n{credential_header}Connection: close\r\n\r\n"
    );
    let exchange = async {
        tokio::join!(
            async {
                let result = Box::pin(handle_forward_proxy(
                    "GET",
                    &target,
                    request.as_bytes(),
                    request.len(),
                    &mut proxy,
                    Some(&identity),
                    Some((
                        "192.0.2.20:42123".parse().unwrap(),
                        "192.0.2.10:3128".parse().unwrap(),
                    )),
                    engine,
                    Arc::new(BinaryIdentityCache::new()),
                    Arc::new(AtomicU32::new(0)),
                    None,
                    AgentProposals::default(),
                    Arc::new(None),
                    Arc::new(None),
                    None,
                    secret_resolver,
                    None,
                    None,
                    None,
                ))
                .await;
                drop(proxy);
                result
            },
            async {
                if policy_denied || credential_failure {
                    assert!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(50),
                            listener.accept()
                        )
                        .await
                        .is_err(),
                        "rejected request reached upstream"
                    );
                } else {
                    let (mut upstream, _) = listener.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        bytes.push(upstream.read_u8().await.unwrap());
                    }
                    assert!(
                        String::from_utf8_lossy(&bytes)
                            .starts_with(&format!("GET {path}?token=SENTINEL-QUERY HTTP/1.1\r\n"))
                    );
                    assert!(!String::from_utf8_lossy(&bytes).contains("forged-receipt"));
                    if !matches!(outcome, Outcome::UpstreamClosed) {
                        upstream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
                    }
                }
            },
            async {
                let mut response = Vec::new();
                app.read_to_end(&mut response).await.unwrap();
                response
            },
        )
    };
    let (result, (), response) =
        async { tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange)).await }
            .with_subscriber(subscriber)
            .await
            .unwrap();
    result.unwrap();
    let spans = capture.spans();
    let expected = (!matches!(outcome, Outcome::UpstreamClosed)).then_some(if policy_denied {
        403
    } else if credential_failure {
        500
    } else {
        200
    });
    let response = String::from_utf8(response).unwrap();
    let records = capture.events.json_events();
    let expected_records = if policy_denied || credential_failure {
        1
    } else {
        2
    };
    assert_eq!(records.len(), expected_records, "{records:?}");
    assert!(records.iter().all(|record| record["class_uid"] == 4002));
    let record = &records[0];
    let decision = match outcome {
        Outcome::PolicyDenied | Outcome::MalformedQueryPolicyDenied => "deny",
        Outcome::AuditDenied => "audit",
        Outcome::Allowed | Outcome::UnresolvedCredential | Outcome::UpstreamClosed => "allow",
    };
    assert!(
        record["message"]
            .as_str()
            .unwrap()
            .starts_with(&format!("FORWARD_L7 {decision} GET "))
    );
    assert_eq!(record["firewall_rule"]["type"], "l7");
    assert!(record.get("status_id").is_none());
    assert!(record.get("status_detail").is_none());
    for control in &records {
        assert_eq!(control["http_request"]["url"]["path"], path);
        assert!(control.get("http_response").is_none());
    }
    if !policy_denied && !credential_failure {
        let forwarded = &records[1];
        assert!(
            forwarded["message"]
                .as_str()
                .unwrap()
                .starts_with("FORWARD allowed GET ")
        );
        assert_eq!(forwarded["firewall_rule"]["type"], "opa");
        assert_eq!(forwarded["action_id"], 1);
        assert_eq!(forwarded["status_id"], 1);
    }
    let receipt = record["metadata"]["correlation_uid"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(receipt).is_ok());
    assert_request_record_sequence(&records, receipt);
    assert!(!format!("{records:?}").contains("SENTINEL"));
    assert!(!format!("{records:?}").contains("forged-receipt"));
    assert!(!format!("{records:?}").contains("%ff"));
    if let Some(expected) = expected {
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected} ")),
            "{response}"
        );
        assert_eq!(response_request_id(response.as_bytes()), receipt);
        if policy_denied {
            let (_, body) = response.split_once("\r\n\r\n").unwrap();
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(body["error"], "policy_denied");
            assert!(
                body["detail"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("GET {ip}:{port}{path} denied by L7 policy: "))
            );
            assert_eq!(body.as_object().unwrap().len(), 2);
        }
    } else {
        assert!(
            response.is_empty(),
            "upstream EOF must not synthesize a response"
        );
    }
    assert_eq!(record["action_id"], if policy_denied { 2 } else { 1 });
    let created = capture.created_span_names();
    assert!(
        !created.contains(&"supervisor.egress.deny"),
        "inspected paths must never create a deny-only span"
    );
    assert_eq!(
        created
            .iter()
            .filter(|name| **name == "openshell.http.request")
            .count(),
        1
    );
    let roots = spans
        .iter()
        .filter(|span| span.name == "openshell.http.request")
        .collect::<Vec<_>>();
    assert_eq!(
        roots.len(),
        usize::from(expect_export),
        "local sampler/export configuration controls request span export"
    );
    if roots.is_empty() {
        assert!(spans.is_empty());
        assert!(records.iter().all(|record| record.get("trace").is_none()));
    } else {
        assert_eq!(roots.len(), 1);
        let root = roots[0];
        assert_eq!(root.parent_span_id, opentelemetry::trace::SpanId::INVALID);
        assert_ne!(root.span_context.trace_id().to_string(), WORKLOAD_TRACE_ID);
        assert_eq!(root.links.links.len(), 1);
        assert_eq!(
            root.links.links[0].span_context.trace_id().to_string(),
            WORKLOAD_TRACE_ID
        );
        assert_eq!(
            root.links.links[0].span_context.span_id().to_string(),
            WORKLOAD_SPAN_ID
        );
        assert!(
            root.links.links[0]
                .span_context
                .trace_state()
                .header()
                .is_empty()
        );
        for record in &records {
            assert_eq!(
                record["trace"]["uid"],
                root.span_context.trace_id().to_string()
            );
        }
        if let Some(expected) = expected {
            assert!(root.attributes.iter().any(|attribute| {
                attribute.key.as_str() == "http.response.status_code"
                    && attribute.value == opentelemetry::Value::I64(expected)
            }));
        } else {
            assert!(
                root.attributes
                    .iter()
                    .all(|attribute| attribute.key.as_str() != "http.response.status_code")
            );
        }
        assert!(root.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "openshell.request.id" && attribute.value.as_str() == receipt
        }));
        let stages = spans
            .iter()
            .filter(|span| span.parent_span_id == root.span_context.span_id())
            .collect::<Vec<_>>();
        assert!(
            stages
                .iter()
                .any(|span| span.name == "openshell.policy.evaluate")
        );
        assert_eq!(
            stages
                .iter()
                .any(|span| span.name == "openshell.upstream.connect"),
            !policy_denied && !credential_failure
        );
        assert_eq!(
            stages
                .iter()
                .any(|span| span.name == "openshell.upstream.resolve"),
            !policy_denied
        );
        assert_eq!(
            matches!(root.status, opentelemetry::trace::Status::Error { .. }),
            matches!(
                outcome,
                Outcome::UpstreamClosed | Outcome::UnresolvedCredential
            ),
            "a policy refusal is an outcome, not an operational tracing failure"
        );
        if credential_failure {
            assert_eq!(
                span_attribute(root, "openshell.request.failure_reason")
                    .unwrap()
                    .as_str(),
                "credential_injection_failed",
            );
            let preparation = stages
                .iter()
                .find(|span| span.name == "openshell.credential.prepare")
                .expect("credential preparation stage");
            assert!(matches!(
                preparation.status,
                opentelemetry::trace::Status::Error { .. }
            ));
            assert_eq!(
                span_attribute(preparation, "openshell.request.failure_reason")
                    .unwrap()
                    .as_str(),
                "credential_resolution_refused",
            );
        }
        assert!(
            stages
                .iter()
                .all(|span| span.span_context.trace_id() == root.span_context.trace_id())
        );
        assert!(!format!("{spans:?}").contains("SENTINEL"));
    }
    capture.shutdown();
}

#[tokio::test]
async fn inspected_forward_traces_all_outcomes_without_sampling_or_export_dependencies() {
    let _lock = openshell_otel_test_support::tracing_test_lock().await;
    let ip = non_loopback_test_ipv4()
        .expect("FORWARD trace qualification requires a non-loopback IPv4 address");
    for outcome in [
        Outcome::Allowed,
        Outcome::PolicyDenied,
        Outcome::AuditDenied,
        Outcome::UnresolvedCredential,
        Outcome::UpstreamClosed,
    ] {
        for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
            forward_case(ip, outcome, sampler).await;
        }
    }
}

#[tokio::test]
async fn inspected_forward_malformed_query_preserves_correlated_l7_denial() {
    let _lock = openshell_otel_test_support::tracing_test_lock().await;
    let ip = non_loopback_test_ipv4()
        .expect("FORWARD trace qualification requires a non-loopback IPv4 address");
    // This malformed query already reaches the L7 deny path. Creating a
    // receipt must not add a stricter parse that aborts before the 403 and its
    // existing policy decision record.
    for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
        forward_case(ip, Outcome::MalformedQueryPolicyDenied, sampler).await;
    }
}

#[test]
fn inspected_forward_error_receipts_preserve_json_bodies() {
    let request_id = "server-owned-receipt";
    let denial = openshell_supervisor_middleware::MiddlewareDenial {
        config_name: "content-guard".into(),
        reason_code: Some("content_match".into()),
    };
    for (original, correlated) in [
        (
            build_json_error_response_with_request_id(
                403,
                "Forbidden",
                "policy_denied",
                "denied by L7 policy",
                None,
            ),
            build_json_error_response_with_request_id(
                403,
                "Forbidden",
                "policy_denied",
                "denied by L7 policy",
                Some(request_id),
            ),
        ),
        (
            build_middleware_deny_response("api-policy", &denial, None),
            build_middleware_deny_response("api-policy", &denial, Some(request_id)),
        ),
        (
            build_middleware_failure_response("api-policy", None, None),
            build_middleware_failure_response("api-policy", None, Some(request_id)),
        ),
        (
            build_middleware_unavailable_response("api-policy", None),
            build_middleware_unavailable_response("api-policy", Some(request_id)),
        ),
    ] {
        let original = String::from_utf8(original).unwrap();
        let correlated = String::from_utf8(correlated).unwrap();
        let (_, original_body) = original.split_once("\r\n\r\n").unwrap();
        let (headers, correlated_body) = correlated.split_once("\r\n\r\n").unwrap();
        assert_eq!(response_request_id(correlated.as_bytes()), request_id);
        assert!(headers.contains(&format!("Content-Length: {}\r\n", correlated_body.len())));
        assert_eq!(correlated_body, original_body);
        let body: serde_json::Value = serde_json::from_str(correlated_body).unwrap();
        assert!(body.get("request_id").is_none());
    }
}

#[tokio::test]
async fn inspected_forward_http_trace_ends_before_websocket_session() {
    forward_websocket_trace_case(true).await;
}

#[tokio::test]
async fn inspected_forward_websocket_frame_denial_stays_outside_http_scope() {
    forward_websocket_trace_case(false).await;
}

async fn forward_websocket_trace_case(allow_frame: bool) {
    let _lock = openshell_otel_test_support::tracing_test_lock().await;
    let ip = non_loopback_test_ipv4()
        .expect("FORWARD trace qualification requires a non-loopback IPv4 address");
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let frame_rule = if allow_frame {
        "          - allow: { method: WEBSOCKET_TEXT, path: /ws }"
    } else {
        ""
    };
    let engine = Arc::new(
        native_identity_engine(
            include_str!("../../../data/sandbox-policy.rego"),
            &format!(
                r#"
network_policies:
  traced_websocket:
    name: traced_websocket
    endpoints:
      - host: "{ip}"
        port: {port}
        allowed_ips: ["{ip}/32"]
        protocol: websocket
        enforcement: enforce
        rules:
          - allow: {{ method: GET, path: /ws }}
{frame_rule}
    binaries:
      - path: /usr/bin/python3
"#
            ),
        )
        .unwrap(),
    );
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    let subscriber = capture
        .subscriber()
        .with(openshell_otel::supervisor_span_filter("info"));
    let (mut app, proxy) = tokio::io::duplex(8192);
    let target = format!("http://{ip}:{port}/ws");
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\ntraceparent: 00-{WORKLOAD_TRACE_ID}-{WORKLOAD_SPAN_ID}-01\r\n\r\n"
    );
    let handler = tokio::spawn(
        async move {
            let identity = Ok(ContractBinaryIdentity {
                executable: ContractExecutableIdentity {
                    path: executable_path("/usr/bin/python3"),
                    digest: Some("00".repeat(32).parse().unwrap()),
                },
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            });
            let mut proxy: ProxyClient = tokio::io::BufReader::new(Box::new(proxy));
            Box::pin(handle_forward_proxy(
                "GET",
                &target,
                request.as_bytes(),
                request.len(),
                &mut proxy,
                Some(&identity),
                Some((
                    "192.0.2.20:42123".parse().unwrap(),
                    "192.0.2.10:3128".parse().unwrap(),
                )),
                engine,
                Arc::new(BinaryIdentityCache::new()),
                Arc::new(AtomicU32::new(0)),
                None,
                AgentProposals::default(),
                Arc::new(None),
                Arc::new(None),
                None,
                None,
                None,
                None,
                None,
            ))
            .await
        }
        .with_subscriber(subscriber),
    );
    let (release, released) = tokio::sync::oneshot::channel();
    let (activity, observed_activity) = tokio::sync::oneshot::channel();
    let (handshake, ready) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut upstream, _) = listener.accept().await.unwrap();
        let request = read_http_headers(&mut upstream).await;
        assert!(String::from_utf8_lossy(&request).starts_with("GET /ws HTTP/1.1\r\n"));
        upstream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
            .await
            .unwrap();
        handshake.send(()).unwrap();
        let frame = crate::l7::websocket::read_frame_for_test(&mut upstream).await;
        if allow_frame {
            assert_eq!(frame, masked_text_frame(b"after-http-root"));
            upstream.write_all(b"\x81\x02ok").await.unwrap();
        } else {
            assert_eq!(masked_close_code(&frame), 1008);
            let mut remaining = Vec::new();
            upstream.read_to_end(&mut remaining).await.unwrap();
            assert!(
                remaining.is_empty(),
                "blocked text must never reach upstream, before or after the policy close"
            );
        }
        activity.send(std::time::SystemTime::now()).unwrap();
        released.await.unwrap();
    });
    let scenario = async {
        ready.await.unwrap();
        let response = read_http_headers(&mut app).await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 101 "));
        let receipt = response_request_id(&response);
        let root = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let mut roots: Vec<_> = capture
                    .spans()
                    .into_iter()
                    .filter(|span| span.name == "openshell.http.request")
                    .collect();
                if !roots.is_empty() {
                    assert_eq!(roots.len(), 1);
                    break roots.pop().unwrap();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP root must finish while the upgraded connection is still open");
        assert!(!handler.is_finished());
        assert!(!upstream.is_finished());
        assert!(root.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "http.response.status_code"
                && attribute.value == opentelemetry::Value::I64(101)
        }));
        assert!(root.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "openshell.request.outcome"
                && attribute.value.as_str() == "upgraded"
        }));
        app.write_all(&masked_text_frame(b"after-http-root"))
            .await
            .unwrap();
        assert!(root.end_time <= observed_activity.await.unwrap());
        let mut frame = [0; 4];
        app.read_exact(&mut frame).await.unwrap();
        if allow_frame {
            assert_eq!(&frame, b"\x81\x02ok");
            assert!(!handler.is_finished());
        } else {
            assert_eq!(&frame, b"\x88\x02\x03\xf0");
        }
        release.send(()).unwrap();
        drop(app);
        upstream.await.unwrap();
        let result = handler.await.unwrap();
        if allow_frame {
            result.unwrap();
        } else {
            assert!(
                result
                    .expect_err("denied frame must terminate the relay")
                    .to_string()
                    .contains("websocket text message denied by policy")
            );
        }
        let records = capture.events.json_events();
        assert_eq!(records.len(), 4, "{records:?}");
        assert_request_record_sequence(&records[..2], receipt);
        for record in &records[..2] {
            assert_eq!(record["class_uid"], 4002);
            assert_eq!(record["action_id"], 1);
            assert_eq!(record["http_request"]["url"]["path"], "/ws");
            assert!(record.get("http_response").is_none());
            assert_eq!(
                record["trace"]["uid"],
                root.span_context.trace_id().to_string()
            );
        }
        assert!(
            records[0]["message"]
                .as_str()
                .unwrap()
                .starts_with("FORWARD_L7 allow GET ")
        );
        assert_eq!(records[0]["firewall_rule"]["type"], "l7");
        assert!(records[0].get("status_id").is_none());
        assert!(
            records[1]["message"]
                .as_str()
                .unwrap()
                .starts_with("FORWARD allowed GET ")
        );
        assert_eq!(records[1]["firewall_rule"]["type"], "opa");
        assert_eq!(records[1]["status_id"], 1);
        assert_eq!(records[2]["class_uid"], 4001);
        assert_eq!(records[2]["activity_name"], "Upgrade");
        assert!(
            records[2]["message"]
                .as_str()
                .unwrap()
                .starts_with("101 Switching Protocols — websocket parsed relay ")
        );
        assert!(records[2].get("http_response").is_none());
        assert!(records[2].get("http_request").is_none());
        assert_eq!(records[2]["metadata"]["correlation_uid"], receipt);
        assert_eq!(records[2]["unmapped"]["request_sequence"], 3);
        assert_eq!(records[2]["unmapped"]["http_event_kind"], "connection");
        // NetworkActivity has no trace field; the receipt ties the unchanged
        // 101 record to the completed HTTP root without changing its schema.
        assert!(records[2].get("trace").is_none());
        assert_eq!(
            span_attribute(&root, "openshell.request.id")
                .unwrap()
                .as_str(),
            receipt
        );
        assert_eq!(records[3]["class_uid"], 4001);
        assert!(
            records[3]["message"]
                .as_str()
                .unwrap()
                .starts_with(if allow_frame {
                    "WEBSOCKET_L7_REQUEST allow WEBSOCKET_TEXT "
                } else {
                    "WEBSOCKET_L7_REQUEST deny WEBSOCKET_TEXT "
                })
        );
        assert_eq!(records[3]["firewall_rule"]["type"], "l7-websocket");
        assert_eq!(records[3]["action_id"], if allow_frame { 1 } else { 2 });
        for record in &records[3..] {
            assert!(record["metadata"].get("correlation_uid").is_none());
            assert!(record["unmapped"].get("request_sequence").is_none());
            assert!(record["unmapped"].get("http_event_kind").is_none());
            assert!(record.get("trace").is_none());
        }
        let created = capture.created_span_names();
        assert_eq!(
            created
                .iter()
                .filter(|name| **name == "openshell.http.request")
                .count(),
            1,
            "WebSocket frames must not create HTTP request spans"
        );
        assert!(
            !created.contains(&"supervisor.egress.deny"),
            "WebSocket NetworkActivity decisions must not gain HTTP denial spans"
        );
        assert!(!format!("{records:?}").contains("after-http-root"));
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), scenario)
        .await
        .unwrap();
    capture.shutdown();
}
