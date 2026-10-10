// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks `@transport("tcp")`, which marks a `NetworkConnect` permit's
//! endpoint for native TCP as YAML `protocol: tcp` does, and the load-time
//! rules YAML applies to such endpoints.

use openshell_policy_cedar::{
    AuthorizedNetworkEndpoint, CedarEngine, CedarEngineError, NetworkRequest, NetworkTransport,
};

fn load(policy: &str) -> Result<CedarEngine, CedarEngineError> {
    CedarEngine::from_policy_str(policy)
}

fn endpoint(host: &str, ports: &[u16], transport: NetworkTransport) -> AuthorizedNetworkEndpoint {
    AuthorizedNetworkEndpoint {
        host: host.to_string(),
        ports: ports.to_vec(),
        transport,
        allowed_ips: Vec::new(),
    }
}

const TCP_DATABASE: &str = r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example.com:5432")
when { context.binary_path == "/usr/bin/psql" };
"#;

#[test]
fn tcp_endpoints_are_dns_records_marked_tcp() {
    let policy = format!(
        r#"{TCP_DATABASE}
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ resource.host like("*.cache.example.com", ".") && resource.port == 6379 }};
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example.com:443");
"#
    );
    let engine = load(&policy).expect("policy loads");
    assert_eq!(
        engine.dns_endpoints(),
        [
            endpoint("*.cache.example.com", &[6379], NetworkTransport::Tcp),
            endpoint("db.example.com", &[443], NetworkTransport::Default),
            endpoint("db.example.com", &[5432], NetworkTransport::Tcp),
        ]
    );
    assert_eq!(NetworkTransport::Tcp.protocol(), Some("tcp"));
    assert_eq!(NetworkTransport::Default.protocol(), None);
}

#[test]
fn tcp_endpoints_authorize_as_plain_connections() {
    let engine = load(TCP_DATABASE).expect("policy loads");
    let request = |binary: &str| NetworkRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: "db.example.com".to_string(),
        port: 5432,
        binary_path: binary.to_string(),
        ancestors: Vec::new(),
        binary_aliases: Vec::new(),
        destination_ip: None,
    };
    assert!(
        engine
            .evaluate_network(&request("/usr/bin/psql"))
            .unwrap()
            .is_allow()
    );
    assert!(
        !engine
            .evaluate_network(&request("/usr/bin/curl"))
            .unwrap()
            .is_allow()
    );
    assert!(engine.l7_endpoint("db.example.com", 5432).is_none());
}

#[test]
fn rejects_unknown_transports() {
    let error = load(&TCP_DATABASE.replace("\"tcp\"", "\"udp\"")).unwrap_err();
    assert!(
        matches!(error, CedarEngineError::UnsupportedTransport { ref transport, .. } if transport == "udp"),
        "{error}"
    );
}

#[test]
fn rejects_transport_outside_network_connect_permits() {
    for policy in [
        // A forbid.
        r#"@transport("tcp")
forbid (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example.com:5432");"#,
        // Another action alongside NetworkConnect.
        r#"@transport("tcp")
permit (principal,
        action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
        resource == Sandbox::NetworkEndpoint::"db.example.com:5432");"#,
        // A filesystem action.
        r#"@transport("tcp")
permit (principal, action == Sandbox::Action::"ReadFile",
        resource in Sandbox::FilesystemPath::"/usr");"#,
    ] {
        let error = load(policy).unwrap_err();
        assert!(
            matches!(error, CedarEngineError::UnsupportedPolicy { .. }),
            "{policy}: {error}"
        );
    }
}

#[test]
fn rejects_hostless_tcp_permits() {
    for condition in [
        // No host at all.
        "resource.port == 5432",
        // A host without a port.
        r#"resource.host == "db.example.com""#,
        // A host form policy DNS cannot match exactly.
        r#"resource.host like "*.example.com" && resource.port == 5432"#,
    ] {
        let policy = format!(
            r#"@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ {condition} }};"#
        );
        let error = load(&policy).unwrap_err();
        assert!(
            matches!(error, CedarEngineError::UnsupportedPolicy { ref reason, .. } if reason.contains("hostless")),
            "{condition}: {error}"
        );
    }
}

#[test]
fn rejects_ip_literals_and_invalid_dns_hosts() {
    for host in [
        "10.0.0.5",
        "[::1]",
        "::1",
        "under score!.example.com",
        &format!("{}.example.com", "a".repeat(64)),
    ] {
        let policy = TCP_DATABASE.replace("db.example.com", host);
        let error = load(&policy).unwrap_err();
        assert!(
            matches!(error, CedarEngineError::InvalidTcpHost { .. }),
            "{host}: {error}"
        );
    }
    // The same IP literal without @transport is an ordinary endpoint.
    load(
        &TCP_DATABASE
            .replace("@transport(\"tcp\")", "")
            .replace("db.example.com", "10.0.0.5"),
    )
    .expect("plain IP endpoints load");
}

#[test]
fn rejects_request_policies_on_tcp_endpoints() {
    for (host, port) in [
        ("db.example.com", 5432),
        // An inspected host a native TCP glob covers.
        ("api.cache.example.com", 6379),
    ] {
        let policy = format!(
            r#"{TCP_DATABASE}
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ resource.host like("*.cache.example.com", ".") && resource.port == 6379 }};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:{port}");
"#
        );
        let error = load(&policy).unwrap_err();
        assert!(
            matches!(error, CedarEngineError::ConflictingTransport { ref reason, .. } if reason.contains("HttpRequest")),
            "{host}:{port}: {error}"
        );
    }
    // Inspection on another port of the same host is independent.
    let policy = format!(
        r#"{TCP_DATABASE}
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"db.example.com:443");
"#
    );
    load(&policy).expect("other ports may be inspected");
}

#[test]
fn rejects_overlapping_endpoints_without_tcp() {
    for other in [
        // The same endpoint, for another binary.
        r#"resource == Sandbox::NetworkEndpoint::"db.example.com:5432")"#,
        // A glob covering it.
        r#"resource) when { resource.host like("*.example.com", ".") && resource.port == 5432 }"#,
        r#"resource) when { resource.host like("**.example.com", ".") && resource.port == 5432 }"#,
    ] {
        let policy = format!(
            r#"{TCP_DATABASE}
permit (principal, action == Sandbox::Action::"NetworkConnect", {other};"#
        );
        let error = load(&policy).unwrap_err();
        assert!(
            matches!(error, CedarEngineError::ConflictingTransport { .. }),
            "{other}: {error}"
        );
    }
    for other in [
        // Another port.
        r#"resource == Sandbox::NetworkEndpoint::"db.example.com:5433")"#,
        // A glob that cannot match the host.
        r#"resource) when { resource.host like("*.example.org", ".") && resource.port == 5432 }"#,
        // `*` stays within one label.
        r#"resource) when { resource.host like("*.com", ".") && resource.port == 5432 }"#,
    ] {
        let policy = format!(
            r#"{TCP_DATABASE}
permit (principal, action == Sandbox::Action::"NetworkConnect", {other};"#
        );
        // `*.com` is not eligible for policy DNS, so it names no endpoint.
        load(&policy).unwrap_or_else(|error| panic!("{other}: {error}"));
    }
}

#[test]
fn overlapping_tcp_globs_are_one_transport() {
    let policy = r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 5432 };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("db-*.example.com", ".") && resource.port == 5432 };
"#;
    let error = load(policy).unwrap_err();
    assert!(
        matches!(error, CedarEngineError::ConflictingTransport { .. }),
        "{error}"
    );
    let disjoint = policy.replace("db-*.example.com", "db-*.example.org");
    load(&disjoint).expect("disjoint globs load");
}
