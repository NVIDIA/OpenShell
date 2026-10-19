// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks `context.destination_ip` conditions, the Cedar form of YAML
//! `allowed_ips`: the accepted shapes, the decision made before and after
//! the host resolves, and the ranges reported for each allow.

use std::net::IpAddr;

use openshell_policy_cedar::{
    AuthorizedNetworkEndpoint, CedarEngine, CedarEngineError, Decision, IpNet,
    NetworkConnectRequest, NetworkTransport,
};

fn load(policy: &str) -> Result<CedarEngine, CedarEngineError> {
    CedarEngine::from_policy_str(policy)
}

fn request(host: &str, port: u16, binary: &str, ip: Option<&str>) -> NetworkConnectRequest {
    NetworkConnectRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: host.to_string(),
        port,
        binary_path: binary.to_string(),
        ancestors: Vec::new(),
        binary_aliases: Vec::new(),
        binary_globs: Vec::new(),
        destination_ip: ip.map(|ip| ip.parse::<IpAddr>().expect("test address parses")),
    }
}

fn nets(ranges: &[&str]) -> Vec<IpNet> {
    ranges
        .iter()
        .map(|range| range.parse().expect("test range parses"))
        .collect()
}

fn invalid_destination_ip(policy: &str) -> String {
    match load(policy) {
        Err(CedarEngineError::InvalidDestinationIp { reason, .. }) => reason,
        other => panic!("expected InvalidDestinationIp, got {other:?}"),
    }
}

const POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"my-service.corp.net:8080")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.5.0/24"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.port == 9443
    && context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && (context.destination_ip.isInRange(ip("172.16.0.0/12"))
        || context.destination_ip.isInRange(ip("192.168.1.1")))
};
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.binary_path == "/usr/bin/curl" };
"#;

#[test]
fn host_with_ranges_allows_before_resolution_and_checks_each_address() {
    let engine = load(POLICY).expect("policy loads");
    let unresolved = engine
        .authorize_network(&request("my-service.corp.net", 8080, "/usr/bin/curl", None))
        .expect("evaluates");
    assert!(unresolved.decision.is_allow());
    assert_eq!(unresolved.address_conditions, [nets(&["10.0.5.0/24"])]);
    assert!(!unresolved.unconstrained_permit);
    assert!(unresolved.names_endpoint);

    let inside = request(
        "my-service.corp.net",
        8080,
        "/usr/bin/curl",
        Some("10.0.5.9"),
    );
    assert!(engine.evaluate_network(&inside).unwrap().is_allow());
    let outside = request(
        "my-service.corp.net",
        8080,
        "/usr/bin/curl",
        Some("10.0.6.1"),
    );
    assert!(!engine.evaluate_network(&outside).unwrap().is_allow());
    let other_binary = request("my-service.corp.net", 8080, "/usr/bin/wget", None);
    assert!(!engine.evaluate_network(&other_binary).unwrap().is_allow());
}

#[test]
fn hostless_ranges_allow_any_host_on_their_port() {
    let engine = load(POLICY).expect("policy loads");
    let unresolved = engine
        .authorize_network(&request(
            "anything.example.com",
            9443,
            "/usr/bin/curl",
            None,
        ))
        .expect("evaluates");
    assert!(unresolved.decision.is_allow());
    assert_eq!(
        unresolved.address_conditions,
        [nets(&["172.16.0.0/12", "192.168.1.1/32"])]
    );
    assert!(!unresolved.names_endpoint);
    let wrong_port = request("anything.example.com", 9444, "/usr/bin/curl", None);
    assert!(!engine.evaluate_network(&wrong_port).unwrap().is_allow());
    let resolved = request(
        "anything.example.com",
        9443,
        "/usr/bin/curl",
        Some("192.168.1.1"),
    );
    assert!(engine.evaluate_network(&resolved).unwrap().is_allow());
    let resolved = request(
        "anything.example.com",
        9443,
        "/usr/bin/curl",
        Some("192.168.1.2"),
    );
    assert!(!engine.evaluate_network(&resolved).unwrap().is_allow());
}

#[test]
fn permits_without_ranges_are_unconstrained() {
    let engine = load(POLICY).expect("policy loads");
    let evaluation = engine
        .authorize_network(&request("api.github.com", 443, "/usr/bin/curl", None))
        .expect("evaluates");
    assert!(evaluation.decision.is_allow());
    assert!(evaluation.address_conditions.is_empty());
    assert!(evaluation.unconstrained_permit);
    assert!(evaluation.names_endpoint);
}

#[test]
fn ranges_are_dns_records_of_their_own_and_hostless_permits_are_not() {
    let engine = load(&format!(
        r#"{POLICY}
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.corp.net:5432")
when {{ context has destination_ip && context.destination_ip.isInRange(ip("10.2.0.0/16")) }};
"#
    ))
    .expect("policy loads");
    assert_eq!(
        engine.dns_endpoints(),
        [
            AuthorizedNetworkEndpoint {
                host: "api.github.com".to_string(),
                ports: vec![443],
                transport: NetworkTransport::Default,
                allowed_ips: Vec::new(),
            },
            AuthorizedNetworkEndpoint {
                host: "db.corp.net".to_string(),
                ports: vec![5432],
                transport: NetworkTransport::Tcp,
                allowed_ips: nets(&["10.2.0.0/16"]),
            },
            AuthorizedNetworkEndpoint {
                host: "my-service.corp.net".to_string(),
                ports: vec![8080],
                transport: NetworkTransport::Default,
                allowed_ips: nets(&["10.0.5.0/24"]),
            },
        ]
    );
}

#[test]
fn conjuncts_intersect_their_ranges() {
    let engine = load(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"svc.corp.net:443")
when {
    context has destination_ip
    && (context.destination_ip.isInRange(ip("10.0.0.0/8"))
        || context.destination_ip.isInRange(ip("192.168.0.0/16")))
    && context.destination_ip.isInRange(ip("10.1.0.0/16"))
};
"#,
    )
    .expect("policy loads");
    let evaluation = engine
        .authorize_network(&request("svc.corp.net", 443, "/usr/bin/curl", None))
        .expect("evaluates");
    assert_eq!(evaluation.address_conditions, [nets(&["10.1.0.0/16"])]);
}

#[test]
fn forbids_reading_only_the_address_apply_once_resolved() {
    // Before resolution the `context has destination_ip` guard is false, so
    // a forbid whose only condition reads the address has no effect; after
    // resolution it applies to each address.
    let engine = load(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"svc.corp.net:443");
forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context has destination_ip && !context.destination_ip.isInRange(ip("10.0.0.0/8")) };
"#,
    )
    .expect("policy loads");
    let unresolved = request("svc.corp.net", 443, "/usr/bin/curl", None);
    assert!(engine.evaluate_network(&unresolved).unwrap().is_allow());
    let inside = request("svc.corp.net", 443, "/usr/bin/curl", Some("10.1.2.3"));
    assert!(engine.evaluate_network(&inside).unwrap().is_allow());
    let outside = request("svc.corp.net", 443, "/usr/bin/curl", Some("8.8.8.8"));
    assert!(!engine.evaluate_network(&outside).unwrap().is_allow());
}

#[test]
fn forbids_reading_the_address_still_deny_on_their_other_conditions_before_resolution() {
    // The binary disjunct must fire at CONNECT time: with
    // `proxy_connect_by_hostname` no per-address decision follows, so a
    // forbid left out of the pre-resolution decision would never deny curl.
    let engine = load(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"svc.corp.net:443");
forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    context.binary_path == "/usr/bin/curl"
    || (context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8")))
};
"#,
    )
    .expect("policy loads");
    let curl = request("svc.corp.net", 443, "/usr/bin/curl", None);
    let denied = engine.evaluate_network(&curl).unwrap();
    assert!(!denied.is_allow(), "{denied:?}");
    assert!(
        matches!(&denied, Decision::Deny { matched_policies } if matched_policies == &["policy1"]),
        "{denied:?}"
    );
    let wget = request("svc.corp.net", 443, "/usr/bin/wget", None);
    assert!(engine.evaluate_network(&wget).unwrap().is_allow());
    let wget_private = request("svc.corp.net", 443, "/usr/bin/wget", Some("10.1.2.3"));
    assert!(!engine.evaluate_network(&wget_private).unwrap().is_allow());
    let wget_public = request("svc.corp.net", 443, "/usr/bin/wget", Some("8.8.8.8"));
    assert!(engine.evaluate_network(&wget_public).unwrap().is_allow());
}

#[test]
fn an_unless_forbid_reading_the_address_denies_before_resolution() {
    // The guard is false before resolution, so an `unless` body that reads
    // the address is false and the forbid applies; write address-only
    // forbids with `when`.
    let engine = load(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"svc.corp.net:443");
forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
unless { context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8")) };
"#,
    )
    .expect("policy loads");
    let unresolved = request("svc.corp.net", 443, "/usr/bin/curl", None);
    assert!(!engine.evaluate_network(&unresolved).unwrap().is_allow());
    let inside = request("svc.corp.net", 443, "/usr/bin/curl", Some("10.1.2.3"));
    assert!(engine.evaluate_network(&inside).unwrap().is_allow());
}

#[test]
fn rejects_an_unguarded_address_read() {
    // The pre-resolution decision relies on the guard: without it, strict
    // validation rejects the optional attribute access, in a forbid as in a
    // permit.
    for effect in ["permit", "forbid"] {
        let error = load(&format!(
            r#"{effect} (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ context.destination_ip.isInRange(ip("10.0.0.0/8")) }};"#
        ))
        .expect_err("unguarded read must be rejected");
        assert!(
            matches!(error, CedarEngineError::PolicyValidation { .. }),
            "{effect}: {error}"
        );
    }
}

#[test]
fn names_endpoint_counts_only_allowing_permits() {
    let engine = load(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.corp.net:443")
when { context.binary_path == "/usr/bin/other" };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.corp.net", ".") && resource.port == 443 };
"#,
    )
    .expect("policy loads");
    let evaluation = engine
        .authorize_network(&request("api.corp.net", 443, "/usr/bin/curl", None))
        .expect("evaluates");
    assert!(evaluation.decision.is_allow());
    assert!(!evaluation.names_endpoint);
}

#[test]
fn rejects_ranges_the_proxy_always_blocks() {
    for range in ["127.0.0.0/8", "169.254.169.254", "0.0.0.0/0", "::1"] {
        let reason = invalid_destination_ip(&format!(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ context has destination_ip && context.destination_ip.isInRange(ip("{range}")) }};"#
        ));
        assert!(
            reason.contains("blocked regardless of policy"),
            "{range}: {reason}"
        );
    }
}

#[test]
fn rejects_address_conditions_it_cannot_derive_ranges_from() {
    for (condition, expected) in [
        (
            r#"when { context has destination_ip && context.destination_ip == ip("10.0.0.1") }"#,
            "isInRange",
        ),
        (
            r#"when { context has destination_ip && !context.destination_ip.isInRange(ip("10.0.0.0/8")) }"#,
            "isInRange",
        ),
        (
            r#"when { resource.port == 443 || (context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8"))) }"#,
            "isInRange",
        ),
        (
            r#"unless { context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8")) }"#,
            "only in `when`",
        ),
        (
            "when { context has destination_ip }",
            "must require it to be in a range",
        ),
        (
            r#"when { context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8")) && context.destination_ip.isInRange(ip("192.168.0.0/16")) }"#,
            "admit no address",
        ),
    ] {
        let reason = invalid_destination_ip(&format!(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource) {condition};"#
        ));
        assert!(reason.contains(expected), "{condition}: {reason}");
    }
}

/// A record literal with a key named `Var` still has its value inspected,
/// so an address read inside one is not mistaken for a host condition.
#[test]
fn reads_inside_a_record_keyed_var_are_detected() {
    let reason = invalid_destination_ip(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.0.0/8"))
    && {Var: context.destination_ip} == {Var: ip("10.1.2.3")}
};"#,
    );
    assert!(reason.contains("each `when` conjunct"), "{reason}");
}

#[test]
fn rejects_address_conditions_outside_network_connect() {
    // Only NetworkConnect declares `destination_ip`, so the guard can never
    // hold for the other action in scope.
    let error = load(
        r#"permit (principal, action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"ReadFile"], resource)
when { context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8")) };"#,
    )
    .expect_err("rejected");
    assert!(
        matches!(&error, CedarEngineError::PolicyValidation { reason }
            if reason.contains("`context has destination_ip`") && reason.contains("action ReadFile")),
        "{error}"
    );
}
