// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks for delimited `like` (`expr like("pattern", "delim")`): Cedar
//! enforces segment-aware globs on hosts and paths, and host globs written
//! with a `.` delimiter make hosts eligible for policy DNS when they mean
//! the same thing as a YAML wildcard host.

use openshell_policy_cedar::{
    AuthorizedNetworkEndpoint, CedarEngine, CedarEngineError, L7Request, NetworkRequest,
};

fn engine(policy: &str) -> CedarEngine {
    CedarEngine::from_policy_str(policy).expect("policy must load")
}

/// A `NetworkConnect` permit whose `when` clause is `condition`.
fn connect_policy(condition: &str) -> String {
    format!(
        r#"permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  is Sandbox::NetworkEndpoint
)
when {{ {condition} }};"#
    )
}

fn dns_hosts(condition: &str) -> Vec<AuthorizedNetworkEndpoint> {
    engine(&connect_policy(condition)).dns_endpoints().to_vec()
}

fn eligible(host: &str, ports: &[u16]) -> Vec<AuthorizedNetworkEndpoint> {
    vec![AuthorizedNetworkEndpoint {
        host: host.to_string(),
        ports: ports.to_vec(),
    }]
}

fn connect(host: &str) -> NetworkRequest {
    NetworkRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: host.to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".to_string(),
        ancestors: Vec::new(),
    }
}

#[test]
fn delimited_single_wildcard_matches_one_host_label() {
    let engine = engine(&connect_policy(
        r#"resource.host like("*.example.com", ".") && resource.port == 443"#,
    ));
    let allows = |host: &str| engine.evaluate_network(&connect(host)).unwrap().is_allow();
    assert!(allows("api.example.com"));
    assert!(!allows("a.b.example.com"));
    assert!(!allows("example.com"));
}

#[test]
fn delimited_double_wildcard_matches_several_host_labels() {
    let engine = engine(&connect_policy(
        r#"resource.host like("**.example.com", ".") && resource.port == 443"#,
    ));
    let allows = |host: &str| engine.evaluate_network(&connect(host)).unwrap().is_allow();
    assert!(allows("api.example.com"));
    assert!(allows("a.b.example.com"));
    assert!(!allows("example.org"));
}

#[test]
fn delimited_path_glob_stays_within_one_segment() {
    let policy = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.github.com:443"
);
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when { context.method == "GET" && context.path like("/repos/*/*", "/") };
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when { context.method == "GET" && context.path like("/orgs/**", "/") };
"#;
    let engine = engine(policy);
    let allows = |path: &str| {
        engine
            .evaluate_l7(&L7Request {
                user: "sandbox".to_string(),
                group: "sandbox".to_string(),
                binary_path: "/usr/bin/curl".to_string(),
                ancestors: Vec::new(),
                host: "api.github.com".to_string(),
                port: 443,
                method: "GET".to_string(),
                path: path.to_string(),
                command: String::new(),
                jsonrpc_method: String::new(),
            })
            .unwrap()
            .is_allow()
    };
    assert!(allows("/repos/nvidia/openshell"));
    assert!(!allows("/repos/nvidia/openshell/hooks"));
    assert!(allows("/orgs/nvidia/members/someone"));
}

#[test]
fn host_globs_with_a_port_are_eligible_for_policy_dns() {
    for (pattern, glob) in [
        ("*.example.com", "*.example.com"),
        ("**.example.com", "**.example.com"),
        ("api-*.example.com", "api-*.example.com"),
        ("api.*.example.com", "api.*.example.com"),
    ] {
        assert_eq!(
            dns_hosts(&format!(
                r#"resource.host like("{pattern}", ".") && resource.port == 443"#
            )),
            eligible(glob, &[443]),
            "{pattern}"
        );
    }
}

#[test]
fn exact_hosts_in_conditions_are_eligible_for_policy_dns() {
    assert_eq!(
        dns_hosts(r#"443 == resource.port && resource.host == "pypi.org""#),
        eligible("pypi.org", &[443])
    );
}

#[test]
fn eligibility_ignores_other_required_conditions() {
    assert_eq!(
        dns_hosts(
            r#"resource.host like("*.example.com", ".") && resource.port == 443
               && context.binary_path == "/usr/bin/curl""#
        ),
        eligible("*.example.com", &[443])
    );
}

#[test]
fn host_constraints_that_policy_dns_cannot_match_exactly_are_not_eligible() {
    for condition in [
        // Undelimited `*` crosses labels; policy DNS would match fewer hosts.
        r#"resource.host like "*.example.com" && resource.port == 443"#,
        // Another delimiter is not label-aware.
        r#"resource.host like("*.example.com", "-") && resource.port == 443"#,
        // A wildcard top-level domain, rejected for YAML hosts too.
        r#"resource.host like("*.com", ".") && resource.port == 443"#,
        r#"resource.host like("**.com", ".") && resource.port == 443"#,
        // `**` spans labels anywhere but the whole first label.
        r#"resource.host like("api.**.example.com", ".") && resource.port == 443"#,
        r#"resource.host like("a**.example.com", ".") && resource.port == 443"#,
        // A partial wildcard outside the first label.
        r#"resource.host like("api.v*.example.com", ".") && resource.port == 443"#,
        // An escaped `*` is a literal star, which no host contains.
        r#"resource.host like("\*.example.com", ".") && resource.port == 443"#,
        // Requests carry lowercase hosts, so this never matches.
        r#"resource.host like("*.Example.com", ".") && resource.port == 443"#,
        r#"resource.host like("*.example.com.", ".") && resource.port == 443"#,
    ] {
        assert!(dns_hosts(condition).is_empty(), "{condition}");
    }
}

#[test]
fn conditions_without_a_single_required_host_and_port_are_not_eligible() {
    for condition in [
        r#"resource.host like("*.example.com", ".")"#,
        "resource.port == 443",
        r#"resource.host like("*.example.com", ".") || resource.port == 443"#,
        r#"(resource.host == "a.example.com" || resource.host == "b.example.com")
           && resource.port == 443"#,
        r#"resource.host like("*.example.com", ".") && resource.host == "api.example.com"
           && resource.port == 443"#,
        r#"resource.host like("*.example.com", ".") && resource.port == 443
           && resource.port == 8443"#,
    ] {
        assert!(dns_hosts(condition).is_empty(), "{condition}");
    }
}

#[test]
fn unless_and_forbid_grant_no_eligibility() {
    let unless = r#"permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  is Sandbox::NetworkEndpoint
)
unless { resource.host like("*.example.com", ".") && resource.port == 443 };"#;
    assert!(engine(unless).dns_endpoints().is_empty());

    let forbid =
        connect_policy(r#"resource.host like("*.example.com", ".") && resource.port == 443"#)
            .replacen("permit", "forbid", 1);
    assert!(engine(&forbid).dns_endpoints().is_empty());
}

#[test]
fn scope_endpoints_reject_wildcard_hosts() {
    let policy = r#"permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"*.example.com:443"
);"#;
    let error =
        CedarEngine::from_policy_str(policy).expect_err("a wildcard scope host is rejected");
    assert!(
        matches!(error, CedarEngineError::InvalidEndpoint { .. }),
        "{error}"
    );
}

#[test]
fn scope_and_condition_endpoints_merge_by_host() {
    let policy = format!(
        r#"permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:8443"
);
{}"#,
        connect_policy(r#"resource.host == "api.example.com" && resource.port == 443"#)
    );
    assert_eq!(
        engine(&policy).dns_endpoints(),
        eligible("api.example.com", &[443, 8443]).as_slice()
    );
}
