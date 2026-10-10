// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks that [`CedarEngine::dns_endpoints`] lists exactly the
//! `NetworkEndpoint`s named in `NetworkConnect` permit scopes, for DNS
//! eligibility. Uses the same fixture `tests/network.rs` uses for
//! CONNECT-time evaluation.

use openshell_policy_cedar::{
    AuthorizedNetworkEndpoint, CedarEngine, CedarEngineError, NetworkTransport,
};

const POLICIES: &str = include_str!("fixtures/policies.cedar");

fn dns_endpoints(policy: &str) -> Vec<AuthorizedNetworkEndpoint> {
    CedarEngine::from_policy_str(policy)
        .expect("policy must load")
        .dns_endpoints()
        .to_vec()
}

#[test]
fn lists_every_permitted_endpoint_grouped_by_host() {
    assert_eq!(
        dns_endpoints(POLICIES),
        vec![
            AuthorizedNetworkEndpoint {
                host: "files.pythonhosted.org".to_string(),
                ports: vec![443],
                transport: NetworkTransport::Default,
                allowed_ips: Vec::new(),
            },
            AuthorizedNetworkEndpoint {
                host: "integrate.api.nvidia.com".to_string(),
                ports: vec![443],
                transport: NetworkTransport::Default,
                allowed_ips: Vec::new(),
            },
            AuthorizedNetworkEndpoint {
                host: "pypi.org".to_string(),
                ports: vec![443],
                transport: NetworkTransport::Default,
                allowed_ips: Vec::new(),
            },
        ]
    );
}

#[test]
fn ignores_filesystem_only_policies() {
    let endpoints = dns_endpoints(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"ReadFile",
    resource  in Sandbox::FilesystemPath::"/usr"
);
"#,
    );
    assert!(endpoints.is_empty());
}

#[test]
fn forbid_grants_no_eligibility() {
    let endpoints = dns_endpoints(
        r#"
forbid (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"evil.example.com:443"
);
"#,
    );
    assert!(endpoints.is_empty());
}

#[test]
fn endpoints_named_only_in_conditions_are_not_eligible() {
    // An `unless` clause naming an endpoint excludes it; reading literals
    // out of conditions would have made it eligible.
    let endpoints = dns_endpoints(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  is Sandbox::NetworkEndpoint
)
unless { resource == Sandbox::NetworkEndpoint::"evil.example.com:443" };
"#,
    );
    assert!(endpoints.is_empty());
}

#[test]
fn groups_multiple_ports_for_the_same_host() {
    let endpoints = dns_endpoints(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"example.com:443"
);
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"example.com:8443"
);
"#,
    );
    assert_eq!(
        endpoints,
        vec![AuthorizedNetworkEndpoint {
            host: "example.com".to_string(),
            ports: vec![443, 8443],
            transport: NetworkTransport::Default,
            allowed_ips: Vec::new(),
        }]
    );
}

#[test]
fn rejects_invalid_endpoint_literals() {
    for endpoint in [
        "API.example.com:443",
        "example.com.:443",
        "example.com",
        "example.com:0",
    ] {
        let policy = format!(
            r#"permit(principal, action == Sandbox::Action::"NetworkConnect",
                      resource == Sandbox::NetworkEndpoint::"{endpoint}");"#
        );
        let error = CedarEngine::from_policy_str(&policy)
            .expect_err(&format!("{endpoint} must be rejected"));
        assert!(
            matches!(error, CedarEngineError::InvalidEndpoint { .. }),
            "{endpoint}: {error}"
        );
    }
}
