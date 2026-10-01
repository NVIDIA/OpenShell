// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-10-01

//! Checks that [`extract_authorized_network_endpoints`] pulls the exact
//! `NetworkEndpoint` literals an authored policy permits, for DNS
//! eligibility — the same fixture `tests/network.rs` uses for CONNECT-time
//! evaluation.

use cedar_policy::PolicySet;
use openshell_policy_cedar::{AuthorizedNetworkEndpoint, extract_authorized_network_endpoints};
use std::str::FromStr;

const POLICIES: &str = include_str!("fixtures/policies.cedar");

#[test]
fn extracts_every_permitted_endpoint_grouped_by_host() {
    let policies = PolicySet::from_str(POLICIES).expect("fixture policy set must parse");
    let mut endpoints = extract_authorized_network_endpoints(&policies);
    endpoints.sort_by(|a, b| a.host.cmp(&b.host));

    assert_eq!(
        endpoints,
        vec![
            AuthorizedNetworkEndpoint {
                host: "files.pythonhosted.org".to_string(),
                ports: vec![443],
            },
            AuthorizedNetworkEndpoint {
                host: "integrate.api.nvidia.com".to_string(),
                ports: vec![443],
            },
            AuthorizedNetworkEndpoint {
                host: "pypi.org".to_string(),
                ports: vec![443],
            },
        ]
    );
}

#[test]
fn ignores_filesystem_only_policies() {
    let policies = PolicySet::from_str(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"ReadFile",
    resource  is Sandbox::FilesystemPath
)
when { resource in Sandbox::FilesystemPath::"/usr" };
"#,
    )
    .expect("policy must parse");
    assert!(extract_authorized_network_endpoints(&policies).is_empty());
}

#[test]
fn forbid_grants_no_eligibility() {
    let policies = PolicySet::from_str(
        r#"
forbid (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"evil.example.com:443"
);
"#,
    )
    .expect("policy must parse");
    assert!(extract_authorized_network_endpoints(&policies).is_empty());
}

#[test]
fn groups_multiple_ports_for_the_same_host() {
    let policies = PolicySet::from_str(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  is Sandbox::NetworkEndpoint
)
when {
    (resource == Sandbox::NetworkEndpoint::"example.com:443"
        || resource == Sandbox::NetworkEndpoint::"example.com:8443")
    && context.binary_path == "/usr/bin/curl"
};
"#,
    )
    .expect("policy must parse");
    let endpoints = extract_authorized_network_endpoints(&policies);
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].host, "example.com");
    assert_eq!(endpoints[0].ports, vec![443, 8443]);
}
