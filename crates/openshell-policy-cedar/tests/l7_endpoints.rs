// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-10-01

//! Checks that [`extract_l7_endpoints`] identifies which `NetworkEndpoint`s
//! an authored Cedar policy set designates for L7 inspection, and reads the
//! `@protocol(...)` annotation that declares the wire parser to use.

use cedar_policy::PolicySet;
use openshell_policy_cedar::{AuthorizedL7Endpoint, extract_l7_endpoints};
use std::str::FromStr;

#[test]
fn http_request_permit_without_annotation_defaults_to_rest() {
    let policies = PolicySet::from_str(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "GET" };
"#,
    )
    .expect("policy must parse");

    let endpoints = extract_l7_endpoints(&policies);
    assert_eq!(
        endpoints,
        vec![AuthorizedL7Endpoint {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "rest".to_string(),
        }]
    );
}

#[test]
fn protocol_annotation_is_read() {
    let policies = PolicySet::from_str(
        r#"
@protocol("sql")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"db.example.com:5432"
)
when { context.command == "SELECT" };
"#,
    )
    .expect("policy must parse");

    let endpoints = extract_l7_endpoints(&policies);
    assert_eq!(
        endpoints,
        vec![AuthorizedL7Endpoint {
            host: "db.example.com".to_string(),
            port: 5432,
            protocol: "sql".to_string(),
        }]
    );
}

#[test]
fn connect_only_policies_are_not_l7_endpoints() {
    let policies = PolicySet::from_str(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.binary_path == "/usr/bin/curl" };
"#,
    )
    .expect("policy must parse");

    assert!(extract_l7_endpoints(&policies).is_empty());
}

#[test]
fn forbid_grants_no_l7_endpoint() {
    let policies = PolicySet::from_str(
        r#"
forbid (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"evil.example.com:443"
);
"#,
    )
    .expect("policy must parse");

    assert!(extract_l7_endpoints(&policies).is_empty());
}

#[test]
fn deny_only_endpoint_still_reports_the_permit_protocol() {
    // A forbid narrowing an already-permitted endpoint must not suppress
    // the L7 designation granted by the permit.
    let policies = PolicySet::from_str(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "GET" };

forbid (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.path == "/admin" };
"#,
    )
    .expect("policy must parse");

    let endpoints = extract_l7_endpoints(&policies);
    assert_eq!(
        endpoints,
        vec![AuthorizedL7Endpoint {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "rest".to_string(),
        }]
    );
}
