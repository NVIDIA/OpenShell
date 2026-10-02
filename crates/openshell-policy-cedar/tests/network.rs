// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end checks that [`CedarNetworkEngine`] evaluates `NetworkConnect`
//! requests against the canonical schema
//! (`openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC`) and
//! `tests/fixtures/policies.cedar` the way the policy authoring intends:
//! identity-guarded, method-restricted per-endpoint allowlisting.

use openshell_policy_cedar::{
    CedarEngineError, CedarNetworkEngine, NetworkDecision, NetworkRequest,
};

const POLICIES: &str = include_str!("fixtures/policies.cedar");

fn engine() -> CedarNetworkEngine {
    CedarNetworkEngine::from_policy_str(POLICIES).expect("fixture policy set must parse")
}

fn sandbox_request(host: &str, port: u16, method: &str) -> NetworkRequest {
    NetworkRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: host.to_string(),
        port,
        binary_path: "/sandbox/.venv/bin/python3".to_string(),
        ancestors: Vec::new(),
        method: method.to_string(),
        path: String::new(),
        command: String::new(),
    }
}

#[test]
fn allows_pypi_get_from_sandbox_identity() {
    let decision = engine()
        .evaluate_network(&sandbox_request("pypi.org", 443, "GET"))
        .expect("request must be representable in the schema");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );
}

#[test]
fn allows_nvidia_api_post_from_sandbox_identity() {
    let decision = engine()
        .evaluate_network(&sandbox_request("integrate.api.nvidia.com", 443, "POST"))
        .expect("request must be representable in the schema");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );
}

#[test]
fn denies_pypi_post_because_endpoint_is_read_only() {
    let decision = engine()
        .evaluate_network(&sandbox_request("pypi.org", 443, "POST"))
        .expect("request must be representable in the schema");
    assert!(
        matches!(decision, NetworkDecision::Deny { .. }),
        "{decision:?}"
    );
}

#[test]
fn denies_any_connect_without_the_sandbox_identity() {
    let mut request = sandbox_request("pypi.org", 443, "GET");
    request.user = "root".to_string();
    request.group = "root".to_string();
    let decision = engine()
        .evaluate_network(&request)
        .expect("request must be representable in the schema");
    assert!(
        matches!(decision, NetworkDecision::Deny { .. }),
        "{decision:?}"
    );
}

#[test]
fn denies_connect_to_an_endpoint_with_no_matching_policy() {
    let decision = engine()
        .evaluate_network(&sandbox_request("example.com", 443, "GET"))
        .expect("request must be representable in the schema");
    assert!(
        matches!(decision, NetworkDecision::Deny { .. }),
        "{decision:?}"
    );
}

#[test]
fn allows_a_dns_resolved_host_with_a_trailing_dot() {
    // DNS-resolved hostnames (as published by policy_dns and read back via
    // ResolvedEndpointStore::lookup) are absolute FQDNs with a trailing
    // dot; the authored policy host literal never has one.
    let decision = engine()
        .evaluate_network(&sandbox_request("pypi.org.", 443, "GET"))
        .expect("request must be representable in the schema");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );
}

#[test]
fn rejects_a_policy_that_fails_schema_validation() {
    // A misspelled context field would otherwise make Cedar skip this
    // forbid at request time, letting the permit allow `nc`.
    let error = CedarNetworkEngine::from_policy_str(
        r#"
permit(principal, action == Sandbox::Action::"NetworkConnect",
       resource == Sandbox::NetworkEndpoint::"example.com:443");
forbid(principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context.binray_path == "/usr/bin/nc" };
"#,
    )
    .expect_err("policy must be rejected");
    assert!(
        matches!(error, CedarEngineError::PolicyValidation { .. }),
        "{error}"
    );
}

#[test]
fn fails_the_request_when_a_policy_errors_during_evaluation() {
    // Integer overflow passes validation but errors at request time. Cedar
    // would skip the erroring forbid and allow.
    let engine = CedarNetworkEngine::from_policy_str(
        r#"
permit(principal, action == Sandbox::Action::"NetworkConnect",
       resource == Sandbox::NetworkEndpoint::"pypi.org:443");
forbid(principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.port * 9223372036854775807 > 0 };
"#,
    )
    .expect("policy must load");
    let error = engine
        .evaluate_network(&sandbox_request("pypi.org", 443, "GET"))
        .expect_err("evaluation error must fail the request");
    assert!(
        matches!(error, CedarEngineError::Evaluation { .. }),
        "{error}"
    );
}
