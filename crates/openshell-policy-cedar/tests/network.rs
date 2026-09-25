// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-19

//! End-to-end checks that [`CedarNetworkEngine`] evaluates `NetworkConnect`
//! requests against the canonical schema
//! (`openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC`) and
//! `tests/fixtures/policies.cedar` the way the policy authoring intends:
//! identity-guarded, method-restricted per-endpoint allowlisting.

use openshell_policy_cedar::{CedarNetworkEngine, NetworkDecision, NetworkRequest};

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
        protocol: "rest".to_string(),
        binary_path: "/sandbox/.venv/bin/python3".to_string(),
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
