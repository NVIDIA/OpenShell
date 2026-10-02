// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end checks that [`CedarEngine::evaluate_l7`] evaluates
//! `HttpRequest` requests against hand-authored `HttpRequest` policies in
//! `tests/fixtures/policies.cedar` — the authoritative Cedar-sourced-sandbox
//! path, where L7 policies are authored directly (no compilation step).

use openshell_policy_cedar::{CedarEngine, L7Request};

const POLICIES: &str = include_str!("fixtures/policies.cedar");

fn engine() -> CedarEngine {
    CedarEngine::from_policy_str(POLICIES).expect("fixture policy set must parse")
}

fn request(method: &str, path: &str) -> L7Request {
    L7Request {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        binary_path: "/sandbox/.venv/bin/python3".to_string(),
        ancestors: Vec::new(),
        host: "integrate.api.nvidia.com".to_string(),
        port: 443,
        method: method.to_string(),
        path: path.to_string(),
        command: String::new(),
        jsonrpc_method: String::new(),
    }
}

#[test]
fn allows_the_exact_permitted_request() {
    let allowed = engine()
        .evaluate_l7(&request("POST", "/v1/chat/completions"))
        .expect("request must be representable in the schema")
        .is_allow();
    assert!(allowed);
}

#[test]
fn denies_a_different_path_on_the_same_tunnel() {
    let allowed = engine()
        .evaluate_l7(&request("POST", "/v1/admin/delete-everything"))
        .expect("request must be representable in the schema")
        .is_allow();
    assert!(!allowed);
}

#[test]
fn denies_wrong_method() {
    let allowed = engine()
        .evaluate_l7(&request("GET", "/v1/chat/completions"))
        .expect("request must be representable in the schema")
        .is_allow();
    assert!(!allowed);
}

#[test]
fn denies_an_endpoint_with_no_http_request_policy() {
    let mut req = request("GET", "/simple/");
    req.host = "pypi.org".to_string();
    let allowed = engine()
        .evaluate_l7(&req)
        .expect("request must be representable in the schema")
        .is_allow();
    assert!(!allowed);
}

#[test]
fn allows_a_dns_resolved_host_with_a_trailing_dot() {
    let mut req = request("POST", "/v1/chat/completions");
    req.host = "integrate.api.nvidia.com.".to_string();
    let allowed = engine()
        .evaluate_l7(&req)
        .expect("request must be representable in the schema")
        .is_allow();
    assert!(allowed);
}
