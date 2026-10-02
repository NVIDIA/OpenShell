// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks which `NetworkEndpoint`s [`CedarNetworkEngine::l7_protocol`]
//! routes into L7 inspection, how the `@protocol(...)` annotation is read,
//! and that `HttpRequest` policies the proxy could not route are rejected.

use openshell_policy_cedar::{CedarEngineError, CedarNetworkEngine, L7Protocol};

fn engine(policy: &str) -> CedarNetworkEngine {
    CedarNetworkEngine::from_policy_str(policy).expect("policy must load")
}

fn rejection(policy: &str) -> CedarEngineError {
    CedarNetworkEngine::from_policy_str(policy).expect_err("policy must be rejected")
}

#[test]
fn http_request_permit_without_annotation_defaults_to_rest() {
    let engine = engine(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "GET" };
"#,
    );
    assert_eq!(
        engine.l7_protocol("api.example.com", 443),
        Some(L7Protocol::Rest)
    );
    assert_eq!(
        engine.l7_protocol("API.example.com.", 443),
        Some(L7Protocol::Rest),
        "lookup normalizes the requested host"
    );
    assert_eq!(engine.l7_protocol("api.example.com", 8443), None);
}

#[test]
fn protocol_annotation_is_read() {
    let engine = engine(
        r#"
@protocol("json-rpc")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"rpc.example.com:443"
)
when { context.jsonrpc_method == "eth_blockNumber" };
"#,
    );
    assert_eq!(
        engine.l7_protocol("rpc.example.com", 443),
        Some(L7Protocol::JsonRpc)
    );
}

#[test]
fn connect_only_policies_are_not_l7_endpoints() {
    let engine = engine(
        r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.binary_path == "/usr/bin/curl" };
"#,
    );
    assert_eq!(engine.l7_protocol("api.example.com", 443), None);
}

#[test]
fn forbid_alone_still_routes_the_endpoint_into_inspection() {
    // Cedar denies by default, so a forbid-only endpoint denies every
    // request. Skipping inspection would instead allow every request.
    let engine = engine(
        r#"
forbid (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "DELETE" };
"#,
    );
    assert_eq!(
        engine.l7_protocol("api.example.com", 443),
        Some(L7Protocol::Rest)
    );
}

#[test]
fn unannotated_policies_take_the_declared_protocol() {
    let engine = engine(
        r#"
@protocol("json-rpc")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"rpc.example.com:443"
);

forbid (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"rpc.example.com:443"
)
when { context.jsonrpc_method == "admin_shutdown" };
"#,
    );
    assert_eq!(
        engine.l7_protocol("rpc.example.com", 443),
        Some(L7Protocol::JsonRpc)
    );
}

#[test]
fn rejects_http_request_policies_without_a_scope_endpoint() {
    let cases = [
        r#"permit(principal, action == Sandbox::Action::"HttpRequest", resource)
           when { resource.host == "api.example.com" && context.method == "GET" };"#,
        r#"permit(principal, action == Sandbox::Action::"HttpRequest", resource)
           when { resource.host like "*.example.com" };"#,
        r#"forbid(principal, action == Sandbox::Action::"HttpRequest", resource)
           when { context.method == "DELETE" };"#,
    ];
    for policy in cases {
        let error = rejection(policy);
        assert!(
            matches!(error, CedarEngineError::UnsupportedPolicy { .. }),
            "{policy}: {error}"
        );
    }
}

#[test]
fn rejects_unsupported_protocols() {
    for protocol in ["sql", "mcp", "graphql", "http", "REST", "bogus"] {
        let policy = format!(
            r#"@protocol("{protocol}")
               permit(principal, action == Sandbox::Action::"HttpRequest",
                      resource == Sandbox::NetworkEndpoint::"db.example.com:5432");"#
        );
        let error = rejection(&policy);
        assert!(
            matches!(error, CedarEngineError::UnsupportedL7Protocol { .. }),
            "{protocol}: {error}"
        );
    }
}

#[test]
fn rejects_conflicting_protocols_for_one_endpoint() {
    let error = rejection(
        r#"
@protocol("json-rpc")
permit(principal, action == Sandbox::Action::"HttpRequest",
       resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("rest")
permit(principal, action == Sandbox::Action::"HttpRequest",
       resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#,
    );
    assert!(
        matches!(error, CedarEngineError::ConflictingL7Protocol { .. }),
        "{error}"
    );
}

#[test]
fn rejects_protocol_annotation_on_a_connect_policy() {
    let error = rejection(
        r#"
@protocol("rest")
permit(principal, action == Sandbox::Action::"NetworkConnect",
       resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#,
    );
    assert!(
        matches!(error, CedarEngineError::UnsupportedPolicy { .. }),
        "{error}"
    );
}
