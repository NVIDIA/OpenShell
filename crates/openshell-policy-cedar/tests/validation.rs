// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks that strict schema validation rejects policies reading attributes
//! the schema does not declare for their action, instead of loading a
//! policy that could never match.

use openshell_policy_cedar::{CedarEngine, CedarEngineError};

fn validation_failure(policy: &str) -> String {
    match CedarEngine::from_policy_str(policy) {
        Err(CedarEngineError::PolicyValidation { reason }) => reason,
        other => panic!("expected PolicyValidation, got {other:?}"),
    }
}

#[test]
fn network_connect_has_no_request_fields() {
    // No request has been read at CONNECT time. A connection permit that
    // read one of these used to compare against "" and silently deny every
    // connection.
    for (expected, condition) in [
        ("method", r#"context.method == "GET""#),
        ("path", r#"context.path like("/repos/**", "/")"#),
        ("command", r#"context.command == "SELECT""#),
        // Cedar accepts a `has` test of an undeclared attribute, as always
        // false; OpenShell rejects it, since the policy could never match.
        ("`context has method`", "context has method"),
        ("`context has path`", "!(context has path)"),
    ] {
        let reason = validation_failure(&format!(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when {{ {condition} }};"#
        ));
        assert!(reason.contains(expected), "{condition}: {reason}");
    }
}

#[test]
fn has_tests_of_declared_attributes_load() {
    // A forbid, since a permit may read `destination_ip` only in range tests.
    let engine = CedarEngine::from_policy_str(
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context has destination_ip && context has binary_path && principal has user
       && resource has host_port && {workdir: "/sandbox"} has workdir };
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context has method && context has query };"#,
    );
    assert!(engine.is_ok(), "{engine:?}");
}

#[test]
fn has_tests_are_checked_for_every_action_in_scope() {
    let reason = validation_failure(
        r#"permit (
    principal,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when { context has method };"#,
    );
    assert!(reason.contains("action NetworkConnect"), "{reason}");

    // `resource has host` is false for every file, and the unconstrained
    // scope covers the filesystem actions.
    let reason =
        validation_failure("forbid (principal, action, resource) when { resource has host };");
    assert!(reason.contains("Sandbox::FilesystemPath"), "{reason}");
    let network_only = CedarEngine::from_policy_str(
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource has host };"#,
    );
    assert!(network_only.is_ok(), "{network_only:?}");
}

#[test]
fn a_policy_on_both_network_actions_cannot_read_request_fields() {
    // The scope covers NetworkConnect, which has no `method`, so the policy
    // fails validation; split it into one policy per action.
    let reason = validation_failure(
        r#"permit (
    principal,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when { context.method == "GET" };"#,
    );
    assert!(reason.contains("method"), "{reason}");

    let split = CedarEngine::from_policy_str(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.method == "GET" };"#,
    );
    assert!(split.is_ok(), "{split:?}");
}

#[test]
fn http_request_keeps_the_request_fields() {
    let engine = CedarEngine::from_policy_str(
        r#"permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.method == "GET" && context.path == "/" && context.command == "" };"#,
    );
    assert!(engine.is_ok(), "{engine:?}");
}

#[test]
fn process_has_no_workdir() {
    // `workdir` was declared optional and never populated, so a condition
    // on it could only ever be false.
    for (expected, condition) in [
        ("`principal has workdir`", "principal has workdir"),
        (
            "workdir",
            r#"principal.workdir in Sandbox::FilesystemPath::"/sandbox""#,
        ),
    ] {
        let reason = validation_failure(&format!(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when {{ {condition} }};"#
        ));
        assert!(reason.contains(expected), "{condition}: {reason}");
    }
}
