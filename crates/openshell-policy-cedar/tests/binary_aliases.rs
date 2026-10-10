// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks `context.binary_aliases`: which binary paths a policy set asks the
//! supervisor to resolve, the forms it accepts, and how the set decides
//! requests on both network actions.

use openshell_policy_cedar::{CedarEngine, CedarEngineError, L7Request, NetworkRequest};

fn load(policy: &str) -> Result<CedarEngine, CedarEngineError> {
    CedarEngine::from_policy_str(policy)
}

fn connect(binary: &str, ancestors: &[&str], aliases: &[&str]) -> NetworkRequest {
    NetworkRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: "pypi.org".to_string(),
        port: 443,
        binary_path: binary.to_string(),
        ancestors: ancestors.iter().map(ToString::to_string).collect(),
        binary_aliases: aliases.iter().map(ToString::to_string).collect(),
        destination_ip: None,
    }
}

/// The Cedar form of a YAML binary entry for `/usr/bin/python3`.
const PYTHON: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when {
    context.binary_path == "/usr/bin/python3"
    || context.ancestors.contains("/usr/bin/python3")
    || context.binary_aliases.contains("/usr/bin/python3")
};
"#;

#[test]
fn alias_paths_are_collected_from_every_accepted_form() {
    let policy = format!(
        r#"{PYTHON}
forbid (principal, action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when {{
    context.binary_aliases.containsAny(["/usr/bin/node", "/usr/bin/python3"])
    || context.binary_aliases.containsAll(["/usr/local/bin/tool"])
}};
"#
    );
    let engine = load(&policy).expect("policy loads");
    assert_eq!(
        engine.binary_alias_paths().collect::<Vec<_>>(),
        ["/usr/bin/node", "/usr/bin/python3", "/usr/local/bin/tool"]
    );
    assert_eq!(
        load(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context.binary_path == "/x" };"#
        )
        .expect("policy loads")
        .binary_alias_paths()
        .count(),
        0
    );
}

#[test]
fn unsupported_alias_forms_are_rejected() {
    for condition in [
        "context.binary_aliases.isEmpty()",
        r#"context.binary_aliases == ["/usr/bin/python3"]"#,
        "context.binary_aliases.contains(context.binary_path)",
        r"context.binary_aliases.containsAny(context.ancestors)",
        r#"context.binary_aliases.contains("python3")"#,
        r#"context.binary_aliases.contains("/usr/bin/*")"#,
        r#"context.binary_aliases.containsAny(["/usr/bin/python3", "/opt/*/python"])"#,
        r"context == context",
    ] {
        let policy = format!(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ {condition} }};"#
        );
        let error = load(&policy).expect_err(condition);
        assert!(
            matches!(error, CedarEngineError::InvalidBinaryAlias { .. }),
            "{condition}: {error}"
        );
    }
}

#[test]
fn reading_other_context_fields_needs_no_alias_paths() {
    let engine = load(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context has binary_aliases && context.ancestors.contains("/bin/bash") };"#,
    )
    .expect("policy loads");
    assert_eq!(engine.binary_alias_paths().count(), 0);
}

#[test]
fn an_alias_matches_a_connection_like_the_symlinked_path() {
    let engine = load(PYTHON).expect("policy loads");
    let allows = |request: NetworkRequest| {
        engine
            .evaluate_network(&request)
            .expect("evaluates")
            .is_allow()
    };
    assert!(allows(connect("/usr/bin/python3", &[], &[])));
    assert!(allows(connect(
        "/usr/bin/python3.11",
        &[],
        &["/usr/bin/python3"]
    )));
    assert!(allows(connect(
        "/usr/bin/curl",
        &["/usr/bin/python3.11"],
        &["/usr/bin/python3"]
    )));
    assert!(!allows(connect("/usr/bin/python3.11", &[], &[])));
}

#[test]
fn an_alias_reaches_a_forbid_on_requests() {
    let engine = load(
        r#"
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443");
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { context.binary_aliases.contains("/usr/bin/python3") };
"#,
    )
    .expect("policy loads");
    let allows = |aliases: &[&str]| {
        engine
            .evaluate_l7(&L7Request {
                user: "sandbox".to_string(),
                group: "sandbox".to_string(),
                binary_path: "/usr/bin/python3.11".to_string(),
                binary_aliases: aliases.iter().map(ToString::to_string).collect(),
                host: "pypi.org".to_string(),
                port: 443,
                method: "GET".to_string(),
                path: "/simple/".to_string(),
                ..Default::default()
            })
            .expect("evaluates")
            .is_allow()
    };
    assert!(allows(&[]));
    assert!(!allows(&["/usr/bin/python3"]));
}
