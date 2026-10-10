// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks Landlock grant derivation from authored Cedar policies, and that
//! filesystem policies whose meaning Landlock cannot enforce are rejected.

use openshell_policy_cedar::{CedarEngine, CedarEngineError, FilesystemGrants};

fn grants(policy: &str) -> FilesystemGrants {
    CedarEngine::from_policy_str(policy)
        .expect("policy must load")
        .filesystem_grants()
        .clone()
}

fn rejection(policy: &str) -> CedarEngineError {
    CedarEngine::from_policy_str(policy).expect_err("policy must be rejected")
}

#[test]
fn derives_read_only_and_read_write_from_when_clause_permits() {
    let extracted = grants(
        r#"
        permit(
            principal is Sandbox::Process,
            action == Sandbox::Action::"ReadFile",
            resource is Sandbox::FilesystemPath
        )
        when {
            resource in Sandbox::FilesystemPath::"/usr"
            || resource in Sandbox::FilesystemPath::"/etc"
        };

        permit(
            principal is Sandbox::Process,
            action in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
            resource is Sandbox::FilesystemPath
        )
        when { resource in Sandbox::FilesystemPath::"/sandbox" };
        "#,
    );
    assert_eq!(extracted.read_only, vec!["/etc", "/usr"]);
    assert_eq!(extracted.read_write, vec!["/sandbox"]);
}

#[test]
fn derives_grants_from_scope_paths() {
    let extracted = grants(
        r#"
        permit(
            principal,
            action == Sandbox::Action::"ReadFile",
            resource in Sandbox::FilesystemPath::"/opt"
        );
        "#,
    );
    assert_eq!(extracted.read_only, vec!["/opt"]);
    assert!(extracted.read_write.is_empty());
}

#[test]
fn write_only_action_still_counts_as_read_write() {
    let extracted = grants(
        r#"
        permit(
            principal is Sandbox::Process,
            action == Sandbox::Action::"WriteFile",
            resource in Sandbox::FilesystemPath::"/tmp"
        );
        "#,
    );
    assert!(extracted.read_only.is_empty());
    assert_eq!(extracted.read_write, vec!["/tmp"]);
}

#[test]
fn network_policies_grant_no_paths() {
    let extracted = grants(
        r#"
        permit(
            principal is Sandbox::Process,
            action == Sandbox::Action::"NetworkConnect",
            resource is Sandbox::NetworkEndpoint
        )
        when { resource.host_port == "pypi.org:443" };
        "#,
    );
    assert!(extracted.read_only.is_empty());
    assert!(extracted.read_write.is_empty());
}

#[test]
fn rejects_forbid_on_a_filesystem_path() {
    let error = rejection(
        r#"
        permit(
            principal is Sandbox::Process,
            action == Sandbox::Action::"ReadFile",
            resource in Sandbox::FilesystemPath::"/usr"
        );

        forbid(
            principal is Sandbox::Process,
            action == Sandbox::Action::"ReadFile",
            resource in Sandbox::FilesystemPath::"/usr/secret"
        );
        "#,
    );
    assert!(
        matches!(error, CedarEngineError::FilesystemForbidUnsupported { .. }),
        "{error}"
    );
}

#[test]
fn rejects_forbid_without_a_path_literal() {
    // Previously undetected: no FilesystemPath literal, yet it forbids all
    // writes, which Landlock would not enforce.
    let error = rejection(
        r#"
        permit(
            principal,
            action == Sandbox::Action::"WriteFile",
            resource in Sandbox::FilesystemPath::"/data"
        );
        forbid(principal, action == Sandbox::Action::"WriteFile", resource);
        "#,
    );
    assert!(
        matches!(error, CedarEngineError::FilesystemForbidUnsupported { .. }),
        "{error}"
    );
}

#[test]
fn rejects_unsupported_filesystem_policy_shapes() {
    let cases = [
        (
            "unless clause naming the path",
            r#"permit(principal, action == Sandbox::Action::"ReadFile", resource)
               unless { resource in Sandbox::FilesystemPath::"/secret" };"#,
        ),
        (
            "condition that never holds",
            r#"permit(principal, action == Sandbox::Action::"ReadFile",
                      resource in Sandbox::FilesystemPath::"/etc")
               when { false };"#,
        ),
        (
            "write literal only inside a condition",
            r#"permit(principal, action, resource in Sandbox::FilesystemPath::"/data")
               when { action != Sandbox::Action::"WriteFile" };"#,
        ),
        (
            "principal constraint",
            r#"permit(principal == Sandbox::Process::"nobody",
                      action == Sandbox::Action::"WriteFile",
                      resource in Sandbox::FilesystemPath::"/");"#,
        ),
        (
            "exact path match",
            r#"permit(principal, action == Sandbox::Action::"ReadFile",
                      resource == Sandbox::FilesystemPath::"/");"#,
        ),
        (
            "unconstrained action",
            r#"permit(principal, action, resource in Sandbox::FilesystemPath::"/data");"#,
        ),
        (
            "binary-scoped condition",
            r#"permit(principal, action == Sandbox::Action::"WriteFile", resource)
               when { resource in Sandbox::FilesystemPath::"/etc"
                      && principal.user == Sandbox::User::"root" };"#,
        ),
        (
            "unbounded resource",
            r#"permit(principal, action == Sandbox::Action::"ReadFile",
                      resource is Sandbox::FilesystemPath);"#,
        ),
    ];
    for (name, policy) in cases {
        let error =
            CedarEngine::from_policy_str(policy).expect_err(&format!("{name} must be rejected"));
        assert!(
            matches!(error, CedarEngineError::UnsupportedPolicy { .. }),
            "{name}: {error}"
        );
    }
}

#[test]
fn rejects_misspelled_action() {
    let error = rejection(
        r#"permit(principal, action == Sandbox::Action::"Writefile",
                  resource in Sandbox::FilesystemPath::"/data");"#,
    );
    assert!(
        matches!(error, CedarEngineError::PolicyValidation { .. }),
        "{error}"
    );
}
