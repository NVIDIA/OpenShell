// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks Landlock grant derivation from authored Cedar policies, and that
//! filesystem policy verification catches the authoring mistakes it's meant
//! to catch while staying quiet on clean policies.

use openshell_policy_cedar::filesystem::{
    FilesystemAccess, FilesystemFinding, FilesystemPolicyInput, compile_filesystem_entities,
    verify_filesystem_policy,
};
use openshell_policy_cedar::{CedarEngineError, CedarNetworkEngine};

#[test]
fn clean_policy_has_no_findings() {
    let input = FilesystemPolicyInput {
        read_only: vec!["/usr".to_string(), "/etc".to_string()],
        read_write: vec!["/sandbox".to_string(), "/tmp".to_string()],
    };
    assert_eq!(verify_filesystem_policy(&input), vec![]);
}

#[test]
fn flags_conflicting_grant_between_read_only_and_read_write() {
    let input = FilesystemPolicyInput {
        read_only: vec!["/usr".to_string()],
        read_write: vec!["/usr/local/bin".to_string()],
    };
    let findings = verify_filesystem_policy(&input);
    assert_eq!(
        findings,
        vec![FilesystemFinding::ConflictingGrant {
            path: "/usr/local/bin".to_string(),
            read_only_entry: "/usr".to_string(),
            read_write_entry: "/usr/local/bin".to_string(),
        }]
    );
}

#[test]
fn flags_exact_duplicate_as_conflicting_grant() {
    let input = FilesystemPolicyInput {
        read_only: vec!["/etc".to_string()],
        read_write: vec!["/etc".to_string()],
    };
    let findings = verify_filesystem_policy(&input);
    assert_eq!(
        findings,
        vec![FilesystemFinding::ConflictingGrant {
            path: "/etc".to_string(),
            read_only_entry: "/etc".to_string(),
            read_write_entry: "/etc".to_string(),
        }]
    );
}

#[test]
fn flags_redundant_entry_within_the_same_access_list() {
    let input = FilesystemPolicyInput {
        read_only: vec!["/usr".to_string(), "/usr/bin".to_string()],
        read_write: vec![],
    };
    let findings = verify_filesystem_policy(&input);
    assert_eq!(
        findings,
        vec![FilesystemFinding::RedundantEntry {
            path: "/usr/bin".to_string(),
            covered_by: "/usr".to_string(),
            access: FilesystemAccess::ReadOnly,
        }]
    );
}

#[test]
fn does_not_confuse_sibling_paths_with_shared_prefixes() {
    // "/usr" must not be treated as an ancestor of "/usrbin" - component-aware
    // matching, not a raw string prefix check.
    let input = FilesystemPolicyInput {
        read_only: vec!["/usr".to_string(), "/usrbin".to_string()],
        read_write: vec![],
    };
    assert_eq!(verify_filesystem_policy(&input), vec![]);
}

#[test]
fn compiles_entities_for_a_clean_policy() {
    // `Entities::from_entities` also injects the schema's Action entities
    // (ReadFile/WriteFile/NetworkConnect) alongside the FilesystemPath
    // entities built here, so assert on individual FilesystemPath uids
    // rather than the total entity count.
    let input = FilesystemPolicyInput {
        read_only: vec!["/usr".to_string(), "/usr/bin".to_string()],
        read_write: vec!["/sandbox".to_string()],
    };
    let entities =
        compile_filesystem_entities(&input).expect("policy must compile to Cedar entities");

    for path in ["/usr", "/usr/bin", "/sandbox"] {
        let uid: cedar_policy::EntityUid = format!("Sandbox::FilesystemPath::{path:?}")
            .parse()
            .unwrap();
        assert!(
            entities.get(&uid).is_some(),
            "expected a FilesystemPath entity for {path}"
        );
    }

    let bin_uid: cedar_policy::EntityUid = "Sandbox::FilesystemPath::\"/usr/bin\"".parse().unwrap();
    let usr_uid: cedar_policy::EntityUid = "Sandbox::FilesystemPath::\"/usr\"".parse().unwrap();
    assert!(
        entities
            .ancestors(&bin_uid)
            .is_some_and(|mut ancestors| ancestors.any(|a| a == &usr_uid)),
        "/usr/bin must have /usr as a Cedar hierarchy ancestor"
    );
}

fn grants(policy: &str) -> FilesystemPolicyInput {
    CedarNetworkEngine::from_policy_str(policy)
        .expect("policy must load")
        .filesystem_grants()
        .clone()
}

fn rejection(policy: &str) -> CedarEngineError {
    CedarNetworkEngine::from_policy_str(policy).expect_err("policy must be rejected")
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
        let error = CedarNetworkEngine::from_policy_str(policy)
            .expect_err(&format!("{name} must be rejected"));
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
