// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-30

//! Checks that filesystem policy verification catches the authoring
//! mistakes it's meant to catch, and stays quiet on clean policies.

use openshell_policy_cedar::filesystem::{
    FilesystemAccess, FilesystemFinding, FilesystemPolicyInput, compile_filesystem_entities,
    verify_filesystem_policy,
};

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
